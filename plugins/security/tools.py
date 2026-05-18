"""Offline security helper tools for the bundled security plugin."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse


SECURITY_SCOPE_CHECK_SCHEMA = {
    "name": "security_scope_check",
    "description": (
        "Check whether a hostname, URL, IP, or CIDR is inside an explicit "
        "authorized security assessment scope. Deny rules win over allow rules."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Hostname, URL, IP address, or CIDR to check.",
            },
            "allowed_targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Allowed hostnames, wildcard domains such as *.example.com, "
                    "URLs, IP addresses, or CIDR ranges."
                ),
                "default": [],
            },
            "denied_targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Explicit deny rules. These override allowed_targets.",
                "default": [],
            },
            "allow_if_unscoped": {
                "type": "boolean",
                "description": (
                    "When true, allow targets that do not match any allow rule. "
                    "Use only for inventory triage, not active testing."
                ),
                "default": False,
            },
        },
        "required": ["target"],
    },
}


SECURITY_EXTRACT_IOCS_SCHEMA = {
    "name": "security_extract_iocs",
    "description": (
        "Extract common defensive indicators from text: URLs, domains, IPs, "
        "emails, hashes, and CVE identifiers. Handles simple defanged forms."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Text to inspect."},
            "include_private_ips": {
                "type": "boolean",
                "description": "Include private, loopback, and link-local IP addresses.",
                "default": True,
            },
        },
        "required": ["text"],
    },
}


SECURITY_NORMALIZE_FINDINGS_SCHEMA = {
    "name": "security_normalize_findings",
    "description": (
        "Normalize generic, Nuclei-style, Trivy-style, and Semgrep-style "
        "scanner findings into a common JSON structure."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "scanner_output": {
                "oneOf": [{"type": "string"}, {"type": "object"}, {"type": "array"}],
                "description": "Scanner JSON as a string, object, or array.",
            },
            "source": {
                "type": "string",
                "description": "Optional source label such as nuclei, trivy, semgrep, or generic.",
                "default": "generic",
            },
        },
        "required": ["scanner_output"],
    },
}


SECURITY_PRIORITIZE_FINDINGS_SCHEMA = {
    "name": "security_prioritize_findings",
    "description": (
        "Score and sort normalized or raw security findings using severity, "
        "CVSS, exposure, exploitability, and optional asset context."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "findings": {
                "oneOf": [{"type": "string"}, {"type": "object"}, {"type": "array"}],
                "description": "Findings as normalized JSON, raw scanner JSON, object, or array.",
            },
            "asset_context": {
                "type": "object",
                "description": (
                    "Optional map of asset name to context, for example "
                    "{\"app.example.com\": {\"exposure\": \"internet\", \"criticality\": \"high\"}}."
                ),
                "default": {},
            },
            "max_items": {
                "type": "integer",
                "description": "Maximum prioritized findings to return.",
                "default": 50,
                "minimum": 1,
                "maximum": 500,
            },
        },
        "required": ["findings"],
    },
}


_SEVERITY_BASE = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "moderate": 45,
    "low": 20,
    "info": 5,
    "informational": 5,
    "unknown": 10,
}


def handle_scope_check(args: dict[str, Any], **_: Any) -> str:
    target = str(args.get("target", "")).strip()
    allowed_targets = _coerce_string_list(args.get("allowed_targets"))
    denied_targets = _coerce_string_list(args.get("denied_targets"))
    allow_if_unscoped = bool(args.get("allow_if_unscoped", False))

    normalized = _normalize_target(target)
    if not normalized["value"]:
        return _json({"success": False, "allowed": False, "error": "target is required"})

    denied_match = _first_matching_rule(normalized, denied_targets)
    if denied_match:
        return _json({
            "success": True,
            "allowed": False,
            "reason": "target matched denied scope",
            "target": normalized,
            "matched_rule": denied_match,
        })

    allowed_match = _first_matching_rule(normalized, allowed_targets)
    if allowed_match:
        return _json({
            "success": True,
            "allowed": True,
            "reason": "target matched allowed scope",
            "target": normalized,
            "matched_rule": allowed_match,
        })

    if allow_if_unscoped:
        return _json({
            "success": True,
            "allowed": True,
            "reason": "target did not match any allow rule, but allow_if_unscoped is true",
            "target": normalized,
            "matched_rule": None,
        })

    return _json({
        "success": True,
        "allowed": False,
        "reason": "target is outside the authorized scope",
        "target": normalized,
        "matched_rule": None,
    })


def handle_extract_iocs(args: dict[str, Any], **_: Any) -> str:
    text = str(args.get("text", ""))
    include_private_ips = bool(args.get("include_private_ips", True))
    normalized_text = _refang(text)

    urls = _unique(_trim_url(url) for url in re.findall(r"\bhttps?://[^\s<>'\"]+", normalized_text, re.I))
    emails = _unique(match.lower() for match in re.findall(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        normalized_text,
        re.I,
    ))
    cves = _unique(match.upper() for match in re.findall(r"\bCVE-\d{4}-\d{4,}\b", normalized_text, re.I))

    hashes = {
        "md5": _unique(re.findall(r"\b[a-fA-F0-9]{32}\b", normalized_text)),
        "sha1": _unique(re.findall(r"\b[a-fA-F0-9]{40}\b", normalized_text)),
        "sha256": _unique(re.findall(r"\b[a-fA-F0-9]{64}\b", normalized_text)),
    }

    ip_candidates = set(re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", normalized_text))
    ipv4: list[str] = []
    for candidate in sorted(ip_candidates):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.version != 4:
            continue
        if not include_private_ips and not ip.is_global:
            continue
        ipv4.append(str(ip))

    ipv6: list[str] = []
    for token in re.findall(r"(?<![\w:])(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9]{0,4}(?![\w:])", normalized_text):
        try:
            ip = ipaddress.ip_address(token.strip("[]"))
        except ValueError:
            continue
        if ip.version != 6:
            continue
        if not include_private_ips and not ip.is_global:
            continue
        ipv6.append(str(ip))

    domain_candidates: set[str] = set()
    for url in urls:
        host = urlparse(url).hostname
        if host:
            domain_candidates.add(host.lower())
    for email in emails:
        domain_candidates.add(email.rsplit("@", 1)[1].lower())
    for match in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b", normalized_text):
        domain_candidates.add(match.lower().strip("."))

    domains = []
    for domain in sorted(domain_candidates):
        if _is_ip_literal(domain):
            continue
        domains.append(domain)

    return _json({
        "success": True,
        "counts": {
            "urls": len(urls),
            "domains": len(domains),
            "ipv4": len(ipv4),
            "ipv6": len(ipv6),
            "emails": len(emails),
            "cves": len(cves),
            "hashes": sum(len(v) for v in hashes.values()),
        },
        "indicators": {
            "urls": urls,
            "domains": domains,
            "ipv4": ipv4,
            "ipv6": _unique(ipv6),
            "emails": emails,
            "cves": cves,
            "hashes": hashes,
        },
    })


def handle_normalize_findings(args: dict[str, Any], **_: Any) -> str:
    scanner_output = args.get("scanner_output")
    source = str(args.get("source", "generic") or "generic")
    parsed = _parse_jsonish(scanner_output)
    findings = normalize_findings(parsed, source=source)
    return _json({
        "success": True,
        "source": source,
        "count": len(findings),
        "severity_counts": dict(Counter(f["severity"] for f in findings)),
        "findings": findings,
    })


def handle_prioritize_findings(args: dict[str, Any], **_: Any) -> str:
    parsed = _parse_jsonish(args.get("findings"))
    asset_context = args.get("asset_context") if isinstance(args.get("asset_context"), dict) else {}
    max_items = _bounded_int(args.get("max_items", 50), minimum=1, maximum=500)

    findings = _extract_normalized_findings(parsed)
    if not findings:
        findings = normalize_findings(parsed, source="generic")

    prioritized = []
    for finding in findings:
        item = dict(finding)
        score, factors = _score_finding(item, asset_context)
        item["priority_score"] = score
        item["priority"] = _priority_label(score)
        item["priority_factors"] = factors
        prioritized.append(item)

    prioritized.sort(key=lambda item: item["priority_score"], reverse=True)
    return _json({
        "success": True,
        "count": len(prioritized),
        "returned": min(len(prioritized), max_items),
        "findings": prioritized[:max_items],
    })


def normalize_findings(data: Any, source: str = "generic") -> list[dict[str, Any]]:
    records = _iter_finding_records(data)
    findings = []
    for record, parent in records:
        finding = _normalize_record(record, parent=parent, source=source)
        if finding:
            findings.append(finding)
    return findings


def _normalize_record(record: dict[str, Any], parent: dict[str, Any] | None, source: str) -> dict[str, Any] | None:
    info = record.get("info") if isinstance(record.get("info"), dict) else {}
    vulnerability_id = _first_value(
        record,
        "id", "finding_id", "vulnerability_id", "VulnerabilityID",
        "cve", "CVE", "rule_id", "check_id", "template-id", "template_id",
    )
    if vulnerability_id is None and info:
        vulnerability_id = _first_value(info, "id", "name")

    title = _first_value(record, "title", "Title", "name", "message", "description", "Summary")
    if title is None and info:
        title = _first_value(info, "name", "description")
    if title is None:
        title = str(vulnerability_id or "Untitled finding")

    severity = _normalize_severity(
        _first_value(record, "severity", "Severity", "level", "priority")
        or _first_value(info, "severity")
    )
    cvss = _coerce_float(
        _first_value(record, "cvss", "CVSS", "cvss_score", "CVSSScore")
        or _nested_value(record, ("CVSS", "nvd", "V3Score"))
        or _nested_value(record, ("CVSS", "redhat", "V3Score"))
    )
    if cvss is not None and severity == "unknown":
        severity = _severity_from_cvss(cvss)

    asset = _first_value(record, "asset", "target", "host", "url", "matched-at", "matched_at", "resource")
    if asset is None and parent:
        asset = _first_value(parent, "Target", "target", "asset", "host", "resource")
    package_name = _first_value(record, "PkgName", "package", "packageName", "component")

    evidence = _first_value(record, "evidence", "location", "path", "file", "uri", "matched-at", "matched_at")
    if evidence is None and parent:
        evidence = _first_value(parent, "Target", "target")

    references = record.get("references") or record.get("References") or info.get("reference")
    if isinstance(references, str):
        references = [references]
    if not isinstance(references, list):
        references = []

    exploit_available = _coerce_bool(
        _first_value(record, "exploit_available", "ExploitAvailable", "has_exploit")
    )

    return {
        "id": str(vulnerability_id or "").strip() or None,
        "title": str(title).strip(),
        "severity": severity,
        "cvss": cvss,
        "asset": str(asset).strip() if asset is not None else None,
        "package": str(package_name).strip() if package_name is not None else None,
        "evidence": str(evidence).strip() if evidence is not None else None,
        "exploit_available": exploit_available,
        "source": source,
        "references": [str(ref) for ref in references[:10]],
        "raw": record,
    }


def _iter_finding_records(data: Any) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    if isinstance(data, list):
        return [(item, None) for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []

    records: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for key in ("findings", "results", "vulnerabilities", "matches", "issues"):
        value = data.get(key)
        if isinstance(value, list):
            records.extend((item, data) for item in value if isinstance(item, dict))

    trivy_results = data.get("Results")
    if isinstance(trivy_results, list):
        for result in trivy_results:
            if not isinstance(result, dict):
                continue
            for vuln in result.get("Vulnerabilities") or []:
                if isinstance(vuln, dict):
                    records.append((vuln, result))
            for secret in result.get("Secrets") or []:
                if isinstance(secret, dict):
                    records.append((secret, result))

    semgrep_results = data.get("results")
    if isinstance(semgrep_results, list):
        records.extend((item, data) for item in semgrep_results if isinstance(item, dict))

    if not records and _looks_like_finding(data):
        records.append((data, None))
    return records


def _score_finding(finding: dict[str, Any], asset_context: dict[str, Any]) -> tuple[int, list[str]]:
    severity = _normalize_severity(finding.get("severity"))
    score = _SEVERITY_BASE.get(severity, 10)
    factors = [f"severity:{severity}"]

    cvss = _coerce_float(finding.get("cvss"))
    if cvss is not None:
        cvss_score = int(min(max(cvss, 0), 10) * 10)
        if cvss_score > score:
            score = cvss_score
            factors.append(f"cvss:{cvss:g}")

    asset = str(finding.get("asset") or "")
    context = asset_context.get(asset, {}) if isinstance(asset_context, dict) else {}
    if not isinstance(context, dict):
        context = {}

    exposure = str(finding.get("exposure") or context.get("exposure") or "").lower()
    if exposure in {"internet", "public", "external"}:
        score += 15
        factors.append("internet_exposed")

    criticality = str(finding.get("criticality") or context.get("criticality") or "").lower()
    if criticality in {"critical", "tier0"}:
        score += 20
        factors.append("critical_asset")
    elif criticality in {"high", "important"}:
        score += 10
        factors.append("high_value_asset")

    if finding.get("exploit_available") is True:
        score += 15
        factors.append("exploit_available")

    if str(finding.get("package") or "").lower() in {"openssl", "log4j", "spring-core"}:
        score += 5
        factors.append("sensitive_component")

    return min(score, 100), factors


def _extract_normalized_findings(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [dict(item) for item in data["findings"] if isinstance(item, dict)]
    if isinstance(data, list) and all(isinstance(item, dict) and "severity" in item for item in data):
        return [dict(item) for item in data]
    return []


def _priority_label(score: int) -> str:
    if score >= 90:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 45:
        return "P2"
    if score >= 20:
        return "P3"
    return "P4"


def _normalize_target(value: str) -> dict[str, Any]:
    raw = value.strip()
    if not raw:
        return {"raw": value, "value": "", "kind": "empty"}

    try:
        if "/" in raw and "://" not in raw:
            network = ipaddress.ip_network(raw.strip("[]"), strict=False)
            return {
                "raw": value,
                "value": str(network),
                "host": str(network),
                "kind": "cidr",
                "is_private": not network.is_global,
            }
        ip = ipaddress.ip_address(raw.strip("[]"))
        return {
            "raw": value,
            "value": str(ip),
            "host": str(ip),
            "kind": "ip",
            "is_private": not ip.is_global,
        }
    except ValueError:
        pass

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw
    host = host.strip().strip("[]").lower().rstrip(".")
    if "@" in host:
        host = host.rsplit("@", 1)[1]

    network = None
    ip = None
    kind = "hostname"
    try:
        if "/" in host:
            network = ipaddress.ip_network(host, strict=False)
            kind = "cidr"
        else:
            ip = ipaddress.ip_address(host)
            kind = "ip"
    except ValueError:
        pass

    return {
        "raw": value,
        "value": str(network or ip or host),
        "host": host,
        "kind": kind,
        "is_private": bool((ip and not ip.is_global) or (network and not network.is_global)),
    }


def _first_matching_rule(target: dict[str, Any], rules: list[str]) -> str | None:
    for rule in rules:
        if _rule_matches(target, rule):
            return rule
    return None


def _rule_matches(target: dict[str, Any], rule: str) -> bool:
    normalized_rule = _normalize_target(rule)
    if not normalized_rule["value"]:
        return False

    target_host = str(target.get("host") or target.get("value") or "").lower()
    rule_host = str(normalized_rule.get("host") or normalized_rule.get("value") or "").lower()

    try:
        if normalized_rule["kind"] == "cidr":
            network = ipaddress.ip_network(normalized_rule["value"], strict=False)
            if target["kind"] == "cidr":
                return ipaddress.ip_network(target["value"], strict=False).subnet_of(network)
            if target["kind"] == "ip":
                return ipaddress.ip_address(target["value"]) in network
        elif normalized_rule["kind"] == "ip":
            if target["kind"] == "cidr":
                target_network = ipaddress.ip_network(target["value"], strict=False)
                rule_ip = ipaddress.ip_address(normalized_rule["value"])
                return target_network.num_addresses == 1 and rule_ip in target_network
            return target["kind"] == "ip" and target["value"] == normalized_rule["value"]
    except ValueError:
        return False

    if rule_host.startswith("*."):
        suffix = rule_host[1:]
        return target_host.endswith(suffix) and target_host != rule_host[2:]
    return target_host == rule_host


def _parse_jsonish(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON input: {exc}") from exc
    return value


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _coerce_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _coerce_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def _bounded_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = minimum
    return min(max(parsed, minimum), maximum)


def _first_value(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _nested_value(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    current: Any = record
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _normalize_severity(value: Any) -> str:
    severity = str(value or "unknown").strip().lower()
    return severity if severity in _SEVERITY_BASE else "unknown"


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _looks_like_finding(data: dict[str, Any]) -> bool:
    keys = set(data)
    return bool(keys & {
        "id", "finding_id", "vulnerability_id", "VulnerabilityID", "cve",
        "severity", "Severity", "title", "message", "template-id", "rule_id",
    })


def _refang(text: str) -> str:
    result = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    return (
        result
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":")
    )


def _trim_url(url: str) -> str:
    return url.rstrip(".,;)]}")


def _unique(values: Any) -> list[str]:
    seen = set()
    result = []
    for value in values:
        item = str(value)
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False
