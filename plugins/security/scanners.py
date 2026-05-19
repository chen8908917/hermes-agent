"""Controlled scanner adapters for the security plugin."""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from .workflows import _scope_decision


SECURITY_PARSE_NMAP_XML_SCHEMA = {
    "name": "security_parse_nmap_xml",
    "description": "Parse nmap XML output into normalized hosts, ports, services, and summary counts.",
    "parameters": {
        "type": "object",
        "properties": {
            "nmap_xml": {
                "type": "string",
                "description": "Raw nmap XML, for example from nmap -oX -.",
            },
        },
        "required": ["nmap_xml"],
    },
}


SECURITY_NMAP_PLAN_SCHEMA = {
    "name": "security_nmap_plan",
    "description": (
        "Create a scoped, conservative nmap scan plan using approved profiles. "
        "Does not execute nmap."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Hosts, URLs, IPs, or CIDRs to scan.",
            },
            "allowed_targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Authorized hostnames, wildcard domains, IPs, or CIDRs.",
                "default": [],
            },
            "denied_targets": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "mode": {
                "type": "string",
                "enum": ["assessment", "range", "ctf"],
                "default": "assessment",
            },
            "phase_id": {
                "type": "string",
                "description": "Expected active phase, for example active_recon, service_enumeration, or ctf_target_recon.",
                "default": "active_recon",
            },
            "scan_profile": {
                "type": "string",
                "enum": ["host_discovery", "top_ports", "service_detection", "specific_ports"],
                "default": "top_ports",
            },
            "ports": {
                "type": "string",
                "description": "Comma-separated ports/ranges for specific_ports profile, for example 22,80,443,8000-8100.",
                "default": "",
            },
            "timing": {
                "type": "string",
                "enum": ["polite", "normal"],
                "default": "polite",
            },
            "top_ports": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000,
                "default": 100,
            },
            "max_cidr_hosts": {
                "type": "integer",
                "description": "Largest CIDR target size allowed by this adapter.",
                "minimum": 1,
                "maximum": 4096,
                "default": 256,
            },
        },
        "required": ["targets", "allowed_targets"],
    },
}


SECURITY_NMAP_SCAN_SCHEMA = {
    "name": "security_nmap_scan",
    "description": (
        "Run a scoped nmap scan through conservative profiles. Defaults to dry-run; "
        "requires execute=true, active_testing approval, and workflow gate success."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            **SECURITY_NMAP_PLAN_SCHEMA["parameters"]["properties"],
            "execute": {
                "type": "boolean",
                "description": "When false, return the scan plan without running nmap.",
                "default": False,
            },
            "approvals": {
                "type": "object",
                "description": "Approval flags, for example {\"active_testing\": true}.",
                "default": {},
            },
            "available_artifacts": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Workflow artifacts available to the active phase.",
                "default": [],
            },
            "timeout_seconds": {
                "type": "integer",
                "minimum": 5,
                "maximum": 300,
                "default": 60,
            },
        },
        "required": ["targets", "allowed_targets"],
    },
}


_TARGET_SCOPE_PROPERTIES = {
    "target": {
        "type": "string",
        "description": "Single URL, host, domain, IP, or CIDR target.",
    },
    "targets": {
        "type": "array",
        "items": {"type": "string"},
        "description": "URLs, hosts, domains, IPs, or CIDRs.",
        "default": [],
    },
    "allowed_targets": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Authorized domains, wildcard domains, hosts, IPs, or CIDRs.",
        "default": [],
    },
    "denied_targets": {
        "type": "array",
        "items": {"type": "string"},
        "default": [],
    },
    "mode": {
        "type": "string",
        "enum": ["assessment", "range", "ctf"],
        "default": "assessment",
    },
    "phase_id": {
        "type": "string",
        "default": "active_recon",
    },
}


SECURITY_DIR_ENUM_PLAN_SCHEMA = {
    "name": "security_dir_enum_plan",
    "description": "Create a scoped dirsearch/gobuster directory enumeration plan. Does not execute.",
    "parameters": {
        "type": "object",
        "properties": {
            **_TARGET_SCOPE_PROPERTIES,
            "tool": {
                "type": "string",
                "enum": ["dirsearch", "gobuster"],
                "default": "dirsearch",
            },
            "wordlist": {
                "type": "string",
                "description": "Optional wordlist path. Required for gobuster execution; omitted in dry-run plans.",
                "default": "",
            },
            "extensions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Small allow-listed extension set for web content discovery.",
                "default": [],
            },
            "rate_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 50,
                "default": 5,
            },
        },
        "required": ["target", "allowed_targets"],
    },
}


SECURITY_DIR_ENUM_SCAN_SCHEMA = {
    "name": "security_dir_enum_scan",
    "description": "Run scoped dirsearch/gobuster enumeration with conservative limits. Defaults to dry-run.",
    "parameters": {
        "type": "object",
        "properties": {
            **SECURITY_DIR_ENUM_PLAN_SCHEMA["parameters"]["properties"],
            "execute": {"type": "boolean", "default": False},
            "approvals": {"type": "object", "default": {}},
            "available_artifacts": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "timeout_seconds": {
                "type": "integer",
                "minimum": 5,
                "maximum": 300,
                "default": 60,
            },
        },
        "required": ["target", "allowed_targets"],
    },
}


SECURITY_WHOIS_LOOKUP_SCHEMA = {
    "name": "security_whois_lookup",
    "description": "Run a scoped whois lookup for an authorized domain or IP target.",
    "parameters": {
        "type": "object",
        "properties": {
            "target": _TARGET_SCOPE_PROPERTIES["target"],
            "allowed_targets": _TARGET_SCOPE_PROPERTIES["allowed_targets"],
            "denied_targets": _TARGET_SCOPE_PROPERTIES["denied_targets"],
            "execute": {"type": "boolean", "default": False},
            "timeout_seconds": {
                "type": "integer",
                "minimum": 5,
                "maximum": 60,
                "default": 15,
            },
        },
        "required": ["target", "allowed_targets"],
    },
}


SECURITY_SUBFINDER_PLAN_SCHEMA = {
    "name": "security_subfinder_plan",
    "description": "Create a scoped subfinder passive subdomain collection plan. Does not execute.",
    "parameters": {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Root domain to enumerate."},
            "allowed_targets": _TARGET_SCOPE_PROPERTIES["allowed_targets"],
            "denied_targets": _TARGET_SCOPE_PROPERTIES["denied_targets"],
            "max_results": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
        },
        "required": ["domain", "allowed_targets"],
    },
}


SECURITY_SUBFINDER_SCAN_SCHEMA = {
    "name": "security_subfinder_scan",
    "description": "Run scoped subfinder passive subdomain collection. Defaults to dry-run.",
    "parameters": {
        "type": "object",
        "properties": {
            **SECURITY_SUBFINDER_PLAN_SCHEMA["parameters"]["properties"],
            "execute": {"type": "boolean", "default": False},
            "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 180, "default": 60},
        },
        "required": ["domain", "allowed_targets"],
    },
}


SECURITY_SQLMAP_PLAN_SCHEMA = {
    "name": "security_sqlmap_plan",
    "description": "Create a gated sqlmap injection-test plan. This adapter does not execute sqlmap.",
    "parameters": {
        "type": "object",
        "properties": {
            **_TARGET_SCOPE_PROPERTIES,
            "risk": {"type": "integer", "minimum": 1, "maximum": 2, "default": 1},
            "level": {"type": "integer", "minimum": 1, "maximum": 2, "default": 1},
            "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            "parameter": {"type": "string", "description": "Optional parameter name to test.", "default": ""},
            "approvals": {"type": "object", "default": {}},
        },
        "required": ["target", "allowed_targets"],
    },
}


SECURITY_MSF_RPC_PLAN_SCHEMA = {
    "name": "security_msf_rpc_plan",
    "description": "Create a Metasploit RPC module execution plan. This adapter does not execute modules.",
    "parameters": {
        "type": "object",
        "properties": {
            **_TARGET_SCOPE_PROPERTIES,
            "module": {"type": "string", "description": "Metasploit module name, for planning only."},
            "options": {"type": "object", "default": {}},
            "approvals": {"type": "object", "default": {}},
        },
        "required": ["target", "allowed_targets", "module"],
    },
}


SECURITY_HYDRA_PLAN_SCHEMA = {
    "name": "security_hydra_plan",
    "description": "Create a gated Hydra weak-password test plan. This adapter does not execute credential attacks.",
    "parameters": {
        "type": "object",
        "properties": {
            **_TARGET_SCOPE_PROPERTIES,
            "service": {"type": "string", "description": "Service protocol, for example ssh, ftp, http-post-form."},
            "username_count": {"type": "integer", "minimum": 1, "maximum": 50, "default": 1},
            "password_count": {"type": "integer", "minimum": 1, "maximum": 200, "default": 10},
            "approvals": {"type": "object", "default": {}},
        },
        "required": ["target", "allowed_targets", "service"],
    },
}


SECURITY_TSHARK_PLAN_SCHEMA = {
    "name": "security_tshark_plan",
    "description": "Create a tshark traffic capture or pcap analysis plan. Does not execute.",
    "parameters": {
        "type": "object",
        "properties": {
            "interface": {"type": "string", "description": "Capture interface for live capture.", "default": ""},
            "pcap_path": {"type": "string", "description": "Existing pcap file for offline analysis.", "default": ""},
            "protocol": {"type": "string", "description": "Optional display filter protocol such as dns, http, tls.", "default": ""},
            "capture_seconds": {"type": "integer", "minimum": 1, "maximum": 60, "default": 10},
            "mode": {"type": "string", "enum": ["assessment", "range", "ctf"], "default": "assessment"},
        },
        "required": [],
    },
}


SECURITY_TSHARK_CAPTURE_SCHEMA = {
    "name": "security_tshark_capture",
    "description": "Run gated tshark pcap analysis or short live capture. Defaults to dry-run.",
    "parameters": {
        "type": "object",
        "properties": {
            **SECURITY_TSHARK_PLAN_SCHEMA["parameters"]["properties"],
            "execute": {"type": "boolean", "default": False},
            "approvals": {"type": "object", "default": {}},
            "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 90, "default": 30},
        },
        "required": [],
    },
}


_ALLOWED_NMAP_PHASES = {"active_recon", "service_enumeration", "ctf_target_recon"}
_PROFILE_ARGS = {
    "host_discovery": ["-sn"],
    "top_ports": ["-sT"],
    "service_detection": ["-sT", "-sV", "--version-light"],
    "specific_ports": ["-sT", "-sV", "--version-light"],
}
_TIMING_ARGS = {
    "polite": "-T2",
    "normal": "-T3",
}
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")
_SAFE_PORTS_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")


def handle_parse_nmap_xml(args: dict[str, Any], **_: Any) -> str:
    xml_text = str(args.get("nmap_xml", "") or "")
    parsed = parse_nmap_xml(xml_text)
    return _json({"success": True, **parsed})


def handle_nmap_plan(args: dict[str, Any], **_: Any) -> str:
    plan = build_nmap_plan(args)
    return _json(plan)


def handle_nmap_scan(args: dict[str, Any], **_: Any) -> str:
    plan = build_nmap_plan(args)
    if not plan["success"]:
        return _json(plan)

    execute = bool(args.get("execute", False))
    if not execute:
        return _json({
            **plan,
            "executed": False,
            "reason": "dry run; set execute=true to run after review",
        })

    gate = _nmap_gate(args)
    if not gate["allowed"]:
        return _json({
            "success": False,
            "executed": False,
            "error": "nmap execution blocked by workflow gate",
            "gate": gate,
            "plan": plan,
        })

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return _json({
            "success": False,
            "executed": False,
            "error": "nmap executable not found on PATH",
            "plan": plan,
        })

    argv = [nmap_path, *plan["argv"][1:]]
    timeout_seconds = _bounded_int(args.get("timeout_seconds", 60), 5, 300)
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return _json({
            "success": False,
            "executed": True,
            "error": f"nmap timed out after {timeout_seconds} seconds",
            "stdout": _truncate(exc.stdout or ""),
            "stderr": _truncate(exc.stderr or ""),
            "plan": plan,
        })

    parsed = None
    if completed.stdout.strip().startswith("<?xml") or "<nmaprun" in completed.stdout[:2000]:
        try:
            parsed = parse_nmap_xml(completed.stdout)
        except ValueError:
            parsed = None

    return _json({
        "success": completed.returncode == 0,
        "executed": True,
        "exit_code": completed.returncode,
        "stdout": _truncate(completed.stdout),
        "stderr": _truncate(completed.stderr),
        "parsed": parsed,
        "plan": plan,
    })


def handle_dir_enum_plan(args: dict[str, Any], **_: Any) -> str:
    return _json(build_dir_enum_plan(args))


def handle_dir_enum_scan(args: dict[str, Any], **_: Any) -> str:
    plan = build_dir_enum_plan(args)
    if not plan["success"]:
        return _json(plan)
    if not bool(args.get("execute", False)):
        return _json({**plan, "executed": False, "reason": "dry run; set execute=true to run after review"})
    if plan["tool"] == "gobuster" and "<wordlist-required-for-execution>" in plan["argv"]:
        return _json({
            "success": False,
            "executed": False,
            "error": "gobuster execution requires an explicit wordlist path",
            "plan": plan,
        })

    gate = _active_tool_gate(args, [str(args.get("target", ""))], default_phase="service_enumeration")
    if not gate["allowed"]:
        return _json({"success": False, "executed": False, "error": "directory enumeration blocked by workflow gate", "gate": gate, "plan": plan})

    exe = shutil.which(plan["tool"])
    if not exe:
        return _json({"success": False, "executed": False, "error": f"{plan['tool']} executable not found on PATH", "plan": plan})

    argv = [exe, *plan["argv"][1:]]
    timeout_seconds = _bounded_int(args.get("timeout_seconds", 60), 5, 300)
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_seconds, shell=False, check=False)
    return _json({
        "success": completed.returncode == 0,
        "executed": True,
        "exit_code": completed.returncode,
        "stdout": _truncate(completed.stdout),
        "stderr": _truncate(completed.stderr),
        "plan": plan,
    })


def handle_whois_lookup(args: dict[str, Any], **_: Any) -> str:
    target = _target_host(str(args.get("target") or ""))
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))
    if not target:
        return _json({"success": False, "error": "target is required"})
    decision = _scope_decision(target, allowed_targets, denied_targets)
    if not decision["allowed"]:
        return _json({"success": False, "error": f"target outside authorized scope: {decision['reason']}", "target": target})
    argv = ["whois", target]
    if not bool(args.get("execute", False)):
        return _json({"success": True, "executed": False, "argv": argv, "command_preview": _argv_preview(argv)})
    exe = shutil.which("whois")
    if not exe:
        return _json({"success": False, "executed": False, "error": "whois executable not found on PATH"})
    timeout_seconds = _bounded_int(args.get("timeout_seconds", 15), 5, 60)
    completed = subprocess.run([exe, target], capture_output=True, text=True, timeout=timeout_seconds, shell=False, check=False)
    return _json({
        "success": completed.returncode == 0,
        "executed": True,
        "exit_code": completed.returncode,
        "stdout": _truncate(completed.stdout),
        "stderr": _truncate(completed.stderr),
        "target": target,
    })


def handle_subfinder_plan(args: dict[str, Any], **_: Any) -> str:
    return _json(build_subfinder_plan(args))


def handle_subfinder_scan(args: dict[str, Any], **_: Any) -> str:
    plan = build_subfinder_plan(args)
    if not plan["success"]:
        return _json(plan)
    if not bool(args.get("execute", False)):
        return _json({**plan, "executed": False, "reason": "dry run; set execute=true to run after review"})
    exe = shutil.which("subfinder")
    if not exe:
        return _json({"success": False, "executed": False, "error": "subfinder executable not found on PATH", "plan": plan})
    timeout_seconds = _bounded_int(args.get("timeout_seconds", 60), 5, 180)
    completed = subprocess.run([exe, *plan["argv"][1:]], capture_output=True, text=True, timeout=timeout_seconds, shell=False, check=False)
    subdomains = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    max_results = _bounded_int(args.get("max_results", 200), 1, 1000)
    return _json({
        "success": completed.returncode == 0,
        "executed": True,
        "exit_code": completed.returncode,
        "subdomains": subdomains[:max_results],
        "count": min(len(subdomains), max_results),
        "stderr": _truncate(completed.stderr),
        "plan": plan,
    })


def handle_sqlmap_plan(args: dict[str, Any], **_: Any) -> str:
    return _json(_high_risk_plan(
        args,
        tool="sqlmap",
        category="injection_testing",
        phase_id=str(args.get("phase_id") or "controlled_validation"),
        required_approval="controlled_validation",
        argv=_sqlmap_argv(args),
        execution_supported=False,
    ))


def handle_msf_rpc_plan(args: dict[str, Any], **_: Any) -> str:
    module = str(args.get("module") or "").strip()
    if not module or not re.match(r"^[A-Za-z0-9_/-]+$", module):
        return _json({"success": False, "errors": ["module is required and must be a valid Metasploit module path"]})
    return _json(_high_risk_plan(
        args,
        tool="metasploit_rpc",
        category="exploit_framework",
        phase_id=str(args.get("phase_id") or "controlled_validation"),
        required_approval="controlled_validation",
        argv=["msfrpc", module],
        execution_supported=False,
        extra={"module": module, "options": args.get("options") if isinstance(args.get("options"), dict) else {}},
    ))


def handle_hydra_plan(args: dict[str, Any], **_: Any) -> str:
    service = str(args.get("service") or "").strip().lower()
    if not service or not re.match(r"^[a-z0-9_-]+(?:-[a-z0-9_-]+)?$", service):
        return _json({"success": False, "errors": ["service is required and must be a hydra protocol name"]})
    username_count = _bounded_int(args.get("username_count", 1), 1, 50)
    password_count = _bounded_int(args.get("password_count", 10), 1, 200)
    return _json(_high_risk_plan(
        args,
        tool="hydra",
        category="credential_testing",
        phase_id=str(args.get("phase_id") or "controlled_validation"),
        required_approval="credential_testing",
        argv=["hydra", "-L", "<user-list>", "-P", "<password-list>", "<target>", service],
        execution_supported=False,
        extra={
            "service": service,
            "username_count": username_count,
            "password_count": password_count,
            "attempt_limit": username_count * password_count,
        },
    ))


def handle_tshark_plan(args: dict[str, Any], **_: Any) -> str:
    return _json(build_tshark_plan(args))


def handle_tshark_capture(args: dict[str, Any], **_: Any) -> str:
    plan = build_tshark_plan(args)
    if not plan["success"]:
        return _json(plan)
    if not bool(args.get("execute", False)):
        return _json({**plan, "executed": False, "reason": "dry run; set execute=true to run after review"})
    if (
        plan["capture_type"] == "live"
        and _normalize_mode(args.get("mode")) != "ctf"
        and not bool((args.get("approvals") or {}).get("traffic_capture"))
    ):
        return _json({"success": False, "executed": False, "error": "live capture requires traffic_capture approval", "plan": plan})
    exe = shutil.which("tshark")
    if not exe:
        return _json({"success": False, "executed": False, "error": "tshark executable not found on PATH", "plan": plan})
    timeout_seconds = _bounded_int(args.get("timeout_seconds", 30), 5, 90)
    completed = subprocess.run([exe, *plan["argv"][1:]], capture_output=True, text=True, timeout=timeout_seconds, shell=False, check=False)
    return _json({
        "success": completed.returncode == 0,
        "executed": True,
        "exit_code": completed.returncode,
        "stdout": _truncate(completed.stdout),
        "stderr": _truncate(completed.stderr),
        "plan": plan,
    })


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    if not xml_text.strip():
        raise ValueError("nmap_xml is required")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nmap XML: {exc}") from exc

    hosts = []
    for host in root.findall("host"):
        status_node = host.find("status")
        address_nodes = host.findall("address")
        addresses = [
            {
                "addr": node.get("addr"),
                "type": node.get("addrtype"),
                "vendor": node.get("vendor"),
            }
            for node in address_nodes
            if node.get("addr")
        ]
        hostnames = [
            node.get("name")
            for node in host.findall("./hostnames/hostname")
            if node.get("name")
        ]
        ports = []
        for port in host.findall("./ports/port"):
            state_node = port.find("state")
            service_node = port.find("service")
            scripts = [
                {"id": script.get("id"), "output": script.get("output")}
                for script in port.findall("script")
                if script.get("id") or script.get("output")
            ]
            ports.append({
                "protocol": port.get("protocol"),
                "port": _coerce_int(port.get("portid")),
                "state": state_node.get("state") if state_node is not None else None,
                "reason": state_node.get("reason") if state_node is not None else None,
                "service": {
                    "name": service_node.get("name") if service_node is not None else None,
                    "product": service_node.get("product") if service_node is not None else None,
                    "version": service_node.get("version") if service_node is not None else None,
                    "extrainfo": service_node.get("extrainfo") if service_node is not None else None,
                    "tunnel": service_node.get("tunnel") if service_node is not None else None,
                },
                "scripts": scripts,
            })
        hosts.append({
            "status": status_node.get("state") if status_node is not None else None,
            "addresses": addresses,
            "hostnames": hostnames,
            "ports": ports,
        })

    open_ports = [
        port
        for host in hosts
        for port in host["ports"]
        if port.get("state") == "open"
    ]
    return {
        "scanner": "nmap",
        "args": root.get("args"),
        "start": root.get("startstr"),
        "version": root.get("version"),
        "host_count": len(hosts),
        "open_port_count": len(open_ports),
        "hosts": hosts,
    }


def build_nmap_plan(args: dict[str, Any]) -> dict[str, Any]:
    targets = _string_list(args.get("targets"))
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))
    mode = _normalize_mode(args.get("mode"))
    phase_id = _effective_phase_id(args, "active_recon")
    profile = str(args.get("scan_profile") or "top_ports").strip().lower()
    timing = str(args.get("timing") or "polite").strip().lower()
    max_cidr_hosts = _bounded_int(args.get("max_cidr_hosts", 256), 1, 4096)

    errors = []
    if mode not in {"assessment", "range", "ctf"}:
        errors.append("nmap scans require assessment, range, or ctf mode")
    if phase_id not in _ALLOWED_NMAP_PHASES:
        errors.append(f"phase_id must be one of: {', '.join(sorted(_ALLOWED_NMAP_PHASES))}")
    if not targets:
        errors.append("at least one target is required")
    if not allowed_targets and mode != "ctf":
        errors.append("allowed_targets is required for nmap planning")
    if profile not in _PROFILE_ARGS:
        errors.append(f"scan_profile must be one of: {', '.join(sorted(_PROFILE_ARGS))}")
    if timing not in _TIMING_ARGS:
        errors.append("timing must be polite or normal")

    normalized_targets = []
    for target in targets:
        normalized = _normalize_target_for_nmap(target)
        if normalized.get("error"):
            errors.append(f"invalid target {target!r}: {normalized['error']}")
            continue
        effective_allowed = allowed_targets or ([normalized["scope_target"]] if mode == "ctf" else [])
        decision = _scope_decision(normalized["scope_target"], effective_allowed, denied_targets)
        if not decision["allowed"]:
            errors.append(f"target outside authorized scope: {target} ({decision['reason']})")
            continue
        cidr_error = _cidr_size_error(normalized["nmap_target"], max_cidr_hosts)
        if cidr_error:
            errors.append(cidr_error)
            continue
        normalized_targets.append({
            "input": target,
            "nmap_target": normalized["nmap_target"],
            "scope_target": normalized["scope_target"],
            "matched_rule": decision.get("matched_rule"),
        })

    if errors:
        return {"success": False, "errors": _dedupe(errors)}

    argv = ["nmap", *_PROFILE_ARGS[profile]]
    if profile in {"top_ports", "service_detection"}:
        top_ports = _bounded_int(args.get("top_ports", 100), 1, 1000)
        argv.extend(["--top-ports", str(top_ports)])
    if profile == "specific_ports":
        ports = _sanitize_ports(str(args.get("ports") or ""))
        if not ports:
            return {"success": False, "errors": ["specific_ports profile requires a valid ports value"]}
        argv.extend(["-p", ports])
    argv.extend([_TIMING_ARGS[timing], "--max-retries", "2", "-oX", "-"])
    argv.extend(item["nmap_target"] for item in normalized_targets)

    return {
        "success": True,
        "mode": mode,
        "phase_id": phase_id,
        "scan_profile": profile,
        "timing": timing,
        "targets": normalized_targets,
        "argv": argv,
        "command_preview": _argv_preview(argv),
        "restrictions": [
            "no arbitrary nmap arguments",
            "no spoofing, decoys, fragmentation, script execution, or evasion flags",
            "XML output forced with -oX -",
            "targets must match allowed scope and avoid denied scope",
        ],
    }


def build_dir_enum_plan(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target") or "").strip()
    tool = str(args.get("tool") or "dirsearch").strip().lower()
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))
    mode = _normalize_mode(args.get("mode"))
    rate_limit = _bounded_int(args.get("rate_limit", 5), 1, 50)
    errors = []

    if tool not in {"dirsearch", "gobuster"}:
        errors.append("tool must be dirsearch or gobuster")
    if not _is_http_url(target):
        errors.append("target must be an http or https URL")
    effective_allowed = allowed_targets or ([target] if mode == "ctf" else [])
    decision = _scope_decision(target, effective_allowed, denied_targets)
    if not decision["allowed"]:
        errors.append(f"target outside authorized scope: {target} ({decision['reason']})")

    extensions = _safe_extensions(args.get("extensions"))
    wordlist = str(args.get("wordlist") or "").strip()
    if wordlist and not _safe_local_path(wordlist):
        errors.append("wordlist path contains unsupported characters")

    if errors:
        return {"success": False, "errors": _dedupe(errors)}

    if tool == "dirsearch":
        argv = ["dirsearch", "-u", target, "--rate", str(rate_limit), "--format", "json"]
        if extensions:
            argv.extend(["-e", ",".join(extensions)])
        if wordlist:
            argv.extend(["-w", wordlist])
    else:
        argv = ["gobuster", "dir", "-u", target, "-q"]
        if wordlist:
            argv.extend(["-w", wordlist])
        else:
            argv.extend(["-w", "<wordlist-required-for-execution>"])
        if extensions:
            argv.extend(["-x", ",".join(extensions)])
    return {
        "success": True,
        "tool": tool,
        "target": target,
        "argv": argv,
        "command_preview": _argv_preview(argv),
        "matched_rule": decision.get("matched_rule"),
        "restrictions": [
            "single in-scope URL only",
            "rate_limit is capped at 50 requests per second",
            "no recursive aggressive mode",
            "no arbitrary tool arguments",
        ],
    }


def build_subfinder_plan(args: dict[str, Any]) -> dict[str, Any]:
    domain = _target_host(str(args.get("domain") or ""))
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))
    mode = _normalize_mode(args.get("mode"))
    errors = []
    if not domain or "/" in domain or ":" in domain:
        errors.append("domain must be a hostname, not a URL or CIDR")
    effective_allowed = allowed_targets or ([domain] if mode == "ctf" else [])
    decision = _scope_decision(domain, effective_allowed, denied_targets)
    if not decision["allowed"]:
        errors.append(f"domain outside authorized scope: {domain} ({decision['reason']})")
    if errors:
        return {"success": False, "errors": _dedupe(errors)}
    max_results = _bounded_int(args.get("max_results", 200), 1, 1000)
    argv = ["subfinder", "-silent", "-d", domain]
    return {
        "success": True,
        "domain": domain,
        "max_results": max_results,
        "argv": argv,
        "command_preview": _argv_preview(argv),
        "matched_rule": decision.get("matched_rule"),
    }


def build_tshark_plan(args: dict[str, Any]) -> dict[str, Any]:
    interface = str(args.get("interface") or "").strip()
    pcap_path = str(args.get("pcap_path") or "").strip()
    protocol = str(args.get("protocol") or "").strip().lower()
    capture_seconds = _bounded_int(args.get("capture_seconds", 10), 1, 60)
    errors = []

    if interface and pcap_path:
        errors.append("provide interface for live capture or pcap_path for offline analysis, not both")
    if not interface and not pcap_path:
        errors.append("interface or pcap_path is required")
    if interface and not re.match(r"^[A-Za-z0-9_.:-]+$", interface):
        errors.append("interface contains unsupported characters")
    if pcap_path and not _safe_local_path(pcap_path):
        errors.append("pcap_path contains unsupported characters")
    if protocol and not re.match(r"^[a-z0-9_.-]+$", protocol):
        errors.append("protocol contains unsupported characters")
    if errors:
        return {"success": False, "errors": _dedupe(errors)}

    argv = ["tshark"]
    capture_type = "offline"
    if pcap_path:
        argv.extend(["-r", pcap_path])
    else:
        capture_type = "live"
        argv.extend(["-i", interface, "-a", f"duration:{capture_seconds}"])
    if protocol:
        argv.extend(["-Y", protocol])
    argv.extend(["-T", "json"])
    return {
        "success": True,
        "capture_type": capture_type,
        "protocol": protocol or None,
        "argv": argv,
        "command_preview": _argv_preview(argv),
        "restrictions": [
            "offline pcap analysis is preferred",
            "live capture requires traffic_capture approval",
            "display filter is limited to a protocol token",
        ],
    }


def _high_risk_plan(
    args: dict[str, Any],
    *,
    tool: str,
    category: str,
    phase_id: str,
    required_approval: str,
    argv: list[str],
    execution_supported: bool,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = str(args.get("target") or "").strip()
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))
    mode = _normalize_mode(args.get("mode"))
    errors = []
    if mode == "ctf" and not phase_id.startswith("ctf_"):
        phase_id = "ctf_foothold"
    if mode not in {"assessment", "range", "ctf"}:
        errors.append(f"{tool} planning requires assessment, range, or ctf mode")
    if not target:
        errors.append("target is required")
    effective_allowed = allowed_targets or ([target] if mode == "ctf" else [])
    decision = _scope_decision(target, effective_allowed, denied_targets)
    if not decision["allowed"]:
        errors.append(f"target outside authorized scope: {target} ({decision['reason']})")

    approvals = args.get("approvals") if isinstance(args.get("approvals"), dict) else {}
    auto_authorized = mode == "ctf"
    approved = auto_authorized or bool(approvals.get(required_approval) or approvals.get(category))
    gate = {
        "required_approval": required_approval,
        "approved": approved,
        "auto_authorized_in_ctf": auto_authorized,
        "phase_id": phase_id,
        "execution_supported": execution_supported,
    }
    if errors:
        return {"success": False, "errors": _dedupe(errors), "gate": gate}

    plan = {
        "success": True,
        "tool": tool,
        "category": category,
        "target": target,
        "mode": mode,
        "phase_id": phase_id,
        "argv_template": argv,
        "command_preview": _argv_preview(argv),
        "gate": gate,
        "matched_rule": decision.get("matched_rule"),
        "execution_supported": execution_supported,
        "restrictions": [
            "planning only; this adapter does not execute high-risk exploit or credential attacks",
            "requires explicit written authorization and human operator review",
            "target must remain inside allowed scope",
        ],
    }
    if extra:
        plan.update(extra)
    return plan


def _sqlmap_argv(args: dict[str, Any]) -> list[str]:
    target = str(args.get("target") or "<target>").strip()
    risk = str(_bounded_int(args.get("risk", 1), 1, 2))
    level = str(_bounded_int(args.get("level", 1), 1, 2))
    method = str(args.get("method") or "GET").upper()
    argv = ["sqlmap", "-u", target, "--batch", "--risk", risk, "--level", level, "--method", method]
    parameter = str(args.get("parameter") or "").strip()
    if parameter and re.match(r"^[A-Za-z0-9_.:-]+$", parameter):
        argv.extend(["-p", parameter])
    return argv


def _nmap_gate(args: dict[str, Any]) -> dict[str, Any]:
    from .workflows import handle_workflow_gate

    mode = _normalize_mode(args.get("mode"))
    phase_id = _effective_phase_id(args, "active_recon")
    available_artifacts = _string_list(args.get("available_artifacts"))
    if phase_id == "active_recon" and not available_artifacts:
        available_artifacts = ["scope_matrix"]
    elif phase_id == "service_enumeration" and not available_artifacts:
        available_artifacts = ["active_recon_results"]
    elif phase_id == "ctf_target_recon" and not available_artifacts:
        available_artifacts = ["challenge_type"]

    gate_args = {
        "phase_id": phase_id,
        "mode": mode,
        "allowed_targets": _string_list(args.get("allowed_targets")),
        "denied_targets": _string_list(args.get("denied_targets")),
        "requested_targets": _string_list(args.get("targets")),
        "available_artifacts": available_artifacts,
        "approvals": args.get("approvals") if isinstance(args.get("approvals"), dict) else {},
    }
    return json.loads(handle_workflow_gate(gate_args))


def _active_tool_gate(args: dict[str, Any], requested_targets: list[str], default_phase: str) -> dict[str, Any]:
    from .workflows import handle_workflow_gate

    phase_id = _effective_phase_id(args, default_phase)
    available_artifacts = _string_list(args.get("available_artifacts"))
    if not available_artifacts:
        if phase_id == "ctf_target_recon":
            available_artifacts = ["challenge_type"]
        else:
            available_artifacts = ["active_recon_results"] if phase_id == "service_enumeration" else ["scope_matrix"]
    gate_args = {
        "phase_id": phase_id,
        "mode": _normalize_mode(args.get("mode")),
        "allowed_targets": _string_list(args.get("allowed_targets")),
        "denied_targets": _string_list(args.get("denied_targets")),
        "requested_targets": requested_targets,
        "available_artifacts": available_artifacts,
        "approvals": args.get("approvals") if isinstance(args.get("approvals"), dict) else {},
    }
    return json.loads(handle_workflow_gate(gate_args))


def _effective_phase_id(args: dict[str, Any], default_phase: str) -> str:
    mode = _normalize_mode(args.get("mode"))
    supplied = str(args.get("phase_id") or "").strip()
    if mode == "ctf":
        if supplied.startswith("ctf_"):
            return supplied
        return "ctf_target_recon"
    return supplied or default_phase


def _normalize_target_for_nmap(target: str) -> dict[str, str]:
    raw = target.strip()
    if not raw:
        return {"error": "empty target"}
    if not _SAFE_TARGET_RE.match(raw):
        return {"error": "target contains unsupported characters"}
    if raw.startswith("-"):
        return {"error": "target must not start with '-'"}

    if "://" in raw:
        parsed = urlparse(raw)
        if not parsed.hostname:
            return {"error": "URL target has no hostname"}
        host = parsed.hostname.strip("[]")
        return {"nmap_target": host, "scope_target": raw}
    return {"nmap_target": raw, "scope_target": raw}


def _target_host(target: str) -> str:
    raw = target.strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or "").strip("[]").lower()
    return raw.strip("[]").lower()


def _is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def _safe_extensions(value: Any) -> list[str]:
    allowed = []
    for item in _string_list(value):
        ext = item.strip().lstrip(".").lower()
        if re.match(r"^[a-z0-9]{1,12}$", ext):
            allowed.append(ext)
    return _dedupe(allowed)[:10]


def _safe_local_path(value: str) -> bool:
    if not value:
        return False
    if value.startswith("-"):
        return False
    return bool(re.match(r"^[A-Za-z0-9_./: -]+$", value))


def _cidr_size_error(target: str, max_cidr_hosts: int) -> str | None:
    if "/" not in target:
        return None
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None
    if network.num_addresses > max_cidr_hosts:
        return f"CIDR target {target} has {network.num_addresses} addresses; max_cidr_hosts is {max_cidr_hosts}"
    return None


def _sanitize_ports(value: str) -> str:
    ports = value.strip().replace(" ", "")
    if not ports or not _SAFE_PORTS_RE.match(ports):
        return ""
    for part in ports.split(","):
        if "-" in part:
            start, end = [int(piece) for piece in part.split("-", 1)]
            if start < 1 or end > 65535 or start > end:
                return ""
        else:
            port = int(part)
            if port < 1 or port > 65535:
                return ""
    return ports


def _normalize_mode(value: Any) -> str:
    mode = str(value or "assessment").strip().lower()
    return mode if mode in {"assessment", "range", "ctf"} else "assessment"


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _bounded_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = minimum
    return min(max(parsed, minimum), maximum)


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _truncate(value: str, limit: int = 20000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def _argv_preview(argv: list[str]) -> str:
    return " ".join(_quote_arg(arg) for arg in argv)


def _quote_arg(arg: str) -> str:
    if re.match(r"^[A-Za-z0-9_./:=,-]+$", arg):
        return arg
    return json.dumps(arg)


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
