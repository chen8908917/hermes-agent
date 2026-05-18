from __future__ import annotations

import json

import pytest


def _loads(result: str) -> dict:
    return json.loads(result)


class TestSecurityScopeCheck:
    def test_allows_wildcard_domain_scope(self):
        from plugins.security.tools import handle_scope_check

        result = _loads(handle_scope_check({
            "target": "https://api.example.com/v1",
            "allowed_targets": ["*.example.com"],
        }))

        assert result["success"] is True
        assert result["allowed"] is True
        assert result["matched_rule"] == "*.example.com"

    def test_deny_rule_wins_over_allow_rule(self):
        from plugins.security.tools import handle_scope_check

        result = _loads(handle_scope_check({
            "target": "admin.example.com",
            "allowed_targets": ["*.example.com"],
            "denied_targets": ["admin.example.com"],
        }))

        assert result["allowed"] is False
        assert result["reason"] == "target matched denied scope"

    def test_allows_ip_inside_authorized_cidr(self):
        from plugins.security.tools import handle_scope_check

        result = _loads(handle_scope_check({
            "target": "10.10.4.12",
            "allowed_targets": ["10.10.0.0/16"],
        }))

        assert result["allowed"] is True
        assert result["matched_rule"] == "10.10.0.0/16"

    def test_blocks_unscoped_target_by_default(self):
        from plugins.security.tools import handle_scope_check

        result = _loads(handle_scope_check({
            "target": "outside.example.net",
            "allowed_targets": ["*.example.com"],
        }))

        assert result["allowed"] is False
        assert result["reason"] == "target is outside the authorized scope"

    def test_single_ip_rule_does_not_allow_broader_cidr_target(self):
        from plugins.security.tools import handle_scope_check

        result = _loads(handle_scope_check({
            "target": "10.10.0.0/24",
            "allowed_targets": ["10.10.0.4"],
        }))

        assert result["allowed"] is False


class TestSecurityIocExtraction:
    def test_extracts_refanged_iocs(self):
        from plugins.security.tools import handle_extract_iocs

        result = _loads(handle_extract_iocs({
            "text": (
                "Investigate hxxps://evil[.]example/path, 8.8.8.8, "
                "CVE-2026-12345, analyst@example.org, and "
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
            )
        }))

        indicators = result["indicators"]
        assert "https://evil.example/path" in indicators["urls"]
        assert "evil.example" in indicators["domains"]
        assert "example.org" in indicators["domains"]
        assert "8.8.8.8" in indicators["ipv4"]
        assert "CVE-2026-12345" in indicators["cves"]
        assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in indicators["hashes"]["md5"]

    def test_can_exclude_private_ips(self):
        from plugins.security.tools import handle_extract_iocs

        result = _loads(handle_extract_iocs({
            "text": "Seen 10.0.0.4 and 8.8.8.8",
            "include_private_ips": False,
        }))

        assert "10.0.0.4" not in result["indicators"]["ipv4"]
        assert "8.8.8.8" in result["indicators"]["ipv4"]


class TestSecurityFindingTools:
    def test_normalizes_trivy_vulnerabilities(self):
        from plugins.security.tools import handle_normalize_findings

        trivy = {
            "Results": [{
                "Target": "container:latest",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-2222",
                    "PkgName": "openssl",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 8.1}},
                    "Title": "test vuln",
                }],
            }]
        }

        result = _loads(handle_normalize_findings({
            "scanner_output": trivy,
            "source": "trivy",
        }))

        assert result["count"] == 1
        finding = result["findings"][0]
        assert finding["id"] == "CVE-2026-2222"
        assert finding["asset"] == "container:latest"
        assert finding["package"] == "openssl"
        assert finding["severity"] == "high"

    def test_prioritizes_exposed_exploitable_critical_assets(self):
        from plugins.security.tools import handle_prioritize_findings

        findings = {
            "findings": [
                {
                    "id": "CVE-2026-1111",
                    "title": "critical public issue",
                    "severity": "high",
                    "cvss": 8.5,
                    "asset": "app.example.com",
                    "exploit_available": True,
                },
                {
                    "id": "LOW-1",
                    "title": "minor issue",
                    "severity": "low",
                    "asset": "devbox",
                },
            ]
        }

        result = _loads(handle_prioritize_findings({
            "findings": findings,
            "asset_context": {
                "app.example.com": {"exposure": "internet", "criticality": "high"}
            },
        }))

        assert result["findings"][0]["id"] == "CVE-2026-1111"
        assert result["findings"][0]["priority"] == "P0"
        assert result["findings"][0]["priority_score"] == 100


def test_security_plugin_registers_tools():
    pytest.importorskip("yaml")
    import hermes_cli.plugins as plugins_mod
    from tools.registry import registry

    plugins_mod.discover_plugins(force=True)

    assert "security_scope_check" in registry.get_all_tool_names()
    assert "security_build_workflow" in registry.get_all_tool_names()
    assert "security_workflow_gate" in registry.get_all_tool_names()
    assert "security_parse_nmap_xml" in registry.get_all_tool_names()
    assert "security_nmap_plan" in registry.get_all_tool_names()
    assert "security_nmap_scan" in registry.get_all_tool_names()
    assert "security_dir_enum_plan" in registry.get_all_tool_names()
    assert "security_dir_enum_scan" in registry.get_all_tool_names()
    assert "security_whois_lookup" in registry.get_all_tool_names()
    assert "security_subfinder_plan" in registry.get_all_tool_names()
    assert "security_subfinder_scan" in registry.get_all_tool_names()
    assert "security_sqlmap_plan" in registry.get_all_tool_names()
    assert "security_msf_rpc_plan" in registry.get_all_tool_names()
    assert "security_hydra_plan" in registry.get_all_tool_names()
    assert "security_tshark_plan" in registry.get_all_tool_names()
    assert "security_tshark_capture" in registry.get_all_tool_names()
    assert "security_build_agent_team" in registry.get_all_tool_names()
    assert "security_dispatch_agent_tasks" in registry.get_all_tool_names()
    assert "security_collect_agent_handoffs" in registry.get_all_tool_names()
    assert "security_generate_skill" in registry.get_all_tool_names()
    assert "security_merge_skills" in registry.get_all_tool_names()
    assert registry.get_toolset_for_tool("security_scope_check") == "security"
