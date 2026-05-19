from __future__ import annotations

import json


def _loads(result: str) -> dict:
    return json.loads(result)


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - scanme.example" version="7.94" startstr="Mon May 18 00:00:00 2026">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="scanme.example" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https" tunnel="ssl"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNmapXmlParser:
    def test_parse_nmap_xml_normalizes_hosts_and_ports(self):
        from plugins.security.scanners import handle_parse_nmap_xml

        result = _loads(handle_parse_nmap_xml({"nmap_xml": _NMAP_XML}))

        assert result["success"] is True
        assert result["scanner"] == "nmap"
        assert result["host_count"] == 1
        assert result["open_port_count"] == 1
        host = result["hosts"][0]
        assert host["status"] == "up"
        assert host["addresses"][0]["addr"] == "192.0.2.10"
        assert host["hostnames"] == ["scanme.example"]
        assert host["ports"][0]["port"] == 22
        assert host["ports"][0]["service"]["name"] == "ssh"


class TestNmapPlan:
    def test_builds_scoped_service_detection_plan(self):
        from plugins.security.scanners import handle_nmap_plan

        result = _loads(handle_nmap_plan({
            "targets": ["api.example.com"],
            "allowed_targets": ["*.example.com"],
            "mode": "assessment",
            "phase_id": "service_enumeration",
            "scan_profile": "service_detection",
            "timing": "polite",
            "top_ports": 50,
        }))

        assert result["success"] is True
        assert result["argv"] == [
            "nmap",
            "-sT",
            "-sV",
            "--version-light",
            "--top-ports",
            "50",
            "-T2",
            "--max-retries",
            "2",
            "-oX",
            "-",
            "api.example.com",
        ]

    def test_specific_ports_rejects_invalid_ports(self):
        from plugins.security.scanners import handle_nmap_plan

        result = _loads(handle_nmap_plan({
            "targets": ["api.example.com"],
            "allowed_targets": ["*.example.com"],
            "scan_profile": "specific_ports",
            "ports": "22,70000",
        }))

        assert result["success"] is False
        assert "specific_ports profile requires a valid ports value" in result["errors"]

    def test_blocks_target_outside_scope(self):
        from plugins.security.scanners import handle_nmap_plan

        result = _loads(handle_nmap_plan({
            "targets": ["outside.example.net"],
            "allowed_targets": ["*.example.com"],
        }))

        assert result["success"] is False
        assert any("target outside authorized scope" in error for error in result["errors"])

    def test_blocks_over_broad_cidr_by_default(self):
        from plugins.security.scanners import handle_nmap_plan

        result = _loads(handle_nmap_plan({
            "targets": ["10.10.0.0/16"],
            "allowed_targets": ["10.10.0.0/16"],
        }))

        assert result["success"] is False
        assert any("max_cidr_hosts" in error for error in result["errors"])

    def test_ctf_nmap_plan_allows_target_without_explicit_scope(self):
        from plugins.security.scanners import handle_nmap_plan

        result = _loads(handle_nmap_plan({
            "targets": ["10.10.10.5"],
            "mode": "ctf",
            "scan_profile": "top_ports",
        }))

        assert result["success"] is True
        assert result["targets"][0]["scope_target"] == "10.10.10.5"


class TestNmapScan:
    def test_scan_defaults_to_dry_run(self):
        from plugins.security.scanners import handle_nmap_scan

        result = _loads(handle_nmap_scan({
            "targets": ["api.example.com"],
            "allowed_targets": ["*.example.com"],
            "mode": "assessment",
            "phase_id": "active_recon",
        }))

        assert result["success"] is True
        assert result["executed"] is False
        assert "dry run" in result["reason"]

    def test_execute_blocks_without_active_testing_approval(self):
        from plugins.security.scanners import handle_nmap_scan

        result = _loads(handle_nmap_scan({
            "targets": ["api.example.com"],
            "allowed_targets": ["*.example.com"],
            "mode": "assessment",
            "phase_id": "active_recon",
            "execute": True,
            "approvals": {},
        }))

        assert result["success"] is False
        assert result["executed"] is False
        assert result["error"] == "nmap execution blocked by workflow gate"
        assert "missing required approval: active_testing" in result["gate"]["blockers"]

    def test_ctf_execute_does_not_require_active_testing_approval(self, monkeypatch):
        from plugins.security import scanners

        monkeypatch.setattr(scanners.shutil, "which", lambda name: None)
        result = _loads(scanners.handle_nmap_scan({
            "targets": ["box.ctf.local"],
            "allowed_targets": ["*.ctf.local"],
            "mode": "ctf",
            "execute": True,
            "approvals": {},
        }))

        assert result["success"] is False
        assert result["executed"] is False
        assert result["error"] == "nmap executable not found on PATH"
        assert result["plan"]["phase_id"] == "ctf_target_recon"


class TestReconAdapters:
    def test_dir_enum_plan_builds_dirsearch_command(self):
        from plugins.security.scanners import handle_dir_enum_plan

        result = _loads(handle_dir_enum_plan({
            "target": "https://app.example.com",
            "allowed_targets": ["*.example.com"],
            "tool": "dirsearch",
            "extensions": ["php", ".txt", "../../bad"],
            "rate_limit": 10,
        }))

        assert result["success"] is True
        assert result["tool"] == "dirsearch"
        assert result["argv"][:6] == ["dirsearch", "-u", "https://app.example.com", "--rate", "10", "--format"]
        assert "-e" in result["argv"]
        assert "../../bad" not in result["argv"]

    def test_dir_enum_scan_defaults_to_dry_run(self):
        from plugins.security.scanners import handle_dir_enum_scan

        result = _loads(handle_dir_enum_scan({
            "target": "https://app.example.com",
            "allowed_targets": ["*.example.com"],
            "tool": "gobuster",
            "wordlist": "wordlists/common.txt",
        }))

        assert result["success"] is True
        assert result["executed"] is False

    def test_gobuster_execution_requires_explicit_wordlist(self):
        from plugins.security.scanners import handle_dir_enum_scan

        result = _loads(handle_dir_enum_scan({
            "target": "https://app.example.com",
            "allowed_targets": ["*.example.com"],
            "tool": "gobuster",
            "execute": True,
        }))

        assert result["success"] is False
        assert result["executed"] is False
        assert "wordlist" in result["error"]

    def test_ctf_dir_enum_execution_does_not_require_approval(self, monkeypatch):
        from plugins.security import scanners

        monkeypatch.setattr(scanners.shutil, "which", lambda name: None)
        result = _loads(scanners.handle_dir_enum_scan({
            "target": "https://box.ctf.local",
            "allowed_targets": ["*.ctf.local"],
            "mode": "ctf",
            "tool": "dirsearch",
            "execute": True,
            "approvals": {},
        }))

        assert result["success"] is False
        assert result["executed"] is False
        assert result["error"] == "dirsearch executable not found on PATH"

    def test_ctf_dir_enum_plan_allows_url_without_explicit_scope(self):
        from plugins.security.scanners import handle_dir_enum_plan

        result = _loads(handle_dir_enum_plan({
            "target": "https://box.ctf.local",
            "mode": "ctf",
            "tool": "dirsearch",
        }))

        assert result["success"] is True
        assert result["target"] == "https://box.ctf.local"

    def test_whois_lookup_blocks_out_of_scope_target(self):
        from plugins.security.scanners import handle_whois_lookup

        result = _loads(handle_whois_lookup({
            "target": "outside.example.net",
            "allowed_targets": ["*.example.com"],
        }))

        assert result["success"] is False
        assert "outside authorized scope" in result["error"]

    def test_subfinder_plan_builds_passive_command(self):
        from plugins.security.scanners import handle_subfinder_plan

        result = _loads(handle_subfinder_plan({
            "domain": "example.com",
            "allowed_targets": ["example.com", "*.example.com"],
            "max_results": 25,
        }))

        assert result["success"] is True
        assert result["argv"] == ["subfinder", "-silent", "-d", "example.com"]
        assert result["max_results"] == 25

    def test_ctf_subfinder_plan_allows_domain_without_explicit_scope(self):
        from plugins.security.scanners import handle_subfinder_plan

        result = _loads(handle_subfinder_plan({
            "domain": "ctf.local",
            "mode": "ctf",
        }))

        assert result["success"] is True
        assert result["argv"] == ["subfinder", "-silent", "-d", "ctf.local"]


class TestHighRiskPlanningAdapters:
    def test_sqlmap_plan_is_planning_only(self):
        from plugins.security.scanners import handle_sqlmap_plan

        result = _loads(handle_sqlmap_plan({
            "target": "https://app.example.com/item?id=1",
            "allowed_targets": ["*.example.com"],
            "approvals": {"controlled_validation": True},
            "parameter": "id",
        }))

        assert result["success"] is True
        assert result["tool"] == "sqlmap"
        assert result["execution_supported"] is False
        assert result["gate"]["approved"] is True

    def test_msf_rpc_plan_requires_valid_module(self):
        from plugins.security.scanners import handle_msf_rpc_plan

        result = _loads(handle_msf_rpc_plan({
            "target": "10.10.0.5",
            "allowed_targets": ["10.10.0.0/24"],
            "module": "../../bad",
        }))

        assert result["success"] is False
        assert "module is required" in result["errors"][0]

    def test_hydra_plan_is_planning_only_and_caps_attempts(self):
        from plugins.security.scanners import handle_hydra_plan

        result = _loads(handle_hydra_plan({
            "target": "10.10.0.5",
            "allowed_targets": ["10.10.0.0/24"],
            "service": "ssh",
            "username_count": 100,
            "password_count": 1000,
        }))

        assert result["success"] is True
        assert result["tool"] == "hydra"
        assert result["execution_supported"] is False
        assert result["attempt_limit"] == 50 * 200

    def test_ctf_high_risk_plan_is_auto_authorized(self):
        from plugins.security.scanners import handle_sqlmap_plan

        result = _loads(handle_sqlmap_plan({
            "target": "https://box.ctf.local/item?id=1",
            "allowed_targets": ["*.ctf.local"],
            "mode": "ctf",
            "approvals": {},
        }))

        assert result["success"] is True
        assert result["gate"]["approved"] is True
        assert result["gate"]["auto_authorized_in_ctf"] is True
        assert result["gate"]["phase_id"] == "ctf_foothold"

    def test_ctf_high_risk_plan_allows_target_without_explicit_scope(self):
        from plugins.security.scanners import handle_hydra_plan

        result = _loads(handle_hydra_plan({
            "target": "10.10.10.5",
            "mode": "ctf",
            "service": "ssh",
        }))

        assert result["success"] is True
        assert result["gate"]["approved"] is True


class TestTrafficAdapters:
    def test_tshark_plan_for_offline_pcap(self):
        from plugins.security.scanners import handle_tshark_plan

        result = _loads(handle_tshark_plan({
            "pcap_path": "captures/sample.pcap",
            "protocol": "dns",
        }))

        assert result["success"] is True
        assert result["capture_type"] == "offline"
        assert result["argv"] == ["tshark", "-r", "captures/sample.pcap", "-Y", "dns", "-T", "json"]

    def test_tshark_live_capture_requires_approval(self):
        from plugins.security.scanners import handle_tshark_capture

        result = _loads(handle_tshark_capture({
            "interface": "eth0",
            "protocol": "http",
            "execute": True,
            "approvals": {},
        }))

        assert result["success"] is False
        assert result["executed"] is False
        assert "traffic_capture approval" in result["error"]

    def test_ctf_tshark_live_capture_does_not_require_approval(self, monkeypatch):
        from plugins.security import scanners

        monkeypatch.setattr(scanners.shutil, "which", lambda name: None)
        result = _loads(scanners.handle_tshark_capture({
            "interface": "eth0",
            "protocol": "http",
            "mode": "ctf",
            "execute": True,
            "approvals": {},
        }))

        assert result["success"] is False
        assert result["executed"] is False
        assert result["error"] == "tshark executable not found on PATH"
