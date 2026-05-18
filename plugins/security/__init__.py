"""Bundled security tool plugin.

Most tools in this plugin are offline helpers: they validate authorized scope,
extract indicators, normalize scanner output, and prioritize findings. Active
scanner adapters are gated by workflow mode, scope, approval, and conservative
argument allow-lists. They do not expose arbitrary command execution,
exploitation, persistence, or credential access.
"""

from __future__ import annotations

from .tools import (
    SECURITY_EXTRACT_IOCS_SCHEMA,
    SECURITY_NORMALIZE_FINDINGS_SCHEMA,
    SECURITY_PRIORITIZE_FINDINGS_SCHEMA,
    SECURITY_SCOPE_CHECK_SCHEMA,
    handle_extract_iocs,
    handle_normalize_findings,
    handle_prioritize_findings,
    handle_scope_check,
)
from .multi_agent import (
    SECURITY_BUILD_AGENT_TEAM_SCHEMA,
    SECURITY_COLLECT_AGENT_HANDOFFS_SCHEMA,
    SECURITY_DISPATCH_AGENT_TASKS_SCHEMA,
    handle_build_agent_team,
    handle_collect_agent_handoffs,
    handle_dispatch_agent_tasks,
)
from .skill_ops import (
    SECURITY_GENERATE_SKILL_SCHEMA,
    SECURITY_MERGE_SKILLS_SCHEMA,
    handle_generate_skill,
    handle_merge_skills,
)
from .scanners import (
    SECURITY_DIR_ENUM_PLAN_SCHEMA,
    SECURITY_DIR_ENUM_SCAN_SCHEMA,
    SECURITY_HYDRA_PLAN_SCHEMA,
    SECURITY_MSF_RPC_PLAN_SCHEMA,
    SECURITY_NMAP_PLAN_SCHEMA,
    SECURITY_NMAP_SCAN_SCHEMA,
    SECURITY_PARSE_NMAP_XML_SCHEMA,
    SECURITY_SQLMAP_PLAN_SCHEMA,
    SECURITY_SUBFINDER_PLAN_SCHEMA,
    SECURITY_SUBFINDER_SCAN_SCHEMA,
    SECURITY_TSHARK_CAPTURE_SCHEMA,
    SECURITY_TSHARK_PLAN_SCHEMA,
    SECURITY_WHOIS_LOOKUP_SCHEMA,
    handle_dir_enum_plan,
    handle_dir_enum_scan,
    handle_hydra_plan,
    handle_msf_rpc_plan,
    handle_nmap_plan,
    handle_nmap_scan,
    handle_parse_nmap_xml,
    handle_sqlmap_plan,
    handle_subfinder_plan,
    handle_subfinder_scan,
    handle_tshark_capture,
    handle_tshark_plan,
    handle_whois_lookup,
)
from .workflows import (
    SECURITY_BUILD_WORKFLOW_SCHEMA,
    SECURITY_WORKFLOW_GATE_SCHEMA,
    handle_build_workflow,
    handle_workflow_gate,
)


_TOOLS = (
    ("security_scope_check", SECURITY_SCOPE_CHECK_SCHEMA, handle_scope_check),
    ("security_extract_iocs", SECURITY_EXTRACT_IOCS_SCHEMA, handle_extract_iocs),
    ("security_normalize_findings", SECURITY_NORMALIZE_FINDINGS_SCHEMA, handle_normalize_findings),
    ("security_prioritize_findings", SECURITY_PRIORITIZE_FINDINGS_SCHEMA, handle_prioritize_findings),
    ("security_build_workflow", SECURITY_BUILD_WORKFLOW_SCHEMA, handle_build_workflow),
    ("security_workflow_gate", SECURITY_WORKFLOW_GATE_SCHEMA, handle_workflow_gate),
    ("security_parse_nmap_xml", SECURITY_PARSE_NMAP_XML_SCHEMA, handle_parse_nmap_xml),
    ("security_nmap_plan", SECURITY_NMAP_PLAN_SCHEMA, handle_nmap_plan),
    ("security_nmap_scan", SECURITY_NMAP_SCAN_SCHEMA, handle_nmap_scan),
    ("security_dir_enum_plan", SECURITY_DIR_ENUM_PLAN_SCHEMA, handle_dir_enum_plan),
    ("security_dir_enum_scan", SECURITY_DIR_ENUM_SCAN_SCHEMA, handle_dir_enum_scan),
    ("security_whois_lookup", SECURITY_WHOIS_LOOKUP_SCHEMA, handle_whois_lookup),
    ("security_subfinder_plan", SECURITY_SUBFINDER_PLAN_SCHEMA, handle_subfinder_plan),
    ("security_subfinder_scan", SECURITY_SUBFINDER_SCAN_SCHEMA, handle_subfinder_scan),
    ("security_sqlmap_plan", SECURITY_SQLMAP_PLAN_SCHEMA, handle_sqlmap_plan),
    ("security_msf_rpc_plan", SECURITY_MSF_RPC_PLAN_SCHEMA, handle_msf_rpc_plan),
    ("security_hydra_plan", SECURITY_HYDRA_PLAN_SCHEMA, handle_hydra_plan),
    ("security_tshark_plan", SECURITY_TSHARK_PLAN_SCHEMA, handle_tshark_plan),
    ("security_tshark_capture", SECURITY_TSHARK_CAPTURE_SCHEMA, handle_tshark_capture),
    ("security_build_agent_team", SECURITY_BUILD_AGENT_TEAM_SCHEMA, handle_build_agent_team),
    ("security_dispatch_agent_tasks", SECURITY_DISPATCH_AGENT_TASKS_SCHEMA, handle_dispatch_agent_tasks),
    ("security_collect_agent_handoffs", SECURITY_COLLECT_AGENT_HANDOFFS_SCHEMA, handle_collect_agent_handoffs),
    ("security_generate_skill", SECURITY_GENERATE_SKILL_SCHEMA, handle_generate_skill),
    ("security_merge_skills", SECURITY_MERGE_SKILLS_SCHEMA, handle_merge_skills),
)


def register(ctx) -> None:
    """Register the security helper tools."""
    for name, schema, handler in _TOOLS:
        ctx.register_tool(
            name=name,
            toolset="security",
            schema=schema,
            handler=handler,
            emoji="security",
        )
