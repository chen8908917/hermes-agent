"""Runtime state and enforcement for security workflows.

The workflow builders in :mod:`plugins.security.workflows` describe the
process. This module turns that process into an enforceable runtime state for
one agent task/session. Enforcement is intentionally conservative and scoped:
normal Hermes coding sessions are not blocked unless a security workflow is
active, or a terminal command clearly invokes security assessment tooling.
"""

from __future__ import annotations

import json
import re
import time
from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

from .workflows import handle_build_workflow, _phase_catalog, _scope_decision


SECURITY_START_WORKFLOW_SCHEMA = {
    "name": "security_start_workflow",
    "description": (
        "Start an enforceable security workflow state for this task/session. "
        "After this, active tools must follow the current phase, artifacts, "
        "scope, and dispatch requirements."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "task_name": {"type": "string"},
            "objective": {"type": "string"},
            "mode": {
                "type": "string",
                "enum": ["defensive", "assessment", "range", "ctf"],
                "default": "assessment",
            },
            "allowed_targets": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "denied_targets": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "assets": {"type": "array", "items": {"type": "object"}, "default": []},
            "findings": {"type": "array", "items": {"type": "object"}, "default": []},
            "constraints": {"type": "object", "default": {}},
            "include_active_testing": {"type": "boolean", "default": True},
            "require_agent_dispatch": {
                "type": "boolean",
                "description": (
                    "Require dispatch/collect handoffs on active phases. "
                    "When omitted, defaults to false for CTF and true for other modes."
                ),
                "default": False,
            },
            "permission_profile": {
                "type": "string",
                "enum": ["standard", "relaxed"],
                "description": (
                    "Permission strictness for phase and scope gates. When omitted, "
                    "CTF/range default to relaxed and assessment/defensive default to standard."
                ),
                "default": "relaxed",
            },
            "workflow_id": {
                "type": "string",
                "description": "Optional explicit workflow id. Defaults to task/session context.",
                "default": "",
            },
            "reset_existing": {"type": "boolean", "default": False},
        },
        "required": ["task_name", "objective"],
    },
}


SECURITY_GET_WORKFLOW_STATE_SCHEMA = {
    "name": "security_get_workflow_state",
    "description": "Return the current enforceable security workflow state.",
    "parameters": {
        "type": "object",
        "properties": {
            "workflow_id": {"type": "string", "default": ""},
        },
    },
}


SECURITY_NEXT_ACTION_SCHEMA = {
    "name": "security_next_action",
    "description": (
        "Return the required next action for the active security workflow, "
        "including phase gates, missing artifacts, dispatch status, and allowed tools."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "workflow_id": {"type": "string", "default": ""},
        },
    },
}


SECURITY_RECORD_ARTIFACT_SCHEMA = {
    "name": "security_record_artifact",
    "description": (
        "Record a workflow artifact for the current phase, such as scope_matrix, "
        "ctf_attack_surface, foothold_evidence, candidate_flags, or skill_draft."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string"},
            "content": {
                "description": "Sanitized artifact content or summary.",
                "oneOf": [{"type": "string"}, {"type": "object"}, {"type": "array"}],
            },
            "phase_id": {"type": "string", "default": ""},
            "source_tool": {"type": "string", "default": ""},
            "workflow_id": {"type": "string", "default": ""},
        },
        "required": ["artifact_id", "content"],
    },
}


SECURITY_ADVANCE_PHASE_SCHEMA = {
    "name": "security_advance_phase",
    "description": (
        "Advance the active security workflow to the next phase after exit "
        "criteria are satisfied."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "workflow_id": {"type": "string", "default": ""},
            "completed_artifacts": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "rationale": {"type": "string", "default": ""},
            "force": {
                "type": "boolean",
                "description": "Allow an explicit user-approved phase override.",
                "default": False,
            },
        },
    },
}


SECURITY_RECORD_HYPOTHESIS_SCHEMA = {
    "name": "security_record_hypothesis",
    "description": "Record a tested security/CTF hypothesis and its evidence-backed result.",
    "parameters": {
        "type": "object",
        "properties": {
            "hypothesis": {"type": "string"},
            "technique": {"type": "string", "default": ""},
            "phase_id": {"type": "string", "default": ""},
            "evidence": {"type": "string", "default": ""},
            "result": {
                "type": "string",
                "enum": ["untested", "supported", "rejected", "inconclusive"],
                "default": "untested",
            },
            "workflow_id": {"type": "string", "default": ""},
        },
        "required": ["hypothesis"],
    },
}


SECURITY_MARK_DEAD_END_SCHEMA = {
    "name": "security_mark_dead_end",
    "description": (
        "Mark a repeated or exhausted path as a dead end so the workflow can "
        "force a change of approach instead of retrying the same tactic."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "technique": {"type": "string"},
            "reason": {"type": "string"},
            "phase_id": {"type": "string", "default": ""},
            "workflow_id": {"type": "string", "default": ""},
        },
        "required": ["technique", "reason"],
    },
}


SECURITY_RECORD_ATTACK_PATH_SCHEMA = {
    "name": "security_record_attack_path",
    "description": (
        "Record a candidate attack/solution path discovered during breadth-first "
        "reconnaissance. Use this before deep exploitation so paths can be ranked."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path_id": {"type": "string", "default": ""},
            "title": {"type": "string"},
            "target": {"type": "string", "default": ""},
            "entrypoint": {"type": "string", "default": ""},
            "technique": {"type": "string", "default": ""},
            "hypothesis": {"type": "string", "default": ""},
            "evidence": {"type": "string", "default": ""},
            "signals": {"type": "array", "items": {"type": "string"}, "default": []},
            "prerequisites": {"type": "array", "items": {"type": "string"}, "default": []},
            "success_probability": {"type": "integer", "minimum": 0, "maximum": 5, "default": 3},
            "impact": {"type": "integer", "minimum": 0, "maximum": 5, "default": 3},
            "cost": {"type": "integer", "minimum": 0, "maximum": 5, "default": 2},
            "noise": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1},
            "privilege_gain": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1},
            "phase_id": {"type": "string", "default": ""},
            "workflow_id": {"type": "string", "default": ""},
        },
        "required": ["title"],
    },
}


SECURITY_RANK_ATTACK_PATHS_SCHEMA = {
    "name": "security_rank_attack_paths",
    "description": (
        "Rank candidate attack paths by probability, impact, privilege gain, "
        "cost, noise, and known dead ends. Returns the current priority queue."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "include_closed": {"type": "boolean", "default": False},
            "workflow_id": {"type": "string", "default": ""},
        },
    },
}


SECURITY_SELECT_ATTACK_PATH_SCHEMA = {
    "name": "security_select_attack_path",
    "description": (
        "Select one ranked attack path for focused depth-first validation. "
        "If path_id is omitted, selects the highest-ranked open path."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path_id": {"type": "string", "default": ""},
            "rationale": {"type": "string", "default": ""},
            "workflow_id": {"type": "string", "default": ""},
        },
    },
}


SECURITY_UPDATE_ATTACK_PATH_SCHEMA = {
    "name": "security_update_attack_path",
    "description": (
        "Update the active or specified attack path after a depth-first attempt. "
        "Use rejected/dead_end to return to the ranked queue, supported to continue, "
        "or complete when the objective is achieved."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path_id": {"type": "string", "default": ""},
            "status": {
                "type": "string",
                "enum": ["queued", "selected", "testing", "supported", "rejected", "dead_end", "complete"],
                "default": "testing",
            },
            "evidence": {"type": "string", "default": ""},
            "result": {"type": "string", "default": ""},
            "new_signals": {"type": "array", "items": {"type": "string"}, "default": []},
            "next_steps": {"type": "array", "items": {"type": "string"}, "default": []},
            "score_adjustment": {"type": "integer", "minimum": -10, "maximum": 10, "default": 0},
            "workflow_id": {"type": "string", "default": ""},
        },
    },
}


STATE_TOOL_NAMES = {
    "security_start_workflow",
    "security_get_workflow_state",
    "security_next_action",
    "security_record_artifact",
    "security_advance_phase",
    "security_record_hypothesis",
    "security_mark_dead_end",
    "security_record_attack_path",
    "security_rank_attack_paths",
    "security_select_attack_path",
    "security_update_attack_path",
}

WORKFLOW_META_TOOLS = {
    "security_build_workflow",
    "security_workflow_gate",
    "security_build_agent_team",
    "security_dispatch_agent_tasks",
    "security_collect_agent_handoffs",
}

SECURITY_SCANNER_TOOLS = {
    "security_nmap_scan",
    "security_dir_enum",
    "security_dir_enum_scan",
    "security_whois_lookup",
    "security_subfinder_scan",
    "security_tshark_capture",
}

SECURITY_PLAN_TOOLS = {
    "security_parse_nmap_xml",
    "security_nmap_plan",
    "security_dir_enum_plan",
    "security_subfinder_plan",
    "security_sqlmap_plan",
    "security_msf_rpc_plan",
    "security_hydra_plan",
    "security_tshark_plan",
}

SECURITY_ANALYSIS_TOOLS = {
    "security_scope_check",
    "security_extract_iocs",
    "security_normalize_findings",
    "security_prioritize_findings",
    "security_generate_skill",
    "security_merge_skills",
}

OPERATIONAL_TOOL_NAMES = {"terminal", "process", "execute_code"}
DELEGATION_TOOL_NAMES = {"delegate_task"}
FILE_TOOL_NAMES = {"read_file", "search_files", "write_file", "patch"}
WEB_TOOL_NAMES = {"web_extract"}
MEDIA_URL_TOOL_NAMES = {"vision_analyze", "video_analyze"}
BROWSER_TOOL_NAMES = {
    "browser_navigate",
    "browser_snapshot",
    "browser_click",
    "browser_type",
    "browser_scroll",
    "browser_back",
    "browser_press",
    "browser_get_images",
    "browser_vision",
    "browser_console",
}
PRIVATE_URL_SCOPED_TOOL_NAMES = WEB_TOOL_NAMES | MEDIA_URL_TOOL_NAMES | BROWSER_TOOL_NAMES

SECURITY_ENFORCED_TOOL_NAMES = (
    SECURITY_SCANNER_TOOLS
    | {"security_sqlmap_plan", "security_msf_rpc_plan", "security_hydra_plan"}
)

DISPATCH_REQUIRED_PHASES = {
    "active_recon",
    "service_enumeration",
    "vulnerability_analysis",
    "validation_planning",
    "controlled_validation",
    "ctf_target_recon",
    "ctf_vulnerability_discovery",
    "ctf_foothold",
    "ctf_privilege_escalation",
    "ctf_flag_discovery",
}

PHASE_ALLOWED_TOOLS: dict[str, set[str]] = {
    "intake_authorization": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES,
    "resource_inventory": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | {"security_scope_check"},
    "scope_validation": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | {"security_scope_check"},
    "passive_recon": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | SECURITY_ANALYSIS_TOOLS,
    "active_recon": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | DELEGATION_TOOL_NAMES | SECURITY_SCANNER_TOOLS | SECURITY_PLAN_TOOLS,
    "service_enumeration": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | DELEGATION_TOOL_NAMES | SECURITY_SCANNER_TOOLS | SECURITY_PLAN_TOOLS,
    "vulnerability_analysis": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | DELEGATION_TOOL_NAMES | SECURITY_ANALYSIS_TOOLS | SECURITY_PLAN_TOOLS,
    "validation_planning": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | DELEGATION_TOOL_NAMES | SECURITY_PLAN_TOOLS | {"security_workflow_gate"},
    "controlled_validation": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | DELEGATION_TOOL_NAMES | SECURITY_PLAN_TOOLS | {"security_workflow_gate"},
    "post_validation_boundary": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | SECURITY_ANALYSIS_TOOLS,
    "detection_response": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | SECURITY_ANALYSIS_TOOLS | {"security_tshark_plan", "security_tshark_capture"},
    "remediation": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | SECURITY_ANALYSIS_TOOLS,
    "reporting": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | SECURITY_ANALYSIS_TOOLS,
    "retest_closeout": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | SECURITY_ANALYSIS_TOOLS | SECURITY_SCANNER_TOOLS,
    "skill_generation": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | SECURITY_ANALYSIS_TOOLS,
    "skill_consolidation": STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | SECURITY_ANALYSIS_TOOLS,
}

CTF_ACTIVE_TOOLS = (
    STATE_TOOL_NAMES
    | WORKFLOW_META_TOOLS
    | DELEGATION_TOOL_NAMES
    | FILE_TOOL_NAMES
    | WEB_TOOL_NAMES
    | MEDIA_URL_TOOL_NAMES
    | BROWSER_TOOL_NAMES
    | OPERATIONAL_TOOL_NAMES
    | SECURITY_SCANNER_TOOLS
    | SECURITY_PLAN_TOOLS
    | SECURITY_ANALYSIS_TOOLS
)

for _phase in (
    "ctf_target_recon",
    "ctf_vulnerability_discovery",
    "ctf_foothold",
    "ctf_privilege_escalation",
    "ctf_flag_discovery",
):
    PHASE_ALLOWED_TOOLS[_phase] = set(CTF_ACTIVE_TOOLS)

for _phase in (
    "ctf_intake",
    "ctf_challenge_classification",
    "ctf_flag_validation",
    "ctf_submission",
    "ctf_writeup",
    "ctf_cleanup",
    "ctf_skill_generation",
    "ctf_skill_consolidation",
):
    PHASE_ALLOWED_TOOLS[_phase] = (
        STATE_TOOL_NAMES | WORKFLOW_META_TOOLS | FILE_TOOL_NAMES | SECURITY_ANALYSIS_TOOLS
    )

PHASE_EXIT_ARTIFACTS: dict[str, set[str]] = {
    "intake_authorization": {"authorization_record", "rules_of_engagement"},
    "resource_inventory": {"asset_inventory"},
    "scope_validation": {"scope_matrix"},
    "passive_recon": {"passive_recon_notes", "candidate_attack_surface"},
    "active_recon": {"active_recon_results", "live_hosts", "observed_services"},
    "service_enumeration": {"service_inventory", "technology_fingerprints", "auth_surface_map"},
    "vulnerability_analysis": {"normalized_findings", "prioritized_findings", "validation_candidates"},
    "validation_planning": {"validation_plan"},
    "controlled_validation": {"validated_findings", "false_positive_notes", "validation_evidence"},
    "post_validation_boundary": {"boundary_decision", "post_validation_notes"},
    "detection_response": {"detection_notes", "traffic_timeline", "iocs"},
    "remediation": {"remediation_plan"},
    "reporting": {"technical_report", "executive_summary"},
    "retest_closeout": {"closeout_record", "retest_results"},
    "skill_generation": {"skill_draft"},
    "skill_consolidation": {"skill_merge_plan"},
    "ctf_intake": {"ctf_rules", "flag_format", "challenge_metadata"},
    "ctf_challenge_classification": {"challenge_type", "analysis_plan"},
    "ctf_target_recon": {"ctf_attack_surface", "entrypoint_candidates"},
    "ctf_vulnerability_discovery": {"candidate_solution_paths", "failed_hypotheses"},
    "ctf_foothold": {"foothold_evidence", "access_context"},
    "ctf_privilege_escalation": {"escalation_path", "expanded_access_evidence"},
    "ctf_flag_discovery": {"candidate_flags", "flag_locations"},
    "ctf_flag_validation": {"validated_flag", "rejected_candidates"},
    "ctf_submission": {"submission_record"},
    "ctf_writeup": {"ctf_writeup", "reproduction_steps"},
    "ctf_cleanup": {"cleanup_record"},
    "ctf_skill_generation": {"skill_draft"},
    "ctf_skill_consolidation": {"skill_merge_plan"},
}

AUTO_ARTIFACT_BY_TOOL = {
    "security_nmap_scan": "active_recon_results",
    "security_dir_enum": "service_inventory",
    "security_dir_enum_scan": "service_inventory",
    "security_whois_lookup": "passive_recon_notes",
    "security_subfinder_scan": "candidate_attack_surface",
    "security_tshark_capture": "traffic_timeline",
    "security_normalize_findings": "normalized_findings",
    "security_prioritize_findings": "prioritized_findings",
    "security_generate_skill": "skill_draft",
    "security_merge_skills": "skill_merge_plan",
}

SECURITY_COMMAND_RE = re.compile(
    r"(?i)(^|\s|/)(nmap|sqlmap|hydra|msfconsole|msfrpcd?|gobuster|dirsearch|ffuf|"
    r"feroxbuster|subfinder|tshark|tcpdump|linpeas|linenum|pspy|nc|netcat|telnet|"
    r"ftp|ssh|smbclient|enum4linux|rpcclient|dig|nslookup|host|ldapsearch|showmount|"
    r"snmpwalk)(\s|$)"
)
HIGH_RISK_COMMAND_RE = re.compile(
    r"(?i)(sudo\s+-l|/etc/shadow|\.sudo_as_admin_successful|find\s+/.*-perm\s+-?4000|nc\s+-e|bash\s+-i)"
)
CTF_AUTO_SCOPE_COMMAND_RE = re.compile(
    r"(?i)(^|\s|/)(curl|wget|httpie|python|nmap|sqlmap|hydra|msfconsole|msfrpcd?|"
    r"gobuster|dirsearch|ffuf|feroxbuster|subfinder|tshark|tcpdump|nc|netcat|"
    r"telnet|ftp|ssh|smbclient|enum4linux|rpcclient|dig|nslookup|host|ldapsearch|"
    r"showmount|snmpwalk)(\s|$)"
)
HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URL_RE = re.compile(r"(?i)\bhttps?://[^\s'\"<>]+")

_WORKFLOWS: dict[str, dict[str, Any]] = {}
_PRIVATE_URL_ALLOW_TOKENS: dict[str, Any] = {}


def handle_start_workflow(args: dict[str, Any], **kw: Any) -> str:
    key = _workflow_key(args, kw)
    if key in _WORKFLOWS and not bool(args.get("reset_existing", False)):
        return _json({
            "success": False,
            "error": "security workflow already active for this task/session",
            "workflow_id": key,
            "next_step": "Call security_get_workflow_state or pass reset_existing=true.",
        })

    workflow_args = {
        "task_name": args.get("task_name", ""),
        "objective": args.get("objective", ""),
        "mode": args.get("mode", "assessment"),
        "allowed_targets": _string_list(args.get("allowed_targets")),
        "denied_targets": _string_list(args.get("denied_targets")),
        "assets": _object_list(args.get("assets")),
        "findings": _object_list(args.get("findings")),
        "constraints": args.get("constraints") if isinstance(args.get("constraints"), dict) else {},
        "include_active_testing": bool(args.get("include_active_testing", True)),
    }
    workflow = json.loads(handle_build_workflow(workflow_args))
    if not workflow.get("success"):
        return _json({"success": False, "error": "failed to build workflow", "workflow": workflow})

    phases = [phase for phase in workflow.get("workflow", []) if phase.get("status") != "blocked"]
    if not phases:
        return _json({"success": False, "error": "workflow has no runnable phases", "workflow": workflow})

    mode = workflow_args["mode"] if workflow_args["mode"] in {"defensive", "assessment", "range", "ctf"} else workflow.get("task", {}).get("mode", "assessment")
    require_agent_dispatch = (
        bool(args.get("require_agent_dispatch"))
        if "require_agent_dispatch" in args
        else mode != "ctf"
    )
    permission_profile = _permission_profile(args.get("permission_profile"), mode)

    state = {
        "workflow_id": key,
        "status": "active",
        "created_at": time.time(),
        "updated_at": time.time(),
        "task": workflow.get("task", {}),
        "policy": workflow.get("policy", {}),
        "mode": mode,
        "allowed_targets": workflow_args["allowed_targets"],
        "denied_targets": workflow_args["denied_targets"],
        "constraints": workflow_args["constraints"],
        "require_agent_dispatch": require_agent_dispatch,
        "permission_profile": permission_profile,
        "phases": phases,
        "phase_index": 0,
        "completed_phases": [],
        "blocked_phases": [],
        "artifacts": {},
        "available_artifacts": [],
        "hypotheses": [],
        "dead_ends": [],
        "attack_paths": [],
        "active_attack_path_id": None,
        "deferred_tool_calls": [],
        "dispatch": {},
        "last_tool": None,
        "workflow": workflow,
    }
    _WORKFLOWS[key] = state
    for alias in _workflow_aliases(args, kw):
        _WORKFLOWS[alias] = state
    return _json({
        "success": True,
        "workflow_id": key,
        "current_phase": _current_phase(state),
        "state": _public_state(state),
        "next_action": _next_action(state),
    })


def handle_get_workflow_state(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    return _json({"success": True, "state": _public_state(state), "next_action": _next_action(state)})


def handle_next_action(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({
            "success": False,
            "error": "no active security workflow",
            "workflow_id": _workflow_key(args, kw),
            "next_action": "Call security_start_workflow before active security work.",
        })
    return _json({"success": True, "workflow_id": state["workflow_id"], "next_action": _next_action(state)})


def handle_record_artifact(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    artifact_id = str(args.get("artifact_id") or "").strip()
    if not artifact_id:
        return _json({"success": False, "error": "artifact_id is required"})
    phase_id = str(args.get("phase_id") or "").strip() or _current_phase_id(state)
    _record_artifact(
        state,
        artifact_id=artifact_id,
        content=args.get("content"),
        phase_id=phase_id,
        source_tool=str(args.get("source_tool") or "security_record_artifact"),
    )
    return _json({
        "success": True,
        "workflow_id": state["workflow_id"],
        "artifact_id": artifact_id,
        "available_artifacts": state["available_artifacts"],
        "next_action": _next_action(state),
    })


def handle_advance_phase(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    phase = _current_phase(state)
    if not phase:
        return _json({"success": False, "error": "workflow has no current phase"})

    for artifact_id in _string_list(args.get("completed_artifacts")):
        if artifact_id not in state["available_artifacts"]:
            state["available_artifacts"].append(artifact_id)

    missing = _missing_exit_artifacts(state, phase["id"])
    dispatch_blocker = _dispatch_blocker(state, phase["id"])
    force = bool(args.get("force", False))
    rationale = str(args.get("rationale") or "").strip()
    if (missing or dispatch_blocker) and not (force and rationale):
        return _json({
            "success": False,
            "workflow_id": state["workflow_id"],
            "phase_id": phase["id"],
            "missing_exit_artifacts": missing,
            "dispatch_blocker": dispatch_blocker,
            "error": "phase exit criteria are not satisfied",
            "next_action": _next_action(state),
        })

    state["completed_phases"].append({
        "phase_id": phase["id"],
        "completed_at": time.time(),
        "rationale": rationale,
        "forced": force,
    })
    state["phase_index"] += 1
    state["updated_at"] = time.time()
    if state["phase_index"] >= len(state["phases"]):
        state["status"] = "completed"
        return _json({
            "success": True,
            "workflow_id": state["workflow_id"],
            "status": "completed",
            "completed_phase": phase["id"],
        })

    return _json({
        "success": True,
        "workflow_id": state["workflow_id"],
        "completed_phase": phase["id"],
        "current_phase": _current_phase(state),
        "next_action": _next_action(state),
    })


def handle_record_hypothesis(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    hypothesis = str(args.get("hypothesis") or "").strip()
    if not hypothesis:
        return _json({"success": False, "error": "hypothesis is required"})
    item = {
        "phase_id": str(args.get("phase_id") or "").strip() or _current_phase_id(state),
        "hypothesis": hypothesis,
        "technique": str(args.get("technique") or "").strip().lower(),
        "evidence": str(args.get("evidence") or "").strip(),
        "result": str(args.get("result") or "untested").strip().lower(),
        "recorded_at": time.time(),
    }
    state["hypotheses"].append(item)
    state["updated_at"] = time.time()
    repeated = _repeated_rejections(state, item["technique"])
    return _json({
        "success": True,
        "workflow_id": state["workflow_id"],
        "hypothesis": item,
        "repeat_warning": repeated if repeated else None,
        "next_action": _next_action(state),
    })


def handle_mark_dead_end(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    technique = str(args.get("technique") or "").strip().lower()
    reason = str(args.get("reason") or "").strip()
    if not technique or not reason:
        return _json({"success": False, "error": "technique and reason are required"})
    item = {
        "phase_id": str(args.get("phase_id") or "").strip() or _current_phase_id(state),
        "technique": technique,
        "reason": reason,
        "recorded_at": time.time(),
    }
    state["dead_ends"].append(item)
    state["updated_at"] = time.time()
    return _json({
        "success": True,
        "workflow_id": state["workflow_id"],
        "dead_end": item,
        "next_action": _next_action(state),
    })


def handle_record_attack_path(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    title = str(args.get("title") or "").strip()
    if not title:
        return _json({"success": False, "error": "title is required"})

    paths = state.setdefault("attack_paths", [])
    path_id = str(args.get("path_id") or "").strip()
    existing = _find_attack_path(state, path_id) if path_id else None
    if not path_id:
        path_id = f"path-{len(paths) + 1}"
    phase_id = str(args.get("phase_id") or "").strip() or _current_phase_id(state)
    item = existing or {
        "path_id": path_id,
        "created_at": time.time(),
        "attempts": [],
    }
    item.update({
        "path_id": path_id,
        "phase_id": phase_id,
        "title": title,
        "target": str(args.get("target") or item.get("target") or "").strip(),
        "entrypoint": str(args.get("entrypoint") or item.get("entrypoint") or "").strip(),
        "technique": str(args.get("technique") or item.get("technique") or "").strip().lower(),
        "hypothesis": str(args.get("hypothesis") or item.get("hypothesis") or "").strip(),
        "evidence": str(args.get("evidence") or item.get("evidence") or "").strip(),
        "signals": _dedupe(_string_list(item.get("signals")) + _string_list(args.get("signals"))),
        "prerequisites": _dedupe(_string_list(item.get("prerequisites")) + _string_list(args.get("prerequisites"))),
        "success_probability": _bounded_score(args.get("success_probability"), item.get("success_probability", 3)),
        "impact": _bounded_score(args.get("impact"), item.get("impact", 3)),
        "cost": _bounded_score(args.get("cost"), item.get("cost", 2)),
        "noise": _bounded_score(args.get("noise"), item.get("noise", 1)),
        "privilege_gain": _bounded_score(args.get("privilege_gain"), item.get("privilege_gain", 1)),
        "status": str(item.get("status") or "queued"),
        "updated_at": time.time(),
    })
    item["score"] = _attack_path_score(item)
    if existing is None:
        paths.append(item)
    _sync_attack_path_artifact(state, phase_id)
    state["updated_at"] = time.time()
    return _json({
        "success": True,
        "workflow_id": state["workflow_id"],
        "attack_path": deepcopy(item),
        "ranked_attack_paths": _ranked_attack_paths(state),
        "next_action": _next_action(state),
    })


def handle_rank_attack_paths(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    include_closed = bool(args.get("include_closed", False))
    ranked = _ranked_attack_paths(state, include_closed=include_closed)
    return _json({
        "success": True,
        "workflow_id": state["workflow_id"],
        "active_attack_path": _active_attack_path(state),
        "ranked_attack_paths": ranked,
        "next_action": _next_action(state),
    })


def handle_select_attack_path(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    path_id = str(args.get("path_id") or "").strip()
    path = _find_attack_path(state, path_id) if path_id else None
    if path is None and not path_id:
        ranked = _ranked_attack_paths(state)
        if ranked:
            path = _find_attack_path(state, ranked[0]["path_id"])
    if path is None:
        return _json({
            "success": False,
            "error": "no open attack path available to select",
            "next_step": "Record breadth-first candidates with security_record_attack_path first.",
            "ranked_attack_paths": _ranked_attack_paths(state),
        })
    path["status"] = "selected"
    path["selected_at"] = time.time()
    path["selection_rationale"] = str(args.get("rationale") or "").strip()
    path["updated_at"] = time.time()
    path["score"] = _attack_path_score(path)
    state["active_attack_path_id"] = path["path_id"]
    state["updated_at"] = time.time()
    return _json({
        "success": True,
        "workflow_id": state["workflow_id"],
        "active_attack_path": deepcopy(path),
        "next_action": _next_action(state),
    })


def handle_update_attack_path(args: dict[str, Any], **kw: Any) -> str:
    state = _get_state(args, kw)
    if not state:
        return _json({"success": False, "error": "no active security workflow", "workflow_id": _workflow_key(args, kw)})
    path_id = str(args.get("path_id") or "").strip() or str(state.get("active_attack_path_id") or "")
    path = _find_attack_path(state, path_id)
    if path is None:
        return _json({"success": False, "error": "attack path not found", "path_id": path_id})

    status = str(args.get("status") or "testing").strip().lower()
    if status not in {"queued", "selected", "testing", "supported", "rejected", "dead_end", "complete"}:
        return _json({"success": False, "error": "invalid attack path status", "status": status})
    attempt = {
        "status": status,
        "phase_id": _current_phase_id(state),
        "evidence": str(args.get("evidence") or "").strip(),
        "result": str(args.get("result") or "").strip(),
        "new_signals": _string_list(args.get("new_signals")),
        "next_steps": _string_list(args.get("next_steps")),
        "recorded_at": time.time(),
    }
    path.setdefault("attempts", []).append(attempt)
    path["status"] = status
    path["evidence"] = attempt["evidence"] or path.get("evidence", "")
    path["signals"] = _dedupe(_string_list(path.get("signals")) + attempt["new_signals"])
    path["next_steps"] = attempt["next_steps"]
    path["score_adjustment"] = int(path.get("score_adjustment") or 0) + _bounded_adjustment(args.get("score_adjustment"))
    path["updated_at"] = time.time()
    path["score"] = _attack_path_score(path)
    if status in {"rejected", "dead_end", "complete"} and state.get("active_attack_path_id") == path["path_id"]:
        state["active_attack_path_id"] = None
    if status == "dead_end":
        state["dead_ends"].append({
            "phase_id": _current_phase_id(state),
            "technique": str(path.get("technique") or path["path_id"]),
            "reason": attempt["result"] or attempt["evidence"] or "attack path exhausted",
            "attack_path_id": path["path_id"],
            "recorded_at": time.time(),
        })
    _sync_attack_path_artifact(state, _current_phase_id(state))
    state["updated_at"] = time.time()
    return _json({
        "success": True,
        "workflow_id": state["workflow_id"],
        "attack_path": deepcopy(path),
        "active_attack_path": _active_attack_path(state),
        "ranked_attack_paths": _ranked_attack_paths(state),
        "next_action": _next_action(state),
    })


def security_pre_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
) -> dict[str, str] | None:
    tool_args = args if isinstance(args, dict) else {}
    private_url_key = _private_url_scope_key(tool_call_id, task_id, session_id, tool_name)
    _reset_private_url_scope(private_url_key)
    state = _get_state(tool_args, {"task_id": task_id, "session_id": session_id})

    if not state:
        if _active_workflow_count() > 1 and (
            tool_name in SECURITY_ENFORCED_TOOL_NAMES
            or (tool_name in OPERATIONAL_TOOL_NAMES and _looks_like_security_command(tool_args))
        ):
            return _block("Multiple active security workflows exist; pass workflow_id so phase and scope gates cannot be bypassed.")
        if tool_name in SECURITY_ENFORCED_TOOL_NAMES:
            return _block("Start a security workflow with security_start_workflow before using active security tools.")
        if tool_name in OPERATIONAL_TOOL_NAMES and _looks_like_security_command(tool_args):
            return _block("Start a security workflow with security_start_workflow before running security assessment commands.")
        return None

    if state.get("status") != "active":
        return None
    if tool_name in STATE_TOOL_NAMES:
        return None

    phase = _current_phase(state)
    if not phase:
        return _block("Security workflow has no current phase. Call security_get_workflow_state.")
    phase_id = phase["id"]

    if tool_name in {"security_dispatch_agent_tasks", "security_collect_agent_handoffs"}:
        requested_phase = str(tool_args.get("phase_id") or "").strip()
        if requested_phase and requested_phase != phase_id:
            return _block(f"Security workflow is in phase {phase_id}; cannot operate on phase {requested_phase}.")
        return None

    allowed_tools = _allowed_tools_for_state(state, phase_id)

    if tool_name in DELEGATION_TOOL_NAMES:
        if tool_name not in allowed_tools:
            return _block(_phase_tool_block_message(state, phase_id, tool_name, tool_args))
        blocker = _delegate_blocker(state, phase_id)
        return _block(blocker) if blocker else None

    dispatch_blocker = _dispatch_blocker(state, phase_id)
    if dispatch_blocker and tool_name not in WORKFLOW_META_TOOLS:
        return _block(dispatch_blocker)

    if tool_name not in allowed_tools:
        return _block(_phase_tool_block_message(state, phase_id, tool_name, tool_args))

    supplied_phase = str(tool_args.get("phase_id") or "").strip()
    if supplied_phase and supplied_phase != phase_id:
        return _block(f"Security workflow is in phase {phase_id}; tool requested phase {supplied_phase}.")

    target_blocker = _target_blocker(state, tool_name, tool_args)
    if target_blocker:
        return _block(target_blocker)

    repeat_blocker = _repeat_blocker(state, tool_name, tool_args)
    if repeat_blocker:
        return _block(repeat_blocker)

    _maybe_enable_private_url_scope(private_url_key, state, tool_name)
    return None


def security_post_tool_call(
    *,
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int = 0,
) -> None:
    _reset_private_url_scope(_private_url_scope_key(tool_call_id, task_id, session_id, tool_name))
    tool_args = args if isinstance(args, dict) else {}
    state = _get_state(tool_args, {"task_id": task_id, "session_id": session_id})
    if not state or state.get("status") != "active":
        return

    result_obj = _loads_json(result)
    phase_id = _current_phase_id(state)
    state["last_tool"] = {
        "tool_name": tool_name,
        "phase_id": phase_id,
        "duration_ms": duration_ms,
        "recorded_at": time.time(),
    }
    state["updated_at"] = time.time()

    if tool_name == "security_dispatch_agent_tasks" and result_obj.get("success"):
        requested_phase = str(result_obj.get("phase_id") or tool_args.get("phase_id") or phase_id)
        phase_dispatch = state["dispatch"].setdefault(requested_phase, {})
        phase_dispatch["dispatched"] = True
        phase_dispatch["dispatch_result"] = result_obj
        return

    if tool_name == "security_collect_agent_handoffs" and result_obj.get("success"):
        requested_phase = str(result_obj.get("phase_id") or tool_args.get("phase_id") or phase_id)
        phase_dispatch = state["dispatch"].setdefault(requested_phase, {})
        phase_dispatch["handoffs_collected"] = True
        phase_dispatch["handoff_result"] = result_obj
        _record_artifact(
            state,
            artifact_id="agent_handoffs",
            content=result_obj.get("merged") or result_obj,
            phase_id=requested_phase,
            source_tool=tool_name,
        )
        return

    artifact_id = AUTO_ARTIFACT_BY_TOOL.get(tool_name)
    if artifact_id and result_obj.get("success", True):
        if state["mode"] == "ctf" and tool_name in {"security_nmap_scan", "security_dir_enum", "security_dir_enum_scan", "security_subfinder_scan"}:
            artifact_id = "ctf_attack_surface"
        _record_artifact(
            state,
            artifact_id=artifact_id,
            content=_artifact_summary(result_obj),
            phase_id=phase_id,
            source_tool=tool_name,
        )


def reset_security_workflows() -> None:
    """Test helper: clear in-memory workflow state."""
    _WORKFLOWS.clear()
    for key in list(_PRIVATE_URL_ALLOW_TOKENS):
        _reset_private_url_scope(key)


def _workflow_key(args: dict[str, Any], kw: dict[str, Any]) -> str:
    explicit = str(args.get("workflow_id") or "").strip()
    if explicit:
        return explicit
    task_id = str(kw.get("task_id") or "").strip()
    if task_id:
        return f"task:{task_id}"
    session_id = str(kw.get("session_id") or "").strip()
    if session_id:
        return f"session:{session_id}"
    return "default"


def _get_state(args: dict[str, Any], kw: dict[str, Any]) -> dict[str, Any] | None:
    for key in [_workflow_key(args, kw), *_workflow_aliases(args, kw), "default"]:
        state = _WORKFLOWS.get(key)
        if state is not None:
            return state
    return _sole_active_workflow()


def _sole_active_workflow() -> dict[str, Any] | None:
    active_by_id = {}
    for state in _WORKFLOWS.values():
        if isinstance(state, dict) and state.get("status") == "active":
            active_by_id[str(state.get("workflow_id") or id(state))] = state
    if len(active_by_id) == 1:
        return next(iter(active_by_id.values()))
    return None


def _active_workflow_count() -> int:
    return len({
        str(state.get("workflow_id") or id(state))
        for state in _WORKFLOWS.values()
        if isinstance(state, dict) and state.get("status") == "active"
    })


def _workflow_aliases(args: dict[str, Any], kw: dict[str, Any]) -> list[str]:
    aliases = []
    task_id = str(kw.get("task_id") or "").strip()
    if task_id:
        aliases.append(f"task:{task_id}")
    session_id = str(kw.get("session_id") or "").strip()
    if session_id:
        aliases.append(f"session:{session_id}")
    explicit = str(args.get("workflow_id") or "").strip()
    if explicit:
        aliases.append(explicit)
    return _dedupe(aliases)


def _permission_profile(value: Any, mode: str) -> str:
    requested = str(value or "").strip().lower()
    if requested in {"standard", "relaxed"}:
        return requested
    return "relaxed" if mode in {"ctf", "range"} else "standard"


def _relaxed_permissions(state: dict[str, Any]) -> bool:
    return (
        str(state.get("permission_profile") or "standard") == "relaxed"
        and state.get("mode") in {"ctf", "range"}
    )


def _private_url_scope_key(
    tool_call_id: str,
    task_id: str,
    session_id: str,
    tool_name: str,
) -> str:
    explicit = str(tool_call_id or "").strip()
    if explicit:
        return f"call:{explicit}"
    return f"implicit:{session_id or '-'}:{task_id or '-'}:{tool_name or '-'}"


def _maybe_enable_private_url_scope(
    key: str,
    state: dict[str, Any],
    tool_name: str,
) -> None:
    if not _relaxed_permissions(state):
        return
    if tool_name not in PRIVATE_URL_SCOPED_TOOL_NAMES:
        return
    try:
        from tools.url_safety import set_scoped_private_url_allow

        _PRIVATE_URL_ALLOW_TOKENS[key] = set_scoped_private_url_allow(True)
    except Exception:
        return


def _reset_private_url_scope(key: str) -> None:
    token = _PRIVATE_URL_ALLOW_TOKENS.pop(key, None)
    if token is None:
        return
    try:
        from tools.url_safety import reset_scoped_private_url_allow

        reset_scoped_private_url_allow(token)
    except Exception:
        return


def _allowed_tools_for_state(state: dict[str, Any], phase_id: str) -> set[str]:
    allowed = set(PHASE_ALLOWED_TOOLS.get(phase_id, STATE_TOOL_NAMES | WORKFLOW_META_TOOLS))
    if not _relaxed_permissions(state):
        return allowed
    return (
        allowed
        | STATE_TOOL_NAMES
        | WORKFLOW_META_TOOLS
        | FILE_TOOL_NAMES
        | WEB_TOOL_NAMES
        | MEDIA_URL_TOOL_NAMES
        | BROWSER_TOOL_NAMES
        | OPERATIONAL_TOOL_NAMES
        | SECURITY_SCANNER_TOOLS
        | SECURITY_PLAN_TOOLS
        | SECURITY_ANALYSIS_TOOLS
    )


def _current_phase(state: dict[str, Any]) -> dict[str, Any] | None:
    phases = state.get("phases") if isinstance(state.get("phases"), list) else []
    index = int(state.get("phase_index") or 0)
    if index < 0 or index >= len(phases):
        return None
    return phases[index]


def _current_phase_id(state: dict[str, Any]) -> str:
    phase = _current_phase(state)
    return str(phase.get("id") if phase else "")


def _public_state(state: dict[str, Any]) -> dict[str, Any]:
    phase = _current_phase(state)
    return {
        "workflow_id": state["workflow_id"],
        "status": state["status"],
        "mode": state["mode"],
        "task": state["task"],
        "current_phase": phase,
        "phase_index": state["phase_index"],
        "phase_count": len(state["phases"]),
        "completed_phases": state["completed_phases"],
        "available_artifacts": state["available_artifacts"],
        "artifact_count": len(state["artifacts"]),
        "hypothesis_count": len(state["hypotheses"]),
        "dead_ends": state["dead_ends"][-5:],
        "attack_path_count": len(state.get("attack_paths", [])),
        "active_attack_path": _active_attack_path(state),
        "ranked_attack_paths": _ranked_attack_paths(state)[:5],
        "deferred_tool_calls": state.get("deferred_tool_calls", [])[-10:],
        "dispatch": state["dispatch"],
        "require_agent_dispatch": state["require_agent_dispatch"],
        "permission_profile": state.get("permission_profile", "standard"),
        "allowed_targets": state["allowed_targets"],
        "denied_targets": state["denied_targets"],
        "last_tool": state.get("last_tool"),
    }


def _next_action(state: dict[str, Any]) -> dict[str, Any]:
    phase = _current_phase(state)
    if not phase:
        return {"action": "complete", "message": "Workflow has no remaining phases."}
    phase_id = phase["id"]
    missing = _missing_exit_artifacts(state, phase_id)
    dispatch_blocker = _dispatch_blocker(state, phase_id)
    repeated = _latest_repeat_warning(state)
    deferred_ready = _deferred_calls_for_phase(state, phase_id)
    path_strategy = _path_strategy(state, phase_id)
    return {
        "action": "execute_current_phase",
        "phase_id": phase_id,
        "phase_name": phase.get("name"),
        "objective": phase.get("objective"),
        "required_artifacts": phase.get("required_artifacts", []),
        "exit_artifacts_any_of": sorted(PHASE_EXIT_ARTIFACTS.get(phase_id, set())),
        "missing_exit_artifacts": missing,
        "dispatch_required": _phase_requires_dispatch(state, phase_id),
        "dispatch_blocker": dispatch_blocker,
        "allowed_tools": sorted(_allowed_tools_for_state(state, phase_id)),
        "repeat_warning": repeated,
        "path_strategy": path_strategy,
        "deferred_tool_calls_ready": deferred_ready,
        "instructions": _phase_instructions(state, phase_id, dispatch_blocker, missing, repeated, path_strategy),
    }


def _phase_instructions(
    state: dict[str, Any],
    phase_id: str,
    dispatch_blocker: str | None,
    missing: list[str],
    repeated: str | None,
    path_strategy: dict[str, Any] | None = None,
) -> list[str]:
    instructions = []
    if dispatch_blocker:
        instructions.append(dispatch_blocker)
    if repeated:
        instructions.append(repeated)
    if missing:
        instructions.append("Record at least one exit artifact before advancing: " + ", ".join(missing))
    if path_strategy and path_strategy.get("instruction"):
        instructions.append(str(path_strategy["instruction"]))
    if phase_id in DISPATCH_REQUIRED_PHASES and not dispatch_blocker:
        instructions.append("Merge handoffs with security_collect_agent_handoffs before advancing.")
    instructions.append("Call security_advance_phase only after the phase exit criteria are met.")
    return instructions


def _phase_tool_block_message(
    state: dict[str, Any],
    phase_id: str,
    tool_name: str,
    args: dict[str, Any],
) -> str:
    base = f"Tool {tool_name} is not allowed during security phase {phase_id}."
    next_phase = _next_phase_allowing_tool(state, tool_name)
    missing = _missing_exit_artifacts(state, phase_id)
    missing_text = ", ".join(missing) if missing else "the current phase exit artifact"
    deferred = _record_deferred_tool_call(
        state,
        current_phase=phase_id,
        target_phase=next_phase,
        tool_name=tool_name,
        args=args,
        reason="tool_not_allowed_in_current_phase",
    )
    deferred_text = (
        f" Deferred call id {deferred['id']} has been recorded for {next_phase}."
        if next_phase else
        f" Deferred call id {deferred['id']} has been recorded for later review."
    )

    if state.get("mode") == "ctf" and tool_name in OPERATIONAL_TOOL_NAMES and _is_http_request_command(args):
        retry_text = f" then retry the HTTP request in {next_phase}" if next_phase else ""
        return (
            f"{base} Continue the current phase without the HTTP request: complete the remaining phase tasks, "
            f"record {missing_text} with security_record_artifact, call security_advance_phase,{retry_text}. "
            "Do not use delegate_task or a subagent to bypass phase or scope gates."
            f"{deferred_text}"
        )

    if tool_name in DELEGATION_TOOL_NAMES:
        retry_text = f" Use delegation later in {next_phase} if needed." if next_phase else ""
        return (
            f"{base} Do not use delegate_task or a subagent to bypass phase or scope gates. "
            f"Continue the current phase, record {missing_text}, and call security_advance_phase when ready."
            f"{retry_text}{deferred_text}"
        )

    retry_text = f" Retry this tool in {next_phase} if it is still needed." if next_phase else ""
    return f"{base} Call security_next_action, continue the current phase, and advance only after exit criteria are met.{retry_text}{deferred_text}"


def _next_phase_allowing_tool(state: dict[str, Any], tool_name: str) -> str:
    phases = state.get("phases") if isinstance(state.get("phases"), list) else []
    start = int(state.get("phase_index") or 0) + 1
    for phase in phases[start:]:
        phase_id = str(phase.get("id") or "")
        if tool_name in _allowed_tools_for_state(state, phase_id):
            return phase_id
    return ""


def _record_deferred_tool_call(
    state: dict[str, Any],
    *,
    current_phase: str,
    target_phase: str,
    tool_name: str,
    args: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    calls = state.setdefault("deferred_tool_calls", [])
    signature = {
        "target_phase": target_phase,
        "tool_name": tool_name,
        "args": _deferred_args(args),
        "reason": reason,
    }
    for call in calls:
        if (
            call.get("target_phase") == signature["target_phase"]
            and call.get("tool_name") == signature["tool_name"]
            and call.get("args") == signature["args"]
            and call.get("reason") == signature["reason"]
            and call.get("status") == "pending"
        ):
            return call
    call = {
        "id": f"deferred-{len(calls) + 1}",
        "status": "pending",
        "current_phase": current_phase,
        "target_phase": target_phase,
        "tool_name": tool_name,
        "args": signature["args"],
        "reason": reason,
        "recorded_at": time.time(),
    }
    calls.append(call)
    state["updated_at"] = time.time()
    return call


def _deferred_calls_for_phase(state: dict[str, Any], phase_id: str) -> list[dict[str, Any]]:
    return [
        call for call in state.get("deferred_tool_calls", [])
        if call.get("status") == "pending" and call.get("target_phase") == phase_id
    ]


def _deferred_args(args: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key in ("command", "target", "targets", "url", "host", "domain", "phase_id"):
        if key in args:
            result[key] = deepcopy(args[key])
    return result


def _is_http_request_command(args: dict[str, Any]) -> bool:
    command = _command_text(args)
    return bool(
        re.search(r"(?i)\bhttps?://", command)
        and re.search(r"(?i)(\bcurl\b|\bwget\b|\bhttpie\b|\bpython\b|\brequests\b|fetch\()", command)
    )


def _phase_requires_dispatch(state: dict[str, Any], phase_id: str) -> bool:
    return bool(state.get("require_agent_dispatch")) and phase_id in DISPATCH_REQUIRED_PHASES


def _dispatch_blocker(state: dict[str, Any], phase_id: str) -> str | None:
    if not _phase_requires_dispatch(state, phase_id):
        return None
    dispatch_state = state.get("dispatch", {}).get(phase_id, {})
    if not dispatch_state.get("dispatched"):
        return f"Phase {phase_id} requires security_dispatch_agent_tasks before direct tool use."
    if not dispatch_state.get("handoffs_collected"):
        return f"Phase {phase_id} requires security_collect_agent_handoffs before direct tool use or phase advance."
    return None


def _delegate_blocker(state: dict[str, Any], phase_id: str) -> str | None:
    if not _phase_requires_dispatch(state, phase_id):
        return None
    dispatch_state = state.get("dispatch", {}).get(phase_id, {})
    if not dispatch_state.get("dispatched"):
        return f"Phase {phase_id} requires security_dispatch_agent_tasks before delegate_task."
    return None


def _missing_exit_artifacts(state: dict[str, Any], phase_id: str) -> list[str]:
    expected = PHASE_EXIT_ARTIFACTS.get(phase_id, set())
    if not expected:
        return []
    available = set(_string_list(state.get("available_artifacts")))
    if expected & available:
        return []
    return sorted(expected)


def _record_artifact(
    state: dict[str, Any],
    *,
    artifact_id: str,
    content: Any,
    phase_id: str,
    source_tool: str,
) -> None:
    state["artifacts"][artifact_id] = {
        "artifact_id": artifact_id,
        "phase_id": phase_id,
        "source_tool": source_tool,
        "content": deepcopy(content),
        "recorded_at": time.time(),
    }
    if artifact_id not in state["available_artifacts"]:
        state["available_artifacts"].append(artifact_id)
    state["updated_at"] = time.time()


def _find_attack_path(state: dict[str, Any], path_id: str) -> dict[str, Any] | None:
    if not path_id:
        return None
    for path in state.get("attack_paths", []):
        if isinstance(path, dict) and path.get("path_id") == path_id:
            return path
    return None


def _active_attack_path(state: dict[str, Any]) -> dict[str, Any] | None:
    path = _find_attack_path(state, str(state.get("active_attack_path_id") or ""))
    return deepcopy(path) if path else None


def _ranked_attack_paths(state: dict[str, Any], include_closed: bool = False) -> list[dict[str, Any]]:
    closed = {"rejected", "dead_end", "complete"}
    ranked = []
    for path in state.get("attack_paths", []):
        if not isinstance(path, dict):
            continue
        if not include_closed and path.get("status") in closed:
            continue
        item = deepcopy(path)
        item["score"] = _attack_path_score(item)
        ranked.append(item)
    ranked.sort(key=lambda item: (item.get("score", 0), item.get("updated_at", 0)), reverse=True)
    return ranked


def _attack_path_score(path: dict[str, Any]) -> int:
    probability = _bounded_score(path.get("success_probability"), 3)
    impact = _bounded_score(path.get("impact"), 3)
    gain = _bounded_score(path.get("privilege_gain"), 1)
    cost = _bounded_score(path.get("cost"), 2)
    noise = _bounded_score(path.get("noise"), 1)
    adjustment = _bounded_adjustment(path.get("score_adjustment"))
    status = str(path.get("status") or "queued")
    status_adjustment = {
        "queued": 0,
        "selected": 3,
        "testing": 2,
        "supported": 6,
        "rejected": -12,
        "dead_end": -20,
        "complete": 10,
    }.get(status, 0)
    return (probability * 4) + (impact * 3) + (gain * 2) - (cost * 2) - noise + adjustment + status_adjustment


def _sync_attack_path_artifact(state: dict[str, Any], phase_id: str) -> None:
    ranked = _ranked_attack_paths(state, include_closed=True)
    if not ranked:
        return
    if phase_id == "ctf_target_recon":
        artifact_id = "entrypoint_candidates"
    elif phase_id in {"ctf_vulnerability_discovery", "ctf_foothold"}:
        artifact_id = "candidate_solution_paths"
    elif phase_id == "vulnerability_analysis":
        artifact_id = "validation_candidates"
    else:
        return
    _record_artifact(
        state,
        artifact_id=artifact_id,
        content={"ranked_attack_paths": ranked},
        phase_id=phase_id,
        source_tool="security_attack_path_queue",
    )


def _path_strategy(state: dict[str, Any], phase_id: str) -> dict[str, Any]:
    active = _active_attack_path(state)
    ranked = _ranked_attack_paths(state)
    if active and phase_id in {"ctf_vulnerability_discovery", "ctf_foothold", "ctf_privilege_escalation", "ctf_flag_discovery", "validation_planning", "controlled_validation"}:
        return {
            "mode": "focused_depth",
            "active_path_id": active["path_id"],
            "active_path": active,
            "instruction": (
                "Continue focused validation of the active attack path. "
                "After each attempt, call security_update_attack_path with supported, rejected, or dead_end."
            ),
        }
    if phase_id in {"ctf_target_recon", "active_recon", "service_enumeration", "passive_recon"}:
        return {
            "mode": "breadth_map",
            "open_path_count": len(ranked),
            "top_paths": ranked[:3],
            "instruction": (
                "Prefer breadth-first mapping now: enumerate services, directories, inputs, and anomalies; "
                "record each plausible route with security_record_attack_path before deep exploitation."
            ),
        }
    if phase_id in {"ctf_vulnerability_discovery", "vulnerability_analysis", "validation_planning"}:
        if ranked:
            return {
                "mode": "rank_then_depth",
                "open_path_count": len(ranked),
                "top_paths": ranked[:3],
                "instruction": (
                    "Rank the candidate paths with security_rank_attack_paths, then select the highest-value "
                    "open path with security_select_attack_path for focused validation."
                ),
            }
        return {
            "mode": "needs_breadth_candidates",
            "open_path_count": 0,
            "instruction": (
                "No open attack paths are recorded. Return to breadth mapping and use security_record_attack_path "
                "instead of guessing a single exploitation route."
            ),
        }
    if phase_id in {"ctf_foothold", "ctf_privilege_escalation", "ctf_flag_discovery", "controlled_validation"}:
        if ranked:
            return {
                "mode": "select_next_depth_path",
                "open_path_count": len(ranked),
                "top_paths": ranked[:3],
                "instruction": "Select the next ranked attack path, validate it, and update its status before switching paths.",
            }
        return {
            "mode": "no_open_paths",
            "open_path_count": 0,
            "instruction": "No open attack paths remain; record a new candidate or mark the phase complete with evidence.",
        }
    return {"mode": "phase_default", "open_path_count": len(ranked), "top_paths": ranked[:3]}


def _bounded_score(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return min(max(parsed, 0), 5)


def _bounded_adjustment(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = 0
    return min(max(parsed, -10), 10)


def _target_blocker(state: dict[str, Any], tool_name: str, args: dict[str, Any]) -> str | None:
    targets = _targets_from_args(args)
    if tool_name in OPERATIONAL_TOOL_NAMES:
        targets.extend(_targets_from_command(args))
    targets = _dedupe([target for target in targets if target])
    if not targets:
        return None
    allowed_targets = _string_list(state.get("allowed_targets"))
    denied_targets = _string_list(state.get("denied_targets"))
    if not allowed_targets:
        if _relaxed_command_allowed_without_scope(state, tool_name, args, targets):
            for target in targets:
                decision = _scope_decision(target, [target], denied_targets)
                if not decision["allowed"]:
                    return f"Target {target} is outside authorized scope: {decision['reason']}"
            return None
        if state.get("mode") == "ctf":
            return "Non-HTTP network targets require explicit allowed_targets even in CTF mode."
        return "Active security workflow requires explicit allowed_targets for network targets."
    for target in targets:
        decision = _scope_decision(target, allowed_targets, denied_targets)
        if not decision["allowed"]:
            return f"Target {target} is outside authorized scope: {decision['reason']}"
    return None


def _ctf_command_allowed_without_scope(
    state: dict[str, Any],
    tool_name: str,
    args: dict[str, Any],
    targets: list[str],
) -> bool:
    if state.get("mode") != "ctf":
        return False
    if _current_phase_id(state) not in {
        "ctf_target_recon",
        "ctf_vulnerability_discovery",
        "ctf_foothold",
        "ctf_privilege_escalation",
        "ctf_flag_discovery",
    }:
        return False
    if tool_name in OPERATIONAL_TOOL_NAMES:
        command = _command_text(args)
        return bool(CTF_AUTO_SCOPE_COMMAND_RE.search(command) or re.search(r"(?i)\bhttps?://", command))
    if tool_name in PRIVATE_URL_SCOPED_TOOL_NAMES:
        return bool(targets)
    if tool_name in SECURITY_ENFORCED_TOOL_NAMES | SECURITY_PLAN_TOOLS:
        return True
    return False


def _relaxed_command_allowed_without_scope(
    state: dict[str, Any],
    tool_name: str,
    args: dict[str, Any],
    targets: list[str],
) -> bool:
    if not _relaxed_permissions(state):
        return _ctf_command_allowed_without_scope(state, tool_name, args, targets)
    if state.get("mode") not in {"ctf", "range"}:
        return False
    if tool_name in OPERATIONAL_TOOL_NAMES:
        return bool(targets)
    if tool_name in PRIVATE_URL_SCOPED_TOOL_NAMES:
        return bool(targets)
    if tool_name in SECURITY_ENFORCED_TOOL_NAMES | SECURITY_PLAN_TOOLS | SECURITY_SCANNER_TOOLS:
        return True
    return False


def _ctf_http_request_allowed_without_scope(
    state: dict[str, Any],
    tool_name: str,
    args: dict[str, Any],
    targets: list[str],
) -> bool:
    if state.get("mode") != "ctf":
        return False
    if _current_phase_id(state) not in {
        "ctf_target_recon",
        "ctf_vulnerability_discovery",
        "ctf_foothold",
        "ctf_privilege_escalation",
        "ctf_flag_discovery",
    }:
        return False
    if tool_name not in OPERATIONAL_TOOL_NAMES or not targets:
        return False
    command = _command_text(args)
    if not re.search(r"(?i)\bhttps?://", command):
        return False
    if not re.search(r"(?i)(\bcurl\b|\bwget\b|\bhttpie\b|\bpython\b|\brequests\b|fetch\()", command):
        return False
    return True


def _repeat_blocker(state: dict[str, Any], tool_name: str, args: dict[str, Any]) -> str | None:
    technique = _technique_from_tool(tool_name, args)
    if not technique:
        return None
    for dead_end in state.get("dead_ends", []):
        if dead_end.get("phase_id") == _current_phase_id(state) and dead_end.get("technique") == technique:
            return f"Technique {technique} is marked as a dead end for this phase: {dead_end.get('reason')}"
    return _repeated_rejections(state, technique)


def _repeated_rejections(state: dict[str, Any], technique: str) -> str | None:
    if not technique:
        return None
    current = _current_phase_id(state)
    rejected = [
        item for item in state.get("hypotheses", [])
        if item.get("phase_id") == current
        and item.get("technique") == technique
        and item.get("result") == "rejected"
    ]
    if len(rejected) >= 2:
        return f"Technique {technique} has already been rejected {len(rejected)} times in {current}; record a new hypothesis or switch approach."
    return None


def _latest_repeat_warning(state: dict[str, Any]) -> str | None:
    techniques = [str(item.get("technique") or "") for item in state.get("hypotheses", [])]
    for technique in reversed(techniques):
        warning = _repeated_rejections(state, technique)
        if warning:
            return warning
    return None


def _looks_like_security_command(args: dict[str, Any]) -> bool:
    command = _command_text(args)
    if not command:
        return False
    return bool(SECURITY_COMMAND_RE.search(command) or HIGH_RISK_COMMAND_RE.search(command))


def _command_text(args: dict[str, Any]) -> str:
    if "command" in args:
        return str(args.get("command") or "")
    if "code" in args:
        return str(args.get("code") or "")
    if "script" in args:
        return str(args.get("script") or "")
    return ""


def _targets_from_args(args: dict[str, Any]) -> list[str]:
    targets = []
    for key in ("target", "domain", "url", "host", "image_url", "video_url"):
        value = str(args.get(key) or "").strip()
        if value:
            targets.append(_target_host(value))
    for key in ("targets", "requested_targets", "urls"):
        value = args.get(key)
        if isinstance(value, list):
            targets.extend(_target_host(str(item)) for item in value)
    return [target for target in targets if target]


def _targets_from_command(args: dict[str, Any]) -> list[str]:
    command = _command_text(args)
    if not command:
        return []
    targets = []
    for match in URL_RE.findall(command):
        host = _target_host(match.rstrip(".,;:)]}"))
        if host:
            targets.append(host)
    command_without_urls = URL_RE.sub(" ", command)
    targets.extend(HOST_RE.findall(command_without_urls))
    targets.extend(IPV4_RE.findall(command_without_urls))
    ignored_suffixes = (
        ".py", ".sh", ".txt", ".md", ".json", ".yaml", ".yml", ".xml",
        ".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".css", ".js",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    )
    return [
        target for target in targets
        if not target.lower().endswith(ignored_suffixes)
        and not target.startswith("127.")
        and target != "localhost"
    ]


def _target_host(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw
    return host.strip("[]").lower()


def _technique_from_tool(tool_name: str, args: dict[str, Any]) -> str:
    if tool_name == "security_sqlmap_plan":
        return "sqli"
    if tool_name == "security_hydra_plan":
        return "credential_testing"
    if tool_name == "security_msf_rpc_plan":
        return "metasploit"
    command = _command_text(args).lower()
    if "sqlmap" in command or "union select" in command or " or 1=1" in command:
        return "sqli"
    if "linpeas" in command or "sudo -l" in command or "-perm -4000" in command:
        return "local_privesc"
    if "hydra" in command:
        return "credential_testing"
    if "nmap" in command:
        return "network_recon"
    return ""


def _artifact_summary(result_obj: dict[str, Any]) -> dict[str, Any]:
    summary = {}
    for key in ("success", "executed", "exit_code", "count", "summary", "parsed", "subdomains", "findings"):
        if key in result_obj:
            summary[key] = result_obj[key]
    if not summary:
        summary = {"result_keys": sorted(result_obj.keys())[:20]}
    return summary


def _loads_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except Exception:
            return {"raw": value[:1000]}
    return {"value": str(value)}


def _block(message: str) -> dict[str, str]:
    return {"action": "block", "message": message}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _object_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False)
