"""Multi-agent orchestration helpers for security workflows."""

from __future__ import annotations

import json
from typing import Any

from .workflows import _phase_catalog, _scope_decision


SECURITY_BUILD_AGENT_TEAM_SCHEMA = {
    "name": "security_build_agent_team",
    "description": (
        "Build a role-based multi-agent team for a security or CTF workflow. "
        "Returns coordinator, specialist roles, responsibilities, inputs, and handoff contracts."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["defensive", "assessment", "range", "ctf"],
                "default": "assessment",
            },
            "objective": {
                "type": "string",
                "description": "Overall task objective for the main agent to coordinate.",
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
            "max_agents": {
                "type": "integer",
                "minimum": 2,
                "maximum": 12,
                "default": 6,
            },
        },
        "required": ["objective"],
    },
}


SECURITY_DISPATCH_AGENT_TASKS_SCHEMA = {
    "name": "security_dispatch_agent_tasks",
    "description": (
        "Create sub-agent dispatch packets for a workflow phase, including "
        "delegate_task-ready prompts, allowed tools, inputs, dependencies, and completion criteria."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["defensive", "assessment", "range", "ctf"],
                "default": "assessment",
            },
            "phase_id": {"type": "string", "description": "Workflow phase to dispatch."},
            "objective": {"type": "string", "description": "Phase objective or user task."},
            "targets": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
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
            "available_artifacts": {
                "type": "array",
                "items": {"type": "string"},
                "default": [],
            },
            "findings": {
                "type": "array",
                "items": {"type": "object"},
                "default": [],
            },
            "max_parallel": {
                "type": "integer",
                "minimum": 1,
                "maximum": 8,
                "default": 4,
            },
        },
        "required": ["phase_id", "objective"],
    },
}


SECURITY_COLLECT_AGENT_HANDOFFS_SCHEMA = {
    "name": "security_collect_agent_handoffs",
    "description": (
        "Merge and validate sub-agent handoffs, surfacing blockers, evidence, "
        "new findings, next tasks, and scope violations for the main agent."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["defensive", "assessment", "range", "ctf"],
                "default": "assessment",
            },
            "phase_id": {"type": "string", "description": "Workflow phase being merged."},
            "handoffs": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Sub-agent result objects.",
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
        },
        "required": ["phase_id", "handoffs"],
    },
}


_BASE_ROLES: list[dict[str, Any]] = [
    {
        "id": "coordinator",
        "name": "Coordinator Agent",
        "responsibility": "Own phase sequencing, dependencies, final decisions, and user-facing synthesis.",
        "allowed_tools": ["security_build_workflow", "security_workflow_gate", "security_collect_agent_handoffs", "delegate_task"],
        "handoff_contract": ["decision", "blockers", "next_phase", "open_questions"],
    },
    {
        "id": "scope_guard",
        "name": "Scope Guard Agent",
        "responsibility": "Validate targets, artifacts, and proposed actions against allow and deny scope.",
        "allowed_tools": ["security_scope_check", "security_workflow_gate"],
        "handoff_contract": ["allowed_targets", "blocked_targets", "scope_rationale"],
    },
    {
        "id": "recon_agent",
        "name": "Recon Agent",
        "responsibility": "Collect and normalize host, service, directory, whois, and subdomain reconnaissance.",
        "allowed_tools": ["security_nmap_plan", "security_nmap_scan", "security_dir_enum_plan", "security_dir_enum_scan", "security_whois_lookup", "security_subfinder_plan", "security_subfinder_scan"],
        "handoff_contract": ["assets", "services", "directories", "subdomains", "raw_evidence_refs"],
    },
    {
        "id": "vulnerability_analyst",
        "name": "Vulnerability Analyst Agent",
        "responsibility": "Normalize findings, prioritize risk, and propose validation candidates.",
        "allowed_tools": ["security_normalize_findings", "security_prioritize_findings", "security_extract_iocs"],
        "handoff_contract": ["normalized_findings", "prioritized_findings", "validation_candidates"],
    },
    {
        "id": "validation_agent",
        "name": "Validation Agent",
        "responsibility": "Plan approved validation steps and collect minimal evidence inside scope.",
        "allowed_tools": ["security_sqlmap_plan", "security_msf_rpc_plan", "security_hydra_plan", "security_workflow_gate"],
        "handoff_contract": ["validation_plan", "evidence", "false_positive_notes", "stop_conditions"],
    },
    {
        "id": "traffic_analyst",
        "name": "Traffic Analyst Agent",
        "responsibility": "Analyze pcap or short approved captures for protocol evidence and timelines.",
        "allowed_tools": ["security_tshark_plan", "security_tshark_capture", "security_extract_iocs"],
        "handoff_contract": ["protocol_summary", "timeline", "iocs", "pcap_evidence_refs"],
    },
    {
        "id": "reporting_agent",
        "name": "Reporting Agent",
        "responsibility": "Convert evidence and decisions into reports, remediation items, retest criteria, and reusable skills.",
        "allowed_tools": ["security_prioritize_findings", "security_generate_skill", "security_merge_skills"],
        "handoff_contract": ["executive_summary", "technical_summary", "remediation_items", "retest_plan", "skill_draft"],
    },
]


_CTF_ROLES: list[dict[str, Any]] = [
    {
        "id": "ctf_lead",
        "name": "CTF Lead Agent",
        "responsibility": "Coordinate challenge classification, solve path decisions, flag validation, and writeup.",
        "allowed_tools": ["security_build_workflow", "security_workflow_gate", "security_collect_agent_handoffs", "delegate_task"],
        "handoff_contract": ["current_hypothesis", "accepted_flag", "next_solver_task", "writeup_outline"],
    },
    {
        "id": "ctf_recon_agent",
        "name": "CTF Recon Agent",
        "responsibility": "Map challenge services, files, endpoints, and observable behavior.",
        "allowed_tools": ["security_nmap_scan", "security_dir_enum_scan", "security_tshark_capture", "security_extract_iocs"],
        "handoff_contract": ["attack_surface", "inputs", "interesting_outputs", "evidence_refs"],
    },
    {
        "id": "ctf_exploit_solver",
        "name": "CTF Exploit Solver Agent",
        "responsibility": "Develop challenge-local foothold and escalation hypotheses toward the flag.",
        "allowed_tools": ["security_sqlmap_plan", "security_msf_rpc_plan", "security_hydra_plan", "security_workflow_gate"],
        "handoff_contract": ["solution_path", "foothold_evidence", "escalation_notes", "candidate_flags"],
    },
    {
        "id": "ctf_flag_agent",
        "name": "CTF Flag Agent",
        "responsibility": "Validate candidate flags, track submissions, and prepare reproducible writeup notes.",
        "allowed_tools": ["security_extract_iocs", "security_generate_skill", "security_merge_skills"],
        "handoff_contract": ["candidate_flags", "validated_flag", "submission_status", "writeup_steps", "skill_draft"],
    },
]


_PHASE_ROLE_MAP: dict[str, list[str]] = {
    "intake_authorization": ["coordinator", "scope_guard"],
    "resource_inventory": ["coordinator", "scope_guard"],
    "scope_validation": ["scope_guard"],
    "passive_recon": ["recon_agent", "scope_guard"],
    "active_recon": ["scope_guard", "recon_agent"],
    "service_enumeration": ["recon_agent", "traffic_analyst"],
    "vulnerability_analysis": ["vulnerability_analyst", "traffic_analyst"],
    "validation_planning": ["vulnerability_analyst", "validation_agent", "scope_guard"],
    "controlled_validation": ["validation_agent", "scope_guard"],
    "post_validation_boundary": ["validation_agent", "traffic_analyst"],
    "detection_response": ["traffic_analyst"],
    "remediation": ["vulnerability_analyst", "reporting_agent"],
    "reporting": ["reporting_agent", "coordinator"],
    "retest_closeout": ["scope_guard", "validation_agent", "reporting_agent"],
    "skill_generation": ["reporting_agent", "coordinator"],
    "skill_consolidation": ["reporting_agent", "coordinator"],
    "ctf_intake": ["ctf_lead"],
    "ctf_challenge_classification": ["ctf_lead", "ctf_recon_agent"],
    "ctf_target_recon": ["ctf_recon_agent"],
    "ctf_vulnerability_discovery": ["ctf_recon_agent", "ctf_exploit_solver"],
    "ctf_foothold": ["ctf_exploit_solver"],
    "ctf_privilege_escalation": ["ctf_exploit_solver"],
    "ctf_flag_discovery": ["ctf_exploit_solver", "ctf_flag_agent"],
    "ctf_flag_validation": ["ctf_flag_agent"],
    "ctf_submission": ["ctf_flag_agent", "ctf_lead"],
    "ctf_writeup": ["ctf_flag_agent", "ctf_lead"],
    "ctf_cleanup": ["ctf_lead"],
    "ctf_skill_generation": ["ctf_flag_agent", "ctf_lead"],
    "ctf_skill_consolidation": ["ctf_flag_agent", "ctf_lead"],
}


def handle_build_agent_team(args: dict[str, Any], **_: Any) -> str:
    mode = _normalize_mode(args.get("mode"))
    max_agents = _bounded_int(args.get("max_agents", 6), 2, 12)
    roles = _roles_for_mode(mode)
    selected = _prioritize_roles(roles, mode, max_agents)
    return _json({
        "success": True,
        "mode": mode,
        "objective": str(args.get("objective") or "").strip(),
        "main_agent_role": "coordinator" if mode != "ctf" else "ctf_lead",
        "coordination_model": {
            "pattern": "hub_and_spoke",
            "controller": "main agent",
            "worker_invocation": "delegate_task",
            "handoff_required": True,
            "scope_guard_required_for_network_targets": True,
        },
        "roles": selected,
        "shared_rules": _shared_rules(mode),
    })


def handle_dispatch_agent_tasks(args: dict[str, Any], **_: Any) -> str:
    mode = _normalize_mode(args.get("mode"))
    phase_id = str(args.get("phase_id") or "").strip()
    objective = str(args.get("objective") or "").strip()
    targets = _string_list(args.get("targets"))
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))
    max_parallel = _bounded_int(args.get("max_parallel", 4), 1, 8)

    phase = next((item for item in _phase_catalog(mode) if item["id"] == phase_id), None)
    if phase is None:
        return _json({"success": False, "error": f"unknown phase_id for {mode}: {phase_id}"})

    scope_blockers = _scope_blockers(targets, allowed_targets, denied_targets)
    role_ids = _PHASE_ROLE_MAP.get(phase_id, ["coordinator"])
    role_map = {role["id"]: role for role in _roles_for_mode(mode)}
    packets = []
    for role_id in role_ids[:max_parallel]:
        role = role_map.get(role_id)
        if not role:
            continue
        packets.append(_dispatch_packet(
            role=role,
            mode=mode,
            phase=phase,
            objective=objective,
            targets=targets,
            available_artifacts=_string_list(args.get("available_artifacts")),
            findings=_object_list(args.get("findings")),
            blocked=bool(scope_blockers),
            scope_blockers=scope_blockers,
        ))

    return _json({
        "success": True,
        "mode": mode,
        "phase_id": phase_id,
        "phase_name": phase["name"],
        "dispatch_allowed": not scope_blockers,
        "scope_blockers": scope_blockers,
        "parallelism": min(len(packets), max_parallel),
        "tasks": packets,
        "main_agent_next_step": (
            "Call delegate_task once per dispatch packet, then merge results with security_collect_agent_handoffs."
            if not scope_blockers else
            "Resolve scope blockers before dispatching worker agents."
        ),
    })


def handle_collect_agent_handoffs(args: dict[str, Any], **_: Any) -> str:
    mode = _normalize_mode(args.get("mode"))
    phase_id = str(args.get("phase_id") or "").strip()
    handoffs = _object_list(args.get("handoffs"))
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))

    merged: dict[str, Any] = {
        "assets": [],
        "services": [],
        "findings": [],
        "evidence": [],
        "candidate_flags": [],
        "validated_flags": [],
        "blockers": [],
        "next_tasks": [],
    }
    invalid_handoffs = []
    scope_violations = []
    for index, handoff in enumerate(handoffs):
        missing = [key for key in ("agent_id", "status", "summary") if not handoff.get(key)]
        if missing:
            invalid_handoffs.append({"index": index, "missing": missing})

        for key in ("assets", "services", "findings", "evidence", "candidate_flags", "next_tasks"):
            value = handoff.get(key)
            if isinstance(value, list):
                merged[key].extend(item for item in value if item not in merged[key])
        if handoff.get("validated_flag"):
            merged["validated_flags"].append(handoff["validated_flag"])
        if isinstance(handoff.get("blockers"), list):
            merged["blockers"].extend(str(item) for item in handoff["blockers"])

        for target in _handoff_targets(handoff):
            decision = _scope_decision(target, allowed_targets, denied_targets)
            if not decision["allowed"]:
                scope_violations.append({
                    "agent_id": handoff.get("agent_id"),
                    "target": target,
                    "reason": decision["reason"],
                })

    decision = "proceed"
    if invalid_handoffs or scope_violations or merged["blockers"]:
        decision = "needs_review"
    if scope_violations:
        decision = "blocked"

    return _json({
        "success": True,
        "mode": mode,
        "phase_id": phase_id,
        "handoff_count": len(handoffs),
        "decision": decision,
        "invalid_handoffs": invalid_handoffs,
        "scope_violations": scope_violations,
        "merged": {
            **merged,
            "blockers": _dedupe(merged["blockers"]),
            "validated_flags": _dedupe([str(item) for item in merged["validated_flags"]]),
        },
        "main_agent_next_step": _handoff_next_step(decision, mode, phase_id),
    })


def _dispatch_packet(
    *,
    role: dict[str, Any],
    mode: str,
    phase: dict[str, Any],
    objective: str,
    targets: list[str],
    available_artifacts: list[str],
    findings: list[dict[str, Any]],
    blocked: bool,
    scope_blockers: list[dict[str, str]],
) -> dict[str, Any]:
    prompt = (
        f"You are {role['name']} working under the main Hermes security coordinator.\n"
        f"Mode: {mode}\n"
        f"Phase: {phase['id']} - {phase['name']}\n"
        f"Objective: {objective or phase['objective']}\n"
        f"Targets: {', '.join(targets) if targets else 'none provided'}\n"
        "Stay within the supplied workflow phase, use only allowed tools, and return a JSON handoff."
    )
    if blocked:
        prompt += "\nDo not perform active work. Report the scope blockers and required clarification."
    return {
        "agent_id": role["id"],
        "agent_name": role["name"],
        "phase_id": phase["id"],
        "can_start": not blocked,
        "blocked_by": scope_blockers,
        "allowed_tools": role["allowed_tools"],
        "inputs": {
            "targets": targets,
            "available_artifacts": available_artifacts,
            "finding_count": len(findings),
        },
        "completion_criteria": role["handoff_contract"],
        "delegate_task_prompt": prompt,
        "expected_handoff_schema": {
            "agent_id": role["id"],
            "status": "completed|blocked|needs_input",
            "summary": "short result summary",
            "evidence": [],
            "findings": [],
            "blockers": [],
            "next_tasks": [],
        },
    }


def _roles_for_mode(mode: str) -> list[dict[str, Any]]:
    if mode == "ctf":
        return _CTF_ROLES
    return _BASE_ROLES


def _prioritize_roles(roles: list[dict[str, Any]], mode: str, max_agents: int) -> list[dict[str, Any]]:
    if mode == "ctf":
        order = ["ctf_lead", "ctf_recon_agent", "ctf_exploit_solver", "ctf_flag_agent"]
    else:
        order = ["coordinator", "scope_guard", "recon_agent", "vulnerability_analyst", "validation_agent", "traffic_analyst", "reporting_agent"]
    role_by_id = {role["id"]: role for role in roles}
    return [role_by_id[role_id] for role_id in order if role_id in role_by_id][:max_agents]


def _shared_rules(mode: str) -> list[str]:
    rules = [
        "Main agent owns scope, sequencing, and final user-facing decisions.",
        "Sub-agents must return structured handoffs instead of making final decisions.",
        "Network targets must stay inside allowed_targets and outside denied_targets.",
        "Do not overwrite or discard another agent's evidence.",
    ]
    if mode == "ctf":
        rules.append("CTF target commands are auto-authorized after scope validation.")
    else:
        rules.append("High-risk validation requires workflow gate approval before dispatch.")
    return rules


def _scope_blockers(targets: list[str], allowed_targets: list[str], denied_targets: list[str]) -> list[dict[str, str]]:
    blockers = []
    for target in targets:
        decision = _scope_decision(target, allowed_targets, denied_targets)
        if not decision["allowed"]:
            blockers.append({"target": target, "reason": decision["reason"]})
    return blockers


def _handoff_targets(handoff: dict[str, Any]) -> list[str]:
    targets = []
    for key in ("targets", "new_targets"):
        value = handoff.get(key)
        if isinstance(value, list):
            targets.extend(str(item) for item in value if str(item).strip())
    for item in handoff.get("assets", []) if isinstance(handoff.get("assets"), list) else []:
        if isinstance(item, dict):
            target = item.get("target") or item.get("host") or item.get("url") or item.get("name")
            if target:
                targets.append(str(target))
    return _dedupe(targets)


def _handoff_next_step(decision: str, mode: str, phase_id: str) -> str:
    if decision == "blocked":
        return "Stop dispatch and resolve scope violations before continuing."
    if decision == "needs_review":
        return "Main agent should review blockers or incomplete handoffs before dispatching the next phase."
    if mode == "ctf" and phase_id == "ctf_flag_validation":
        return "Proceed to ctf_submission if a validated flag is present."
    return "Proceed to the next workflow phase or dispatch follow-up tasks from merged.next_tasks."


def _normalize_mode(value: Any) -> str:
    mode = str(value or "assessment").strip().lower()
    return mode if mode in {"defensive", "assessment", "range", "ctf"} else "assessment"


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _object_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _bounded_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = minimum
    return min(max(parsed, minimum), maximum)


def _dedupe(values: list[Any]) -> list[Any]:
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
