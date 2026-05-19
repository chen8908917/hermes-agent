"""Security assessment workflow builders.

These helpers produce phase plans and gate decisions for authorized security
work. They deliberately return structured workflow data instead of executable
attack commands.
"""

from __future__ import annotations

import ipaddress
import json
from copy import deepcopy
from typing import Any
from urllib.parse import urlparse


SECURITY_BUILD_WORKFLOW_SCHEMA = {
    "name": "security_build_workflow",
    "description": (
        "Build an authorized security assessment workflow from resource "
        "inventory through scoped network penetration validation, remediation, "
        "reporting, and retest. Produces a gated plan, not executable attack commands."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "task_name": {
                "type": "string",
                "description": "Short name for the engagement or assessment task.",
            },
            "objective": {
                "type": "string",
                "description": "Business or technical objective for the assessment.",
            },
            "mode": {
                "type": "string",
                "enum": ["defensive", "assessment", "range", "ctf"],
                "description": (
                    "defensive is analysis-only, assessment permits approved active "
                    "validation, range is for isolated lab/cyber-range exercises, "
                    "ctf is for authorized capture-the-flag challenges."
                ),
                "default": "defensive",
            },
            "allowed_targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Authorized domains, hosts, URLs, IPs, or CIDRs.",
                "default": [],
            },
            "denied_targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Targets explicitly out of scope. Deny rules win.",
                "default": [],
            },
            "assets": {
                "type": "array",
                "items": {"type": "object"},
                "description": (
                    "Known resources, for example objects with name, target, owner, "
                    "criticality, exposure, environment, and notes."
                ),
                "default": [],
            },
            "findings": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Optional known findings to feed validation and remediation phases.",
                "default": [],
            },
            "constraints": {
                "type": "object",
                "description": (
                    "Operational constraints such as time_window, max_rate, "
                    "change_freeze, excluded_methods, contacts, and approval_ticket."
                ),
                "default": {},
            },
            "include_active_testing": {
                "type": "boolean",
                "description": (
                    "Include active network/service validation phases. Requires "
                    "assessment or range mode plus authorized scope, or ctf mode "
                    "for challenge-local work."
                ),
                "default": False,
            },
        },
        "required": ["task_name", "objective"],
    },
}


SECURITY_WORKFLOW_GATE_SCHEMA = {
    "name": "security_workflow_gate",
    "description": (
        "Evaluate whether a security workflow phase may proceed based on "
        "authorized scope, approvals, required artifacts, and mode restrictions."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "phase_id": {
                "type": "string",
                "description": "Workflow phase id, for example active_recon or controlled_validation.",
            },
            "mode": {
                "type": "string",
                "enum": ["defensive", "assessment", "range", "ctf"],
                "default": "defensive",
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
            "requested_targets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Targets the phase would touch.",
                "default": [],
            },
            "available_artifacts": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Artifact ids already present, such as scope, asset_inventory, findings.",
                "default": [],
            },
            "approvals": {
                "type": "object",
                "description": (
                    "Approval flags keyed by phase or category, for example "
                    "{\"active_testing\": true, \"controlled_validation\": true}."
                ),
                "default": {},
            },
        },
        "required": ["phase_id"],
    },
}


_PHASES: list[dict[str, Any]] = [
    {
        "id": "intake_authorization",
        "name": "Intake and authorization",
        "risk": "low",
        "objective": "Capture objectives, owners, contacts, time window, rules of engagement, and written authorization.",
        "required_artifacts": [],
        "outputs": ["authorization_record", "rules_of_engagement", "contacts"],
        "approval_key": None,
        "actions": [
            "Record the business objective and assessment mode.",
            "Identify asset owners, emergency contacts, and stop conditions.",
            "Document allowed and denied targets before any active testing.",
        ],
    },
    {
        "id": "resource_inventory",
        "name": "Resource inventory",
        "risk": "low",
        "objective": "Organize known systems, owners, environments, business criticality, and exposure.",
        "required_artifacts": ["authorization_record"],
        "outputs": ["asset_inventory", "ownership_map", "data_sensitivity_notes"],
        "approval_key": None,
        "actions": [
            "Normalize assets into host, URL, cloud resource, repository, application, and network groups.",
            "Tag each asset with owner, environment, exposure, criticality, and data sensitivity when known.",
            "Mark unknown ownership or ambiguous scope as blockers for active testing.",
        ],
    },
    {
        "id": "scope_validation",
        "name": "Scope validation",
        "risk": "low",
        "objective": "Confirm every target against allow and deny rules before planning active work.",
        "required_artifacts": ["asset_inventory", "rules_of_engagement"],
        "outputs": ["scope_matrix", "out_of_scope_targets", "scope_blockers"],
        "approval_key": None,
        "actions": [
            "Run each target through security_scope_check.",
            "Remove denied and unmatched targets from any active phase.",
            "Escalate ambiguous CIDRs, shared SaaS tenants, and third-party assets for human decision.",
        ],
    },
    {
        "id": "passive_recon",
        "name": "Passive reconnaissance",
        "risk": "low",
        "objective": "Collect non-invasive context without touching target services directly.",
        "required_artifacts": ["scope_matrix"],
        "outputs": ["passive_recon_notes", "candidate_attack_surface"],
        "approval_key": None,
        "actions": [
            "Review existing CMDB, DNS, certificate transparency exports, cloud inventory, tickets, and prior reports.",
            "Extract indicators, domains, and technologies from provided logs and documents.",
            "Keep uncertain discoveries as candidates until scope validation confirms them.",
        ],
    },
    {
        "id": "active_recon",
        "name": "Active reconnaissance",
        "risk": "medium",
        "objective": "Perform approved, rate-limited discovery against in-scope targets.",
        "required_artifacts": ["scope_matrix", "approval:active_testing"],
        "outputs": ["active_recon_results", "live_hosts", "observed_services"],
        "approval_key": "active_testing",
        "actions": [
            "Use only approved targets, ports, timing windows, and rate limits.",
            "Prefer low-noise discovery and stop on errors, abuse reports, or owner request.",
            "Store raw output and normalized summaries for auditability.",
        ],
    },
    {
        "id": "service_enumeration",
        "name": "Service enumeration",
        "risk": "medium",
        "objective": "Identify exposed services, versions, TLS posture, web fingerprints, and authentication boundaries.",
        "required_artifacts": ["active_recon_results", "approval:active_testing"],
        "outputs": ["service_inventory", "technology_fingerprints", "auth_surface_map"],
        "approval_key": "active_testing",
        "actions": [
            "Map services to owners and applications before vulnerability analysis.",
            "Avoid brute force, credential guessing, or disruptive checks unless separately approved.",
            "Flag unknown or sensitive services for owner confirmation.",
        ],
    },
    {
        "id": "vulnerability_analysis",
        "name": "Vulnerability analysis",
        "risk": "medium",
        "objective": "Correlate scanner output, versions, misconfigurations, and known findings into prioritized risks.",
        "required_artifacts": ["service_inventory"],
        "outputs": ["normalized_findings", "prioritized_findings", "validation_candidates"],
        "approval_key": None,
        "actions": [
            "Normalize scanner and manual findings with security_normalize_findings.",
            "Prioritize with asset context, exposure, CVSS, exploit availability, and compensating controls.",
            "Separate evidence-backed issues from hypotheses that need validation.",
        ],
    },
    {
        "id": "validation_planning",
        "name": "Validation planning",
        "risk": "medium",
        "objective": "Define non-destructive validation steps and rollback/stop criteria for each candidate finding.",
        "required_artifacts": ["prioritized_findings", "rules_of_engagement"],
        "outputs": ["validation_plan", "validation_risk_register"],
        "approval_key": None,
        "actions": [
            "Choose the least intrusive proof method for each finding.",
            "Require explicit approval for authentication testing, exploit simulation, or production-impacting probes.",
            "Document expected evidence, maximum attempts, stop conditions, and responsible contact.",
        ],
    },
    {
        "id": "controlled_validation",
        "name": "Controlled penetration validation",
        "risk": "high",
        "objective": "Validate approved findings without persistence, data exfiltration, destructive actions, or uncontrolled lateral movement.",
        "required_artifacts": ["validation_plan", "approval:controlled_validation"],
        "outputs": ["validated_findings", "false_positives", "validation_evidence"],
        "approval_key": "controlled_validation",
        "actions": [
            "Operate only inside authorized scope, time windows, and approved validation plan.",
            "Collect minimal evidence needed to prove impact.",
            "Stop immediately on instability, sensitive data exposure, or scope ambiguity.",
        ],
    },
    {
        "id": "post_validation_boundary",
        "name": "Post-validation boundary checks",
        "risk": "high",
        "objective": "Assess impact boundaries in a controlled way without persistence, stealth, or unauthorized pivoting.",
        "required_artifacts": ["validated_findings", "approval:controlled_validation"],
        "outputs": ["impact_summary", "boundary_risks", "stop_decisions"],
        "approval_key": "controlled_validation",
        "actions": [
            "Map demonstrated access to business impact and reachable data classes.",
            "Do not establish persistence, harvest credentials, or move laterally outside explicit lab/range approval.",
            "For range mode only, record simulated attack path nodes and defensive detections.",
        ],
    },
    {
        "id": "detection_response",
        "name": "Detection and response review",
        "risk": "low",
        "objective": "Correlate activity with logs, alerts, and defensive control behavior.",
        "required_artifacts": ["validation_evidence"],
        "outputs": ["detection_gaps", "control_observations", "timeline"],
        "approval_key": None,
        "actions": [
            "Build an activity timeline from raw evidence and security logs.",
            "Identify missing detections, delayed alerts, and noisy false positives.",
            "Draft Sigma/YARA/SIEM rule ideas only when evidence supports them.",
        ],
    },
    {
        "id": "remediation",
        "name": "Remediation planning",
        "risk": "low",
        "objective": "Turn validated findings into owner-specific fixes, priorities, and retest criteria.",
        "required_artifacts": ["prioritized_findings"],
        "outputs": ["remediation_plan", "owner_action_items", "risk_acceptance_candidates"],
        "approval_key": None,
        "actions": [
            "Assign owners, due dates, compensating controls, and verification steps.",
            "Distinguish quick fixes from architectural remediation.",
            "Record accepted risks separately from unresolved technical debt.",
        ],
    },
    {
        "id": "reporting",
        "name": "Reporting",
        "risk": "low",
        "objective": "Produce executive, technical, and audit-ready reporting from the evidence set.",
        "required_artifacts": ["validated_findings", "remediation_plan"],
        "outputs": ["executive_summary", "technical_report", "evidence_appendix"],
        "approval_key": None,
        "actions": [
            "Include scope, methodology, limitations, timeline, findings, evidence, and remediation.",
            "Avoid including secrets or sensitive records beyond minimal proof.",
            "Separate confirmed findings, false positives, and untested hypotheses.",
        ],
    },
    {
        "id": "retest_closeout",
        "name": "Retest and closeout",
        "risk": "low",
        "objective": "Verify remediation, update residual risk, and close the engagement cleanly.",
        "required_artifacts": ["remediation_plan"],
        "outputs": ["retest_results", "residual_risk_register", "closeout_record"],
        "approval_key": None,
        "actions": [
            "Retest only the affected assets and controls.",
            "Update finding status with fixed, mitigated, accepted, or open.",
            "Archive evidence according to retention rules.",
        ],
    },
    {
        "id": "skill_generation",
        "name": "Skill generation",
        "risk": "low",
        "objective": "Convert reusable lessons from the completed engagement into a sanitized SKILL.md draft.",
        "required_artifacts": ["closeout_record"],
        "outputs": ["skill_draft", "skill_manage_create_payload"],
        "approval_key": None,
        "actions": [
            "Summarize reusable procedure, tools, pitfalls, and verification steps.",
            "Exclude secrets, credentials, flags, customer data, and target-specific evidence.",
            "Generate a SKILL.md draft with security_generate_skill for user review.",
        ],
    },
    {
        "id": "skill_consolidation",
        "name": "Skill consolidation",
        "risk": "low",
        "objective": "Compare the new skill draft with similar existing skills and prepare a merge plan.",
        "required_artifacts": ["skill_draft"],
        "outputs": ["skill_merge_plan", "skill_manage_payloads"],
        "approval_key": None,
        "actions": [
            "Compare the draft against existing security and CTF skills.",
            "Prefer patching an existing umbrella skill when overlap is high.",
            "Only delete absorbed skills after the target skill has been patched and the user confirms.",
        ],
    },
]

_CTF_PHASES: list[dict[str, Any]] = [
    {
        "id": "ctf_intake",
        "name": "CTF intake",
        "risk": "low",
        "objective": "Record challenge rules, flag format, category, target, scoring, and allowed tooling.",
        "required_artifacts": [],
        "outputs": ["ctf_rules", "flag_format", "challenge_metadata"],
        "approval_key": None,
        "actions": [
            "Record challenge type, platform rules, time limit, team constraints, and reset policy.",
            "Capture expected flag pattern without fabricating a flag.",
            "Separate local artifact challenges from network target challenges.",
        ],
    },
    {
        "id": "ctf_challenge_classification",
        "name": "Challenge classification",
        "risk": "low",
        "objective": "Classify the challenge as web, pwn, reverse, crypto, forensics, cloud, mobile, or misc.",
        "required_artifacts": ["ctf_rules"],
        "outputs": ["challenge_type", "hypotheses", "analysis_plan"],
        "approval_key": None,
        "actions": [
            "Identify files, endpoints, binaries, source code, packet captures, hints, and constraints.",
            "Choose a first-pass analysis strategy based on category and available artifacts.",
            "Track assumptions separately from confirmed observations.",
        ],
    },
    {
        "id": "ctf_target_recon",
        "name": "CTF target reconnaissance",
        "risk": "medium",
        "objective": "Map the challenge surface using allowed, non-destructive CTF techniques.",
        "required_artifacts": ["challenge_type"],
        "outputs": ["ctf_attack_surface", "entrypoint_candidates"],
        "approval_key": None,
        "actions": [
            "For local artifacts, inspect metadata, strings, structure, and dependencies.",
            "For network challenges, touch only provided targets and stay within platform limits.",
            "Record every useful endpoint, input, function, file path, and observed behavior.",
        ],
    },
    {
        "id": "ctf_vulnerability_discovery",
        "name": "CTF vulnerability discovery",
        "risk": "medium",
        "objective": "Develop and test challenge-specific hypotheses until a viable path emerges.",
        "required_artifacts": ["ctf_attack_surface"],
        "outputs": ["candidate_solution_paths", "failed_hypotheses", "evidence_notes"],
        "approval_key": None,
        "actions": [
            "Prefer small, reversible probes that reveal parser, logic, memory, crypto, or auth behavior.",
            "Keep failed attempts with reasons to avoid repeated dead ends.",
            "Avoid using techniques outside the CTF rules or against third-party infrastructure.",
        ],
    },
    {
        "id": "ctf_foothold",
        "name": "CTF foothold",
        "risk": "high",
        "objective": "Obtain the first challenge-controlled read, execution, or authenticated state needed for progress.",
        "required_artifacts": ["candidate_solution_paths"],
        "outputs": ["foothold_evidence", "access_context", "next_constraints"],
        "approval_key": None,
        "actions": [
            "Use only the intended CTF target, sandbox, or artifact.",
            "Capture minimal proof of the new state and preserve reproducibility.",
            "Do not reuse credentials, tokens, or artifacts outside the challenge environment.",
        ],
    },
    {
        "id": "ctf_privilege_escalation",
        "name": "CTF privilege escalation",
        "risk": "high",
        "objective": "Expand challenge-local access only when needed to reach the flag.",
        "required_artifacts": ["foothold_evidence"],
        "outputs": ["escalation_path", "expanded_access_evidence"],
        "approval_key": None,
        "actions": [
            "Limit escalation to the challenge VM, container, binary, account, or sandbox.",
            "Record exact preconditions and evidence for writeup reproducibility.",
            "Stop if the path leaves the CTF environment or touches unrelated systems.",
        ],
    },
    {
        "id": "ctf_flag_discovery",
        "name": "Flag discovery",
        "risk": "medium",
        "objective": "Locate candidate flags in challenge-approved files, output, memory, traffic, or application state.",
        "required_artifacts": ["foothold_evidence"],
        "outputs": ["candidate_flags", "flag_locations", "discovery_evidence"],
        "approval_key": None,
        "actions": [
            "Search only challenge-approved data sources.",
            "Record where each candidate flag came from and the context needed to reproduce it.",
            "Avoid dumping unrelated sensitive data when a minimal flag proof is enough.",
        ],
    },
    {
        "id": "ctf_flag_validation",
        "name": "Flag validation",
        "risk": "low",
        "objective": "Validate candidate flags against format, challenge context, and platform response.",
        "required_artifacts": ["candidate_flags", "flag_format"],
        "outputs": ["validated_flag", "rejected_candidates"],
        "approval_key": None,
        "actions": [
            "Check the expected flag pattern and challenge identity.",
            "Submit only through the official CTF platform or record a local validation result.",
            "Do not fabricate a flag when evidence is incomplete.",
        ],
    },
    {
        "id": "ctf_submission",
        "name": "Submission tracking",
        "risk": "low",
        "objective": "Track submission status, score, timestamps, and any failed attempts.",
        "required_artifacts": ["validated_flag"],
        "outputs": ["submission_record", "score_delta"],
        "approval_key": None,
        "actions": [
            "Record accepted, rejected, duplicate, and rate-limited submissions.",
            "Keep the final accepted flag in the evidence record according to team rules.",
        ],
    },
    {
        "id": "ctf_writeup",
        "name": "CTF writeup",
        "risk": "low",
        "objective": "Produce a reproducible solution narrative with evidence, false starts, and lessons learned.",
        "required_artifacts": ["submission_record"],
        "outputs": ["ctf_writeup", "reproduction_steps", "lessons_learned"],
        "approval_key": None,
        "actions": [
            "Explain the vulnerability or puzzle insight, not just the final answer.",
            "Include sanitized snippets and screenshots only when allowed by event rules.",
            "Preserve enough detail for teammates to reproduce the solve.",
        ],
    },
    {
        "id": "ctf_cleanup",
        "name": "CTF cleanup",
        "risk": "low",
        "objective": "Clean temporary artifacts, stop local services, and note any challenge reset requirements.",
        "required_artifacts": ["ctf_writeup"],
        "outputs": ["cleanup_record"],
        "approval_key": None,
        "actions": [
            "Stop local listeners, containers, debuggers, and temporary services used for the challenge.",
            "Archive challenge files and notes according to team policy.",
        ],
    },
    {
        "id": "ctf_skill_generation",
        "name": "CTF skill generation",
        "risk": "low",
        "objective": "Turn reusable solve patterns into a sanitized CTF SKILL.md draft.",
        "required_artifacts": ["cleanup_record"],
        "outputs": ["skill_draft", "skill_manage_create_payload"],
        "approval_key": None,
        "actions": [
            "Capture the reusable challenge pattern, not just the final flag.",
            "Exclude live flags or event-prohibited writeup details unless explicitly allowed.",
            "Generate a skill draft with security_generate_skill.",
        ],
    },
    {
        "id": "ctf_skill_consolidation",
        "name": "CTF skill consolidation",
        "risk": "low",
        "objective": "Merge similar CTF solve skills into a reusable umbrella skill when appropriate.",
        "required_artifacts": ["skill_draft"],
        "outputs": ["skill_merge_plan", "skill_manage_payloads"],
        "approval_key": None,
        "actions": [
            "Compare against existing CTF skills by category and solve pattern.",
            "Patch an umbrella skill when overlap is high.",
            "Keep challenge-specific artifacts out of the reusable skill.",
        ],
    },
]

_ACTIVE_PHASES = {
    "active_recon",
    "service_enumeration",
    "controlled_validation",
    "post_validation_boundary",
    "ctf_target_recon",
    "ctf_vulnerability_discovery",
    "ctf_foothold",
    "ctf_privilege_escalation",
    "ctf_flag_discovery",
}
_HIGH_RISK_PHASES = {
    "controlled_validation",
    "post_validation_boundary",
    "ctf_foothold",
    "ctf_privilege_escalation",
}
_CTF_ACTIVE_PHASES = {
    "ctf_target_recon",
    "ctf_vulnerability_discovery",
    "ctf_foothold",
    "ctf_privilege_escalation",
    "ctf_flag_discovery",
}


def handle_build_workflow(args: dict[str, Any], **_: Any) -> str:
    mode = _normalize_mode(args.get("mode"))
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))
    assets = _object_list(args.get("assets"))
    findings = _object_list(args.get("findings"))
    constraints = args.get("constraints") if isinstance(args.get("constraints"), dict) else {}
    include_active_testing = bool(args.get("include_active_testing", False))

    scope = _build_scope_summary(allowed_targets, denied_targets, assets)
    blockers = _workflow_blockers(mode, allowed_targets, scope, include_active_testing)
    phases = _build_phases(mode, include_active_testing, constraints, blockers)
    active_testing_enabled = (
        include_active_testing
        and mode in {"assessment", "range", "ctf"}
        and (bool(allowed_targets) or mode == "ctf")
    )

    return _json({
        "success": True,
        "task": {
            "name": str(args.get("task_name", "")).strip(),
            "objective": str(args.get("objective", "")).strip(),
            "mode": mode,
        },
        "policy": {
            "authorized_scope_required": mode != "ctf" or bool(allowed_targets),
            "active_testing_enabled": active_testing_enabled,
            "high_risk_requires_explicit_approval": mode != "ctf",
            "ctf_target_commands_auto_authorized": mode == "ctf",
            "ctf_mode_enabled": mode == "ctf",
            "ctf_scope_note": (
                "CTF mode permits local artifact work without network scope, "
                "but any requested network target must still match allowed_targets."
                if mode == "ctf" else None
            ),
            "disallowed_by_default": [
                "targets outside scope",
                "persistence",
                "credential harvesting",
                "destructive actions",
                "unapproved lateral movement",
                "data exfiltration beyond minimal proof",
            ],
        },
        "scope": scope,
        "resources": _resource_summary(assets, findings, constraints),
        "workflow": phases,
        "blockers": blockers,
        "next_actions": _next_actions(phases),
    })


def handle_workflow_gate(args: dict[str, Any], **_: Any) -> str:
    phase_id = str(args.get("phase_id", "")).strip()
    mode = _normalize_mode(args.get("mode"))
    allowed_targets = _string_list(args.get("allowed_targets"))
    denied_targets = _string_list(args.get("denied_targets"))
    requested_targets = _string_list(args.get("requested_targets"))
    available_artifacts = set(_string_list(args.get("available_artifacts")))
    approvals = args.get("approvals") if isinstance(args.get("approvals"), dict) else {}

    phase = next((item for item in _phase_catalog(mode) if item["id"] == phase_id), None)
    if phase is None and phase_id.startswith("ctf_"):
        phase = next((item for item in _CTF_PHASES if item["id"] == phase_id), None)
    if phase is None:
        return _json({"success": False, "allowed": False, "error": f"unknown phase_id: {phase_id}"})

    blockers: list[str] = []
    warnings: list[str] = []

    if phase_id in _ACTIVE_PHASES and mode == "defensive":
        blockers.append("defensive mode does not permit active testing phases")
    if phase_id.startswith("ctf_") and mode != "ctf":
        blockers.append("ctf phases require ctf mode")
    if phase_id in _HIGH_RISK_PHASES and mode not in {"assessment", "range", "ctf"}:
        blockers.append("high-risk validation requires assessment, range, or ctf mode")
    if phase_id == "post_validation_boundary" and mode != "range":
        warnings.append("boundary checks are limited to impact description unless running in isolated range mode")

    missing_artifacts = []
    for required in phase.get("required_artifacts", []):
        if required.startswith("approval:"):
            continue
        if required not in available_artifacts:
            missing_artifacts.append(required)
    if missing_artifacts:
        blockers.append("missing required artifacts: " + ", ".join(sorted(missing_artifacts)))

    approval_key = phase.get("approval_key")
    if approval_key and not bool(approvals.get(approval_key) or approvals.get(phase_id)):
        blockers.append(f"missing required approval: {approval_key}")

    if phase_id in _ACTIVE_PHASES:
        if not allowed_targets and not phase_id.startswith("ctf_"):
            blockers.append("active phases require explicit allowed_targets")
        ctf_http_targets_auto_allowed = (
            mode == "ctf"
            and phase_id.startswith("ctf_")
            and requested_targets
            and _all_http_targets(requested_targets)
        )
        if requested_targets and not allowed_targets and not ctf_http_targets_auto_allowed:
            blockers.append("requested network targets require explicit allowed_targets")
        for target in requested_targets:
            effective_allowed = [target] if ctf_http_targets_auto_allowed and not allowed_targets else allowed_targets
            decision = _scope_decision(target, effective_allowed, denied_targets)
            if not decision["allowed"]:
                blockers.append(f"target outside authorized scope: {target} ({decision['reason']})")

    return _json({
        "success": True,
        "allowed": not blockers,
        "phase_id": phase_id,
        "mode": mode,
        "required_artifacts": phase.get("required_artifacts", []),
        "missing_artifacts": missing_artifacts,
        "blockers": _dedupe(blockers),
        "warnings": _dedupe(warnings),
        "decision": "proceed" if not blockers else "blocked",
    })


def _build_phases(
    mode: str,
    include_active_testing: bool,
    constraints: dict[str, Any],
    workflow_blockers: list[str],
) -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = []
    for index, phase in enumerate(_phase_catalog(mode), start=1):
        item = deepcopy(phase)
        item["order"] = index
        item["status"] = "planned"
        item["entry_gate"] = _entry_gate(item, mode, include_active_testing, constraints)
        if item["id"] in _ACTIVE_PHASES and not include_active_testing:
            item["status"] = "blocked"
            item["blockers"] = ["active testing not requested"]
        elif item["id"] in _ACTIVE_PHASES and workflow_blockers:
            item["status"] = "blocked"
            item["blockers"] = workflow_blockers
        else:
            item["blockers"] = []
        item["allowed_tool_categories"] = _allowed_tool_categories(item["id"], mode, include_active_testing)
        phases.append(item)
    return phases


def _entry_gate(
    phase: dict[str, Any],
    mode: str,
    include_active_testing: bool,
    constraints: dict[str, Any],
) -> dict[str, Any]:
    gate = {
        "requires_scope_check": phase["id"] in _ACTIVE_PHASES,
        "requires_human_approval": bool(phase.get("approval_key")),
        "approval_key": phase.get("approval_key"),
        "mode_required": "assessment_range_or_ctf" if phase["id"] in _HIGH_RISK_PHASES else "any",
        "required_artifacts": phase.get("required_artifacts", []),
    }
    if phase["id"] in _ACTIVE_PHASES:
        gate["active_testing_requested"] = include_active_testing
        gate["time_window"] = constraints.get("time_window")
        gate["max_rate"] = constraints.get("max_rate")
        gate["stop_conditions"] = constraints.get("stop_conditions") or [
            "owner requests stop",
            "service instability is observed",
            "scope ambiguity appears",
            "sensitive data exposure exceeds minimal proof",
        ]
    if phase["id"] in _CTF_ACTIVE_PHASES:
        gate["ctf_mode_required"] = True
        gate["network_scope_required_when_targets_are_requested"] = True
    if phase["id"] == "post_validation_boundary" and mode != "range":
        gate["range_only_actions_removed"] = True
    return gate


def _allowed_tool_categories(phase_id: str, mode: str, include_active_testing: bool) -> list[str]:
    if phase_id.startswith("ctf_"):
        if phase_id in {"ctf_intake", "ctf_challenge_classification", "ctf_flag_validation", "ctf_submission", "ctf_writeup", "ctf_cleanup"}:
            return ["ctf_notes", "file", "read_only_analysis"]
        if not include_active_testing:
            return ["blocked_until_ctf_active_work_requested"]
        return ["ctf_allowed_tools", "challenge_local_analysis", "security_scope_check", "evidence_capture"]
    if phase_id in {"intake_authorization", "resource_inventory", "scope_validation"}:
        return ["security_scope_check", "file", "read_only_inventory"]
    if phase_id in {"passive_recon", "vulnerability_analysis", "remediation", "reporting", "retest_closeout"}:
        return ["security_extract_iocs", "security_normalize_findings", "security_prioritize_findings", "read_only_analysis"]
    if phase_id in _ACTIVE_PHASES:
        if not include_active_testing or mode == "defensive":
            return ["blocked_until_approved"]
        return ["approved_scanners", "non_destructive_validation", "security_scope_check", "evidence_capture"]
    if phase_id == "detection_response":
        return ["log_analysis", "timeline_reconstruction", "detection_engineering"]
    return ["read_only_analysis"]


def _build_scope_summary(
    allowed_targets: list[str],
    denied_targets: list[str],
    assets: list[dict[str, Any]],
) -> dict[str, Any]:
    asset_decisions = []
    for asset in assets:
        target = str(asset.get("target") or asset.get("name") or asset.get("url") or asset.get("host") or "").strip()
        if not target:
            continue
        decision = _scope_decision(target, allowed_targets, denied_targets)
        asset_decisions.append({
            "asset": asset,
            "target": target,
            "allowed": decision["allowed"],
            "reason": decision["reason"],
            "matched_rule": decision.get("matched_rule"),
        })

    return {
        "allowed_targets": allowed_targets,
        "denied_targets": denied_targets,
        "asset_decisions": asset_decisions,
        "allowed_asset_count": sum(1 for item in asset_decisions if item["allowed"]),
        "blocked_asset_count": sum(1 for item in asset_decisions if not item["allowed"]),
        "unclassified_asset_count": sum(1 for asset in assets if not (asset.get("target") or asset.get("name") or asset.get("url") or asset.get("host"))),
    }


def _all_http_targets(targets: list[str]) -> bool:
    return all(str(target).strip().lower().startswith(("http://", "https://")) for target in targets)


def _resource_summary(
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    constraints: dict[str, Any],
) -> dict[str, Any]:
    owners = sorted({str(asset.get("owner")) for asset in assets if asset.get("owner")})
    environments = sorted({str(asset.get("environment")) for asset in assets if asset.get("environment")})
    exposure_counts: dict[str, int] = {}
    for asset in assets:
        exposure = str(asset.get("exposure") or "unknown").lower()
        exposure_counts[exposure] = exposure_counts.get(exposure, 0) + 1

    return {
        "asset_count": len(assets),
        "finding_count": len(findings),
        "owners": owners,
        "environments": environments,
        "exposure_counts": exposure_counts,
        "constraints": constraints,
    }


def _workflow_blockers(
    mode: str,
    allowed_targets: list[str],
    scope: dict[str, Any],
    include_active_testing: bool,
) -> list[str]:
    blockers = []
    if include_active_testing and mode == "defensive":
        blockers.append("defensive mode cannot include active network testing")
    if include_active_testing and not allowed_targets and mode != "ctf":
        blockers.append("active testing requires explicit allowed_targets")
    if include_active_testing and scope.get("blocked_asset_count", 0):
        blockers.append("one or more supplied assets are outside authorized scope")
    return blockers


def _phase_catalog(mode: str) -> list[dict[str, Any]]:
    return _CTF_PHASES if mode == "ctf" else _PHASES


def _next_actions(phases: list[dict[str, Any]]) -> list[str]:
    for phase in phases:
        if phase["status"] == "planned":
            return [
                f"Start phase: {phase['id']}",
                "Collect required artifacts: " + ", ".join(phase.get("required_artifacts") or ["none"]),
                "Resolve blockers before any phase marked medium or high risk.",
            ]
    return ["Resolve workflow blockers before proceeding."]


def _scope_decision(target: str, allowed_targets: list[str], denied_targets: list[str]) -> dict[str, Any]:
    normalized = _normalize_target(target)
    denied_match = _first_matching_rule(normalized, denied_targets)
    if denied_match:
        return {"allowed": False, "reason": "matched denied scope", "matched_rule": denied_match}
    allowed_match = _first_matching_rule(normalized, allowed_targets)
    if allowed_match:
        return {"allowed": True, "reason": "matched allowed scope", "matched_rule": allowed_match}
    return {"allowed": False, "reason": "no allowed scope rule matched", "matched_rule": None}


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


def _normalize_target(value: str) -> dict[str, Any]:
    raw = value.strip()
    if not raw:
        return {"raw": value, "value": "", "kind": "empty"}
    try:
        if "/" in raw and "://" not in raw:
            network = ipaddress.ip_network(raw.strip("[]"), strict=False)
            return {"raw": value, "value": str(network), "host": str(network), "kind": "cidr"}
        ip = ipaddress.ip_address(raw.strip("[]"))
        return {"raw": value, "value": str(ip), "host": str(ip), "kind": "ip"}
    except ValueError:
        pass

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or raw).strip().strip("[]").lower().rstrip(".")
    return {"raw": value, "value": host, "host": host, "kind": "hostname"}


def _normalize_mode(value: Any) -> str:
    mode = str(value or "defensive").strip().lower()
    return mode if mode in {"defensive", "assessment", "range", "ctf"} else "defensive"


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


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
