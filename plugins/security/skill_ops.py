"""Skill generation and consolidation helpers for security workflows."""

from __future__ import annotations

import json
import re
from typing import Any


SECURITY_GENERATE_SKILL_SCHEMA = {
    "name": "security_generate_skill",
    "description": (
        "Draft a reusable Hermes SKILL.md from a completed security or CTF workflow. "
        "Returns skill_manage payloads; does not write files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["defensive", "assessment", "range", "ctf"],
                "default": "assessment",
            },
            "skill_name": {
                "type": "string",
                "description": "Optional lowercase skill name. Generated from task_name when omitted.",
                "default": "",
            },
            "task_name": {"type": "string", "description": "Completed task or challenge name."},
            "objective": {"type": "string", "description": "What the workflow achieved."},
            "successful_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Reusable steps that worked.",
                "default": [],
            },
            "tools_used": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Hermes tools or external adapters used.",
                "default": [],
            },
            "pitfalls": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Mistakes, false starts, or edge cases discovered.",
                "default": [],
            },
            "verification": {
                "type": "array",
                "items": {"type": "string"},
                "description": "How to verify the workflow succeeded.",
                "default": [],
            },
            "evidence_summary": {
                "type": "string",
                "description": "Sanitized evidence summary. Do not include secrets or flags unless allowed.",
                "default": "",
            },
            "category": {
                "type": "string",
                "description": "Skill category for skill_manage create.",
                "default": "security",
            },
        },
        "required": ["task_name", "objective"],
    },
}


SECURITY_MERGE_SKILLS_SCHEMA = {
    "name": "security_merge_skills",
    "description": (
        "Compare a drafted security skill with existing skills and propose create, "
        "patch, or merge/delete skill_manage actions. Does not write files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "candidate_skill": {
                "type": "object",
                "description": "Candidate from security_generate_skill or object with name, description, content.",
            },
            "existing_skills": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Existing skills with name, description, optional content/category.",
                "default": [],
            },
            "similarity_threshold": {
                "type": "number",
                "description": "Score at or above this value recommends merging into an existing skill.",
                "default": 0.42,
            },
        },
        "required": ["candidate_skill"],
    },
}


def handle_generate_skill(args: dict[str, Any], **_: Any) -> str:
    mode = _normalize_mode(args.get("mode"))
    task_name = str(args.get("task_name") or "").strip()
    objective = str(args.get("objective") or "").strip()
    if not task_name or not objective:
        return _json({"success": False, "error": "task_name and objective are required"})

    skill_name = _skill_name(str(args.get("skill_name") or "") or task_name, mode)
    description = _description(mode, task_name)
    successful_steps = _string_list(args.get("successful_steps"))
    tools_used = _string_list(args.get("tools_used"))
    pitfalls = _string_list(args.get("pitfalls"))
    verification = _string_list(args.get("verification"))
    evidence_summary = str(args.get("evidence_summary") or "").strip()
    category = _category(str(args.get("category") or "security"))
    content = _skill_content(
        name=skill_name,
        description=description,
        mode=mode,
        task_name=task_name,
        objective=objective,
        successful_steps=successful_steps,
        tools_used=tools_used,
        pitfalls=pitfalls,
        verification=verification,
        evidence_summary=evidence_summary,
    )

    payload = {
        "action": "create",
        "name": skill_name,
        "category": category,
        "content": content,
    }
    return _json({
        "success": True,
        "skill": {
            "name": skill_name,
            "description": description,
            "category": category,
            "content": content,
        },
        "quality_checks": _quality_checks(description, content),
        "skill_manage_payload": payload,
        "requires_user_confirmation": True,
        "next_step": "Review the draft, compare with existing skills via security_merge_skills, then call skill_manage after confirmation.",
    })


def handle_merge_skills(args: dict[str, Any], **_: Any) -> str:
    candidate = args.get("candidate_skill") if isinstance(args.get("candidate_skill"), dict) else {}
    existing_skills = _object_list(args.get("existing_skills"))
    threshold = _float(args.get("similarity_threshold"), default=0.42)

    candidate_name = str(candidate.get("name") or "").strip()
    candidate_description = str(candidate.get("description") or "").strip()
    candidate_content = str(candidate.get("content") or "").strip()
    if not candidate_name and not candidate_content:
        return _json({"success": False, "error": "candidate_skill must include name or content"})

    scored = []
    candidate_text = _skill_text(candidate)
    for skill in existing_skills:
        score = _similarity(candidate_text, _skill_text(skill))
        scored.append({
            "name": str(skill.get("name") or "").strip(),
            "description": str(skill.get("description") or "").strip(),
            "score": round(score, 3),
            "has_content": bool(skill.get("content")),
        })
    scored.sort(key=lambda item: item["score"], reverse=True)

    best = scored[0] if scored else None
    if best and best["score"] >= threshold:
        target_name = best["name"]
        recommendation = "merge_into_existing"
        payloads = _merge_payloads(candidate, target_name)
    else:
        recommendation = "create_new"
        payloads = [{
            "action": "create",
            "name": candidate_name or _skill_name(candidate_description or "security-workflow", "assessment"),
            "category": str(candidate.get("category") or "security"),
            "content": candidate_content,
        }]

    return _json({
        "success": True,
        "recommendation": recommendation,
        "best_match": best,
        "matches": scored[:10],
        "skill_manage_payloads": payloads,
        "requires_user_confirmation": True,
        "merge_notes": [
            "Patch/create the umbrella skill before deleting any absorbed skill.",
            "Use skill_manage delete with absorbed_into only after the merge content is present.",
            "Do not merge secrets, target-specific credentials, or sensitive evidence into reusable skills.",
        ],
    })


def _skill_content(
    *,
    name: str,
    description: str,
    mode: str,
    task_name: str,
    objective: str,
    successful_steps: list[str],
    tools_used: list[str],
    pitfalls: list[str],
    verification: list[str],
    evidence_summary: str,
) -> str:
    title = name.replace("-", " ").title()
    steps = successful_steps or [
        "Confirm the authorized scope and mode before touching any target.",
        "Build or resume the workflow with `security_build_workflow`.",
        "Use `security_workflow_gate` before active phases.",
        "Dispatch specialist workers with `security_dispatch_agent_tasks` when parallel analysis helps.",
        "Merge handoffs with `security_collect_agent_handoffs` before moving to the next phase.",
    ]
    tools = tools_used or ["security_build_workflow", "security_workflow_gate", "security_collect_agent_handoffs"]
    pitfalls = pitfalls or ["Do not reuse target-specific secrets, flags, or credentials in a reusable skill."]
    verification = verification or ["Confirm scope decisions, evidence, blockers, and final outcome are documented."]
    evidence_line = evidence_summary or "Keep evidence sanitized and move sensitive details into case-local notes."

    return "\n".join([
        "---",
        f"name: {name}",
        f"description: {description}",
        "version: 1.0.0",
        "author: Hermes Agent",
        "metadata:",
        "  hermes:",
        "    category: security",
        "    tags: [security, workflow]",
        "---",
        "",
        f"# {title} Skill",
        "",
        f"Use this skill when a similar {mode} task appears. It captures the reusable procedure from `{task_name}` while avoiding target-specific secrets or evidence.",
        f"Goal: {objective}",
        "",
        "## When to Use",
        "",
        f"- Similar {mode} tasks with comparable scope, tooling, or validation flow.",
        "- The user wants a repeatable process rather than one-off notes.",
        "",
        "## Prerequisites",
        "",
        "- Written authorization or CTF/range rules for every target.",
        "- Known `allowed_targets` and `denied_targets` for network activity.",
        "- Access to the relevant Hermes security tools.",
        "",
        "## How to Run",
        "",
        "1. Confirm mode, scope, and objective.",
        "2. Build the workflow with `security_build_workflow`.",
        "3. Gate active phases with `security_workflow_gate`.",
        "4. Use specialist tools or subagents only within the gate decision.",
        "5. Preserve sanitized evidence and blockers for reporting.",
        "",
        "## Quick Reference",
        "",
        f"- Mode: `{mode}`",
        "- Primary tools: " + ", ".join(f"`{tool}`" for tool in tools),
        f"- Evidence note: {evidence_line}",
        "",
        "## Procedure",
        "",
        *[f"{idx}. {step}" for idx, step in enumerate(steps, start=1)],
        "",
        "## Pitfalls",
        "",
        *[f"- {item}" for item in pitfalls],
        "",
        "## Verification",
        "",
        *[f"- {item}" for item in verification],
        "",
    ])


def _merge_payloads(candidate: dict[str, Any], target_name: str) -> list[dict[str, Any]]:
    candidate_name = str(candidate.get("name") or "").strip()
    candidate_content = str(candidate.get("content") or "").strip()
    summary = _extract_procedure_summary(candidate_content)
    payloads = [{
        "action": "patch",
        "name": target_name,
        "old_string": "## Pitfalls\n",
        "new_string": f"## Merged Notes From {candidate_name or 'Candidate'}\n\n{summary}\n\n## Pitfalls\n",
    }]
    if candidate_name and candidate_name != target_name:
        payloads.append({
            "action": "delete",
            "name": candidate_name,
            "absorbed_into": target_name,
        })
    return payloads


def _extract_procedure_summary(content: str) -> str:
    if not content:
        return "- Review candidate skill content manually before merging."
    lines = [line for line in content.splitlines() if line.strip()]
    selected = []
    in_sections = False
    for line in lines:
        if line.startswith("## Procedure") or line.startswith("## Pitfalls") or line.startswith("## Verification"):
            in_sections = True
            selected.append(line)
            continue
        if in_sections:
            if line.startswith("## ") and not any(line.startswith(prefix) for prefix in ("## Procedure", "## Pitfalls", "## Verification")):
                break
            selected.append(line)
        if len(selected) >= 40:
            break
    return "\n".join(selected).strip() or "- Review candidate skill content manually before merging."


def _description(mode: str, task_name: str) -> str:
    noun = "CTF solve" if mode == "ctf" else "security workflow"
    text = f"Repeat a {noun} from sanitized evidence."
    return text[:59] + "." if not text.endswith(".") else text


def _quality_checks(description: str, content: str) -> dict[str, Any]:
    required_sections = ["## When to Use", "## Prerequisites", "## How to Run", "## Quick Reference", "## Procedure", "## Pitfalls", "## Verification"]
    return {
        "description_len": len(description),
        "description_ok": len(description) <= 60 and description.endswith("."),
        "has_required_sections": all(section in content for section in required_sections),
        "contains_skill_manage_payload_only": True,
    }


def _skill_text(skill: dict[str, Any]) -> str:
    return " ".join(str(skill.get(key) or "") for key in ("name", "description", "content", "category"))


def _similarity(left: str, right: str) -> float:
    left_tokens = _tokens(left)
    right_tokens = _tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def _tokens(value: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9_/-]{3,}", value.lower()) if token not in _STOPWORDS}


_STOPWORDS = {"the", "and", "for", "with", "from", "this", "that", "skill", "security", "workflow"}


def _skill_name(value: str, mode: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not base:
        base = f"{mode}-security-workflow"
    if not base.startswith(("security-", "ctf-")):
        base = f"{'ctf' if mode == 'ctf' else 'security'}-{base}"
    return base[:64].strip("-")


def _category(value: str) -> str:
    category = re.sub(r"[^a-z0-9_-]+", "-", value.lower()).strip("-")
    return category or "security"


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


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
