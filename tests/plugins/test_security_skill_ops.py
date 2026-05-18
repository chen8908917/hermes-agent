from __future__ import annotations

import json


def _loads(result: str) -> dict:
    return json.loads(result)


class TestSecurityGenerateSkill:
    def test_generates_skill_manage_create_payload(self):
        from plugins.security.skill_ops import handle_generate_skill

        result = _loads(handle_generate_skill({
            "mode": "assessment",
            "task_name": "External Web Assessment",
            "objective": "repeat scoped web exposure assessment",
            "successful_steps": [
                "Build the workflow and validate scope.",
                "Run conservative recon plans before active scans.",
            ],
            "tools_used": ["security_build_workflow", "security_nmap_plan"],
            "pitfalls": ["Do not include customer hostnames in reusable examples."],
            "verification": ["Confirm findings are prioritized and evidence is sanitized."],
        }))

        assert result["success"] is True
        assert result["skill"]["name"] == "security-external-web-assessment"
        assert result["skill_manage_payload"]["action"] == "create"
        assert result["requires_user_confirmation"] is True
        assert result["quality_checks"]["description_ok"] is True
        assert "## Procedure" in result["skill"]["content"]
        assert "`security_nmap_plan`" in result["skill"]["content"]

    def test_generates_ctf_skill_name_and_sections(self):
        from plugins.security.skill_ops import handle_generate_skill

        result = _loads(handle_generate_skill({
            "mode": "ctf",
            "task_name": "JWT None Challenge",
            "objective": "recognize and verify JWT alg none challenge pattern",
        }))

        assert result["success"] is True
        assert result["skill"]["name"] == "ctf-jwt-none-challenge"
        assert "## Verification" in result["skill"]["content"]


class TestSecurityMergeSkills:
    def test_recommends_merge_when_existing_skill_is_similar(self):
        from plugins.security.skill_ops import handle_generate_skill, handle_merge_skills

        draft = _loads(handle_generate_skill({
            "mode": "assessment",
            "task_name": "External Web Assessment",
            "objective": "repeat scoped web exposure assessment",
            "tools_used": ["security_nmap_plan", "security_dir_enum_plan"],
        }))["skill"]

        result = _loads(handle_merge_skills({
            "candidate_skill": draft,
            "existing_skills": [
                {
                    "name": "security-web-assessment",
                    "description": "Repeat a security workflow from sanitized evidence.",
                    "content": draft["content"],
                }
            ],
            "similarity_threshold": 0.2,
        }))

        assert result["success"] is True
        assert result["recommendation"] == "merge_into_existing"
        assert result["best_match"]["name"] == "security-web-assessment"
        assert result["skill_manage_payloads"][0]["action"] == "patch"

    def test_recommends_create_for_dissimilar_skill(self):
        from plugins.security.skill_ops import handle_merge_skills

        result = _loads(handle_merge_skills({
            "candidate_skill": {
                "name": "ctf-jwt-none-challenge",
                "description": "Repeat a CTF solve from sanitized evidence.",
                "content": "jwt alg none token validation procedure",
            },
            "existing_skills": [
                {
                    "name": "security-kubernetes-hardening",
                    "description": "Review Kubernetes hardening baselines.",
                    "content": "pods admission policies namespaces network policy",
                }
            ],
            "similarity_threshold": 0.9,
        }))

        assert result["recommendation"] == "create_new"
        assert result["skill_manage_payloads"][0]["action"] == "create"
