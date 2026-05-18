from __future__ import annotations

import json


def _loads(result: str) -> dict:
    return json.loads(result)


class TestSecurityAgentTeam:
    def test_builds_assessment_team_with_scope_guard_and_recon(self):
        from plugins.security.multi_agent import handle_build_agent_team

        result = _loads(handle_build_agent_team({
            "mode": "assessment",
            "objective": "assess external web estate",
            "allowed_targets": ["*.example.com"],
            "max_agents": 5,
        }))

        assert result["success"] is True
        assert result["main_agent_role"] == "coordinator"
        role_ids = [role["id"] for role in result["roles"]]
        assert role_ids[:3] == ["coordinator", "scope_guard", "recon_agent"]
        assert "delegate_task" in result["coordination_model"]["worker_invocation"]

    def test_builds_ctf_team(self):
        from plugins.security.multi_agent import handle_build_agent_team

        result = _loads(handle_build_agent_team({
            "mode": "ctf",
            "objective": "solve web challenge",
        }))

        assert result["success"] is True
        assert result["main_agent_role"] == "ctf_lead"
        role_ids = [role["id"] for role in result["roles"]]
        assert role_ids == ["ctf_lead", "ctf_recon_agent", "ctf_exploit_solver", "ctf_flag_agent"]
        assert any("auto-authorized" in rule for rule in result["shared_rules"])


class TestSecurityAgentDispatch:
    def test_dispatches_active_recon_to_scope_and_recon_agents(self):
        from plugins.security.multi_agent import handle_dispatch_agent_tasks

        result = _loads(handle_dispatch_agent_tasks({
            "mode": "assessment",
            "phase_id": "active_recon",
            "objective": "map open services",
            "targets": ["api.example.com"],
            "allowed_targets": ["*.example.com"],
            "available_artifacts": ["scope_matrix"],
        }))

        assert result["success"] is True
        assert result["dispatch_allowed"] is True
        agent_ids = [task["agent_id"] for task in result["tasks"]]
        assert agent_ids == ["scope_guard", "recon_agent"]
        assert all(task["can_start"] is True for task in result["tasks"])
        assert "delegate_task" in result["main_agent_next_step"]

    def test_dispatch_blocks_out_of_scope_target(self):
        from plugins.security.multi_agent import handle_dispatch_agent_tasks

        result = _loads(handle_dispatch_agent_tasks({
            "mode": "assessment",
            "phase_id": "active_recon",
            "objective": "map open services",
            "targets": ["outside.example.net"],
            "allowed_targets": ["*.example.com"],
        }))

        assert result["success"] is True
        assert result["dispatch_allowed"] is False
        assert result["scope_blockers"][0]["target"] == "outside.example.net"
        assert all(task["can_start"] is False for task in result["tasks"])

    def test_dispatches_ctf_flag_discovery_agents(self):
        from plugins.security.multi_agent import handle_dispatch_agent_tasks

        result = _loads(handle_dispatch_agent_tasks({
            "mode": "ctf",
            "phase_id": "ctf_flag_discovery",
            "objective": "find and validate candidate flags",
            "targets": ["box.ctf.local"],
            "allowed_targets": ["*.ctf.local"],
        }))

        assert result["dispatch_allowed"] is True
        agent_ids = [task["agent_id"] for task in result["tasks"]]
        assert agent_ids == ["ctf_exploit_solver", "ctf_flag_agent"]
        assert "ctf_flag_discovery" in result["tasks"][0]["delegate_task_prompt"]


class TestSecurityAgentHandoffs:
    def test_collects_handoffs_and_merges_evidence(self):
        from plugins.security.multi_agent import handle_collect_agent_handoffs

        result = _loads(handle_collect_agent_handoffs({
            "mode": "assessment",
            "phase_id": "vulnerability_analysis",
            "allowed_targets": ["*.example.com"],
            "handoffs": [
                {
                    "agent_id": "recon_agent",
                    "status": "completed",
                    "summary": "found HTTPS service",
                    "assets": [{"target": "api.example.com"}],
                    "evidence": ["nmap:api"],
                },
                {
                    "agent_id": "vulnerability_analyst",
                    "status": "completed",
                    "summary": "prioritized finding",
                    "findings": [{"id": "F-1", "severity": "high"}],
                    "next_tasks": ["validate F-1"],
                },
            ],
        }))

        assert result["success"] is True
        assert result["decision"] == "proceed"
        assert result["merged"]["evidence"] == ["nmap:api"]
        assert result["merged"]["findings"][0]["id"] == "F-1"
        assert result["merged"]["next_tasks"] == ["validate F-1"]

    def test_collect_blocks_scope_violations(self):
        from plugins.security.multi_agent import handle_collect_agent_handoffs

        result = _loads(handle_collect_agent_handoffs({
            "mode": "assessment",
            "phase_id": "active_recon",
            "allowed_targets": ["*.example.com"],
            "handoffs": [
                {
                    "agent_id": "recon_agent",
                    "status": "completed",
                    "summary": "found external asset",
                    "new_targets": ["outside.example.net"],
                },
            ],
        }))

        assert result["decision"] == "blocked"
        assert result["scope_violations"][0]["target"] == "outside.example.net"

    def test_collect_requires_basic_handoff_fields(self):
        from plugins.security.multi_agent import handle_collect_agent_handoffs

        result = _loads(handle_collect_agent_handoffs({
            "phase_id": "active_recon",
            "handoffs": [{"agent_id": "recon_agent"}],
        }))

        assert result["decision"] == "needs_review"
        assert result["invalid_handoffs"][0]["missing"] == ["status", "summary"]
