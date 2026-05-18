from __future__ import annotations

import json


def _loads(result: str) -> dict:
    return json.loads(result)


class TestSecurityBuildWorkflow:
    def test_builds_complete_assessment_workflow(self):
        from plugins.security.workflows import handle_build_workflow

        result = _loads(handle_build_workflow({
            "task_name": "external assessment",
            "objective": "validate exposed risk for owned web assets",
            "mode": "assessment",
            "allowed_targets": ["*.example.com", "10.10.0.0/16"],
            "denied_targets": ["admin.example.com"],
            "include_active_testing": True,
            "assets": [
                {
                    "name": "api",
                    "target": "api.example.com",
                    "owner": "platform",
                    "environment": "prod",
                    "exposure": "internet",
                    "criticality": "high",
                }
            ],
            "constraints": {
                "time_window": "2026-06-01T01:00Z/2026-06-01T03:00Z",
                "max_rate": "low",
            },
        }))

        assert result["success"] is True
        assert result["task"]["mode"] == "assessment"
        assert result["policy"]["active_testing_enabled"] is True
        phase_ids = [phase["id"] for phase in result["workflow"]]
        assert phase_ids == [
            "intake_authorization",
            "resource_inventory",
            "scope_validation",
            "passive_recon",
            "active_recon",
            "service_enumeration",
            "vulnerability_analysis",
            "validation_planning",
            "controlled_validation",
            "post_validation_boundary",
            "detection_response",
            "remediation",
            "reporting",
            "retest_closeout",
            "skill_generation",
            "skill_consolidation",
        ]
        assert result["scope"]["allowed_asset_count"] == 1

    def test_defensive_mode_blocks_active_testing(self):
        from plugins.security.workflows import handle_build_workflow

        result = _loads(handle_build_workflow({
            "task_name": "blue team review",
            "objective": "triage known risk",
            "mode": "defensive",
            "allowed_targets": ["*.example.com"],
            "include_active_testing": True,
        }))

        assert result["policy"]["active_testing_enabled"] is False
        assert "defensive mode cannot include active network testing" in result["blockers"]
        active_recon = next(phase for phase in result["workflow"] if phase["id"] == "active_recon")
        assert active_recon["status"] == "blocked"

    def test_out_of_scope_asset_blocks_active_phases(self):
        from plugins.security.workflows import handle_build_workflow

        result = _loads(handle_build_workflow({
            "task_name": "mixed scope",
            "objective": "assess approved assets",
            "mode": "assessment",
            "allowed_targets": ["*.example.com"],
            "include_active_testing": True,
            "assets": [{"name": "outside", "target": "outside.example.net"}],
        }))

        assert result["scope"]["blocked_asset_count"] == 1
        assert "one or more supplied assets are outside authorized scope" in result["blockers"]

    def test_ctf_mode_uses_flag_workflow(self):
        from plugins.security.workflows import handle_build_workflow

        result = _loads(handle_build_workflow({
            "task_name": "web ctf",
            "objective": "solve challenge and submit flag",
            "mode": "ctf",
            "include_active_testing": True,
            "constraints": {"challenge_type": "web", "flag_format": "flag{...}"},
        }))

        assert result["task"]["mode"] == "ctf"
        assert result["policy"]["ctf_mode_enabled"] is True
        assert result["policy"]["active_testing_enabled"] is True
        phase_ids = [phase["id"] for phase in result["workflow"]]
        assert phase_ids == [
            "ctf_intake",
            "ctf_challenge_classification",
            "ctf_target_recon",
            "ctf_vulnerability_discovery",
            "ctf_foothold",
            "ctf_privilege_escalation",
            "ctf_flag_discovery",
            "ctf_flag_validation",
            "ctf_submission",
            "ctf_writeup",
            "ctf_cleanup",
            "ctf_skill_generation",
            "ctf_skill_consolidation",
        ]


class TestSecurityWorkflowGate:
    def test_gate_allows_approved_active_recon_in_scope(self):
        from plugins.security.workflows import handle_workflow_gate

        result = _loads(handle_workflow_gate({
            "phase_id": "active_recon",
            "mode": "assessment",
            "allowed_targets": ["*.example.com"],
            "requested_targets": ["api.example.com"],
            "available_artifacts": ["scope_matrix", "approval:active_testing"],
            "approvals": {"active_testing": True},
        }))

        assert result["allowed"] is True
        assert result["decision"] == "proceed"

    def test_gate_blocks_unapproved_controlled_validation(self):
        from plugins.security.workflows import handle_workflow_gate

        result = _loads(handle_workflow_gate({
            "phase_id": "controlled_validation",
            "mode": "assessment",
            "allowed_targets": ["*.example.com"],
            "requested_targets": ["api.example.com"],
            "available_artifacts": ["validation_plan"],
            "approvals": {"active_testing": True},
        }))

        assert result["allowed"] is False
        assert "missing required approval: controlled_validation" in result["blockers"]

    def test_gate_blocks_target_outside_scope(self):
        from plugins.security.workflows import handle_workflow_gate

        result = _loads(handle_workflow_gate({
            "phase_id": "service_enumeration",
            "mode": "assessment",
            "allowed_targets": ["*.example.com"],
            "denied_targets": ["admin.example.com"],
            "requested_targets": ["admin.example.com"],
            "available_artifacts": ["active_recon_results"],
            "approvals": {"active_testing": True},
        }))

        assert result["allowed"] is False
        assert any("target outside authorized scope: admin.example.com" in blocker for blocker in result["blockers"])

    def test_gate_blocks_defensive_active_phase(self):
        from plugins.security.workflows import handle_workflow_gate

        result = _loads(handle_workflow_gate({
            "phase_id": "active_recon",
            "mode": "defensive",
            "allowed_targets": ["*.example.com"],
            "requested_targets": ["api.example.com"],
            "available_artifacts": ["scope_matrix"],
            "approvals": {"active_testing": True},
        }))

        assert result["allowed"] is False
        assert "defensive mode does not permit active testing phases" in result["blockers"]

    def test_gate_allows_ctf_local_active_phase_without_network_scope(self):
        from plugins.security.workflows import handle_workflow_gate

        result = _loads(handle_workflow_gate({
            "phase_id": "ctf_target_recon",
            "mode": "ctf",
            "available_artifacts": ["challenge_type"],
            "approvals": {},
        }))

        assert result["allowed"] is True
        assert result["decision"] == "proceed"

    def test_gate_requires_scope_for_ctf_requested_network_target(self):
        from plugins.security.workflows import handle_workflow_gate

        result = _loads(handle_workflow_gate({
            "phase_id": "ctf_target_recon",
            "mode": "ctf",
            "requested_targets": ["challenge.example.com"],
            "available_artifacts": ["challenge_type"],
        }))

        assert result["allowed"] is False
        assert "requested network targets require explicit allowed_targets" in result["blockers"]

    def test_gate_blocks_ctf_phase_outside_ctf_mode(self):
        from plugins.security.workflows import handle_workflow_gate

        result = _loads(handle_workflow_gate({
            "phase_id": "ctf_flag_discovery",
            "mode": "assessment",
            "available_artifacts": ["foothold_evidence"],
        }))

        assert result["allowed"] is False
        assert "ctf phases require ctf mode" in result["blockers"]

    def test_gate_auto_authorizes_ctf_target_high_risk_phase(self):
        from plugins.security.workflows import handle_workflow_gate

        result = _loads(handle_workflow_gate({
            "phase_id": "ctf_foothold",
            "mode": "ctf",
            "allowed_targets": ["*.ctf.local"],
            "requested_targets": ["box.ctf.local"],
            "available_artifacts": ["candidate_solution_paths"],
            "approvals": {},
        }))

        assert result["allowed"] is True
        assert result["decision"] == "proceed"
