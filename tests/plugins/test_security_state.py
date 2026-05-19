from __future__ import annotations

import json

import pytest


def _loads(result: str) -> dict:
    return json.loads(result)


@pytest.fixture(autouse=True)
def _reset_security_state():
    from plugins.security.state import reset_security_workflows

    reset_security_workflows()
    yield
    reset_security_workflows()


class TestSecurityWorkflowRuntime:
    def test_starts_records_and_advances_ctf_workflow(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
        )

        started = _loads(handle_start_workflow({
            "task_name": "web ctf",
            "objective": "solve the challenge",
            "mode": "ctf",
            "allowed_targets": ["*.ctf.local"],
            "include_active_testing": True,
        }, task_id="ctf-1"))

        assert started["success"] is True
        assert started["current_phase"]["id"] == "ctf_intake"
        assert started["next_action"]["phase_id"] == "ctf_intake"

        blocked = _loads(handle_advance_phase({}, task_id="ctf-1"))
        assert blocked["success"] is False
        assert "ctf_rules" in blocked["missing_exit_artifacts"]

        recorded = _loads(handle_record_artifact({
            "artifact_id": "ctf_rules",
            "content": {"flag_format": "flag{...}", "target": "box.ctf.local"},
        }, task_id="ctf-1"))
        assert recorded["success"] is True
        assert "ctf_rules" in recorded["available_artifacts"]

        advanced = _loads(handle_advance_phase({
            "rationale": "CTF rules and target are recorded.",
        }, task_id="ctf-1"))
        assert advanced["success"] is True
        assert advanced["completed_phase"] == "ctf_intake"
        assert advanced["current_phase"]["id"] == "ctf_challenge_classification"

    def test_records_repeated_rejected_hypotheses(self):
        from plugins.security.state import (
            handle_record_hypothesis,
            handle_start_workflow,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "solve the challenge",
            "mode": "ctf",
        }, task_id="ctf-repeat")

        first = _loads(handle_record_hypothesis({
            "hypothesis": "login parameter is injectable",
            "technique": "sqli",
            "result": "rejected",
        }, task_id="ctf-repeat"))
        assert first["repeat_warning"] is None

        second = _loads(handle_record_hypothesis({
            "hypothesis": "id parameter is injectable",
            "technique": "sqli",
            "result": "rejected",
        }, task_id="ctf-repeat"))
        assert "already been rejected 2 times" in second["repeat_warning"]


class TestSecurityWorkflowHooks:
    def test_blocks_security_terminal_command_without_workflow(self):
        from plugins.security.state import security_pre_tool_call

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "nmap -sV 10.10.10.5"},
            task_id="no-workflow",
        )

        assert result == {
            "action": "block",
            "message": "Start a security workflow with security_start_workflow before running security assessment commands.",
        }

    def test_allows_non_security_terminal_command_without_workflow(self):
        from plugins.security.state import security_pre_tool_call

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "python -m pytest tests/plugins/test_security_state.py -q"},
            task_id="normal-coding",
        )

        assert result is None

    def test_blocks_active_phase_direct_tool_until_dispatch_and_handoff(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
            security_post_tool_call,
            security_pre_tool_call,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "solve challenge",
            "mode": "ctf",
            "allowed_targets": ["*.ctf.local"],
            "include_active_testing": True,
            "require_agent_dispatch": True,
        }, task_id="ctf-dispatch")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-dispatch")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-dispatch")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-dispatch")
        handle_advance_phase({"rationale": "classified as web"}, task_id="ctf-dispatch")

        blocked = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "nmap box.ctf.local"},
            task_id="ctf-dispatch",
        )
        assert blocked is not None
        assert "requires security_dispatch_agent_tasks" in blocked["message"]

        assert security_pre_tool_call(
            tool_name="security_dispatch_agent_tasks",
            args={"phase_id": "ctf_target_recon"},
            task_id="ctf-dispatch",
        ) is None
        security_post_tool_call(
            tool_name="security_dispatch_agent_tasks",
            args={"phase_id": "ctf_target_recon"},
            result=json.dumps({"success": True, "phase_id": "ctf_target_recon", "tasks": []}),
            task_id="ctf-dispatch",
        )

        blocked_until_handoff = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "nmap box.ctf.local"},
            task_id="ctf-dispatch",
        )
        assert blocked_until_handoff is not None
        assert "requires security_collect_agent_handoffs" in blocked_until_handoff["message"]

        security_post_tool_call(
            tool_name="security_collect_agent_handoffs",
            args={"phase_id": "ctf_target_recon"},
            result=json.dumps({
                "success": True,
                "phase_id": "ctf_target_recon",
                "merged": {"assets": [{"target": "box.ctf.local"}]},
            }),
            task_id="ctf-dispatch",
        )

        allowed = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "nmap box.ctf.local"},
            task_id="ctf-dispatch",
        )
        assert allowed is None

    def test_blocks_wrong_phase_tool_args(self):
        from plugins.security.state import handle_start_workflow, security_pre_tool_call

        handle_start_workflow({
            "task_name": "external assessment",
            "objective": "assess services",
            "mode": "assessment",
            "allowed_targets": ["*.example.com"],
            "include_active_testing": True,
        }, task_id="phase-check")

        result = security_pre_tool_call(
            tool_name="security_nmap_scan",
            args={
                "phase_id": "active_recon",
                "targets": ["api.example.com"],
                "allowed_targets": ["*.example.com"],
            },
            task_id="phase-check",
        )

        assert result is not None
        assert "not allowed during security phase intake_authorization" in result["message"]

    def test_subagent_can_inherit_workflow_by_session_id(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
            security_post_tool_call,
            security_pre_tool_call,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "solve challenge",
            "mode": "ctf",
            "allowed_targets": ["*.ctf.local"],
            "include_active_testing": True,
            "require_agent_dispatch": True,
        }, task_id="parent-task", session_id="shared-session")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="parent-task")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="parent-task")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="parent-task")
        handle_advance_phase({"rationale": "classified"}, task_id="parent-task")
        security_post_tool_call(
            tool_name="security_dispatch_agent_tasks",
            args={"phase_id": "ctf_target_recon"},
            result=json.dumps({"success": True, "phase_id": "ctf_target_recon", "tasks": []}),
            task_id="parent-task",
            session_id="shared-session",
        )
        security_post_tool_call(
            tool_name="security_collect_agent_handoffs",
            args={"phase_id": "ctf_target_recon"},
            result=json.dumps({"success": True, "phase_id": "ctf_target_recon", "merged": {}}),
            task_id="parent-task",
            session_id="shared-session",
        )

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "nmap box.ctf.local"},
            task_id="child-task",
            session_id="shared-session",
        )

        assert result is None

    def test_ctf_http_request_can_run_without_explicit_allowed_targets(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
            security_pre_tool_call,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "probe challenge web service",
            "mode": "ctf",
            "include_active_testing": True,
            "require_agent_dispatch": False,
        }, task_id="ctf-http")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-http")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-http")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-http")
        handle_advance_phase({"rationale": "classified"}, task_id="ctf-http")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "curl -i http://10.10.10.5:8080/"},
            task_id="ctf-http",
        )

        assert result is None

    def test_ctf_non_http_network_command_still_requires_scope(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
            security_pre_tool_call,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "probe challenge host",
            "mode": "ctf",
            "include_active_testing": True,
            "require_agent_dispatch": False,
        }, task_id="ctf-non-http")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-non-http")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-non-http")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-non-http")
        handle_advance_phase({"rationale": "classified"}, task_id="ctf-non-http")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "nmap 10.10.10.5"},
            task_id="ctf-non-http",
        )

        assert result is not None
        assert "Non-HTTP network targets require explicit allowed_targets" in result["message"]

    def test_ctf_http_request_respects_denied_targets(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
            security_pre_tool_call,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "probe challenge web service",
            "mode": "ctf",
            "denied_targets": ["10.10.10.5"],
            "include_active_testing": True,
            "require_agent_dispatch": False,
        }, task_id="ctf-http-denied")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-http-denied")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-http-denied")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-http-denied")
        handle_advance_phase({"rationale": "classified"}, task_id="ctf-http-denied")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "curl -i http://10.10.10.5:8080/"},
            task_id="ctf-http-denied",
        )

        assert result is not None
        assert "matched denied scope" in result["message"]
