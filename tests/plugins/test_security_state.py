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

    def test_attack_paths_are_breadth_ranked_then_selected_for_depth(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_get_workflow_state,
            handle_record_artifact,
            handle_record_attack_path,
            handle_rank_attack_paths,
            handle_select_attack_path,
            handle_start_workflow,
            handle_update_attack_path,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "solve web challenge",
            "mode": "ctf",
            "allowed_targets": ["192.168.15.129"],
            "include_active_testing": True,
        }, task_id="ctf-paths")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-paths")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-paths")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-paths")
        handle_advance_phase({"rationale": "classified"}, task_id="ctf-paths")

        low = _loads(handle_record_attack_path({
            "title": "try static backup files",
            "entrypoint": "/backup.zip",
            "technique": "source_disclosure",
            "success_probability": 2,
            "impact": 3,
            "cost": 1,
            "noise": 1,
        }, task_id="ctf-paths"))
        high = _loads(handle_record_attack_path({
            "title": "test graffiti id parameter",
            "entrypoint": "/graffiti.php?id=1",
            "technique": "sqli",
            "success_probability": 4,
            "impact": 4,
            "cost": 1,
            "noise": 1,
            "privilege_gain": 3,
        }, task_id="ctf-paths"))

        assert low["success"] is True
        assert high["success"] is True
        state = _loads(handle_get_workflow_state({}, task_id="ctf-paths"))["state"]
        assert "entrypoint_candidates" in state["available_artifacts"]
        assert state["ranked_attack_paths"][0]["title"] == "test graffiti id parameter"

        ranked = _loads(handle_rank_attack_paths({}, task_id="ctf-paths"))
        assert ranked["ranked_attack_paths"][0]["title"] == "test graffiti id parameter"

        selected = _loads(handle_select_attack_path({}, task_id="ctf-paths"))
        assert selected["success"] is True
        assert selected["active_attack_path"]["title"] == "test graffiti id parameter"

        updated = _loads(handle_update_attack_path({
            "status": "rejected",
            "evidence": "no injection behavior observed",
            "result": "parameter is static",
            "score_adjustment": -5,
        }, task_id="ctf-paths"))
        assert updated["success"] is True
        assert updated["active_attack_path"] is None
        assert updated["ranked_attack_paths"][0]["title"] == "try static backup files"


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

    def test_independent_subagent_context_cannot_bypass_sole_active_workflow(self):
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
            "permission_profile": "standard",
        }, task_id="parent-only")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="parent-only")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="parent-only")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "curl -i http://10.10.10.5:8080/"},
            task_id="independent-child",
        )

        assert result is not None
        assert "Continue the current phase without the HTTP request" in result["message"]
        assert "Do not use delegate_task or a subagent to bypass" in result["message"]

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

    def test_terminal_scope_ignores_url_path_file_names(self):
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
            "allowed_targets": ["192.168.15.129"],
            "include_active_testing": True,
            "require_agent_dispatch": False,
        }, task_id="ctf-url-path")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-url-path")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-url-path")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-url-path")
        handle_advance_phase({"rationale": "classified"}, task_id="ctf-url-path")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "curl -i 'http://192.168.15.129/graffiti.php?id=1'"},
            task_id="ctf-url-path",
        )

        assert result is None

    @pytest.mark.parametrize("phase_artifact", [
        ("ctf_target_recon", "challenge_type"),
        ("ctf_vulnerability_discovery", "ctf_attack_surface"),
        ("ctf_foothold", "candidate_solution_paths"),
        ("ctf_privilege_escalation", "foothold_evidence"),
        ("ctf_flag_discovery", "foothold_evidence"),
    ])
    def test_ctf_active_phases_do_not_block_http_requests(self, phase_artifact):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
            security_pre_tool_call,
        )

        target_phase, artifact_id = phase_artifact
        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "probe challenge web service",
            "mode": "ctf",
            "include_active_testing": True,
        }, task_id=f"ctf-http-{target_phase}")
        phase_artifacts = {
            "ctf_intake": "ctf_rules",
            "ctf_challenge_classification": "challenge_type",
            "ctf_target_recon": "ctf_attack_surface",
            "ctf_vulnerability_discovery": "candidate_solution_paths",
            "ctf_foothold": "foothold_evidence",
            "ctf_privilege_escalation": "escalation_path",
        }
        while True:
            if target_phase == "ctf_flag_discovery":
                current_artifact = artifact_id
            else:
                current_artifact = phase_artifacts.get(target_phase)
            if current_artifact and current_artifact in {"challenge_type", "ctf_attack_surface", "candidate_solution_paths", "foothold_evidence"}:
                pass
            # Stop once the current state has reached the phase under test.
            from plugins.security.state import handle_get_workflow_state
            state = _loads(handle_get_workflow_state({}, task_id=f"ctf-http-{target_phase}"))["state"]
            current_phase = state["current_phase"]["id"]
            if current_phase == target_phase:
                break
            handle_record_artifact({
                "artifact_id": phase_artifacts[current_phase],
                "content": current_phase,
            }, task_id=f"ctf-http-{target_phase}")
            handle_advance_phase({"rationale": f"{current_phase} done"}, task_id=f"ctf-http-{target_phase}")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "curl -i http://10.10.10.5:8080/"},
            task_id=f"ctf-http-{target_phase}",
        )

        assert result is None

    def test_ctf_curl_blocked_before_active_phase_with_progression_guidance(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_get_workflow_state,
            handle_next_action,
            handle_record_artifact,
            handle_start_workflow,
            security_pre_tool_call,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "probe challenge web service",
            "mode": "ctf",
            "include_active_testing": True,
            "permission_profile": "standard",
        }, task_id="ctf-curl-too-early")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-curl-too-early")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-curl-too-early")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "curl -i http://10.10.10.5:8080/"},
            task_id="ctf-curl-too-early",
        )

        assert result is not None
        assert "Continue the current phase without the HTTP request" in result["message"]
        assert "ctf_target_recon" in result["message"]
        assert "Do not use delegate_task or a subagent to bypass" in result["message"]
        assert "Deferred call id deferred-1" in result["message"]

        state = _loads(handle_get_workflow_state({}, task_id="ctf-curl-too-early"))["state"]
        assert state["deferred_tool_calls"][0]["tool_name"] == "terminal"
        assert state["deferred_tool_calls"][0]["target_phase"] == "ctf_target_recon"

        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-curl-too-early")
        handle_advance_phase({"rationale": "classified"}, task_id="ctf-curl-too-early")
        next_action = _loads(handle_next_action({}, task_id="ctf-curl-too-early"))["next_action"]
        assert next_action["phase_id"] == "ctf_target_recon"
        assert next_action["deferred_tool_calls_ready"][0]["id"] == "deferred-1"

    def test_ctf_delegate_task_cannot_bypass_non_delegation_phase(self):
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
        }, task_id="ctf-delegate-too-early")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-delegate-too-early")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-delegate-too-early")

        result = security_pre_tool_call(
            tool_name="delegate_task",
            args={"goal": "curl http://10.10.10.5:8080/"},
            task_id="ctf-delegate-too-early",
        )

        assert result is not None
        assert "Do not use delegate_task or a subagent to bypass" in result["message"]

    def test_ctf_common_network_command_can_run_without_explicit_allowed_targets(self):
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

        assert result is None

    def test_ctf_unlisted_network_command_still_requires_scope(self):
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
            "permission_profile": "standard",
        }, task_id="ctf-ping")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-ping")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-ping")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-ping")
        handle_advance_phase({"rationale": "classified"}, task_id="ctf-ping")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "ping 10.10.10.5"},
            task_id="ctf-ping",
        )

        assert result is not None
        assert "Non-HTTP network targets require explicit allowed_targets" in result["message"]

    def test_relaxed_ctf_allows_unlisted_network_commands_without_scope(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
            security_pre_tool_call,
        )

        started = _loads(handle_start_workflow({
            "task_name": "web ctf",
            "objective": "probe challenge host",
            "mode": "ctf",
            "include_active_testing": True,
        }, task_id="ctf-relaxed-ping"))
        assert started["state"]["permission_profile"] == "relaxed"
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-relaxed-ping")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-relaxed-ping")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "ping -c 1 10.10.10.5"},
            task_id="ctf-relaxed-ping",
        )

        assert result is None

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

    def test_ctf_default_does_not_require_dispatch_for_direct_tooling(self):
        from plugins.security.state import (
            handle_advance_phase,
            handle_record_artifact,
            handle_start_workflow,
            security_pre_tool_call,
        )

        handle_start_workflow({
            "task_name": "web ctf",
            "objective": "solve challenge",
            "mode": "ctf",
            "include_active_testing": True,
        }, task_id="ctf-relaxed-dispatch")
        handle_record_artifact({"artifact_id": "ctf_rules", "content": "rules"}, task_id="ctf-relaxed-dispatch")
        handle_advance_phase({"rationale": "rules recorded"}, task_id="ctf-relaxed-dispatch")
        handle_record_artifact({"artifact_id": "challenge_type", "content": "web"}, task_id="ctf-relaxed-dispatch")
        handle_advance_phase({"rationale": "classified"}, task_id="ctf-relaxed-dispatch")

        result = security_pre_tool_call(
            tool_name="terminal",
            args={"command": "nc 10.10.10.5 1337"},
            task_id="ctf-relaxed-dispatch",
        )

        assert result is None
