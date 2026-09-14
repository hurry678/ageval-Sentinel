from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from platform_api import config, suites, targets
from platform_api.app import create_app
from sentinel_agent_plugin.executor import agent_kinds as plugin_agent_kinds

from redsentinel.adapters.inproc import agent_kinds as registered_agent_kinds

pytestmark = pytest.mark.fast


def test_health_describes_platform_capabilities() -> None:
    client = TestClient(create_app())

    response = client.get("/api/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["target_kinds"] == list(targets.KINDS)
    assert payload["inproc_agents"] == list(registered_agent_kinds())
    assert payload["pipeline_nodes"]


def test_inproc_agent_lists_stay_in_sync() -> None:
    assert targets.INPROC_AGENTS == registered_agent_kinds() == plugin_agent_kinds()


def test_unknown_inproc_agent_is_rejected_with_known_values() -> None:
    target, reason = targets.validate({"id": "demo", "kind": "inproc", "agent_kind": "missing"})

    assert target is None
    assert "ecommerce / openmanus-offline" in reason


def test_http_target_requires_secret_env_for_non_loopback() -> None:
    target, reason = targets.validate(
        {
            "id": "remote-agent",
            "kind": "http",
            "model": "remote-model",
            "base_url": "https://api.example.com/v1",
        }
    )

    assert target is None
    assert "api_key_env" in reason


def test_loopback_http_target_can_omit_secret_env() -> None:
    target, reason = targets.validate(
        {
            "id": "local-agent",
            "kind": "http",
            "model": "local-model",
            "base_url": "http://127.0.0.1:8799/v1",
        }
    )

    assert reason == ""
    assert target is not None
    assert target.api_key_env == ""


def test_http_target_never_materializes_plaintext_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(targets, "PROFILES_STATE", tmp_path)
    target = targets.Target(
        id="remote-agent",
        name="Remote Agent",
        kind="http",
        model="remote-model",
        base_url="https://api.example.com/v1",
        api_key_env="REMOTE_AGENT_KEY",
    )

    document = targets.profiles_document(target)
    path = Path(targets.materialize_profiles(target))
    serialized_target = json.dumps(target.as_dict(), ensure_ascii=False)

    assert "sk-live-secret" not in serialized_target
    assert document["agent_profiles"]["sentinel"]["api_key"] == "${REMOTE_AGENT_KEY}"
    assert "sk-live-secret" not in path.read_text(encoding="utf-8")


def test_suite_discovery_is_data_driven(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite_root = tmp_path / "third-party-suite"
    task_dir = suite_root / "tasks" / "task-one" / "evaluation"
    task_dir.mkdir(parents=True)
    (suite_root / "ageval.yaml").write_text(
        "format: ageval.dataset/1\ndataset_id: third-party\nversion: '1.0.0'\ntasks:\n  root: tasks\n",
        encoding="utf-8",
    )
    (suite_root / "tasks" / "task-one" / "task.yaml").write_text(
        "format: ageval.task/1\ntask_id: task-one\nparameters:\n  risk_category: prompt_injection\n  severity: high\n",
        encoding="utf-8",
    )
    (task_dir / "expected.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(config, "WORKSPACE", tmp_path)

    discovered = config.suite_roots()

    assert discovered == [suite_root]
    listed = suites.list_suites()
    assert [item["suite_id"] for item in listed] == ["third-party-suite"]


def test_unknown_suite_category_degrades_to_missing_coverage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    suite_root = tmp_path / "unknown-category-suite"
    task_dir = suite_root / "tasks" / "task-one" / "evaluation"
    task_dir.mkdir(parents=True)
    (suite_root / "ageval.yaml").write_text(
        "format: ageval.dataset/1\ndataset_id: unknown-category\nversion: '1.0.0'\ntasks:\n  root: tasks\n",
        encoding="utf-8",
    )
    (suite_root / "tasks" / "task-one" / "task.yaml").write_text(
        "format: ageval.task/1\ntask_id: task-one\nparameters:\n  risk_category: future_risk\n  severity: high\n",
        encoding="utf-8",
    )
    (task_dir / "expected.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(config, "WORKSPACE", tmp_path)

    detail = suites.get_suite("unknown-category-suite")

    assert detail is not None
    assert detail["task_count"] == 1
    assert detail["tasks"][0]["nodes"] == []
    assert detail["node_coverage"]["ratio"] == 0.0
