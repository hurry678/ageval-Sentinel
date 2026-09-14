"""The registry of Agents under test — what makes the platform general.

Onboarding an Agent is one entry in ``targets.yaml``. Two kinds exist today:

``inproc``   a Sentinel adapter running in this process (no key, no network)
``http``     any OpenAI-compatible endpoint

A target is turned into an ageval ``profiles.yaml`` at run time and handed over
with ``ageval run --profiles``, so no dataset file is ever edited to point at a
different Agent. That indirection is the whole reason a new Agent costs one entry.
"""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

import yaml

from platform_api.config import PROFILES_STATE, TARGETS_FILE, ensure_state
from redsentinel.adapters.inproc import DEFAULT_AGENT_KIND, agent_kinds

KINDS = ("inproc", "http")
# Derived, never duplicated: the registry in redsentinel is the single place a
# built-in Agent is registered, and the ageval executor plugin reads the same one.
INPROC_AGENTS = agent_kinds()
# The role every generated profile binds. Datasets reference this id.
ROLE_ID = "sentinel"
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def is_loopback(base_url: str) -> bool:
    """Loopback endpoints run without a credential, which is what makes a local
    mock Agent usable as a zero-key target."""
    return (urlparse(base_url).hostname or "").lower() in LOOPBACK_HOSTS


@dataclass
class Target:
    id: str
    name: str
    kind: str
    # inproc
    agent_kind: str = DEFAULT_AGENT_KIND
    # http
    model: str = ""
    base_url: str = ""
    api_key_env: str = ""
    note: str = ""
    tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def label(self) -> str:
        return self.model or f"sentinel/{self.agent_kind}-agent"

    @property
    def offline(self) -> bool:
        """Runs with no credential and no network — safe to launch unattended."""
        return self.kind == "inproc"


def _default_targets() -> list[Target]:
    """The two Agents this workspace ships with, so the platform is never empty."""
    return [
        Target(
            id="sentinel-ecommerce-agent",
            name="Sentinel 电商企业 Agent",
            kind="inproc",
            agent_kind="ecommerce",
            note="内置确定性电商 Agent，自带工具与防护，无需密钥或网络。",
            tags=["内置", "确定性", "离线"],
        ),
        Target(
            id="sentinel-openmanus-agent",
            name="Sentinel OpenManus Agent（离线）",
            kind="inproc",
            agent_kind="openmanus-offline",
            note="OpenManus 离线模拟器，支持 baseline / guarded 防护对比。",
            tags=["内置", "确定性", "离线", "支持防御对比"],
        ),
    ]


def load_targets() -> list[Target]:
    if not TARGETS_FILE.is_file():
        save_targets(_default_targets())
    raw = yaml.safe_load(TARGETS_FILE.read_text(encoding="utf-8")) or {}
    items = raw.get("targets") or []
    return [Target(**item) for item in items if isinstance(item, dict)]


def save_targets(targets: list[Target]) -> None:
    TARGETS_FILE.write_text(
        yaml.safe_dump(
            {"format": "sentinel.targets/1", "targets": [t.as_dict() for t in targets]},
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def get_target(target_id: str) -> Target | None:
    return next((t for t in load_targets() if t.id == target_id), None)


def upsert_target(target: Target) -> Target:
    targets = [t for t in load_targets() if t.id != target.id]
    targets.append(target)
    save_targets(targets)
    return target


def delete_target(target_id: str) -> bool:
    targets = load_targets()
    remaining = [t for t in targets if t.id != target_id]
    if len(remaining) == len(targets):
        return False
    save_targets(remaining)
    return True


def profiles_document(target: Target) -> dict[str, Any]:
    """The ageval profiles.yaml that binds this target to the dataset's role."""
    if target.kind == "inproc":
        binding: dict[str, Any] = {
            "executor": "sentinel-agent",
            "model": target.label,
            "options": {"agent_kind": target.agent_kind},
            "extensions": [{"plugin": "sentinel-agent"}, {"plugin": "local"}],
        }
    else:
        binding = {
            "executor": "openai-http",
            "model": target.model,
            "base_url": target.base_url,
            "extensions": [{"plugin": "openai-http"}, {"plugin": "local"}],
        }
        if target.api_key_env:
            # ageval rejects a bare name: the locator must be ${ENV_NAME} so the
            # secret itself never enters a profile or a lock file.
            binding["api_key"] = f"${{{target.api_key_env}}}"
    return {
        "format": "ageval.profiles/1",
        "environment": "local",
        # Bound to the named role and to "*", so a dataset works either way.
        # Deep-copied so the emitted YAML has no anchors — an auditor reads this file.
        "agent_profiles": {ROLE_ID: binding, "*": deepcopy(binding)},
    }


def materialize_profiles(target: Target) -> str:
    """Write the override and return its path for ``ageval run --profiles``."""
    ensure_state()
    path = PROFILES_STATE / f"{target.id}.yaml"
    path.write_text(
        yaml.safe_dump(profiles_document(target), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return str(path)


def validate(payload: dict[str, Any]) -> tuple[Target | None, str]:
    """Reject a target the platform could not run, with a reason the UI can show."""
    target_id = str(payload.get("id") or "").strip()
    if not target_id:
        return None, "id 不能为空"
    kind = str(payload.get("kind") or "").strip()
    if kind not in KINDS:
        return None, f"kind 必须是 {' / '.join(KINDS)}"
    if kind == "inproc" and str(payload.get("agent_kind")) not in INPROC_AGENTS:
        return None, f"agent_kind 必须是 {' / '.join(INPROC_AGENTS)}"
    if kind == "http":
        if not str(payload.get("model") or "").strip():
            return None, "http 目标必须填 model"
        base_url = str(payload.get("base_url") or "").strip()
        if not base_url.startswith(("http://", "https://")):
            return None, "base_url 必须是 http(s) 开头的完整地址"
        key_env = str(payload.get("api_key_env") or "").strip()
        # A loopback endpoint needs no credential — ageval skips the key check there.
        if not key_env and not is_loopback(base_url):
            return None, "http 目标必须填 api_key_env（环境变量名，不要填明文密钥）"
        if key_env and not ENV_NAME_RE.fullmatch(key_env):
            return None, "api_key_env 只能是环境变量名（字母/数字/下划线，不能以数字开头）"
    known = {f.name for f in Target.__dataclass_fields__.values()}
    clean = {key: value for key, value in payload.items() if key in known}
    clean.setdefault("name", target_id)
    return Target(**clean), ""


__all__ = [
    "INPROC_AGENTS",
    "KINDS",
    "ROLE_ID",
    "Target",
    "delete_target",
    "get_target",
    "is_loopback",
    "load_targets",
    "materialize_profiles",
    "profiles_document",
    "save_targets",
    "upsert_target",
    "validate",
]
