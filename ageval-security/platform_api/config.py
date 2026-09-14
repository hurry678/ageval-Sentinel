"""Where the platform finds everything.

One module so no other file hardcodes a path. The layout is fixed by the repo,
not configurable — this is a workspace tool, not a deployable service.
"""

from __future__ import annotations

from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parent
WORKSPACE = PLATFORM_ROOT.parent
REPO_ROOT = WORKSPACE.parent

# `ageval` is invoked as a CLI from its own checkout so it picks up its project env.
AGEVAL_ROOT = WORKSPACE / "ageval"
TOOLS_ROOT = WORKSPACE / "tools"

# Registry of Agents under test. Lives in the workspace so it is reviewable.
TARGETS_FILE = WORKSPACE / "targets.yaml"

# Platform-owned state: run records, generated profile overrides, event logs.
STATE_ROOT = WORKSPACE / ".platform"
RUNS_STATE = STATE_ROOT / "runs"
PROFILES_STATE = STATE_ROOT / "profiles"
CUSTOM_SUITES_ROOT = STATE_ROOT / "custom-suites"

WEB_DIST = PLATFORM_ROOT / "web" / "dist"


def suite_roots() -> list[Path]:
    """Every ageval dataset in the workspace, discovered by its manifest."""
    roots = [
        path.parent
        for path in WORKSPACE.glob("*/ageval.yaml")
        if (path.parent / "tasks").is_dir()
    ]
    custom_root = WORKSPACE / ".platform" / "custom-suites"
    if custom_root.is_dir():
        roots.extend(
            path.parent
            for path in custom_root.glob("*/ageval.yaml")
            if (path.parent / "tasks").is_dir()
        )
    return sorted(roots, key=lambda path: path.name)


def ensure_state() -> None:
    for path in (STATE_ROOT, RUNS_STATE, PROFILES_STATE, CUSTOM_SUITES_ROOT):
        path.mkdir(parents=True, exist_ok=True)
