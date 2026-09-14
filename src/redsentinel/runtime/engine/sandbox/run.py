from __future__ import annotations

from datetime import datetime, timezone

from redsentinel.attacks.engine.injectors.memory_poisoning import MemoryPoisoningInjector
from redsentinel.runtime.engine.sandbox.config import ScenarioConfig
from redsentinel.runtime.engine.sandbox.session import SandboxEnvironment
from redsentinel.runtime.engine.telemetry import TrajectoryRecorder


def get_backend(framework: str):
    if framework == "direct_api":
        from redsentinel.runtime.engine.sandbox.backends.direct_api import DirectAPIBackend

        return DirectAPIBackend()
    if framework == "langgraph":
        from redsentinel.runtime.engine.sandbox.backends.langgraph import LangGraphBackend

        return LangGraphBackend()
    if framework == "autogen":
        raise ValueError(
            "AutoGen backend is scaffold-only and is not a runnable sandbox framework."
        )
    if framework == "docker":
        from redsentinel.runtime.engine.sandbox.backends.docker import DockerBackend

        return DockerBackend()
    raise ValueError(f"Unsupported framework: {framework}")


def run_scenario(path: str) -> dict:
    config = ScenarioConfig.from_yaml(path)
    env = SandboxEnvironment()
    session = env.create_session(config)
    backend = get_backend(config.agent.framework)
    started_at = datetime.now(tz=timezone.utc)
    MemoryPoisoningInjector().apply(session)
    backend.run(session)
    return TrajectoryRecorder.from_session(session, started_at=started_at)
