from __future__ import annotations

from redsentinel.runtime.engine.events.models import StepEvent
from redsentinel.runtime.engine.sandbox.session import SandboxSession


class AutoGenBackend:
    """Scaffold marker only; do not dispatch this as a runnable sandbox backend."""

    framework = "autogen"

    def run(self, session: SandboxSession) -> list[StepEvent]:
        raise NotImplementedError(
            "AutoGen backend is a scaffold only and is not a runnable sandbox framework."
        )
