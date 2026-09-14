from __future__ import annotations

from pathlib import Path

from redsentinel.application.contracts import AgentLibraryEntry
from redsentinel.application.engine.storage import ProductStorage


OFFICIAL_OPENMANUS_AGENT = AgentLibraryEntry(
    agent_id="openmanus_official",
    name="OpenManus Official",
    framework="OpenManus",
    description="Official OpenManus adapter for RedSentinel platform evaluation.",
    default_benchmark_id="ecommerce-security-v0.1",
    tags=["official", "openmanus"],
    source="official",
    created_by="system",
)


class AgentLibraryService:
    def __init__(self, storage_root: str | Path = "runs/product", *, storage: ProductStorage | None = None) -> None:
        self.storage = storage or ProductStorage(storage_root)

    def ensure_official_entries(self) -> None:
        path = self.storage.agent_library_path(OFFICIAL_OPENMANUS_AGENT.agent_id)
        if not path.exists():
            self.storage.write_agent_library_entry(
                OFFICIAL_OPENMANUS_AGENT.agent_id,
                OFFICIAL_OPENMANUS_AGENT.model_dump(mode="json"),
            )

    def list_entries(self) -> list[AgentLibraryEntry]:
        self.ensure_official_entries()
        entries = [AgentLibraryEntry.model_validate(item) for item in self.storage.list_agent_library_entries()]
        return sorted(entries, key=lambda item: item.agent_id)

    def get_entry(self, agent_id: str) -> AgentLibraryEntry:
        self.ensure_official_entries()
        path = self.storage.agent_library_path(agent_id)
        if not path.exists():
            raise ValueError(f"Agent library entry not found: {agent_id}")
        return AgentLibraryEntry.model_validate(self.storage.read_agent_library_entry(agent_id))

    def upsert_entry(self, entry: AgentLibraryEntry, *, created_by: str) -> AgentLibraryEntry:
        payload = entry.model_copy(update={"created_by": created_by}).model_dump(mode="json")
        return AgentLibraryEntry.model_validate(self.storage.write_agent_library_entry(entry.agent_id, payload))
