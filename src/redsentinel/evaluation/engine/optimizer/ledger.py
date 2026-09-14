from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


LedgerArtifactType = Literal["agent_security_report", "optimization_directive"]


class LedgerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int = Field(ge=0)
    artifact_type: LedgerArtifactType
    artifact_id: str = Field(min_length=1)
    payload_hash: str = Field(min_length=1)
    previous_hash: str | None = None
    entry_hash: str = Field(min_length=1)


class LedgerVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    total_entries: int = Field(ge=0)
    first_invalid_sequence: int | None = None
    errors: list[str] = Field(default_factory=list)


def build_ledger_entry(
    *,
    artifact_type: LedgerArtifactType,
    artifact_id: str,
    payload: dict[str, Any],
    previous_hash: str | None,
    sequence: int,
) -> LedgerEntry:
    payload_hash = _hash_payload(payload)
    entry_hash = _hash_payload(
        {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "payload_hash": payload_hash,
            "previous_hash": previous_hash,
            "sequence": sequence,
        }
    )
    return LedgerEntry(
        sequence=sequence,
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        payload_hash=payload_hash,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
    )


def build_ledger_entries(
    artifacts: list[tuple[LedgerArtifactType, str, dict[str, Any]]],
    *,
    starting_sequence: int = 0,
    previous_hash: str | None = None,
) -> list[LedgerEntry]:
    entries: list[LedgerEntry] = []
    for offset, (artifact_type, artifact_id, payload) in enumerate(artifacts):
        sequence = starting_sequence + offset
        entry = build_ledger_entry(
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            payload=payload,
            previous_hash=previous_hash,
            sequence=sequence,
        )
        entries.append(entry)
        previous_hash = entry.entry_hash
    return entries


def append_ledger_entries(
    artifacts: list[tuple[LedgerArtifactType, str, dict[str, Any]]],
    path: str | Path,
) -> list[LedgerEntry]:
    existing_entries = load_ledger_entries(path)
    if not verify_ledger_entries(existing_entries).valid:
        raise ValueError("Cannot append to an invalid optimizer ledger.")
    entries = build_ledger_entries(
        artifacts,
        starting_sequence=len(existing_entries),
        previous_hash=existing_entries[-1].entry_hash if existing_entries else None,
    )
    write_ledger(entries, path, append=bool(existing_entries))
    return entries


def write_ledger(entries: list[LedgerEntry], path: str | Path, *, append: bool = False) -> None:
    ledger_path = Path(path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(entry.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
        for entry in entries
    ]
    payload = "\n".join(lines) + "\n"
    if append:
        with ledger_path.open("a", encoding="utf-8") as file:
            file.write(payload)
        return
    ledger_path.write_text(payload, encoding="utf-8")


def load_ledger_entries(path: str | Path) -> list[LedgerEntry]:
    ledger_path = Path(path)
    if not ledger_path.exists():
        return []
    return [
        LedgerEntry.model_validate(json.loads(line))
        for line in ledger_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def verify_ledger_entries(entries: list[LedgerEntry]) -> LedgerVerification:
    previous_hash: str | None = None
    errors: list[str] = []
    for expected_sequence, entry in enumerate(entries):
        if entry.sequence != expected_sequence:
            errors.append(f"sequence {entry.sequence} out of order")
            return _verification(entries, entry.sequence, errors)
        if entry.previous_hash != previous_hash:
            errors.append(f"sequence {entry.sequence} previous hash mismatch")
            return _verification(entries, entry.sequence, errors)
        if not _is_sha256(entry.payload_hash):
            errors.append(f"sequence {entry.sequence} payload hash mismatch")
            return _verification(entries, entry.sequence, errors)

        expected_entry_hash = _hash_payload(
            {
                "artifact_id": entry.artifact_id,
                "artifact_type": entry.artifact_type,
                "payload_hash": entry.payload_hash,
                "previous_hash": entry.previous_hash,
                "sequence": entry.sequence,
            }
        )
        if entry.entry_hash != expected_entry_hash:
            errors.append(f"sequence {entry.sequence} entry hash mismatch")
            return _verification(entries, entry.sequence, errors)

        previous_hash = entry.entry_hash

    return LedgerVerification(valid=True, total_entries=len(entries))


def _verification(
    entries: list[LedgerEntry],
    first_invalid_sequence: int,
    errors: list[str],
) -> LedgerVerification:
    return LedgerVerification(
        valid=False,
        total_entries=len(entries),
        first_invalid_sequence=first_invalid_sequence,
        errors=errors,
    )


def _hash_payload(payload: dict[str, Any]) -> str:
    normalized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    if not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


__all__ = [
    "LedgerEntry",
    "LedgerVerification",
    "append_ledger_entries",
    "build_ledger_entries",
    "build_ledger_entry",
    "load_ledger_entries",
    "verify_ledger_entries",
    "write_ledger",
]
