from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from redsentinel.runtime.engine.events.models import MemoryOpPayload

MemoryLayer = Literal["short_term", "long_term", "episodic"]
MemoryOp = Literal["read", "write", "delete"]

VALID_LAYERS: set[str] = {"short_term", "long_term", "episodic"}


@dataclass(frozen=True)
class MemoryRecord:
    namespace: str
    layer: MemoryLayer
    key: str
    value: Any
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    source: str = "agent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "layer": self.layer,
            "key": self.key,
            "value": deepcopy(self.value),
            "metadata": deepcopy(self.metadata),
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
        }


@dataclass(frozen=True)
class MemoryAuditRecord:
    op: MemoryOp
    namespace: str
    layer: MemoryLayer
    key: str
    value: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    source: str = "agent"

    def to_payload(self) -> MemoryOpPayload:
        return MemoryOpPayload(
            op=self.op,
            namespace=self.namespace,
            key=self.key,
            layer=self.layer,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "op": self.op,
            "namespace": self.namespace,
            "layer": self.layer,
            "key": self.key,
            "value": deepcopy(self.value),
            "metadata": deepcopy(self.metadata),
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
        }


class InMemoryMemoryStore:
    """Local memory store with namespace isolation and audit log."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, MemoryLayer, str], MemoryRecord] = {}
        self._audit_log: list[MemoryAuditRecord] = []

    def write(
        self,
        namespace: str,
        layer: MemoryLayer,
        key: str,
        value: Any,
        metadata: dict[str, Any] | None = None,
        source: str = "agent",
    ) -> MemoryAuditRecord:
        valid_layer = self._validate_layer(layer)
        timestamp = self._now()
        record = MemoryRecord(
            namespace=namespace,
            layer=valid_layer,
            key=key,
            value=deepcopy(value),
            metadata=deepcopy(metadata or {}),
            timestamp=timestamp,
            source=source,
        )
        self._records[(namespace, valid_layer, key)] = record
        return self._append_audit(
            op="write",
            namespace=namespace,
            layer=valid_layer,
            key=key,
            value=value,
            metadata=metadata or {},
            source=source,
            timestamp=timestamp,
        )

    def read(
        self,
        namespace: str,
        layer: MemoryLayer,
        key: str,
        source: str = "agent",
    ) -> tuple[Any | None, MemoryAuditRecord]:
        valid_layer = self._validate_layer(layer)
        record = self._records.get((namespace, valid_layer, key))
        value = deepcopy(record.value) if record else None
        audit = self._append_audit(
            op="read",
            namespace=namespace,
            layer=valid_layer,
            key=key,
            value=value,
            metadata={"hit": record is not None},
            source=source,
        )
        return value, audit

    def delete(
        self,
        namespace: str,
        layer: MemoryLayer,
        key: str,
        source: str = "agent",
    ) -> MemoryAuditRecord:
        valid_layer = self._validate_layer(layer)
        record = self._records.pop((namespace, valid_layer, key), None)
        return self._append_audit(
            op="delete",
            namespace=namespace,
            layer=valid_layer,
            key=key,
            value=deepcopy(record.value) if record else None,
            metadata={"existed": record is not None},
            source=source,
        )

    def list_namespace(
        self,
        namespace: str,
        layer: MemoryLayer | None = None,
    ) -> list[MemoryRecord]:
        valid_layer = self._validate_layer(layer) if layer is not None else None
        records = [
            record
            for (record_namespace, record_layer, _), record in self._records.items()
            if record_namespace == namespace and (valid_layer is None or record_layer == valid_layer)
        ]
        return deepcopy(sorted(records, key=lambda record: (record.layer, record.key)))

    def audit_log(self, namespace: str | None = None) -> list[MemoryAuditRecord]:
        records = [
            record for record in self._audit_log if namespace is None or record.namespace == namespace
        ]
        return deepcopy(records)

    def clear_namespace(self, namespace: str) -> None:
        keys_to_delete = [key for key in self._records if key[0] == namespace]
        for key in keys_to_delete:
            del self._records[key]

    def _append_audit(
        self,
        op: MemoryOp,
        namespace: str,
        layer: MemoryLayer,
        key: str,
        value: Any = None,
        metadata: dict[str, Any] | None = None,
        source: str = "agent",
        timestamp: datetime | None = None,
    ) -> MemoryAuditRecord:
        record = MemoryAuditRecord(
            op=op,
            namespace=namespace,
            layer=layer,
            key=key,
            value=deepcopy(value),
            metadata=deepcopy(metadata or {}),
            timestamp=timestamp or self._now(),
            source=source,
        )
        self._audit_log.append(record)
        return deepcopy(record)

    def _validate_layer(self, layer: str) -> MemoryLayer:
        if layer not in VALID_LAYERS:
            raise ValueError(f"Unsupported memory layer: {layer}")
        return layer  # type: ignore[return-value]

    def _now(self) -> datetime:
        return datetime.now(tz=timezone.utc)
