from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from redsentinel.application.contracts import (
    PendingDecisionRecord,
    SupervisionDefaultAction,
    SupervisionEvent,
    SupervisionResponseAction,
    SupervisionResponseRecord,
    utc_now_iso,
)
from redsentinel.application.engine.storage import ProductStorage, sanitize_secret_fields


DEFAULT_RECENT_EVENT_LIMIT = 50
DEFAULT_MAX_EVENTS = 500
DEFAULT_PENDING_TTL_SECONDS = 300
HIGH_RISK_THRESHOLD = 80.0


class SupervisionDecisionError(ValueError):
    def __init__(self, message: str, *, error_code: str, status_code: int) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code


class SupervisionEventStore:
    def __init__(
        self,
        storage_root: str | Path = "runs/product",
        *,
        storage: ProductStorage | None = None,
        max_events: int = DEFAULT_MAX_EVENTS,
        recent_event_limit: int = DEFAULT_RECENT_EVENT_LIMIT,
        pending_ttl_seconds: int = DEFAULT_PENDING_TTL_SECONDS,
        default_action: SupervisionDefaultAction = "deny",
    ) -> None:
        self.storage = storage or ProductStorage(storage_root)
        self.root = self.storage.root / "supervision"
        self.events_path = self.root / "events.jsonl"
        self.latest_path = self.root / "latest.json"
        self.pending_decisions_path = self.root / "pending_decisions.json"
        self.max_events = max_events
        self.recent_event_limit = recent_event_limit
        self.pending_ttl_seconds = pending_ttl_seconds
        self.default_action = default_action

    def append_event(self, event: SupervisionEvent | dict[str, Any]) -> SupervisionEvent:
        stored_event = self._normalize_event(event)
        self.root.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(stored_event.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
            file.write("\n")

        self._trim_events()
        if stored_event.decision == "ask":
            self._initialize_pending_decision(stored_event)
        self.write_latest_snapshot()
        return stored_event

    def read_recent_events(self, limit: int | None = None, *, tenant_id: str | None = None) -> list[SupervisionEvent]:
        if not self.events_path.exists():
            return []
        lines = [line for line in self.events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        events = [SupervisionEvent.model_validate(json.loads(line)) for line in lines]
        if tenant_id is not None:
            events = [event for event in events if event.tenant_id == tenant_id]
        return events[-(limit or self.recent_event_limit):]

    def compute_summary(
        self,
        events: list[SupervisionEvent] | None = None,
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        event_list = events if events is not None else self.read_recent_events(limit=self.max_events, tenant_id=tenant_id)
        decisions = Counter(event.decision for event in event_list)
        statuses = Counter(event.status for event in event_list)
        call_types = Counter(event.call_type for event in event_list)
        latest_event = event_list[-1] if event_list else None
        return {
            "schema_version": "supervision-summary-v0.1",
            "total_events": len(event_list),
            "decision_counts": {key: decisions.get(key, 0) for key in ["allow", "deny", "ask"]},
            "status_counts": {
                key: statuses.get(key, 0)
                for key in ["observed", "blocked", "pending", "approved", "rejected", "expired"]
            },
            "call_type_counts": {
                key: call_types.get(key, 0)
                for key in ["llm_input", "llm_output", "tool_call", "tool_result", "code_execution", "file_access"]
            },
            "high_risk_count": sum(1 for event in event_list if event.risk_score >= HIGH_RISK_THRESHOLD),
            "pending_count": statuses.get("pending", 0),
            "latest_event_id": latest_event.event_id if latest_event else None,
            "latest_timestamp": latest_event.timestamp if latest_event else None,
        }

    def write_latest_snapshot(self, *, tenant_id: str | None = None) -> dict[str, Any]:
        events = self.read_recent_events(tenant_id=tenant_id)
        snapshot = {
            "schema_version": "supervision-latest-v0.1",
            "updated_at": utc_now_iso(),
            "events": [event.model_dump(mode="json") for event in events],
            "summary": self.compute_summary(events, tenant_id=tenant_id),
            "pending_decisions": [
                record.model_dump(mode="json") for record in self.read_pending_decisions(tenant_id=tenant_id)
            ],
        }
        if tenant_id is None:
            self.storage.write_json(self.latest_path, snapshot)
        return snapshot

    def read_pending_decisions(self, *, tenant_id: str | None = None) -> list[PendingDecisionRecord]:
        if not self.pending_decisions_path.exists():
            return []
        payload = self.storage.read_json(self.pending_decisions_path)
        records = [
            PendingDecisionRecord.model_validate(item)
            for item in payload.get("decisions", [])
        ]
        if tenant_id is None:
            return records
        return [record for record in records if self._pending_record_matches_tenant(record, tenant_id)]

    def respond_to_pending(
        self,
        event_id: str,
        *,
        action: SupervisionResponseAction,
        operator: str,
        reason: str,
        tenant_id: str | None = None,
    ) -> SupervisionResponseRecord:
        records = self.read_pending_decisions()
        record_index = next(
            (
                index
                for index, record in enumerate(records)
                if record.event_id == event_id and self._pending_record_matches_tenant(record, tenant_id)
            ),
            None,
        )
        if record_index is None:
            raise SupervisionDecisionError(
                f"Pending supervision event {event_id} was not found.",
                error_code="supervision_event_not_found",
                status_code=404,
            )

        record = records[record_index]
        if record.resolved_at or record.supervisor_action:
            raise SupervisionDecisionError(
                f"Pending supervision event {event_id} has already been resolved.",
                error_code="supervision_event_resolved",
                status_code=409,
            )

        now = utc_now_iso()
        if _is_after(now, record.expires_at):
            expired_record = record.model_copy(update={"supervisor_action": record.default_action, "resolved_at": now})
            records[record_index] = expired_record
            self._write_pending_decisions(records)
            self._update_event_status(event_id, "expired", tenant_id=tenant_id)
            self.write_latest_snapshot(tenant_id=tenant_id)
            raise SupervisionDecisionError(
                f"Pending supervision event {event_id} has expired.",
                error_code="supervision_event_expired",
                status_code=409,
            )

        status = "approved" if action == "approve" else "rejected"
        response = SupervisionResponseRecord(
            event_id=event_id,
            action=action,
            operator=operator,
            reason=reason,
            resolved_at=now,
            status=status,
        )
        records[record_index] = record.model_copy(
            update={"supervisor_action": action, "resolved_at": response.resolved_at}
        )
        self._write_pending_decisions(records)
        self._update_event_status(event_id, status, tenant_id=tenant_id)
        self.write_latest_snapshot(tenant_id=tenant_id)
        return response

    def _normalize_event(self, event: SupervisionEvent | dict[str, Any]) -> SupervisionEvent:
        event_payload = event.model_dump(mode="json") if isinstance(event, SupervisionEvent) else dict(event)
        if isinstance(event_payload.get("payload_summary"), dict):
            event_payload["payload_summary"] = sanitize_secret_fields(event_payload["payload_summary"])
        return SupervisionEvent.model_validate(event_payload)

    def _trim_events(self) -> None:
        if self.max_events <= 0 or not self.events_path.exists():
            return
        lines = [line for line in self.events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(lines) <= self.max_events:
            return
        self.events_path.write_text("\n".join(lines[-self.max_events:]) + "\n", encoding="utf-8")

    def _initialize_pending_decision(self, event: SupervisionEvent) -> None:
        records = self.read_pending_decisions()
        if any(
            record.event_id == event.event_id and self._pending_record_matches_tenant(record, event.tenant_id)
            for record in records
        ):
            return
        requested_at = event.timestamp
        record = PendingDecisionRecord(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            requested_at=requested_at,
            expires_at=_add_seconds(requested_at, self.pending_ttl_seconds),
            default_action=self.default_action,
        )
        records.append(record)
        self._write_pending_decisions(records)

    def _write_pending_decisions(self, records: list[PendingDecisionRecord]) -> None:
        payload = {
            "schema_version": "pending-decisions-v0.1",
            "updated_at": utc_now_iso(),
            "decisions": [record.model_dump(mode="json") for record in records],
        }
        self.storage.write_json(self.pending_decisions_path, payload)

    def _update_event_status(self, event_id: str, status: str, *, tenant_id: str | None = None) -> None:
        if not self.events_path.exists():
            return
        updated_lines: list[str] = []
        for line in self.events_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            if payload.get("event_id") == event_id and (tenant_id is None or payload.get("tenant_id") == tenant_id):
                payload["status"] = status
            updated_lines.append(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        self.events_path.write_text("\n".join(updated_lines) + ("\n" if updated_lines else ""), encoding="utf-8")

    def _pending_record_matches_tenant(self, record: PendingDecisionRecord, tenant_id: str | None) -> bool:
        if tenant_id is None:
            return True
        if record.tenant_id is not None:
            return record.tenant_id == tenant_id
        return any(
            event.tenant_id == tenant_id
            for event in self.read_recent_events(limit=self.max_events)
            if event.event_id == record.event_id
        )


def seed_supervision_demo_events(
    storage_root: str | Path = "runs/product",
    *,
    tenant_id: str = "private_tenant",
    agent_id: str = "ecommerce_customer_guide",
    max_events: int = DEFAULT_MAX_EVENTS,
) -> dict[str, Any]:
    store = SupervisionEventStore(storage_root=storage_root, max_events=max_events)
    for payload in _demo_events(tenant_id=tenant_id, agent_id=agent_id):
        store.append_event(payload)
    return store.write_latest_snapshot(tenant_id=tenant_id)


def _demo_events(*, tenant_id: str, agent_id: str) -> list[dict[str, Any]]:
    return [
        {
            "event_id": "evt_demo_allow_tool_call",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "call_type": "tool_call",
            "decision": "allow",
            "reason": "Normal business tool call stayed within policy.",
            "risk_score": 12.0,
            "confidence": 0.96,
            "payload_summary": {"tool": "send_email", "recipient_domain": "example.test"},
            "source": "demo_seed",
            "status": "observed",
        },
        {
            "event_id": "evt_demo_deny_file_access",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "call_type": "file_access",
            "decision": "deny",
            "reason": "File access attempted outside the allowed workspace boundary.",
            "risk_score": 91.0,
            "confidence": 0.93,
            "payload_summary": {"operation": "read", "path": "../secrets/customer_export.csv"},
            "source": "demo_seed",
            "status": "blocked",
        },
        {
            "event_id": "evt_demo_ask_code_execution",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "call_type": "code_execution",
            "decision": "ask",
            "reason": "Code execution is high impact and requires supervisor confirmation.",
            "risk_score": 76.0,
            "confidence": 0.68,
            "payload_summary": {"language": "python", "command": "python generated_script.py"},
            "source": "demo_seed",
            "status": "pending",
        },
    ]


def _add_seconds(timestamp: str, seconds: int) -> str:
    normalized = timestamp.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed + timedelta(seconds=seconds)).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00",
        "Z",
    )


def _is_after(left: str, right: str) -> bool:
    return _parse_timestamp(left) > _parse_timestamp(right)


def _parse_timestamp(timestamp: str) -> datetime:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


__all__ = [
    "DEFAULT_MAX_EVENTS",
    "DEFAULT_PENDING_TTL_SECONDS",
    "DEFAULT_RECENT_EVENT_LIMIT",
    "HIGH_RISK_THRESHOLD",
    "SupervisionDecisionError",
    "SupervisionEventStore",
    "seed_supervision_demo_events",
]
