from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from redsentinel.application.contracts import utc_now_iso
from redsentinel.application.engine.storage import ProductStorage, sanitize_secret_fields
from redsentinel.application.engine.supervision import HIGH_RISK_THRESHOLD


DEFAULT_MONITOR_EVENT_LIMIT = 50
MAX_MONITOR_EVENT_LIMIT = 500


class SecurityEventReader:
    def __init__(self, storage: ProductStorage) -> None:
        self.storage = storage

    def read_security_events(
        self,
        *,
        limit: int = DEFAULT_MONITOR_EVENT_LIMIT,
        agent_id: str | None = None,
        decision: str | None = None,
        session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        events = self._read_all_events()
        filtered = [
            event
            for event in events
            if _matches_filter(event, agent_id=agent_id, decision=decision, session_id=session_id)
        ]
        bounded_limit = max(1, min(limit, MAX_MONITOR_EVENT_LIMIT))
        return filtered[-bounded_limit:]

    def summarize_security_events(
        self,
        *,
        limit: int = DEFAULT_MONITOR_EVENT_LIMIT,
        agent_id: str | None = None,
        decision: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        events = self.read_security_events(
            limit=limit,
            agent_id=agent_id,
            decision=decision,
            session_id=session_id,
        )
        return summarize_security_events(events)

    def _read_all_events(self) -> list[dict[str, Any]]:
        path = next((candidate for candidate in _candidate_event_paths(self.storage.root) if candidate.exists()), None)
        if path is None:
            return []

        events: list[dict[str, Any]] = []
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                events.append(_normalize_security_event(payload, index=index))
        return events


def summarize_security_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    decisions = Counter(event.get("decision") for event in events)
    latest_event = events[-1] if events else {}
    return {
        "schema_version": "monitor-events-summary-v0.1",
        "updated_at": utc_now_iso(),
        "total_events": len(events),
        "decision_counts": {key: decisions.get(key, 0) for key in ["allow", "deny", "ask"]},
        "high_risk_count": sum(1 for event in events if _float_value(event.get("risk_score")) >= HIGH_RISK_THRESHOLD),
        "latest_event_id": latest_event.get("event_id"),
        "latest_timestamp": latest_event.get("timestamp"),
    }


def _candidate_event_paths(storage_root: Path) -> list[Path]:
    candidates = [
        storage_root / "security_events.jsonl",
        storage_root / "monitor" / "security_events.jsonl",
    ]
    if storage_root.name == "product":
        candidates.append(storage_root.parent / "security_events.jsonl")
    return candidates


def _normalize_security_event(payload: dict[str, Any], *, index: int) -> dict[str, Any]:
    detail = payload.get("detail") if isinstance(payload.get("detail"), dict) else {}
    payload_summary = payload.get("payload_summary")
    if not isinstance(payload_summary, dict):
        payload_summary = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}

    decision = _normalize_decision(payload.get("decision") or detail.get("decision"))
    pending = bool(payload.get("pending") or decision == "ask")
    rule_name = payload.get("rule_name") or detail.get("rule_name") or payload_summary.get("rule_name")

    event = {
        "event_id": str(payload.get("event_id") or f"evt_line_{index}"),
        "timestamp": str(payload.get("timestamp") or ""),
        "session_id": str(payload.get("session_id") or ""),
        "agent_id": str(payload.get("agent_id") or ""),
        "call_type": str(payload.get("call_type") or ""),
        "decision": decision,
        "reason": str(payload.get("reason") or detail.get("blocked_reason") or detail.get("reason") or ""),
        "risk_score": _float_value(payload.get("risk_score", detail.get("risk_score"))),
        "pending": pending,
        "payload_summary": sanitize_secret_fields(payload_summary),
        "status": str(payload.get("status") or _status_for_decision(decision, pending)),
        "source": str(payload.get("source") or "security_events"),
    }
    if rule_name:
        event["rule_name"] = str(rule_name)
    if payload.get("tenant_id"):
        event["tenant_id"] = str(payload["tenant_id"])
    if payload.get("resolved_decision"):
        event["resolved_decision"] = payload["resolved_decision"]
    return event


def _matches_filter(
    event: dict[str, Any],
    *,
    agent_id: str | None,
    decision: str | None,
    session_id: str | None,
) -> bool:
    if agent_id and event.get("agent_id") != agent_id:
        return False
    if decision and event.get("decision") != _normalize_decision(decision):
        return False
    if session_id and event.get("session_id") != session_id:
        return False
    return True


def _normalize_decision(value: Any) -> str:
    decision = str(value or "allow").lower()
    return "deny" if decision in {"block", "blocked"} else decision


def _status_for_decision(decision: str, pending: bool) -> str:
    if pending:
        return "pending"
    if decision == "deny":
        return "blocked"
    return "observed"


def _float_value(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


__all__ = [
    "DEFAULT_MONITOR_EVENT_LIMIT",
    "MAX_MONITOR_EVENT_LIMIT",
    "SecurityEventReader",
    "summarize_security_events",
]
