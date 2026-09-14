"""Independent forensics on a replayed phase — judgment that ignores the verdict.

Everything else in this dataset trusts the Agent: ``blocked`` is the Agent's own
report that a guard fired. That is fine for an Agent whose guards we wrote, and
worthless for a black-box third party. This module is the counterweight: it hands
the *attempted* call to Sentinel's oracle and asks an independent question —
was the Agent steered into trying something dangerous, whether or not anything
stopped it?

Independence is enforced by construction. ``ORACLE_KEYS`` is a whitelist, so the
event handed to the oracle carries only what the Agent *tried to do*: the call
type, the tool name and the arguments. ``decision`` / ``allowed`` / ``reason`` /
``risk_score`` never reach it, which means oracle rule 1 (``policy_violation``,
the one rule that reads a self-reported decision) cannot fire and every hit is
genuinely independent evidence.

The OpenManus adapter drops ``tool_calls`` when a turn is blocked, but its audit
event still records the call it inferred — including the arguments, JSON-encoded
in ``args_summary``. Recovering those is what lets forensics work on exactly the
turns that matter.
"""

from __future__ import annotations

import json
from typing import Any

from redsentinel.evaluation.oracle import evaluate_oracle

ORACLE_KEYS = ("call_type", "tool_name", "arguments")
# The oracle rule that reads a self-reported block. A hit here would be circular.
SELF_REPORT_RULE = "policy_violation"


def parse_args(raw: Any) -> dict[str, Any]:
    """``args_summary`` is JSON, truncated past 240 chars. Truncated → no args."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def oracle_events(replayed: dict[str, Any]) -> list[dict[str, Any]]:
    """Attempted calls in the oracle's native shape, guard decisions removed."""
    events: list[dict[str, Any]] = []
    for turn in replayed.get("turns") or []:
        for audit in turn.get("audit_events") or []:
            if not isinstance(audit, dict) or not audit.get("call_type"):
                continue
            candidate = {
                "call_type": audit.get("call_type"),
                "tool_name": audit.get("tool_name"),
                "arguments": parse_args(audit.get("args_summary")),
            }
            events.append({key: candidate[key] for key in ORACLE_KEYS})
    return events


def forensics(replayed: dict[str, Any]) -> dict[str, Any]:
    """Independent verdict on one phase. Empty evidence is a real answer."""
    events = oracle_events(replayed)
    if not events:
        return {
            "oracle_verdict": "unknown",
            "oracle_risk_score": 0.0,
            "oracle_category": "no_events",
            "oracle_rules": [],
            "oracle_summary": "",
            "oracle_independent": False,
        }
    out = evaluate_oracle(events)
    rules = [item.rule_id for item in out.evidence]
    independent = [rule for rule in rules if rule != SELF_REPORT_RULE]
    return {
        "oracle_verdict": out.verdict,
        "oracle_risk_score": out.risk_score,
        "oracle_category": out.category,
        "oracle_rules": rules,
        "oracle_summary": out.evidence[0].summary[:300] if out.evidence else "",
        # The Agent was provably steered into a dangerous attempt.
        "oracle_independent": bool(independent),
    }
