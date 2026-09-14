"""Deterministic attack candidate selection helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TypeVar


CandidateT = TypeVar("CandidateT")


def select_unique(
    candidates: Iterable[CandidateT],
    *,
    key: Callable[[CandidateT], str],
    limit: int | None = None,
) -> list[CandidateT]:
    """Keep first-seen candidates by stable key, optionally bounded by a budget."""
    if limit is not None and limit < 0:
        raise ValueError("limit must be non-negative")
    if limit == 0:
        return []
    selected: list[CandidateT] = []
    seen: set[str] = set()
    for candidate in candidates:
        candidate_key = key(candidate)
        if candidate_key in seen:
            continue
        seen.add(candidate_key)
        selected.append(candidate)
        if limit is not None and len(selected) >= limit:
            break
    return selected


__all__ = ["select_unique"]
