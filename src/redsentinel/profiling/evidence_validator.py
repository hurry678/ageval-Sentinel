from __future__ import annotations

from pathlib import Path
from typing import Iterable

from redsentinel.profiling.profile_patch import CandidateProfilePatch, EvidenceRef


class EvidenceValidationError(ValueError):
    """Raised when an LLM patch cites files or lines outside the AST summary."""


def validate_evidence_refs_against_ast(patch: CandidateProfilePatch, ast_summary: dict) -> None:
    known_files = _known_files(ast_summary)
    ranges = _known_ranges(ast_summary)
    for evidence in _iter_evidence(patch):
        if not _matches_known_file(evidence.file, known_files):
            raise EvidenceValidationError(f"evidence file not found in AST summary: {evidence.file}")
        if not _matches_known_range(evidence, ranges):
            raise EvidenceValidationError(
                f"evidence line range not found in AST summary: {evidence.file}:{evidence.line_start}-{evidence.line_end}"
            )


def _known_files(ast_summary: dict) -> set[str]:
    known: set[str] = set()
    for item in ast_summary.get("files", []):
        file_value = str(item.get("file") or "")
        if not file_value:
            continue
        known.add(file_value)
        known.add(Path(file_value).name)
    return known


def _matches_known_file(file_value: str, known: set[str]) -> bool:
    if file_value in known or Path(file_value).name in known:
        return True
    return any(str(item).endswith(file_value) for item in known)


def _known_ranges(ast_summary: dict) -> dict[str, list[tuple[int, int]]]:
    ranges: dict[str, list[tuple[int, int]]] = {}
    for item in ast_summary.get("files", []):
        file_value = str(item.get("file") or "")
        if not file_value:
            continue
        file_keys = {file_value, Path(file_value).name}
        file_ranges = [
            (int(function.get("line_start", 1)), int(function.get("line_end", function.get("line_start", 1))))
            for function in item.get("functions", [])
        ]
        for key in file_keys:
            ranges.setdefault(key, []).extend(file_ranges)
    return ranges


def _matches_known_range(evidence: EvidenceRef, ranges: dict[str, list[tuple[int, int]]]) -> bool:
    keys = [evidence.file, Path(evidence.file).name]
    for key, file_ranges in ranges.items():
        if key not in keys and not key.endswith(evidence.file):
            continue
        if any(start <= evidence.line_start and evidence.line_end <= end for start, end in file_ranges):
            return True
    return False


def _iter_evidence(patch: CandidateProfilePatch) -> Iterable[EvidenceRef]:
    for node in patch.nodes:
        yield from node.evidence
    for tool in patch.tools:
        yield from tool.evidence
    if patch.rag is not None:
        yield from patch.rag.evidence
    if patch.memory is not None:
        yield from patch.memory.evidence
