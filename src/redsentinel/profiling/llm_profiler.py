from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from redsentinel.core import AgentProfile
from redsentinel.profiling.code_profiler import CandidateProfileDiff, CodeProfileCandidate
from redsentinel.profiling.evidence_validator import EvidenceValidationError, validate_evidence_refs_against_ast
from redsentinel.profiling.llm_client import LLMClient
from redsentinel.profiling.profile_merge import merge_patch_into_profile
from redsentinel.profiling.profile_patch import CandidateProfilePatch
from redsentinel.profiling.prompts import build_llm_messages


def enhance_profile_with_llm(
    ast_candidate: CodeProfileCandidate,
    *,
    root_path: str | Path,
    base_profile: AgentProfile,
    materials: dict[str, Any] | None = None,
    llm_client: Any = None,
) -> CodeProfileCandidate:
    warnings = list(ast_candidate.notes)
    try:
        client = llm_client or LLMClient()
        raw_patch = client.complete_json(
            build_llm_messages(
                ast_summary=ast_candidate.ast_summary,
                base_profile=base_profile.model_dump(mode="json"),
                materials=materials or {},
            )
        )
        patch = CandidateProfilePatch.model_validate(raw_patch)
        validate_evidence_refs_against_ast(patch, ast_candidate.ast_summary)
        merged_profile, llm_diff = merge_patch_into_profile(ast_candidate.candidate_profile, patch)
        merged_diff = CandidateProfileDiff(
            added_nodes=[*ast_candidate.diff.added_nodes, *llm_diff.added_nodes],
            added_tools=[*ast_candidate.diff.added_tools, *llm_diff.added_tools],
            changed_rag_enabled=ast_candidate.diff.changed_rag_enabled or llm_diff.changed_rag_enabled,
            evidence_refs=[*ast_candidate.diff.evidence_refs, *llm_diff.evidence_refs],
        )
        return ast_candidate.model_copy(
            update={
                "candidate_profile": merged_profile,
                "diff": merged_diff,
                "source": "ast_plus_llm",
                "llm_used": True,
                "llm_model": getattr(client, "model", None),
                "failed_safe": False,
                "notes": [*warnings, *patch.warnings],
            }
        )
    except (ValidationError, EvidenceValidationError, ValueError, KeyError) as exc:
        return ast_candidate.model_copy(
            update={
                "source": "ast_baseline_fallback",
                "llm_used": False,
                "llm_model": None,
                "failed_safe": True,
                "notes": [*warnings, f"LLM profiling failed; fallback to AST baseline: {type(exc).__name__}: {exc}"],
            }
        )
