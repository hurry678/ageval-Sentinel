from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from redsentinel.core import (
    AgentProfile,
    AgentProfileNode,
    AgentProfileTool,
)
from redsentinel.profiling.builder import RISK_SURFACES_BY_NODE_TYPE

NodeTypeName = Literal["input_node", "rag_retriever", "tool_node", "memory_node", "llm_node", "output_node"]

_NODE_KEYWORDS: list[tuple[NodeTypeName, tuple[str, ...]]] = [
    ("input_node", ("input", "normalize", "parse_request")),
    ("rag_retriever", ("retrieve", "retriever", "search_docs", "rag")),
    ("tool_node", ("tool", "execute", "call_api", "action")),
    ("memory_node", ("memory", "remember", "recall", "store")),
    ("output_node", ("output", "format", "render", "respond")),
    ("llm_node", ("agent", "llm", "chat", "invoke", "run")),
]

_HIGH_RISK_TOOL_KEYWORDS = ("delete", "payment", "refund", "update", "create", "write", "send")
_EXCLUDE_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}


class CandidateProfileDiff(BaseModel):
    model_config = ConfigDict(extra="forbid")

    added_nodes: list[str] = Field(default_factory=list)
    added_tools: list[str] = Field(default_factory=list)
    changed_rag_enabled: bool = False
    evidence_refs: list[dict[str, object]] = Field(default_factory=list)


class CodeProfileCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_profile: AgentProfile
    diff: CandidateProfileDiff
    confidence: float
    notes: list[str] = Field(default_factory=list)
    source: Literal["ast_baseline", "ast_plus_llm", "ast_baseline_fallback"] = "ast_baseline"
    ast_summary: dict[str, Any] = Field(default_factory=dict)
    llm_used: bool = False
    llm_model: str | None = None
    failed_safe: bool = False


class _FunctionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: str
    name: str
    node_type: NodeTypeName
    path: str
    line_start: int
    line_end: int
    reason: str

    @property
    def target(self) -> str:
        return f"{self.module}:{self.name}"


def analyze_source_profile(
    root_path: str | Path,
    base_profile: AgentProfile | None = None,
    *,
    materials: dict[str, Any] | None = None,
    llm_client: Any = None,
    enable_llm: bool = False,
) -> CodeProfileCandidate:
    root = Path(root_path).resolve()
    active_base_profile = base_profile or _default_base_profile(root)
    functions = _collect_functions(root)
    existing_targets = {node.target for node in active_base_profile.nodes}
    existing_tool_names = {tool.name for tool in active_base_profile.tools}

    added_nodes: list[AgentProfileNode] = []
    added_tools: list[AgentProfileTool] = []
    evidence_refs: list[dict[str, object]] = []
    for item in functions:
        evidence_refs.append(
            {
                "file": item.path,
                "line_start": item.line_start,
                "line_end": item.line_end,
                "reason": item.reason,
            }
        )
        if item.target not in existing_targets:
            added_nodes.append(
                AgentProfileNode(
                    id=_node_id(item),
                    type=item.node_type,
                    target=item.target,
                    risk_surfaces=list(RISK_SURFACES_BY_NODE_TYPE[item.node_type]),
                )
            )
        if item.node_type == "tool_node" and item.name not in existing_tool_names:
            added_tools.append(
                AgentProfileTool(
                    name=item.name,
                    risk_level=_tool_risk(item.name),
                    side_effect=_tool_risk(item.name) in {"high", "critical"},
                )
            )

    candidate = active_base_profile.model_copy(
        update={
            "nodes": [*active_base_profile.nodes, *added_nodes],
            "tools": [*active_base_profile.tools, *added_tools],
            "rag_enabled": active_base_profile.rag_enabled or any(item.node_type == "rag_retriever" for item in functions),
        }
    )
    diff = CandidateProfileDiff(
        added_nodes=[node.id for node in added_nodes],
        added_tools=[tool.name for tool in added_tools],
        changed_rag_enabled=candidate.rag_enabled != active_base_profile.rag_enabled,
        evidence_refs=_dedupe_evidence(evidence_refs),
    )
    ast_candidate = CodeProfileCandidate(
        candidate_profile=candidate,
        diff=diff,
        confidence=_confidence(functions),
        notes=_notes(root, functions, diff),
        ast_summary=_ast_summary(root, functions, materials or {}),
    )
    if not enable_llm:
        return ast_candidate

    from redsentinel.profiling.llm_profiler import enhance_profile_with_llm

    return enhance_profile_with_llm(
        ast_candidate,
        root_path=root,
        base_profile=active_base_profile,
        materials=materials or {},
        llm_client=llm_client,
    )


def _default_base_profile(root: Path) -> AgentProfile:
    return AgentProfile(
        agent_name=root.name or "external_agent",
        framework="python_function",
        root_path=str(root),
        entrypoint="redsentinel_adapter:invoke",
        business_domain="unknown",
        nodes=[
            AgentProfileNode(
                id="input",
                type="input_node",
                target="redsentinel_adapter:invoke",
                risk_surfaces=list(RISK_SURFACES_BY_NODE_TYPE["input_node"]),
            )
        ],
    )


def _collect_functions(root: Path) -> list[_FunctionEvidence]:
    if not root.exists():
        return []
    files = [root] if root.is_file() else sorted(root.rglob("*.py"))
    items: list[_FunctionEvidence] = []
    for path in files:
        if _skip_path(path):
            continue
        module = _module_name(root, path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node_type = _classify_function(node.name)
                if node_type:
                    reason = _classification_reason(node.name, node_type)
                    items.append(
                        _FunctionEvidence(
                            module=module,
                            name=node.name,
                            node_type=node_type,
                            path=str(path),
                            line_start=node.lineno,
                            line_end=getattr(node, "end_lineno", node.lineno),
                            reason=reason,
                        )
                    )
    return items


def _skip_path(path: Path) -> bool:
    return any(part in _EXCLUDE_DIRS for part in path.parts)


def _classify_function(name: str) -> NodeTypeName | None:
    lowered = name.lower()
    for node_type, keywords in _NODE_KEYWORDS:
        if any(keyword in lowered for keyword in keywords):
            return node_type
    return None


def _classification_reason(name: str, node_type: NodeTypeName) -> str:
    lowered = name.lower()
    keywords = dict(_NODE_KEYWORDS)[node_type]
    matched = next((keyword for keyword in keywords if keyword in lowered), keywords[0])
    return f"function name {name} matched {node_type} heuristic keyword {matched}"


def _module_name(root: Path, path: Path) -> str:
    if root.is_file():
        return path.stem
    relative = path.relative_to(root).with_suffix("")
    return ".".join(relative.parts)


def _node_id(item: _FunctionEvidence) -> str:
    return item.name.lower().replace("__", "_")


def _tool_risk(name: str) -> str:
    lowered = name.lower()
    if "delete" in lowered or "payment" in lowered:
        return "critical"
    if any(keyword in lowered for keyword in _HIGH_RISK_TOOL_KEYWORDS):
        return "high"
    return "medium"


def _confidence(functions: list[_FunctionEvidence]) -> float:
    if not functions:
        return 0.0
    node_types = {item.node_type for item in functions}
    return round(min(0.95, 0.35 + 0.1 * len(node_types)), 4)


def _notes(root: Path, functions: list[_FunctionEvidence], diff: CandidateProfileDiff) -> list[str]:
    notes = [f"Scanned Python source under {root}."]
    if not functions:
        notes.append("No recognizable agent node functions were found.")
    if diff.added_nodes:
        notes.append("Candidate nodes were inferred from function names and should be reviewed.")
    return notes


def _ast_summary(root: Path, functions: list[_FunctionEvidence], materials: dict[str, Any]) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for item in functions:
        entry = files.setdefault(item.path, {"file": item.path, "functions": []})
        entry["functions"].append(
            {
                "name": item.name,
                "target": item.target,
                "inferred_node_type": item.node_type,
                "line_start": item.line_start,
                "line_end": item.line_end,
                "reason": item.reason,
            }
        )
    return {
        "root_path": str(root),
        "files": list(files.values()),
        "materials": materials,
        "heuristic_findings": [
            {
                "id": _node_id(item),
                "type": item.node_type,
                "target": item.target,
                "evidence": {
                    "file": item.path,
                    "line_start": item.line_start,
                    "line_end": item.line_end,
                    "reason": item.reason,
                },
            }
            for item in functions
        ],
    }


def _dedupe_evidence(items: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[object, object, object, object]] = set()
    output: list[dict[str, object]] = []
    for item in items:
        key = (item.get("file"), item.get("line_start"), item.get("line_end"), item.get("reason"))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output
