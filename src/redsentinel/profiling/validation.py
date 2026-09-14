from __future__ import annotations

import importlib
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Iterator

from redsentinel.profiling.manifest import AgentConfig, NodeConfig

DEFENSE_COMPATIBILITY: dict[str, set[str]] = {
    "input_node": {"input_guard"},
    "rag_retriever": {"rag_doc_scanner", "retrieval_guard"},
    "tool_node": {"tool_guard", "permission_guard"},
    "memory_node": {"memory_guard"},
    "llm_node": {"goal_guard"},
    "output_node": {"output_filter"},
}


class ConfigValidationError(ValueError):
    """Raised when an onboarding config is syntactically valid but unusable."""


def validate_agent_config(config: AgentConfig, *, config_path: str | Path | None = None) -> None:
    errors: list[str] = []
    config_dir = Path(config_path).resolve().parent if config_path is not None else Path.cwd()
    root_path = _resolve_path(config.agent.root_path, config_dir)

    if not root_path.exists():
        errors.append(f"agent.root_path does not exist: {root_path}")
    if not _is_target(config.agent.entrypoint):
        errors.append("agent.entrypoint must use module:callable format")

    seen_node_ids: set[str] = set()
    for node in config.nodes:
        if node.id in seen_node_ids:
            errors.append(f"duplicate node id: {node.id}")
        seen_node_ids.add(node.id)
        _validate_node(node, errors)

    if config.rag.enabled and not config.rag.document_paths and not config.rag.retriever_target:
        errors.append("rag.enabled requires rag.document_paths or rag.retriever_target")

    if config.rag.retriever_target and not _is_target(config.rag.retriever_target):
        errors.append("rag.retriever_target must use module:callable format")

    for document_path in config.rag.document_paths:
        resolved_document_path = _resolve_path(document_path, config_dir)
        if not resolved_document_path.exists():
            errors.append(f"rag.document_paths entry does not exist: {resolved_document_path}")

    if root_path.exists():
        _validate_import_target(config.agent.entrypoint, root_path, "agent.entrypoint", errors)
        for node in config.nodes:
            _validate_import_target(node.target, root_path, f"nodes[{node.id}].target", errors)
        if config.rag.retriever_target:
            _validate_import_target(config.rag.retriever_target, root_path, "rag.retriever_target", errors)

    if errors:
        raise ConfigValidationError("; ".join(errors))


def _validate_node(node: NodeConfig, errors: list[str]) -> None:
    if not _is_target(node.target):
        errors.append(f"nodes[{node.id}].target must use module:callable format")

    allowed_defenses = DEFENSE_COMPATIBILITY[node.type]
    for defense in node.defenses:
        if defense not in allowed_defenses:
            errors.append(f"defense {defense!r} is not compatible with node {node.id!r} of type {node.type!r}")


def _resolve_path(path: str, base_dir: Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return (base_dir / candidate).resolve()


def _is_target(value: str) -> bool:
    module_name, separator, callable_name = value.partition(":")
    return bool(module_name and separator and callable_name)


def _validate_import_target(target: str, root_path: Path, label: str, errors: list[str]) -> None:
    module_name, _, callable_name = target.partition(":")
    try:
        with _python_path(root_path):
            module = importlib.import_module(module_name)
        if not hasattr(module, callable_name):
            errors.append(f"{label} callable not found: {target}")
    except Exception as exc:
        errors.append(f"{label} cannot be imported: {target} ({exc})")


@contextmanager
def _python_path(path: Path) -> Iterator[None]:
    path_text = str(path)
    inserted = False
    if path_text not in sys.path:
        sys.path.insert(0, path_text)
        inserted = True
    try:
        yield
    finally:
        if inserted:
            sys.path.remove(path_text)
        _drop_imported_app_modules(path)


def _drop_imported_app_modules(path: Path) -> None:
    path_text = str(path)
    for name, module in list(sys.modules.items()):
        if isinstance(module, ModuleType) and getattr(module, "__file__", None):
            try:
                module_path = str(Path(module.__file__).resolve())
            except OSError:
                continue
            if module_path.startswith(path_text):
                sys.modules.pop(name, None)
