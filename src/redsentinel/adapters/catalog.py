"""Single source of truth for the API-level Agent ``adapter_type`` domain.

This is a pure-data catalog (no imports of contracts or adapter classes) so it can
be imported anywhere—including Pydantic contracts for validation—without cycles.

Note: this is a different axis from ``adapters/registry.py``, which registers
runtime *sandbox backends* (direct_api/langgraph/docker/http/sdk). This catalog
describes how an Agent is *onboarded and audited* (ecommerce_demo/external_sdk/
http_endpoint/openmanus) and centralizes the capability flags that were previously
scattered across service/app/preflight/asset_index as ``adapter_type == "..."``
branches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class AdapterDescriptor:
    adapter_type: str
    allow_source_ingest: bool = False
    requires_audit_infrastructure: bool = False
    requires_hosted_model: bool = False
    supports_openmanus_real: bool = False
    uses_builtin_adapter: bool = False
    builtin_adapter_kind: str | None = None
    auto_onboard_demo_source: bool = False
    audit_benchmark_id: str | None = None
    audit_runtime_mode: str | None = None
    framework_ids: tuple[str, ...] = field(default_factory=tuple)


_DESCRIPTORS: dict[str, AdapterDescriptor] = {
    descriptor.adapter_type: descriptor
    for descriptor in (
        AdapterDescriptor(
            adapter_type="ecommerce_demo",
            allow_source_ingest=True,
            uses_builtin_adapter=True,
            builtin_adapter_kind="ecommerce",
            auto_onboard_demo_source=True,
            audit_benchmark_id="ecommerce-security-v0.1",
            audit_runtime_mode="sdk",
        ),
        AdapterDescriptor(
            adapter_type="external_sdk",
            allow_source_ingest=True,
        ),
        AdapterDescriptor(
            adapter_type="http_endpoint",
        ),
        AdapterDescriptor(
            adapter_type="openmanus",
            allow_source_ingest=True,
            requires_audit_infrastructure=True,
            requires_hosted_model=True,
            supports_openmanus_real=True,
            uses_builtin_adapter=True,
            builtin_adapter_kind="openmanus",
            audit_benchmark_id="openmanus-security-v0.1",
            audit_runtime_mode="openmanus_real",
            framework_ids=("openmanus",),
        ),
    )
}

_FALLBACK_ADAPTER_TYPE = "external_sdk"


def adapter_types() -> tuple[str, ...]:
    """All registered ``adapter_type`` values."""
    return tuple(_DESCRIPTORS)


def is_registered(adapter_type: str) -> bool:
    return adapter_type in _DESCRIPTORS


def default_adapter_type() -> str:
    """Fallback adapter_type when framework identification is inconclusive."""
    return _FALLBACK_ADAPTER_TYPE


def descriptor(adapter_type: str) -> AdapterDescriptor:
    try:
        return _DESCRIPTORS[adapter_type]
    except KeyError as exc:
        raise ValueError(f"Unregistered adapter_type: {adapter_type!r}") from exc


def source_ingest_types() -> frozenset[str]:
    """adapter_type values accepted by the source sandbox build manifest."""
    return frozenset(name for name, d in _DESCRIPTORS.items() if d.allow_source_ingest)


def framework_to_adapter_type(framework_names: Iterable[str]) -> str | None:
    """Map identified framework names to a registered adapter_type, else None.

    A descriptor matches when any of its ``framework_ids`` appears (case-insensitive
    substring) in any identified framework name. Returns ``None`` when no descriptor
    claims the frameworks, so callers can apply an explicit, observable fallback.
    """
    folded = [name.casefold() for name in framework_names]
    for name, d in _DESCRIPTORS.items():
        for framework_id in d.framework_ids:
            token = framework_id.casefold()
            if any(token in candidate for candidate in folded):
                return name
    return None


__all__ = [
    "AdapterDescriptor",
    "adapter_types",
    "default_adapter_type",
    "descriptor",
    "framework_to_adapter_type",
    "is_registered",
    "source_ingest_types",
]
