from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NetworkPolicyType = Literal["disabled", "internal_only", "host", "custom"]


class NetworkPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: NetworkPolicyType = Field(default="disabled")
    custom_network: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)
    deny_internet: bool = Field(default=True)
    description: str = Field(default="")


class NetworkPolicyValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def validate_network_policy(policy: NetworkPolicy) -> NetworkPolicyValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if policy.type == "custom" and not policy.custom_network:
        errors.append("custom network policy requires custom_network to be specified")

    if policy.type == "host":
        warnings.append("using host network may expose sensitive host resources")

    if policy.type == "disabled" and policy.allowed_hosts:
        warnings.append("allowed_hosts is ignored when network is disabled")

    if policy.type not in {"disabled", "internal_only", "host", "custom"}:
        errors.append(f"invalid network policy type: {policy.type}")

    return NetworkPolicyValidationResult(
        valid=not errors,
        errors=errors,
        warnings=warnings,
    )


def get_docker_network_args(policy: NetworkPolicy) -> list[str]:
    if policy.type == "disabled":
        return ["--network=none"]
    if policy.type == "internal_only":
        return ["--network=internal"]
    if policy.type == "host":
        return ["--network=host"]
    if policy.type == "custom" and policy.custom_network:
        return [f"--network={policy.custom_network}"]
    return ["--network=none"]


def default_policy() -> NetworkPolicy:
    return NetworkPolicy(
        type="disabled",
        description="Default: no network access for maximum isolation",
    )


def internal_only_policy() -> NetworkPolicy:
    return NetworkPolicy(
        type="internal_only",
        description="Allow access to internal Docker network only",
    )
