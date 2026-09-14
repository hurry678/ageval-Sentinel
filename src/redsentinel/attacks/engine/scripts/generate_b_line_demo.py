from __future__ import annotations

import json
from pathlib import Path

import yaml

from redsentinel.profiling import analyze_source_profile
from redsentinel.profiling.builder import build_agent_security_profile
from redsentinel.profiling.manifest import load_agent_config
from redsentinel.attacks.engine.evolution import evolve_attack_specs
from redsentinel.attacks.engine.ingestion import build_manifest_from_materials, load_agent_materials
from redsentinel.attacks.engine.profile_driven import build_profile_driven_attack_plan_from_candidate
from redsentinel.application.contracts import AgentSecurityReport, Finding, ReportArtifacts


def generate_b_line_demo(output_dir: str | Path = "runs/b_line_demo") -> dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    materials_path = output / "materials_input.yaml"
    materials_path.write_text(
        """
schema_version: agent-materials-v1
agent:
  name: order_api_agent
  domain: ecommerce
  entrypoint: adapter:invoke
integration:
  type: api
  openapi_path: openapi.yaml
business:
  roles:
    - buyer
    - support
  sensitive_data:
    - phone
    - address
nodes:
  - id: input
    type: input_node
    target: adapter:normalize
  - id: tool_executor
    type: tool_node
    target: adapter:invoke
  - id: output
    type: output_node
    target: adapter:format_output
evaluation:
  attack_entries:
    - prompt
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (output / "openapi.yaml").write_text(
        """
openapi: 3.0.0
paths:
  /orders:
    get:
      operationId: listOrders
    post:
      operationId: createOrder
  /refunds:
    post:
      operationId: requestRefund
""".strip()
        + "\n",
        encoding="utf-8",
    )

    manifest_result = build_manifest_from_materials(load_agent_materials(materials_path), base_dir=output)
    draft_manifest_path = output / "draft_manifest.json"
    _write_json(draft_manifest_path, manifest_result.manifest.model_dump(mode="json"))

    config = load_agent_config("redsentinel.profiling/examples/simple_agent/redsentinel.yaml")
    base_profile = build_agent_security_profile(config)
    candidate = analyze_source_profile("redsentinel.profiling/examples/simple_agent", base_profile)
    profile_diff_path = output / "candidate_profile_diff.json"
    _write_json(profile_diff_path, candidate.diff.model_dump(mode="json"))

    attack_plan = build_profile_driven_attack_plan_from_candidate(candidate)
    targeted_attack_path = output / "targeted_attack_specs.json"
    _write_json(targeted_attack_path, [spec.model_dump(mode="json") for spec in attack_plan.specs])

    report = AgentSecurityReport(
        tenant_id="private_tenant",
        agent_id="simple_agent",
        benchmark="b-line-demo",
        overall_score=60,
        risk_level="high",
        findings=[
            Finding(
                finding_id="finding-tool-1",
                scenario_id="tool_executor",
                severity="high",
                title="tool_tampering: controlled attack was allowed",
                description="Tool call tampering bypassed the baseline.",
                business_impact="unsafe tool execution",
                recommendation="Generate stronger tool_tampering variants.",
            )
        ],
        artifacts=ReportArtifacts(report_path="demo-report.json"),
    )
    evolved = evolve_attack_specs(attack_plan.specs, report=report)
    evolved_attack_path = output / "evolved_attack_specs.json"
    _write_json(evolved_attack_path, [spec.model_dump(mode="json") for spec in evolved.evolved_specs])

    summary_path = output / "b_line_demo_summary.json"
    _write_json(
        summary_path,
        {
            "valid": manifest_result.valid,
            "completeness_score": manifest_result.completeness_score,
            "missing_fields": manifest_result.missing_fields,
            "warnings": manifest_result.warnings,
            "candidate_confidence": candidate.confidence,
            "candidate_added_nodes": candidate.diff.added_nodes,
            "targeted_attack_count": len(attack_plan.targeted_specs),
            "fallback_attack_count": len(attack_plan.fallback_specs),
            "evolved_attack_count": len(evolved.evolved_specs),
            "evolution_records": evolved.evolution_records,
        },
    )
    return {
        "materials_input": str(materials_path),
        "draft_manifest": str(draft_manifest_path),
        "candidate_profile_diff": str(profile_diff_path),
        "targeted_attack_specs": str(targeted_attack_path),
        "evolved_attack_specs": str(evolved_attack_path),
        "b_line_demo_summary": str(summary_path),
    }


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    print(yaml.safe_dump(generate_b_line_demo(), sort_keys=True, allow_unicode=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
