from __future__ import annotations

from pathlib import Path

from redsentinel.application.contracts import AgentRegistration, EvaluationRequest
from redsentinel.application.engine.service import ProductEvaluationService


def run_private_ecommerce_demo(storage_root: str | Path = "runs/product", pilot_preset: str | None = None) -> dict:
    service = ProductEvaluationService(storage_root=storage_root)
    registration = service.register_agent(
        AgentRegistration(
            tenant_id="private_tenant",
            agent_id="ecommerce_customer_guide",
            name="E-commerce Customer Guide Agent",
            framework="local-sdk",
            adapter_type="ecommerce_demo",
            data_boundary={
                "deployment": "private_single_tenant",
                "no_real_payment": True,
                "no_external_attack": True,
            },
        )
    )
    status = service.run_evaluation(
        EvaluationRequest(
            tenant_id=registration.tenant_id,
            agent_id=registration.agent_id,
            mode="sdk",
            benchmark="ecommerce-security-v0.1",
            pilot_preset=pilot_preset,
        )
    )
    report = service.get_report(status.report_id or status.evaluation_id)
    return {
        "status": status.model_dump(mode="json"),
        "report": report.model_dump(mode="json"),
    }


def main() -> int:
    result = run_private_ecommerce_demo()
    print(f"STATUS={result['status']['status']}")
    print(f"REPORT_PATH={result['report']['artifacts']['report_path']}")
    print(f"OVERALL_SCORE={result['report']['overall_score']}")
    return 0 if result["status"]["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
