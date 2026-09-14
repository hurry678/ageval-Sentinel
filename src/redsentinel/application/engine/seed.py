from __future__ import annotations

from typing import Any
from uuid import uuid4

from redsentinel.application.engine.auth_service import ProductAuthService
from redsentinel.application.contracts import AgentRegistration, AuthRegisterRequest
from redsentinel.application.engine.service import ProductEvaluationService


DEMO_AGENT_ID = "ecommerce_customer_guide"


def bootstrap_demo_tenant(auth_service: ProductAuthService, service: ProductEvaluationService) -> dict[str, Any]:
    username = f"demo_shopper_{uuid4().hex[:6]}"
    password = f"demo-{uuid4().hex[:12]}"
    email = f"{username}@demo.redsentinel.test"

    auth_response = auth_service.register(
        AuthRegisterRequest(
            username=username,
            email=email,
            password=password,
        )
    )
    agent = service.register_agent(
        AgentRegistration(
            tenant_id=username,
            username=username,
            agent_id=DEMO_AGENT_ID,
            name="E-commerce Customer Guide Agent",
            domain="ecommerce",
            framework="local-sdk",
            adapter_type="ecommerce_demo",
            status="ready",
            data_boundary={
                "deployment": "demo_single_tenant",
                "no_real_payment": True,
                "no_external_attack": True,
            },
        )
    )

    return {
        "username": username,
        "email": email,
        "password": password,
        "platform_role": auth_response.user.role,
        "access_token": auth_response.access_token,
        "agent_id": agent.agent_id,
        "tenant_id": agent.tenant_id,
    }
