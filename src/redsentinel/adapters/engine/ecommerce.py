from __future__ import annotations

from typing import Any

from redsentinel.adapters.engine.adapter import AgentAdapter
from redsentinel.adapters.engine.models import AgentTurnResult, ToolSpec
from redsentinel.adapters.engine.telemetry import TraceRecorder
from redsentinel.adapters.engine.ecommerce_agent import create_demo_store, invoke_ecommerce_agent
from redsentinel.defenses.engine.security.output.filter import mask_sensitive_info


class EcommerceEnterpriseAdapter(AgentAdapter):
    def __init__(self, session_id: str = "ecommerce-demo") -> None:
        self.store = create_demo_store()
        self.recorder = TraceRecorder(session_id=session_id)

    def send_message(self, user_id: str, message: str, context: dict[str, Any]) -> AgentTurnResult:
        role = str(context.get("role") or "buyer")
        result = invoke_ecommerce_agent(user_id, role, message, self.store)
        turn = AgentTurnResult(
            user_id=user_id,
            message=mask_sensitive_info(message),
            answer=result.answer,
            blocked=result.blocked,
            risk_level=result.risk_level,
            tool_calls=result.tool_calls,
            business_events=result.business_events,
            audit_events=result.audit_events,
        )
        self.recorder.record_turn(turn)
        return turn

    def list_tools(self) -> list[ToolSpec]:
        return [
            ToolSpec("product_search", "low", "Search public products."),
            ToolSpec("get_product_detail", "low", "Read product detail."),
            ToolSpec("cart_add_item", "medium", "Add item to cart."),
            ToolSpec("cart_update_quantity", "medium", "Update cart quantity."),
            ToolSpec("create_order", "high", "Create a mock order."),
            ToolSpec("apply_coupon", "high", "Apply a scoped coupon."),
            ToolSpec("mock_payment", "critical", "Mark an order as paid in mock mode."),
            ToolSpec("request_refund", "high", "Request a mock refund."),
            ToolSpec("support_create_ticket", "medium", "Create support ticket."),
            ToolSpec("merchant_update_price", "critical", "Update merchant product price."),
            ToolSpec("merchant_update_stock", "high", "Update merchant product stock."),
        ]

    def export_trajectory(self) -> dict[str, Any]:
        return self.recorder.export()

    def reset_session(self, session_id: str) -> None:
        self.store = create_demo_store()
        self.recorder.reset(session_id)
