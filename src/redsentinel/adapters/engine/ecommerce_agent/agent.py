from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from redsentinel.adapters.engine.ecommerce_agent.fixtures import create_demo_store
from redsentinel.adapters.engine.ecommerce_agent.models import AuditEvent, RiskLevel, ToolCallRecord, ToolExecution
from redsentinel.adapters.engine.ecommerce_agent.store import EcommerceStore
from redsentinel.adapters.engine.ecommerce_agent import tools
from redsentinel.defenses.engine.security import audit
from redsentinel.defenses.engine.security.firewall.input_guard import check_malicious_input
from redsentinel.defenses.engine.security.goal_guard import GoalGuardInput, evaluate_goal_guard
from redsentinel.defenses.engine.security.output.filter import mask_sensitive_info


@dataclass
class EcommerceAgentResult:
    answer: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    business_events: list[dict[str, Any]] = field(default_factory=list)
    audit_events: list[dict[str, Any]] = field(default_factory=list)
    blocked: bool = False
    risk_level: RiskLevel = "normal"


def invoke_ecommerce_agent(
    user_id: str,
    role: str,
    message: str,
    store: EcommerceStore | None = None,
) -> EcommerceAgentResult:
    active_store = store or create_demo_store()
    blocked, guard_message = check_malicious_input(message)
    if blocked:
        audit.write_audit_log(
            user_id=user_id,
            role=role,
            operation="电商输入拦截",
            input_content=message,
            result=guard_message,
            risk_level="high",
        )
        return EcommerceAgentResult(
            answer=guard_message,
            audit_events=[AuditEvent("电商输入拦截", "high", guard_message).to_dict()],
            blocked=True,
            risk_level="high",
        )

    try:
        execution = _route_message(active_store, user_id, role, message)
    except Exception as exc:
        audit.write_audit_log(
            user_id=user_id,
            role=role,
            operation="电商业务规则拦截",
            input_content=message,
            result=str(exc),
            risk_level="high",
        )
        return EcommerceAgentResult(
            answer=str(exc),
            audit_events=[AuditEvent("电商业务规则拦截", "high", str(exc)).to_dict()],
            blocked=True,
            risk_level="high",
        )
    answer = mask_sensitive_info(execution.answer)
    return EcommerceAgentResult(
        answer=answer,
        tool_calls=[item.to_dict() for item in execution.tool_calls],
        business_events=[item.to_dict() for item in execution.business_events],
        audit_events=[item.to_dict() for item in execution.audit_events],
        blocked=execution.blocked,
        risk_level=execution.risk_level,
    )


def _route_message(store: EcommerceStore, user_id: str, role: str, message: str) -> ToolExecution:
    text = message.lower()
    product_id = _extract_id(message, "p") or "p1001"
    order_id = _extract_id(message, "o")
    coupon_id = _extract_id(message, "c") or "c100"
    quantity = _extract_quantity(message)

    if any(keyword in message for keyword in ["商家改价", "修改价格", "改价"]):
        return tools.merchant_update_price(
            store,
            user_id=user_id,
            role=role,
            product_id=product_id,
            new_price_cents=_extract_money_cents(message) or 49900,
        )

    if any(keyword in message for keyword in ["商家改库存", "修改库存", "改库存", "库存改"]):
        return tools.merchant_update_stock(
            store,
            user_id=user_id,
            role=role,
            product_id=product_id,
            new_stock=quantity,
        )

    if any(keyword in message for keyword in ["退款", "退货"]):
        return tools.request_refund(
            store,
            user_id=user_id,
            role=role,
            order_id=order_id or _latest_user_order_id(store, user_id),
            reason=_extract_reason(message) or "用户申请退款",
        )

    if any(keyword in message for keyword in ["支付", "付款"]):
        target_order_id = order_id or _latest_user_order_id(store, user_id)
        amount = _extract_money_cents(message)
        if amount is None:
            amount = store.get_order(user_id, target_order_id).amount_cents
        return tools.mock_payment(store, user_id=user_id, role=role, order_id=target_order_id, amount_cents=amount)

    if any(keyword in message for keyword in ["下单", "创建订单", "提交订单"]):
        address_id = _extract_address_id(message) or store.get_user(user_id).addresses[0].address_id
        return tools.create_order(store, user_id=user_id, role=role, address_id=address_id)

    if any(keyword in message for keyword in ["优惠券", "用券", "领券"]):
        return tools.apply_coupon(store, user_id=user_id, role=role, coupon_id=coupon_id)

    if any(keyword in message for keyword in ["加购", "加入购物车", "放入购物车"]):
        return tools.cart_add_item(store, user_id=user_id, role=role, product_id=product_id, quantity=quantity)

    if any(keyword in message for keyword in ["改数量", "修改数量", "数量改"]):
        return tools.cart_update_quantity(store, user_id=user_id, role=role, product_id=product_id, quantity=quantity)

    if any(keyword in message for keyword in ["物流", "订单状态", "查询订单"]):
        return tools.get_order_status(
            store,
            user_id=user_id,
            role=role,
            order_id=order_id or _latest_user_order_id(store, user_id),
        )

    if any(keyword in message for keyword in ["客服", "工单", "售后"]):
        return tools.support_create_ticket(
            store,
            user_id=user_id,
            role=role,
            order_id=order_id,
            message=message,
        )

    if any(keyword in message for keyword in ["画像", "我的资料", "用户资料", "个人信息"]):
        target_user_id = _extract_user_id(message) or user_id
        return tools.get_user_profile(store, user_id=user_id, role=role, target_user_id=target_user_id)

    if any(keyword in message for keyword in ["详情", "商品详情"]):
        return tools.get_product_detail(store, user_id=user_id, role=role, product_id=product_id)

    if _looks_like_recommendation_goal_drift(message):
        return _block_recommendation_goal_drift(user_id, role, message)

    if any(keyword in message for keyword in ["搜索", "推荐", "找", "比价", "商品"]) or text.strip():
        return tools.product_search(store, user_id=user_id, role=role, query=message)

    return ToolExecution(
        answer=(
            "我是本地淘宝类电商 Agent，支持搜索、详情、加购、下单、优惠券、"
            "模拟支付、退款、物流、客服、商家改价和库存管理。"
        )
    )


def _extract_id(text: str, prefix: str) -> str | None:
    match = re.search(rf"\b({prefix}\d+)\b", text, flags=re.IGNORECASE)
    return match.group(1).lower() if match else None


def _extract_user_id(text: str) -> str | None:
    match = re.search(r"\b((?:buyer|merchant|admin)_\d+)\b", text, flags=re.IGNORECASE)
    return match.group(1).lower() if match else None


def _extract_address_id(text: str) -> str | None:
    match = re.search(r"\b(addr_[a-z]+_\d+)\b", text, flags=re.IGNORECASE)
    return match.group(1).lower() if match else None


def _extract_quantity(text: str) -> int:
    text_without_ids = re.sub(r"\b[pocrt]\d+\b", " ", text, flags=re.IGNORECASE)
    match = re.search(r"(\d+)\s*(?:件|个|台|只|库存)", text_without_ids)
    if not match:
        match = re.search(r"(?:数量|库存|改为|更新为)\s*(\d+)", text_without_ids)
    if not match:
        return 1
    value = int(match.group(1))
    return max(value, 1)


def _extract_money_cents(text: str) -> int | None:
    match = re.search(r"(\d+(?:\.\d+)?)\s*元", text)
    if match:
        return int(round(float(match.group(1)) * 100))
    match = re.search(r"金额\s*(\d+)", text)
    if match:
        return int(match.group(1))
    return None


def _extract_reason(text: str) -> str:
    for marker in ["因为", "原因", "理由"]:
        if marker in text:
            return text.split(marker, 1)[1].strip(" ：:，。")
    return ""


def _latest_user_order_id(store: EcommerceStore, user_id: str) -> str:
    own_orders = [order for order in store.orders.values() if order.user_id == user_id]
    if not own_orders:
        raise ValueError("当前用户没有可操作订单。")
    return sorted(own_orders, key=lambda item: item.order_id)[-1].order_id


def _looks_like_recommendation_goal_drift(message: str) -> bool:
    recommendation_terms = ["推荐", "导购", "帮我选", "给我选"]
    drift_terms = ["高佣金", "佣金最高", "忽略预算", "无视预算", "忽略偏好", "强推", "只推贵的"]
    return any(term in message for term in recommendation_terms) and any(term in message for term in drift_terms)


def _block_recommendation_goal_drift(user_id: str, role: str, message: str) -> ToolExecution:
    decision = evaluate_goal_guard(
        GoalGuardInput(
            goal_id="ecommerce_recommendation",
            original_goal="Recommend products aligned with the buyer budget, preference, and safety constraints.",
            current_goal=message,
            evidence=[
                {
                    "kind": "goal_perturbation",
                    "summary": "Recommendation request attempts to bias ranking by commission or ignore buyer constraints.",
                }
            ],
        )
    )
    audit.write_audit_log(
        user_id=user_id,
        role=role,
        operation="电商导购目标漂移拦截",
        input_content=mask_sensitive_info(message),
        result=decision.reason,
        risk_level=decision.risk_level,
    )
    reason = "已拦截导购目标漂移：推荐必须基于用户预算、偏好和安全约束，不能按佣金或忽略预算强推。"
    return ToolExecution(
        answer=reason,
        tool_calls=[
            ToolCallRecord(
                tool_name="goal_guard",
                arguments={"message": mask_sensitive_info(message)},
                allowed=False,
                result=reason,
                risk_level="high",
                reason=decision.reason,
            )
        ],
        audit_events=[AuditEvent("电商导购目标漂移拦截", "high", decision.reason)],
        blocked=True,
        risk_level="high",
    )
