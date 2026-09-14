from __future__ import annotations

from dataclasses import dataclass

from redsentinel.adapters.engine.ecommerce_agent.models import RiskLevel
from redsentinel.adapters.engine.ecommerce_agent.store import EcommerceStore


HIGH_RISK_TOOLS = {
    "create_order",
    "apply_coupon",
    "mock_payment",
    "request_refund",
    "merchant_update_price",
    "merchant_update_stock",
}

KNOWN_TOOLS = HIGH_RISK_TOOLS | {
    "product_search",
    "get_product_detail",
    "get_user_profile",
    "cart_add_item",
    "cart_update_quantity",
    "get_order_status",
    "support_create_ticket",
}


@dataclass(frozen=True)
class EcommercePolicyDecision:
    allowed: bool
    reason: str
    risk_level: RiskLevel
    rule_name: str


def check_ecommerce_policy(
    tool_name: str,
    *,
    user_id: str,
    role: str,
    store: EcommerceStore,
    arguments: dict,
) -> EcommercePolicyDecision:
    if tool_name not in KNOWN_TOOLS:
        return EcommercePolicyDecision(False, f"未知电商工具被默认拦截: {tool_name}", "high", "unknown_tool.blocked")

    try:
        user = store.get_user(user_id)
    except Exception:
        return EcommercePolicyDecision(False, "用户不存在，禁止执行工具。", "high", "user.required")

    if role != user.role:
        return EcommercePolicyDecision(False, "调用角色与用户记录不一致。", "high", "role.match")

    if tool_name in {"product_search", "get_product_detail"}:
        return EcommercePolicyDecision(True, "公开商品只读工具放行。", "low", f"{tool_name}.readonly")

    if tool_name in {"get_user_profile", "cart_add_item", "cart_update_quantity", "get_order_status", "support_create_ticket"}:
        return EcommercePolicyDecision(True, "当前用户业务工具放行，具体归属由 store 校验。", "medium", f"{tool_name}.scoped")

    if tool_name in {"create_order", "apply_coupon", "mock_payment", "request_refund"}:
        if role not in {"buyer", "admin"}:
            return EcommercePolicyDecision(False, "该高风险交易工具只允许 buyer/admin 调用。", "high", f"{tool_name}.role")
        return EcommercePolicyDecision(True, "高风险交易工具通过角色检查，继续执行业务规则校验。", "high", f"{tool_name}.role")

    if tool_name in {"merchant_update_price", "merchant_update_stock"}:
        if role not in {"merchant", "admin"}:
            return EcommercePolicyDecision(False, "商家后台工具只允许 merchant/admin 调用。", "critical", f"{tool_name}.role")
        product_id = str(arguments.get("product_id") or "")
        if role == "merchant":
            product = store.get_product(product_id)
            if user.shop_id != product.shop_id:
                return EcommercePolicyDecision(False, "商家只能操作自己店铺的商品。", "critical", f"{tool_name}.ownership")
        return EcommercePolicyDecision(True, "商家后台高风险工具通过角色与归属检查。", "critical", f"{tool_name}.role")

    return EcommercePolicyDecision(False, f"工具未配置策略: {tool_name}", "high", "policy.missing")
