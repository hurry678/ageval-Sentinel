from __future__ import annotations

from collections.abc import Callable
from typing import Any

from redsentinel.adapters.engine.ecommerce_agent.models import (
    AuditEvent,
    BusinessEvent,
    BusinessRuleError,
    ToolCallRecord,
    ToolExecution,
)
from redsentinel.adapters.engine.ecommerce_agent.policy import check_ecommerce_policy
from redsentinel.adapters.engine.ecommerce_agent.store import EcommerceStore, format_money
from redsentinel.defenses.engine.security import audit
from redsentinel.defenses.engine.security.output.filter import mask_sensitive_info
from redsentinel.defenses.engine.security.tool_guard import ToolGuardInput, evaluate_tool_guard


def product_search(store: EcommerceStore, *, user_id: str, role: str, query: str = "") -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="product_search",
        arguments={"query": query},
        operation=lambda: _product_search_impl(store, query),
    )


def get_product_detail(store: EcommerceStore, *, user_id: str, role: str, product_id: str) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="get_product_detail",
        arguments={"product_id": product_id},
        operation=lambda: _get_product_detail_impl(store, product_id),
    )


def get_user_profile(store: EcommerceStore, *, user_id: str, role: str, target_user_id: str | None = None) -> ToolExecution:
    target = target_user_id or user_id
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="get_user_profile",
        arguments={"target_user_id": target},
        operation=lambda: _get_user_profile_impl(store, user_id, target),
    )


def cart_add_item(store: EcommerceStore, *, user_id: str, role: str, product_id: str, quantity: int = 1) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="cart_add_item",
        arguments={"product_id": product_id, "quantity": quantity},
        operation=lambda: _cart_add_item_impl(store, user_id, product_id, quantity),
    )


def cart_update_quantity(
    store: EcommerceStore,
    *,
    user_id: str,
    role: str,
    product_id: str,
    quantity: int,
) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="cart_update_quantity",
        arguments={"product_id": product_id, "quantity": quantity},
        operation=lambda: _cart_update_quantity_impl(store, user_id, product_id, quantity),
    )


def get_order_status(store: EcommerceStore, *, user_id: str, role: str, order_id: str) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="get_order_status",
        arguments={"order_id": order_id},
        operation=lambda: _get_order_status_impl(store, user_id, order_id),
    )


def support_create_ticket(
    store: EcommerceStore,
    *,
    user_id: str,
    role: str,
    message: str,
    order_id: str | None = None,
) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="support_create_ticket",
        arguments={"message": mask_sensitive_info(message), "order_id": order_id},
        operation=lambda: _support_create_ticket_impl(store, user_id, order_id, mask_sensitive_info(message)),
        audit_on_allow=True,
    )


def apply_coupon(store: EcommerceStore, *, user_id: str, role: str, coupon_id: str) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="apply_coupon",
        arguments={"coupon_id": coupon_id},
        operation=lambda: _apply_coupon_impl(store, user_id, coupon_id),
        audit_on_allow=True,
    )


def create_order(store: EcommerceStore, *, user_id: str, role: str, address_id: str) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="create_order",
        arguments={"address_id": address_id},
        operation=lambda: _create_order_impl(store, user_id, address_id),
        audit_on_allow=True,
    )


def mock_payment(store: EcommerceStore, *, user_id: str, role: str, order_id: str, amount_cents: int) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="mock_payment",
        arguments={"order_id": order_id, "amount_cents": amount_cents},
        operation=lambda: _mock_payment_impl(store, user_id, order_id, amount_cents),
        audit_on_allow=True,
    )


def request_refund(store: EcommerceStore, *, user_id: str, role: str, order_id: str, reason: str) -> ToolExecution:
    safe_reason = mask_sensitive_info(reason)
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="request_refund",
        arguments={"order_id": order_id, "reason": safe_reason},
        operation=lambda: _request_refund_impl(store, user_id, order_id, safe_reason),
        audit_on_allow=True,
    )


def merchant_update_price(
    store: EcommerceStore,
    *,
    user_id: str,
    role: str,
    product_id: str,
    new_price_cents: int,
) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="merchant_update_price",
        arguments={"product_id": product_id, "new_price_cents": new_price_cents},
        operation=lambda: _merchant_update_price_impl(store, user_id, role, product_id, new_price_cents),
        audit_on_allow=True,
    )


def merchant_update_stock(
    store: EcommerceStore,
    *,
    user_id: str,
    role: str,
    product_id: str,
    new_stock: int,
) -> ToolExecution:
    return _execute_tool(
        store,
        user_id=user_id,
        role=role,
        tool_name="merchant_update_stock",
        arguments={"product_id": product_id, "new_stock": new_stock},
        operation=lambda: _merchant_update_stock_impl(store, user_id, role, product_id, new_stock),
        audit_on_allow=True,
    )


def _execute_tool(
    store: EcommerceStore,
    *,
    user_id: str,
    role: str,
    tool_name: str,
    arguments: dict[str, Any],
    operation: Callable[[], tuple[str, list[BusinessEvent], Any]],
    audit_on_allow: bool = False,
) -> ToolExecution:
    safe_arguments = _mask_argument_values(arguments)
    policy = check_ecommerce_policy(tool_name, user_id=user_id, role=role, store=store, arguments=arguments)
    if not policy.allowed:
        return _blocked_execution(tool_name, safe_arguments, policy.reason, policy.risk_level, audit_operation="电商策略拦截")

    try:
        answer, business_events, value = operation()
        safe_answer = mask_sensitive_info(answer)
        guard_decision = evaluate_tool_guard(ToolGuardInput(tool_name=tool_name, arguments=safe_arguments, response=value))
        if not guard_decision.allowed:
            return _blocked_execution(
                tool_name,
                safe_arguments,
                guard_decision.reason,
                guard_decision.risk_level,
                audit_operation="电商工具完整性拦截",
            )
        audit_events = []
        if audit_on_allow:
            audit_events.append(_write_tool_audit(user_id, role, tool_name, safe_arguments, "allowed", policy.risk_level))
        record = ToolCallRecord(
            tool_name=tool_name,
            arguments=safe_arguments,
            allowed=True,
            result=safe_answer,
            risk_level=policy.risk_level,
            reason=policy.reason,
        )
        return ToolExecution(
            answer=safe_answer,
            tool_calls=[record],
            business_events=business_events,
            audit_events=audit_events,
            risk_level=policy.risk_level,
            value=value,
        )
    except BusinessRuleError as exc:
        return _blocked_execution(tool_name, safe_arguments, str(exc), exc.risk_level, audit_operation="电商业务规则拦截")


def _blocked_execution(
    tool_name: str,
    arguments: dict[str, Any],
    reason: str,
    risk_level: str,
    *,
    audit_operation: str,
) -> ToolExecution:
    safe_arguments = _mask_argument_values(arguments)
    safe_reason = mask_sensitive_info(reason)
    audit_event = _write_tool_audit("ecommerce_agent", "system", tool_name, safe_arguments, safe_reason, risk_level, operation=audit_operation)
    record = ToolCallRecord(
        tool_name=tool_name,
        arguments=safe_arguments,
        allowed=False,
        result=safe_reason,
        risk_level=risk_level,
        reason=safe_reason,
    )
    return ToolExecution(
        answer=safe_reason,
        tool_calls=[record],
        audit_events=[audit_event],
        blocked=True,
        risk_level=risk_level,
    )


def _write_tool_audit(
    user_id: str,
    role: str,
    tool_name: str,
    arguments: dict[str, Any],
    result: str,
    risk_level: str,
    *,
    operation: str = "电商工具调用",
) -> AuditEvent:
    audit.write_audit_log(
        user_id=user_id,
        role=role,
        operation=operation,
        input_content=f"{tool_name}: {str(arguments)[:120]}",
        result=result,
        risk_level=risk_level,
    )
    return AuditEvent(operation=operation, risk_level=risk_level, result=result)


def _mask_argument_values(arguments: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in arguments.items():
        safe[key] = mask_sensitive_info(value) if isinstance(value, str) else value
    return safe


def _product_search_impl(store: EcommerceStore, query: str) -> tuple[str, list[BusinessEvent], Any]:
    products = store.search_products(query)
    if not products:
        return "没有找到匹配商品。", [], []
    lines = [
        f"{item.product_id} · {item.title} · {format_money(item.price_cents)} · 库存 {item.stock}"
        for item in products
    ]
    return "找到商品：\n" + "\n".join(lines), [], [item.product_id for item in products]


def _get_product_detail_impl(store: EcommerceStore, product_id: str) -> tuple[str, list[BusinessEvent], Any]:
    product = store.get_product(product_id)
    reviews = "；".join(mask_sensitive_info(item) for item in product.review_snippets[:2])
    answer = (
        f"{product.product_id} · {product.title}\n"
        f"类目：{product.category}，品牌：{product.brand}\n"
        f"价格：{format_money(product.price_cents)}，库存：{product.stock}\n"
        f"详情：{mask_sensitive_info(product.description)}\n"
        f"评价摘要：{reviews}"
    )
    return answer, [], {"product_id": product.product_id, "price_cents": product.price_cents, "stock": product.stock}


def _get_user_profile_impl(store: EcommerceStore, user_id: str, target_user_id: str) -> tuple[str, list[BusinessEvent], Any]:
    profile = store.get_profile(user_id, target_user_id)
    answer = (
        f"用户 {profile['user_id']}：{profile['name']}，角色 {profile['role']}，"
        f"会员 {profile['loyalty_level']}，手机号 {profile['phone']}，地址数 {profile['address_count']}"
    )
    return answer, [], profile


def _cart_add_item_impl(store: EcommerceStore, user_id: str, product_id: str, quantity: int) -> tuple[str, list[BusinessEvent], Any]:
    item = store.add_cart_item(user_id, product_id, quantity)
    product = store.get_product(product_id)
    event = BusinessEvent("cart_add_item", product_id, f"加入购物车 {product.title} x{quantity}", "medium")
    return f"已加入购物车：{product.title} x{item.quantity}。", [event], item


def _cart_update_quantity_impl(
    store: EcommerceStore,
    user_id: str,
    product_id: str,
    quantity: int,
) -> tuple[str, list[BusinessEvent], Any]:
    item = store.update_cart_quantity(user_id, product_id, quantity)
    product = store.get_product(product_id)
    event = BusinessEvent("cart_update_quantity", product_id, f"购物车数量更新为 {quantity}", "medium")
    if item is None:
        return f"已从购物车移除：{product.title}。", [event], None
    return f"已更新购物车：{product.title} x{quantity}。", [event], item


def _get_order_status_impl(store: EcommerceStore, user_id: str, order_id: str) -> tuple[str, list[BusinessEvent], Any]:
    order = store.get_order(user_id, order_id)
    answer = (
        f"订单 {order.order_id} 状态：{order.status}，物流：{order.logistics_status}，"
        f"金额：{format_money(order.amount_cents)}。"
    )
    return answer, [], order


def _support_create_ticket_impl(
    store: EcommerceStore,
    user_id: str,
    order_id: str | None,
    message: str,
) -> tuple[str, list[BusinessEvent], Any]:
    ticket = store.create_ticket(user_id, order_id, message)
    event = BusinessEvent("support_ticket_created", ticket.ticket_id, f"创建客服工单 {ticket.ticket_id}", "medium")
    return f"已创建客服工单 {ticket.ticket_id}，内容：{message}", [event], ticket


def _apply_coupon_impl(store: EcommerceStore, user_id: str, coupon_id: str) -> tuple[str, list[BusinessEvent], Any]:
    coupon = store.apply_coupon(user_id, coupon_id)
    event = BusinessEvent("coupon_applied", coupon_id, f"使用优惠券 {coupon_id}", "high")
    return f"已使用优惠券 {coupon_id}，优惠 {format_money(coupon.discount_cents)}。", [event], coupon


def _create_order_impl(store: EcommerceStore, user_id: str, address_id: str) -> tuple[str, list[BusinessEvent], Any]:
    order = store.create_order(user_id, address_id)
    event = BusinessEvent("order_created", order.order_id, f"创建订单 {order.order_id}", "high")
    return f"已创建订单 {order.order_id}，服务端金额 {format_money(order.amount_cents)}，状态 {order.status}。", [event], order


def _mock_payment_impl(store: EcommerceStore, user_id: str, order_id: str, amount_cents: int) -> tuple[str, list[BusinessEvent], Any]:
    payment = store.mock_payment(user_id, order_id, amount_cents)
    event = BusinessEvent("mock_payment_paid", payment.payment_id, f"模拟支付订单 {order_id}", "critical")
    return f"订单 {order_id} 已完成模拟支付，支付单 {payment.payment_id}。", [event], payment


def _request_refund_impl(store: EcommerceStore, user_id: str, order_id: str, reason: str) -> tuple[str, list[BusinessEvent], Any]:
    refund = store.request_refund(user_id, order_id, reason)
    event = BusinessEvent("refund_requested", refund.refund_id, f"申请订单 {order_id} 退款", "high")
    return f"已提交退款申请 {refund.refund_id}，金额 {format_money(refund.amount_cents)}，状态 {refund.status}。", [event], refund


def _merchant_update_price_impl(
    store: EcommerceStore,
    user_id: str,
    role: str,
    product_id: str,
    new_price_cents: int,
) -> tuple[str, list[BusinessEvent], Any]:
    product = store.merchant_update_price(user_id, role, product_id, new_price_cents)
    event = BusinessEvent("merchant_price_updated", product_id, f"商家改价 {product_id}", "critical")
    return f"商品 {product.product_id} 已改价为 {format_money(product.price_cents)}。", [event], product


def _merchant_update_stock_impl(
    store: EcommerceStore,
    user_id: str,
    role: str,
    product_id: str,
    new_stock: int,
) -> tuple[str, list[BusinessEvent], Any]:
    product = store.merchant_update_stock(user_id, role, product_id, new_stock)
    event = BusinessEvent("merchant_stock_updated", product_id, f"商家改库存 {product_id}", "high")
    return f"商品 {product.product_id} 库存已更新为 {product.stock}。", [event], product
