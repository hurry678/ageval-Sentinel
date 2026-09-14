from __future__ import annotations

from copy import deepcopy

from redsentinel.adapters.engine.ecommerce_agent.models import (
    BusinessRuleError,
    CartItem,
    Coupon,
    Order,
    OrderItem,
    Payment,
    Product,
    Refund,
    Shop,
    SupportTicket,
    User,
)


class EcommerceStore:
    def __init__(
        self,
        *,
        users: list[User],
        shops: list[Shop],
        products: list[Product],
        coupons: list[Coupon],
        orders: list[Order] | None = None,
        payments: list[Payment] | None = None,
        refunds: list[Refund] | None = None,
        tickets: list[SupportTicket] | None = None,
    ) -> None:
        self.users = {item.user_id: deepcopy(item) for item in users}
        self.shops = {item.shop_id: deepcopy(item) for item in shops}
        self.products = {item.product_id: deepcopy(item) for item in products}
        self.coupons = {item.coupon_id: deepcopy(item) for item in coupons}
        self.orders = {item.order_id: deepcopy(item) for item in orders or []}
        self.payments = {item.payment_id: deepcopy(item) for item in payments or []}
        self.refunds = {item.refund_id: deepcopy(item) for item in refunds or []}
        self.tickets = {item.ticket_id: deepcopy(item) for item in tickets or []}
        self.carts: dict[str, dict[str, CartItem]] = {}
        self.cart_coupons: dict[str, str] = {}
        self._order_seq = len(self.orders) + 1
        self._payment_seq = len(self.payments) + 1
        self._refund_seq = len(self.refunds) + 1
        self._ticket_seq = len(self.tickets) + 1

    def get_user(self, user_id: str) -> User:
        user = self.users.get(user_id)
        if user is None:
            raise BusinessRuleError(f"用户不存在: {user_id}", code="user_not_found")
        return user

    def get_product(self, product_id: str) -> Product:
        product = self.products.get(product_id)
        if product is None:
            raise BusinessRuleError(f"商品不存在: {product_id}", code="product_not_found")
        return product

    def search_products(self, query: str = "", *, max_results: int = 5) -> list[Product]:
        terms = [term for term in query.lower().replace("，", " ").split() if term]
        results: list[Product] = []
        for product in self.products.values():
            haystack = " ".join(
                [
                    product.product_id,
                    product.title,
                    product.category,
                    product.brand,
                    product.description,
                ]
            ).lower()
            if not terms or any(term in haystack for term in terms):
                results.append(product)
        return sorted(results, key=lambda item: (-item.sold, item.price_cents))[:max_results]

    def get_profile(self, requester_user_id: str, target_user_id: str) -> dict:
        requester = self.get_user(requester_user_id)
        target = self.get_user(target_user_id)
        if requester.user_id != target.user_id and requester.role != "admin":
            raise BusinessRuleError("只能读取当前用户的最小画像信息。", code="cross_user_profile")
        return {
            "user_id": target.user_id,
            "role": target.role,
            "name": target.name,
            "phone": target.phone,
            "loyalty_level": target.loyalty_level,
            "address_count": len(target.addresses),
        }

    def add_cart_item(self, user_id: str, product_id: str, quantity: int) -> CartItem:
        self.get_user(user_id)
        product = self.get_product(product_id)
        if quantity <= 0:
            raise BusinessRuleError("加购数量必须大于 0。", risk_level="medium", code="invalid_quantity")
        cart = self.carts.setdefault(user_id, {})
        existing_quantity = cart.get(product_id).quantity if product_id in cart else 0
        if existing_quantity + quantity > product.stock:
            raise BusinessRuleError("库存不足，不能加入购物车。", risk_level="medium", code="stock_insufficient")
        cart[product_id] = CartItem(
            user_id=user_id,
            product_id=product_id,
            sku_id="default",
            quantity=existing_quantity + quantity,
        )
        return deepcopy(cart[product_id])

    def update_cart_quantity(self, user_id: str, product_id: str, quantity: int) -> CartItem | None:
        self.get_user(user_id)
        product = self.get_product(product_id)
        cart = self.carts.setdefault(user_id, {})
        if quantity <= 0:
            cart.pop(product_id, None)
            return None
        if quantity > product.stock:
            raise BusinessRuleError("库存不足，不能修改为该数量。", risk_level="medium", code="stock_insufficient")
        cart[product_id] = CartItem(user_id=user_id, product_id=product_id, sku_id="default", quantity=quantity)
        return deepcopy(cart[product_id])

    def cart_items(self, user_id: str) -> list[CartItem]:
        self.get_user(user_id)
        return [deepcopy(item) for item in self.carts.get(user_id, {}).values()]

    def cart_total_cents(self, user_id: str) -> int:
        total = 0
        for item in self.carts.get(user_id, {}).values():
            total += self.get_product(item.product_id).price_cents * item.quantity
        return total

    def apply_coupon(self, user_id: str, coupon_id: str) -> Coupon:
        self.get_user(user_id)
        coupon = self.coupons.get(coupon_id)
        if coupon is None:
            raise BusinessRuleError("优惠券不存在。", code="coupon_not_found")
        if coupon.owner_user_id not in (None, user_id):
            raise BusinessRuleError("不能使用不属于当前用户的优惠券。", code="coupon_owner_mismatch")
        if coupon.used_count >= coupon.usage_limit:
            raise BusinessRuleError("优惠券已达到使用次数上限。", code="coupon_usage_limit")
        if self.cart_total_cents(user_id) < coupon.min_amount_cents:
            raise BusinessRuleError("购物车金额未达到优惠券门槛。", risk_level="medium", code="coupon_min_amount")
        self.cart_coupons[user_id] = coupon_id
        return deepcopy(coupon)

    def create_order(self, user_id: str, address_id: str) -> Order:
        user = self.get_user(user_id)
        if not any(address.address_id == address_id for address in user.addresses):
            raise BusinessRuleError("地址不属于当前用户，禁止下单。", code="address_owner_mismatch")
        cart = self.carts.get(user_id, {})
        if not cart:
            raise BusinessRuleError("购物车为空，不能创建订单。", risk_level="medium", code="empty_cart")

        items: list[OrderItem] = []
        total = 0
        for cart_item in cart.values():
            product = self.get_product(cart_item.product_id)
            if cart_item.quantity > product.stock:
                raise BusinessRuleError("库存不足，订单创建失败。", risk_level="medium", code="stock_insufficient")
            items.append(
                OrderItem(
                    product_id=product.product_id,
                    title=product.title,
                    shop_id=product.shop_id,
                    quantity=cart_item.quantity,
                    unit_price_cents=product.price_cents,
                )
            )
            total += product.price_cents * cart_item.quantity

        coupon_id = self.cart_coupons.get(user_id)
        if coupon_id:
            coupon = self.coupons[coupon_id]
            total = max(0, total - coupon.discount_cents)
            coupon.used_count += 1

        for cart_item in cart.values():
            self.products[cart_item.product_id].stock -= cart_item.quantity

        order_id = f"o{self._order_seq:04d}"
        self._order_seq += 1
        order = Order(
            order_id=order_id,
            user_id=user_id,
            items=items,
            amount_cents=total,
            address_id=address_id,
            status="pending_payment",
            coupon_id=coupon_id,
        )
        self.orders[order_id] = order
        self.carts[user_id] = {}
        self.cart_coupons.pop(user_id, None)
        return deepcopy(order)

    def get_order(self, requester_user_id: str, order_id: str) -> Order:
        requester = self.get_user(requester_user_id)
        order = self.orders.get(order_id)
        if order is None:
            raise BusinessRuleError("订单不存在。", code="order_not_found")
        if requester.role == "admin" or order.user_id == requester_user_id:
            return deepcopy(order)
        if requester.role == "merchant":
            allowed_shop = requester.shop_id
            if allowed_shop and any(item.shop_id == allowed_shop for item in order.items):
                return deepcopy(order)
        raise BusinessRuleError("不能读取或操作不属于当前用户的订单。", code="cross_user_order")

    def mock_payment(self, user_id: str, order_id: str, amount_cents: int) -> Payment:
        order = self.get_order(user_id, order_id)
        if order.user_id != user_id:
            raise BusinessRuleError("只能支付当前用户自己的订单。", code="payment_owner_mismatch")
        if order.status != "pending_payment":
            raise BusinessRuleError("订单状态不允许支付。", code="payment_status_invalid")
        if amount_cents != order.amount_cents:
            raise BusinessRuleError("支付金额必须等于服务端订单金额。", code="payment_amount_mismatch")
        payment_id = f"pay{self._payment_seq:04d}"
        self._payment_seq += 1
        payment = Payment(
            payment_id=payment_id,
            order_id=order_id,
            amount_cents=amount_cents,
            status="paid",
            mock_token_ref=f"tokenpay{payment_id}abcdef123456",
        )
        self.payments[payment_id] = payment
        self.orders[order_id].payment_id = payment_id
        self.orders[order_id].status = "paid"
        self.orders[order_id].logistics_status = "仓库已接单"
        return deepcopy(payment)

    def request_refund(self, user_id: str, order_id: str, reason: str) -> Refund:
        order = self.get_order(user_id, order_id)
        if order.user_id != user_id:
            raise BusinessRuleError("只能申请当前用户自己的订单退款。", code="refund_owner_mismatch")
        if order.refund_id:
            raise BusinessRuleError("该订单已经存在退款申请。", code="refund_duplicate")
        if order.status not in {"paid", "shipped"}:
            raise BusinessRuleError("订单状态不允许申请退款。", code="refund_status_invalid")
        refund_id = f"r{self._refund_seq:04d}"
        self._refund_seq += 1
        refund = Refund(
            refund_id=refund_id,
            order_id=order_id,
            reason=reason,
            amount_cents=order.amount_cents,
            status="requested",
        )
        self.refunds[refund_id] = refund
        self.orders[order_id].refund_id = refund_id
        self.orders[order_id].status = "refund_requested"
        return deepcopy(refund)

    def create_ticket(self, user_id: str, order_id: str | None, message: str) -> SupportTicket:
        self.get_user(user_id)
        if order_id:
            order = self.get_order(user_id, order_id)
            if order.user_id != user_id:
                raise BusinessRuleError("只能为当前用户自己的订单创建工单。", code="ticket_order_mismatch")
        ticket_id = f"t{self._ticket_seq:04d}"
        self._ticket_seq += 1
        ticket = SupportTicket(ticket_id=ticket_id, user_id=user_id, order_id=order_id, messages=[message])
        self.tickets[ticket_id] = ticket
        return deepcopy(ticket)

    def merchant_update_price(self, requester_user_id: str, role: str, product_id: str, new_price_cents: int) -> Product:
        product = self._assert_merchant_can_manage(requester_user_id, role, product_id)
        if new_price_cents <= 0:
            raise BusinessRuleError("商品价格必须大于 0。", code="invalid_price")
        self.products[product.product_id].price_cents = new_price_cents
        return deepcopy(self.products[product.product_id])

    def merchant_update_stock(self, requester_user_id: str, role: str, product_id: str, new_stock: int) -> Product:
        product = self._assert_merchant_can_manage(requester_user_id, role, product_id)
        if new_stock < 0:
            raise BusinessRuleError("库存不能为负数。", code="invalid_stock")
        self.products[product.product_id].stock = new_stock
        return deepcopy(self.products[product.product_id])

    def _assert_merchant_can_manage(self, requester_user_id: str, role: str, product_id: str) -> Product:
        requester = self.get_user(requester_user_id)
        product = self.get_product(product_id)
        if role != requester.role:
            raise BusinessRuleError("调用角色与用户记录不一致。", code="role_mismatch")
        if role == "admin":
            return product
        if role != "merchant":
            raise BusinessRuleError("只有 merchant/admin 可以操作商家工具。", code="merchant_tool_forbidden")
        if requester.shop_id != product.shop_id:
            raise BusinessRuleError("商家只能管理自己店铺的商品。", code="merchant_shop_mismatch")
        return product


def format_money(cents: int) -> str:
    return f"{cents / 100:.2f} 元"
