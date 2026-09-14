from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


RiskLevel = Literal["normal", "low", "medium", "high", "critical"]
UserRole = Literal["buyer", "merchant", "admin"]


@dataclass
class Address:
    address_id: str
    user_id: str
    receiver: str
    phone: str
    line: str


@dataclass
class User:
    user_id: str
    role: UserRole
    name: str
    phone: str
    addresses: list[Address] = field(default_factory=list)
    loyalty_level: str = "standard"
    risk_flags: list[str] = field(default_factory=list)
    shop_id: str | None = None


@dataclass
class Shop:
    shop_id: str
    name: str
    seller_id: str
    rating: float
    policy: str = "七天无理由退货，模拟平台不触发真实交易。"


@dataclass
class Product:
    product_id: str
    shop_id: str
    title: str
    category: str
    brand: str
    price_cents: int
    stock: int
    description: str
    review_snippets: list[str] = field(default_factory=list)
    sold: int = 0


@dataclass
class CartItem:
    user_id: str
    product_id: str
    sku_id: str
    quantity: int
    selected: bool = True


@dataclass
class OrderItem:
    product_id: str
    title: str
    shop_id: str
    quantity: int
    unit_price_cents: int


@dataclass
class Order:
    order_id: str
    user_id: str
    items: list[OrderItem]
    amount_cents: int
    address_id: str
    status: str
    coupon_id: str | None = None
    payment_id: str | None = None
    refund_id: str | None = None
    logistics_status: str = "待发货"


@dataclass
class Payment:
    payment_id: str
    order_id: str
    amount_cents: int
    status: str
    mock_token_ref: str


@dataclass
class Refund:
    refund_id: str
    order_id: str
    reason: str
    amount_cents: int
    status: str


@dataclass
class Coupon:
    coupon_id: str
    scope: str
    discount_cents: int
    min_amount_cents: int
    owner_user_id: str | None = None
    usage_limit: int = 1
    used_count: int = 0


@dataclass
class SupportTicket:
    ticket_id: str
    user_id: str
    order_id: str | None
    messages: list[str]
    status: str = "open"


@dataclass
class ToolCallRecord:
    tool_name: str
    arguments: dict[str, Any]
    allowed: bool
    result: str
    risk_level: RiskLevel = "normal"
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BusinessEvent:
    event_type: str
    entity_id: str
    summary: str
    risk_level: RiskLevel = "normal"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditEvent:
    operation: str
    risk_level: RiskLevel
    result: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolExecution:
    answer: str
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    business_events: list[BusinessEvent] = field(default_factory=list)
    audit_events: list[AuditEvent] = field(default_factory=list)
    blocked: bool = False
    risk_level: RiskLevel = "normal"
    value: Any = None


class BusinessRuleError(ValueError):
    def __init__(self, message: str, *, risk_level: RiskLevel = "high", code: str = "business_rule_violation") -> None:
        super().__init__(message)
        self.risk_level = risk_level
        self.code = code
