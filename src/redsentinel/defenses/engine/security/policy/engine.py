"""Tool Policy Engine — 可配置的工具权限策略引擎。

在 tool_node 执行前插入策略检查，拦截危险工具调用。
规则 JSON 可配置，非硬编码。

集成方式 (复用3.2投毒防护的钩子模式):
    try:
        from redsentinel.defenses.engine.security.policy.engine import check_policy
        allowed, reason, detail = check_policy(tool_name, tool_args, state)
        if not allowed:
            # 返回 ToolMessage 告知 LLM 被拦截
    except ImportError:
        pass
"""

import json
import os
import re
from email.utils import parseaddr
from pathlib import Path
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse

PolicyDecisionValue = Literal["allow", "deny", "ask"]


@dataclass(frozen=True)
class PolicyDecision:
    decision: PolicyDecisionValue
    reason: str
    risk_level: str
    detail: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

# ============================================================
# 默认策略规则（可通过 JSON 文件覆盖）
# ============================================================
DEFAULT_POLICY_RULES = {
    "tool_policies": {
        "db_query": {
            "block_sql_keywords": [
                "DROP", "DELETE", "UPDATE", "INSERT", "TRUNCATE", "ALTER", "CREATE",
                "GRANT", "REVOKE", "EXEC", "EXECUTE", "INTO OUTFILE", "INTO DUMPFILE",
                "LOAD_FILE", "LOAD DATA",
            ],
            "allow_only": ["SELECT", "SHOW", "DESCRIBE", "EXPLAIN", "DESC"],
            "risk_level": "critical",
            "message": "SQL写操作被策略引擎拦截。仅允许只读查询(SELECT/SHOW/DESCRIBE/EXPLAIN)。",
        },
        "file_operation": {
            "block_paths": [
                "/etc/", "/sys/", "/proc/", "/dev/", "/root/", "/boot/",
                "C:\\Windows\\", "C:\\Windows\\System32\\", "C:\\Program Files\\",
                "~/.ssh/", "~/.gnupg/", "/var/log/",
            ],
            "block_path_patterns": [
                r"(\\\\|/)\.ssh(\\\\|/)", r"\.pem$", r"\.key$", r"\.crt$",
                r"password", r"credential", r"secret", r"redsentinel_canary",
            ],
            "block_actions": ["delete", "overwrite", "chmod", "chown"],
            "ask_actions": ["write", "append"],
            "allowed_actions": ["read", "list", "stat"],
            "risk_level": "critical",
            "message": "文件写/删操作被策略引擎拦截。仅允许只读操作(read/list/stat)。",
        },
        "api_call": {
            "allowed_domains": [
                "api.internal.com", "localhost", "127.0.0.1",
                "internal.", ".local", ".internal",
            ],
            "block_metadata_hosts": ["169.254.169.254"],
            "block_metadata_paths": ["/latest/meta-data", "/metadata/instance"],
            "block_external_post": True,
            "ask_risk_levels": [],
            "risk_level": "high",
            "message": "向外部域名的POST/PUT请求被策略引擎拦截。仅允许内部API调用。",
        },
        "browser_search": {
            "block_uri_schemes": ["file"],
            "block_metadata_hosts": ["169.254.169.254"],
            "block_metadata_paths": ["/latest/meta-data", "/metadata/instance"],
            "risk_level": "high",
            "message": "浏览搜索访问 metadata endpoint 被策略引擎拦截。",
        },
        "send_email": {
            "max_recipients": 5,
            "block_external_recipients": True,
            "internal_domains": ["@company.com", "@internal.com"],
            "ask_domains": ["*"],
            "block_content_patterns": [
                "password", "credential", "token", "secret", "api_key",
                "密码", "密钥", "令牌", "凭证",
                r"sk-[a-zA-Z0-9]{20,}",
            ],
            "risk_level": "high",
            "message": "邮件发送被策略引擎拦截。检查收件人域/数量/敏感内容。",
        },
        "check_sensitive_information": {
            "note": "现有安全工具 — 只读检测，策略引擎不拦截",
            "risk_level": "low",
        },
        "detect_pdf_sensitive_info": {
            "note": "现有安全工具 — 只读检测，策略引擎不拦截",
            "risk_level": "low",
        },
        "simple_vuln_scan": {
            "note": "现有安全工具 — 只读扫描，策略引擎不拦截",
            "risk_level": "low",
        },
        "check_sql_injection": {
            "note": "现有安全工具 — 只读检测，策略引擎不拦截",
            "risk_level": "low",
        },
        "search_document": {
            "note": "RAG search tool is read-only; policy engine does not block it.",
            "risk_level": "low",
        },
    },
    "rate_limits": {
        "max_calls_per_turn": 3,
        "max_total_calls_per_session": 10,
        "message": "工具调用频率超限：每轮最多3次，单次会话最多10次。",
    },
    "global": {
        "enabled": True,
        "audit_on_block": True,
        "audit_on_allow": False,
    },
}


# ============================================================
# 策略引擎核心
# ============================================================

def _check_sql_policy(args: dict, policy: dict) -> tuple:
    """Check db_query SQL against policy rules."""
    sql = args.get("sql", "")
    sql_no_comments = _strip_sql_comments(sql)
    sql_upper = sql_no_comments.strip().upper()

    # Check: does the SQL contain only allowed operation keywords at the start?
    allowed = policy.get("allow_only", [])
    block_keywords = policy.get("block_sql_keywords", [])

    # Check for blocked keywords anywhere in the SQL
    found_blocked = []
    for kw in block_keywords:
        # Match whole words only, not substrings
        if re.search(r'\b' + re.escape(kw) + r'\b', sql_upper):
            found_blocked.append(kw)

    if found_blocked:
        return (
            False,
            f"{policy['message']} 检测到禁止操作: {', '.join(found_blocked[:5])}。",
            {
                "risk_level": policy["risk_level"],
                "blocked_reason": f"blocked_sql_keywords: {', '.join(found_blocked[:3])}",
                "rule_name": "db_query.block_sql_keywords",
            },
        )

    if allowed:
        allowed_ops = {op.upper() for op in allowed}
        statements = [stmt.strip() for stmt in sql_no_comments.split(";") if stmt.strip()]
        if not statements:
            return _block_sql_disallowed_operation(policy, "empty")

        for stmt in statements:
            operation = _extract_sql_operation(stmt)
            if operation not in allowed_ops:
                return _block_sql_disallowed_operation(policy, operation or "unknown")

    return True, "", {"risk_level": "low", "blocked_reason": None, "rule_name": "db_query.passed"}


def _strip_sql_comments(sql: str) -> str:
    """Remove common SQL comments before policy checks."""
    without_block_comments = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    return re.sub(r"(--|#)[^\r\n]*", " ", without_block_comments)


def _extract_sql_operation(sql: str) -> str:
    """Return the first SQL operation token after leading whitespace/parentheses."""
    match = re.match(r"^\s*\(*\s*([A-Za-z_]+)", sql)
    return match.group(1).upper() if match else ""


def _block_sql_disallowed_operation(policy: dict, operation: str) -> tuple:
    return (
        False,
        f"{policy['message']} SQL operation '{operation}' is not in allow_only.",
        {
            "risk_level": policy["risk_level"],
            "blocked_reason": f"disallowed_sql_operation: {operation}",
            "rule_name": "db_query.allow_only",
        },
    )


def _check_file_policy(args: dict, policy: dict, *, workspace_root: str | None = None) -> tuple:
    """Check file_operation against policy rules."""
    path = args.get("path", "")
    action = args.get("action", "").lower()
    boundary = _file_boundary(path, workspace_root)

    # Check blocked actions
    if action in policy.get("block_actions", []):
        return (
            False,
            f"{policy['message']} 操作 '{action}' 不被允许。允许的操作: {', '.join(policy.get('allowed_actions', []))}",
            {
                "risk_level": policy["risk_level"],
                "blocked_reason": f"blocked_action: {action}",
                "rule_name": "file_operation.block_actions",
                "decision": "deny",
                "file_action": action,
                "boundary": boundary,
            },
        )

    if action in policy.get("ask_actions", []):
        return _ask_result(
            f"文件操作 '{action}' 需要人工确认。",
            {
                "risk_level": "medium",
                "blocked_reason": f"ask_action: {action}",
                "rule_name": "file_operation.ask_actions",
            },
        )

    # Check blocked paths
    for bp in policy.get("block_paths", []):
        if bp.lower() in path.lower():
            return (
                False,
                f"{policy['message']} 路径 '{path}' 位于禁止区域 '{bp}'。",
                {
                    "risk_level": policy["risk_level"],
                    "blocked_reason": f"blocked_path: {bp}",
                    "rule_name": "file_operation.block_paths",
                    "decision": "deny",
                    "file_action": action,
                    "boundary": boundary,
                },
            )

    # Check blocked path patterns
    for pattern in policy.get("block_path_patterns", []):
        if re.search(pattern, path, re.IGNORECASE):
            return (
                False,
                f"{policy['message']} 路径 '{path}' 匹配禁止模式 '{pattern}'。",
                {
                    "risk_level": policy["risk_level"],
                    "blocked_reason": f"blocked_pattern: {pattern}",
                    "rule_name": "file_operation.block_path_patterns",
                    "decision": "deny",
                    "file_action": action,
                    "boundary": boundary,
                },
            )

    if action in {"write", "append"}:
        if boundary["outside_workspace"]:
            return (
                False,
                f"{policy['message']} 写入路径 '{path}' 越出工作区，禁止执行。",
                {
                    "risk_level": "critical",
                    "blocked_reason": "outside_workspace_write",
                    "rule_name": "file_operation.workspace_boundary",
                    "decision": "deny",
                    "file_action": action,
                    "boundary": boundary,
                },
            )
        return (
            False,
            f"文件 {action} 操作需要监督端确认。",
            {
                "risk_level": "medium",
                "blocked_reason": "supervisor_confirmation_required",
                "rule_name": "file_operation.ask_write",
                "decision": "ask",
                "pending": True,
                "file_action": action,
                "boundary": boundary,
            },
        )

    allowed_actions = set(policy.get("allowed_actions", []))
    if allowed_actions and action not in allowed_actions:
        return (
            False,
            f"{policy['message']} 操作 '{action}' 不在允许列表中。",
            {
                "risk_level": policy["risk_level"],
                "blocked_reason": f"unsupported_action: {action}",
                "rule_name": "file_operation.allowed_actions",
                "decision": "deny",
                "file_action": action,
                "boundary": boundary,
            },
        )

    return True, "", {
        "risk_level": "low",
        "blocked_reason": None,
        "rule_name": "file_operation.passed",
        "decision": "allow",
        "file_action": action,
        "boundary": boundary,
    }


def _check_api_policy(args: dict, policy: dict) -> tuple:
    """Check api_call against policy rules."""
    endpoint = args.get("endpoint", "")
    method = args.get("method", "GET").upper()

    # Check if endpoint is internal
    host = _extract_endpoint_host(endpoint)
    is_internal = _host_matches_allowed_domains(host, policy.get("allowed_domains", []))

    metadata_reason = _metadata_endpoint_match(endpoint, policy)
    if metadata_reason:
        return (
            False,
            f"API调用目标 '{endpoint[:60]}' 命中 metadata endpoint 风险: {metadata_reason}。",
            {
                "risk_level": policy["risk_level"],
                "blocked_reason": metadata_reason,
                "rule_name": "api_call.block_metadata_endpoint",
            },
        )

    if not is_internal and method in ("POST", "PUT") and policy.get("block_external_post", True):
        return (
            False,
            f"{policy['message']} 目标 '{endpoint[:60]}' 不在内部域名白名单中。",
            {
                "risk_level": policy["risk_level"],
                "blocked_reason": "external_post_blocked",
                "rule_name": "api_call.block_external_post",
            },
        )

    return True, "", {"risk_level": "low" if is_internal else "medium", "blocked_reason": None, "rule_name": "api_call.passed"}


def _check_browser_search_policy(args: dict, policy: dict) -> tuple:
    """Check browser_search requests against metadata endpoint SSRF rules."""
    query = args.get("query") or args.get("url") or args.get("q") or ""
    scheme = urlparse(str(query).strip()).scheme.lower()
    if scheme in {str(item).lower() for item in policy.get("block_uri_schemes", [])}:
        return (
            False,
            f"浏览器访问 URI scheme '{scheme}' 被策略引擎拦截。",
            {
                "risk_level": policy["risk_level"],
                "blocked_reason": f"uri_scheme: {scheme}",
                "rule_name": "browser_search.block_uri_scheme",
            },
        )
    metadata_reason = _metadata_endpoint_match(query, policy)
    if metadata_reason:
        return (
            False,
            f"{policy['message']} 查询 '{str(query)[:60]}' 命中风险: {metadata_reason}。",
            {
                "risk_level": policy["risk_level"],
                "blocked_reason": metadata_reason,
                "rule_name": "browser_search.block_metadata_endpoint",
            },
        )

    return True, "", {"risk_level": "low", "blocked_reason": None, "rule_name": "browser_search.passed"}


def _metadata_endpoint_match(endpoint: str, policy: dict) -> str:
    hosts = {str(host).lower().strip().rstrip(".") for host in policy.get("block_metadata_hosts", []) if host}
    paths = [str(path).lower().strip() for path in policy.get("block_metadata_paths", []) if path]
    for candidate in _endpoint_candidates(endpoint):
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        host = (parsed.hostname or "").lower().rstrip(".")
        path = (parsed.path or "").lower()
        lowered = candidate.lower()
        if host and host in hosts:
            return f"metadata_host: {host}"
        for blocked_path in paths:
            if blocked_path and (blocked_path in path or blocked_path.strip("/") in lowered):
                return f"metadata_path: {blocked_path}"
    return ""


def _endpoint_candidates(endpoint: str) -> list[str]:
    raw = str(endpoint or "").strip()
    if not raw:
        return []
    urls = re.findall(r"https?://[^\s'\"<>，。；、)）]+", raw, flags=re.IGNORECASE)
    return [raw, *urls]


def _extract_endpoint_host(endpoint: str) -> str:
    """Extract hostname without letting path/query text satisfy host policy."""
    raw = str(endpoint or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or "").lower().rstrip(".")


def _host_matches_allowed_domains(host: str, allowed_domains: list[str]) -> bool:
    if not host:
        return False
    for allowed in allowed_domains:
        pattern = str(allowed).lower().strip()
        if not pattern:
            continue
        if pattern.startswith("."):
            suffix = pattern[1:].rstrip(".")
            if host == suffix or host.endswith(pattern):
                return True
        elif pattern.endswith("."):
            if host.startswith(pattern):
                return True
        elif host == pattern:
            return True
    return False


def _check_email_policy(args: dict, policy: dict) -> tuple:
    """Check send_email against policy rules."""
    to = args.get("to", "")
    subject = args.get("subject", "")
    body = args.get("body", "")

    recipients = [r.strip() for r in to.split(",") if r.strip()]

    # Check max recipients
    max_recips = policy.get("max_recipients", 5)
    if len(recipients) > max_recips:
        return (
            False,
            f"{policy['message']} 收件人数量({len(recipients)})超过上限({max_recips})。",
            {
                "risk_level": policy["risk_level"],
                "blocked_reason": f"max_recipients_exceeded: {len(recipients)} > {max_recips}",
                "rule_name": "send_email.max_recipients",
            },
        )

    # Check content patterns before external recipients so sensitive exfiltration stays deny.
    combined = (subject + " " + body).lower()
    for pattern in policy.get("block_content_patterns", []):
        if re.search(pattern, combined, re.IGNORECASE):
            return (
                False,
                f"{policy['message']} 邮件内容匹配敏感模式 '{pattern}'。",
                {
                    "risk_level": policy["risk_level"],
                    "blocked_reason": f"sensitive_content: matches '{pattern}'",
                    "rule_name": "send_email.block_content_patterns",
                },
            )

    # Check external recipients
    if policy.get("block_external_recipients", True):
        internal_domains = policy.get("internal_domains", [])
        for r in recipients:
            is_internal = _recipient_matches_internal_domain(r, internal_domains)
            if not is_internal:
                _, address = parseaddr(r)
                domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
                if (
                    not _domain_contains_internal_lookalike(domain, internal_domains)
                    and _domain_matches_patterns(domain, policy.get("ask_domains", []))
                ):
                    return _ask_result(
                        f"邮件发送到外部收件人 '{r}' 需要人工确认。",
                        {
                            "risk_level": "medium",
                            "blocked_reason": f"external_recipient: {r}",
                            "rule_name": "send_email.block_external_recipients",
                        },
                    )
                return (
                    False,
                    f"{policy['message']} 收件人 '{r}' 不在内部域白名单中。",
                    {
                        "risk_level": policy["risk_level"],
                        "blocked_reason": f"external_recipient: {r}",
                        "rule_name": "send_email.block_external_recipients",
                    },
                )

    return True, "", {"risk_level": "low", "blocked_reason": None, "rule_name": "send_email.passed"}


def _recipient_matches_internal_domain(recipient: str, internal_domains: list[str]) -> bool:
    _, address = parseaddr(recipient)
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    if not domain:
        return False
    allowed_domains = [str(d).lower().strip().lstrip("@").rstrip(".") for d in internal_domains]
    return any(domain == allowed for allowed in allowed_domains if allowed)


def _domain_contains_internal_lookalike(domain: str, internal_domains: list[str]) -> bool:
    normalized = domain.lower().strip().rstrip(".")
    allowed_domains = [str(d).lower().strip().lstrip("@").rstrip(".") for d in internal_domains]
    return any(allowed and allowed in normalized and normalized != allowed for allowed in allowed_domains)


def _domain_matches_patterns(domain: str, patterns: list[str]) -> bool:
    normalized = domain.lower().strip().rstrip(".")
    if not normalized:
        return False
    for pattern in patterns:
        candidate = str(pattern).lower().strip().lstrip("@").rstrip(".")
        if not candidate:
            continue
        if candidate == "*":
            return True
        if candidate.startswith(".") and normalized.endswith(candidate):
            return True
        if normalized == candidate:
            return True
    return False


def _ask_result(reason: str, detail: dict) -> tuple:
    detail = dict(detail)
    detail["decision"] = "ask"
    detail["pending"] = True
    return False, reason, detail


def _finalize_policy_result(result: tuple, policy: dict | None = None) -> tuple:
    allowed, reason, detail = result
    detail = dict(detail or {})

    decision = detail.get("decision")
    if decision not in {"allow", "deny", "ask"}:
        decision = "allow" if allowed else "deny"

    if allowed and policy and detail.get("risk_level") in policy.get("ask_risk_levels", []):
        allowed = False
        decision = "ask"
        reason = reason or "Policy risk level requires human confirmation."

    detail["decision"] = decision
    detail["pending"] = bool(detail.get("pending")) if decision == "ask" else False
    return allowed, reason, detail


# Policy checker dispatch table
_POLICY_CHECKERS = {
    "db_query": _check_sql_policy,
    "file_operation": _check_file_policy,
    "api_call": _check_api_policy,
    "browser_search": _check_browser_search_policy,
    "send_email": _check_email_policy,
}


def evaluate_policy(tool_name: str, tool_args: dict, state: dict = None, *, workspace_root: str | None = None) -> PolicyDecision:
    allowed, message, detail = check_policy(tool_name, tool_args, state, workspace_root=workspace_root)
    raw_decision = detail.get("decision")
    if raw_decision in {"allow", "deny", "ask"}:
        decision = raw_decision
    else:
        decision = "allow" if allowed else "deny"
    return PolicyDecision(
        decision=decision,
        reason=message or detail.get("blocked_reason") or "allowed",
        risk_level=detail.get("risk_level", "normal"),
        detail=detail,
    )


def check_policy(tool_name: str, tool_args: dict, state: dict = None, *, workspace_root: str | None = None) -> tuple:
    """Check if a tool call complies with security policy.

    Args:
        tool_name: Name of the tool being called
        tool_args: Arguments passed to the tool
        state: Optional AgentState dict (for context-aware checks)

    Returns:
        (allowed: bool, message: str, detail: dict)
        detail keys: risk_level, blocked_reason, rule_name
    """
    rules = _get_rules()

    # Global enable/disable
    if not rules.get("global", {}).get("enabled", True):
        return _finalize_policy_result(
            (True, "", {"risk_level": "low", "blocked_reason": "policy_disabled", "rule_name": "global.disabled"})
        )

    # Rate limit checks
    rate_limits = rules.get("rate_limits", {})
    if state:
        tool_call_count = state.get("tool_call_count", 0)
        max_total = rate_limits.get("max_total_calls_per_session", 10)

        if tool_call_count >= max_total:
            return _finalize_policy_result(
                (
                    False,
                    rate_limits.get("message", "工具调用频率超限"),
                    {
                        "risk_level": "high",
                        "blocked_reason": f"rate_limit: {tool_call_count} >= {max_total} total",
                        "rule_name": "rate_limits.max_total_calls",
                    },
                )
            )

    # Tool-specific policy check
    tool_policies = rules.get("tool_policies", {})
    policy = tool_policies.get(tool_name)

    if policy is None:
        # Unknown tool — allow by default (don't break existing tools)
        return _finalize_policy_result(
            (
                False,
                f"Tool '{tool_name}' has no policy entry and is blocked by default.",
                {"risk_level": "high", "blocked_reason": "unknown_tool", "rule_name": "unknown_tool.blocked"},
            )
        )

    # If policy has a note but no blocking rules, it's a pass-through
    if "note" in policy and "block_sql_keywords" not in policy and "block_paths" not in policy and "block_actions" not in policy:
        return _finalize_policy_result(
            (True, "", {"risk_level": "low", "blocked_reason": None, "rule_name": f"{tool_name}.passthrough"}),
            policy,
        )

    # Dispatch to specific checker
    checker = _POLICY_CHECKERS.get(tool_name)
    if checker:
        return _finalize_policy_result(checker(tool_args, policy), policy)

    # No checker but has policy = unknown dangerous tool, allow with warning
    return _finalize_policy_result(
        (
            False,
            f"Tool '{tool_name}' has policy rules but no checker implementation.",
            {"risk_level": "high", "blocked_reason": "policy_checker_missing", "rule_name": f"{tool_name}.no_checker"},
        ),
        policy,
    )


def _file_boundary(path: str, workspace_root: str | None) -> dict:
    if not workspace_root:
        return {"workspace_root": None, "resolved_path": str(path), "outside_workspace": False}
    try:
        root = Path(workspace_root).resolve()
        resolved = Path(path).expanduser()
        if not resolved.is_absolute():
            resolved = root / resolved
        resolved = resolved.resolve()
        outside = root != resolved and root not in resolved.parents
        return {"workspace_root": str(root), "resolved_path": str(resolved), "outside_workspace": outside}
    except Exception as exc:
        return {"workspace_root": workspace_root, "resolved_path": str(path), "outside_workspace": True, "error": str(exc)}


# ============================================================
# 规则加载与配置
# ============================================================

_current_rules = None


def _get_rules() -> dict:
    """Get current policy rules, loading from file if configured."""
    global _current_rules
    if _current_rules is not None:
        return _current_rules
    return DEFAULT_POLICY_RULES


def load_policy_rules(path: str = None) -> dict:
    """Load custom policy rules from a JSON file, merging with defaults.

    Args:
        path: Path to JSON policy file. If None, uses default rules.

    Returns:
        The merged rules dict.
    """
    global _current_rules

    if path is None:
        _current_rules = DEFAULT_POLICY_RULES
        return _current_rules

    if not os.path.exists(path):
        _current_rules = DEFAULT_POLICY_RULES
        return _current_rules

    with open(path, "r", encoding="utf-8") as f:
        custom_rules = json.load(f)

    # Deep merge: custom rules override defaults
    merged = dict(DEFAULT_POLICY_RULES)
    for section in ["tool_policies", "rate_limits", "global"]:
        if section in custom_rules:
            if section not in merged:
                merged[section] = {}
            merged[section].update(custom_rules[section])

    _current_rules = merged
    return merged


def reset_policy_rules():
    """Reset to default rules."""
    global _current_rules
    _current_rules = None


def get_policy_summary() -> dict:
    """Return a human-readable summary of current policy rules."""
    rules = _get_rules()
    summary = {
        "enabled": rules.get("global", {}).get("enabled", True),
        "tools_with_active_policies": [],
        "rate_limits": rules.get("rate_limits", {}),
    }

    for tool_name, policy in rules.get("tool_policies", {}).items():
        has_active_policy = any(
            k in policy for k in ["block_sql_keywords", "block_paths", "block_actions",
                                   "block_external_post", "block_external_recipients"]
        )
        if has_active_policy:
            summary["tools_with_active_policies"].append({
                "tool": tool_name,
                "risk_level": policy.get("risk_level", "unknown"),
                "has_block_rules": True,
            })

    return summary


# ============================================================
# 审计辅助
# ============================================================

def write_policy_audit(tool_name: str, tool_args: dict, allowed: bool, detail: dict, role: str = "user"):
    """Write an immediate audit log entry for a policy decision.

    Called synchronously in tool_node, not deferred to finalize_node.
    This ensures policy blocks are recorded even if the graph fails later.
    """
    try:
        from redsentinel.defenses.engine.security.audit import write_audit_log

        operation = "策略放行" if allowed else "策略拦截"
        risk_level = detail.get("risk_level", "low") if not allowed else "normal"
        input_content = f"{tool_name}: {str(tool_args)[:120]}"
        result = detail.get("blocked_reason") or "allowed"

        write_audit_log(
            user_id=role,
            role=role,
            operation=operation,
            input_content=input_content,
            result=result[:100],
            risk_level=risk_level,
        )
    except Exception:
        pass  # Audit failure should never block tool execution
