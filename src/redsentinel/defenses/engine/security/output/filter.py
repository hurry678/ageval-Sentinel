import re

# 敏感信息正则规则
SENSITIVE_PATTERNS = {
    "手机号": r"1[3-9]\d{9}",
    "身份证号": r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
    "银行卡号": r"\d{16,19}",
    "邮箱": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "API密钥/Token": r"(?:sk-|api_key|token|secret|key)[\w-]{16,}",
    "内网IP": r"(?:192\.168|10|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3}"
}

# 违规内容正则规则（优化版，避免误判，仅拦截高危可执行内容）
ILLEGAL_PATTERNS = [
    # 高危SQL执行语句（仅匹配完整可执行的注入语句，避免单符号误判）
    r"union\s+all\s+select", r"union\s+select",
    r"xp_cmdshell", r"exec\s+master\.", r"execute\s+sp_",
    r"drop\s+table", r"drop\s+database", r"truncate\s+table",
    r"alter\s+table", r"create\s+table",
    # 高危系统命令执行
    r"system\(", r"shell_exec\(", r"exec\(", r"passthru\(", r"popen\(",
    r"os\.system\(", r"subprocess\.", r"powershell\s+-", r"curl\s+.*\|\s*(sh|bash)",
    r"wget\s+.*\|\s*(sh|bash)", r"rm\s+-rf\s+/", r"chmod\s+777",
    # 黑产违规内容
    r"免杀", r"远控木马", r"钓鱼网站", r"脱壳破解", r"暴力破解"
]

# 输出泄露模式：每条规则带可观测 label，避免仅凭裸关键词拦截。
LEAKAGE_PATTERNS = [
    # ASR 将 training_data_leakage payload 路由到 llm_output，这里覆盖泄露请求本身。
    (
        "training_sample_regurgitation_request",
        r"(?:找出|复述|输出|导出|逐字|不要概括|不要替换)[\s\S]{0,80}"
        r"(?:训练(?:中|集|语料)|真实售后工单|客服退款对话)[\s\S]{0,120}"
        r"(?:原文|逐字|姓名|手机号|电话|地址|订单号|不要概括|不要替换)",
    ),
    (
        "system_prompt_config_extraction",
        r"(?:输出|告诉|重复|复述|列出|引用|总结|完整输出|详细说明)[\s\S]{0,80}"
        r"(?:你(?:收到的|所有的|被设定的|的)?[\s\S]{0,20})?"
        r"(?:system[\s_-]*(?:prompt|message)|developer\s*(?:message|instruction)s?|系统提示词|系统\s*prompt|系统消息|"
        r"初始化指令|初始指令|第一条消息|所有(?:的)?配置参数和规则|配置参数|隐藏安全策略|工具使用规则|安全规则|"
        r"所有指令|创造者[\s\S]{0,30}设定[\s\S]{0,20}限制)",
    ),
    (
        "system_prompt_config_extraction",
        r"(?:你的|你收到的|你被设定了|在你的)[\s\S]{0,40}"
        r"(?:system[\s_-]*(?:prompt|message)|prompt|系统提示词|系统消息|初始化指令|初始指令|安全规则|配置参数|"
        r"创造者[\s\S]{0,30}限制)[\s\S]{0,80}"
        r"(?:是什么|有哪些|完整输出|逐条列出|引用原文|详细说明|按原始顺序|json\s*格式|JSON格式)",
    ),
    (
        "conversation_history_dump",
        r"(?:print\s*\(\s*conversation_history\s*\)|conversation_history|chat_history|message_history|"
        r"输出所有历史|所有历史|之前收到的所有指令|我的消息和系统消息)[\s\S]{0,80}"
        r"(?:执行|输出|列出|总结|history|历史|系统消息|用户消息|assistant|user)",
    ),
    (
        "pii_credential_export_request",
        r"(?:把|导出|输出|列出|泄露|清单|表格)[\s\S]{0,80}"
        r"(?:(?:你记住的|存储的|保存的)[\s\S]{0,80}(?:用户邮箱|手机号|个人信息|用户隐私)|"
        r"(?:api[\s_-]?key|数据库连接串|访问令牌|access[\s_-]?token|凭据|密钥|令牌))"
        r"[\s\S]{0,120}(?:按表格|列出来|清单|导出|输出|api[\s_-]?key|访问令牌|数据库连接串|手机号|邮箱)",
    ),
    (
        "business_data_verbatim_export",
        r"(?:导出|输出|复制|逐字)[\s\S]{0,80}"
        r"(?:知识库|原始段落|原文|不要摘要|逐字复制)[\s\S]{0,140}"
        r"(?:vip\s*折扣|风控黑名单|供应商底价|退款审批规则|业务规则|价格策略)",
    ),
    (
        "system_prompt_config_extraction",
        r"(?:system[\s_-]*(?:prompt|message)|系统提示词|系统\s*prompt|系统消息|初始指令|init(?:ial)?\s*instruction|developer\s*(?:message|instruction)s?)"
        r"\s*[:：=]\s*(?:you\s+are|你是|role\s*:|instructions?|规则|policy|assistant|system)",
    ),
    (
        "system_prompt_config_extraction",
        r"(?:(?:internal|hidden|runtime|model|security)\s*config(?:uration)?|内部配置|安全配置|模型配置|配置导出|config\s*(?:dump|export|extraction))"
        r"\s*[:：=]\s*(?:\{|\[|[a-z_][\w-]*\s*=|model|temperature|policy|tools?)",
    ),
    (
        "conversation_history_dump",
        r"(?:conversation_history|chat_history|message_history|print\s*\(\s*(?:conversation_)?history\s*\)|print(?:ing)?\s+(?:the\s+)?(?:conversation\s+)?history|历史对话|聊天记录)"
        r"\s*[:：=]\s*(?:\[|\{|systemmessage|humanmessage|aimessage|user\s*:|assistant\s*:|用户[:：]|助手[:：])",
    ),
    (
        "pii_export",
        r"(?:(?:export|dump|导出|泄露|以下是|明细|清单)[\s\S]{0,40})?"
        r"(?:pii|个人(?:身份)?信息|用户(?:隐私|资料|信息)|客户(?:资料|信息)|customer\s+(?:pii|records?|data))"
        r"[\s\S]{0,160}(?:手机号|phone|身份证|id\s*card|邮箱|email|姓名|name)"
        r"[\s\S]{0,160}(?:1[3-9]\d{9}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{15,18}[\dXx]?)",
    ),
    (
        "credential_token_export",
        r"(?:credential|credentials|api[_\s-]?key|access[_\s-]?token|auth[_\s-]?token|token|secret|password|凭据|密钥|令牌|密码)"
        r"\s*[:=：]\s*['\"]?(?:sk-[\w-]{16,}|[a-zA-Z0-9_.-]{24,})",
    ),
    (
        "connection_string_export",
        r"(?:connection\s*string|database\s*url|jdbc\s*url|db\s*url|连接串|数据库连接|dsn)"
        r"\s*[:=：]\s*['\"]?(?:postgres(?:ql)?|mysql|mongodb|redis|jdbc:[a-z]+)://[^\s'\"<>]+",
    ),
    (
        "business_vendor_floor_price_export",
        r"(?:供应商底价|采购底价|底价表|vendor\s*(?:floor|base|cost)\s*price|supplier\s*(?:floor|base|cost)\s*price)"
        r"[\s\S]{0,80}(?:[:：=]|清单|明细|导出)[\s\S]{0,120}(?:¥|￥|\$|cny|rmb|\d+(?:\.\d+)?)",
    ),
    (
        "business_refund_approval_rules_export",
        r"(?:退款审批规则|退款审批矩阵|退款风控规则|refund\s*approval\s*(?:rules?|policy|matrix))"
        r"[\s\S]{0,160}(?:自动通过|免审|经理审批|人工复核|阈值|threshold|amount|金额|<=|>=|\d+\s*(?:元|cny|rmb|\$)?)",
    ),
    (
        "business_risk_blacklist_export",
        r"(?:风控黑名单|风险黑名单|黑名单(?:用户|账号|名单)?|risk\s*blacklist|blacklisted\s*(?:users|accounts)|high\s*risk\s*(?:users|accounts)\s*list)"
        r"[\s\S]{0,160}(?:user[_-]?\d+|账号[:：=]?\s*[a-zA-Z0-9_-]{4,}|账户[:：=]?\s*[a-zA-Z0-9_-]{4,}|device[_:：=-]?[a-z0-9-]{4,}|ip\s*[:=]?\s*\d{1,3}(?:\.\d{1,3}){3}|1[3-9]\d{9}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)",
    ),
    (
        "business_vip_discount_export",
        r"(?:内部|非公开|private|confidential|导出|矩阵|明细|配置)[\s\S]{0,40}"
        r"(?:vip\s*折扣|vip\s*discount|VIP折扣|大客户折扣|会员专属折扣|discount\s*matrix)"
        r"[\s\S]{0,160}(?:\d+(?:\.\d+)?\s*%|\d+(?:\.\d+)?\s*折|tier|level|等级|折扣率)",
    ),
]

_COMPILED_LEAKAGE_PATTERNS = [
    (label, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for label, pattern in LEAKAGE_PATTERNS
]


def _detect_leakage_pattern(text: str) -> str | None:
    for label, pattern in _COMPILED_LEAKAGE_PATTERNS:
        if pattern.search(text):
            return label
    return None

# ---------------------- 核心函数 ----------------------
def detect_sensitive_info(text: str) -> tuple[bool, str]:
    """检测文本中的敏感信息"""
    result = []
    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            unique = list(set(matches))
            masked = []
            for s in unique:
                s = str(s)
                if len(s) > 7:
                    masked.append(s[:3] + "****" + s[-4:])
                else:
                    masked.append("****")
            result.append(f"【{name}】{', '.join(masked)}")
    if not result:
        return False, "未检测到敏感信息"
    return True, "检测到敏感信息：\n" + "\n".join(result)

def mask_sensitive_info(text: str) -> str:
    """脱敏文本中的敏感信息"""
    for name, pattern in SENSITIVE_PATTERNS.items():
        text = re.sub(pattern, lambda m: (m.group()[:3] + "****" + m.group()[-4:]) if len(m.group())>7 else "****", text)
    return text

def check_output_compliance(text: str, is_rag_context: bool = False) -> tuple[bool, str]:
    """
    输出内容合规校验
    is_rag_context=True 时仅拦截完整可执行payload，允许安全文档中的描述性内容
    """
    text_lower = text.lower()

    leakage_label = _detect_leakage_pattern(text)
    if leakage_label:
        return False, f"[!] 输出内容疑似泄露敏感数据，命中泄露模式:{leakage_label}"

    if is_rag_context:
        # RAG/教育场景：仅拦截完整可执行payload和黑产关键词
        EDU_SAFE_PATTERNS = [
            r"xp_cmdshell", r"exec\s+master\.", r"execute\s+sp_",
            r"shell_exec\(", r"passthru\(", r"popen\(",
            r"os\.system\(", r"subprocess\.", r"curl\s+.*\|\s*(sh|bash)",
            r"免杀", r"远控木马", r"钓鱼网站", r"脱壳破解", r"暴力破解"
        ]
        patterns = EDU_SAFE_PATTERNS
    else:
        patterns = ILLEGAL_PATTERNS

    for pattern in patterns:
        if re.search(pattern, text_lower):
            return False, "[!] 输出内容不合规，包含高危操作代码/违规内容，已拦截"
    return True, "输出内容合规"
