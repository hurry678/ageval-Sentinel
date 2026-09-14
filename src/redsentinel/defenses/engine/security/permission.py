# 角色权限配置（AI安全最小权限原则，面试必讲亮点）
ROLE_PERMISSIONS = {
    "guest": {
        "name": "游客",
        "allowed_tools": ["search_knowledge_base"],
        "desc": "仅可使用知识库问答功能"
    },
    "user": {
        "name": "普通用户",
        "allowed_tools": ["search_knowledge_base", "check_sensitive_information", "detect_pdf_sensitive_info"],
        "desc": "可使用知识库问答+敏感信息检测功能"
    },
    "admin": {
        "name": "管理员",
        "allowed_tools": [
            "search_knowledge_base",
            "check_sensitive_information",
            "detect_pdf_sensitive_info",
            "simple_vuln_scan",
            "check_sql_injection"
        ],
        "desc": "可使用全部安全工具，包括漏洞扫描、SQL注入检测"
    }
}

# 默认角色
DEFAULT_ROLE = "user"

def check_tool_permission(tool_name: str, role: str = DEFAULT_ROLE) -> tuple[bool, str]:
    """
    校验工具调用权限
    返回：(是否有权限, 提示信息)
    """
    if role not in ROLE_PERMISSIONS:
        role = DEFAULT_ROLE
    
    allowed_tools = ROLE_PERMISSIONS[role]["allowed_tools"]
    if tool_name in allowed_tools:
        return True, "权限校验通过"
    else:
        role_name = ROLE_PERMISSIONS[role]["name"]
        return False, f"[!] 权限不足：您当前是【{role_name}】，无权使用【{tool_name}】工具，请联系管理员开通权限"

def get_role_info(role: str = DEFAULT_ROLE) -> dict:
    """获取角色信息"""
    if role not in ROLE_PERMISSIONS:
        role = DEFAULT_ROLE
    return ROLE_PERMISSIONS[role]

def get_allowed_tools(role: str = DEFAULT_ROLE) -> list:
    """获取当前角色允许使用的工具列表"""
    if role not in ROLE_PERMISSIONS:
        role = DEFAULT_ROLE
    return ROLE_PERMISSIONS[role]["allowed_tools"]