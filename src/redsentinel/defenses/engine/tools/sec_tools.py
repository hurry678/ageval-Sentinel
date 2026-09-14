from langchain_core.tools import tool
from pydantic.v1 import BaseModel, Field
from redsentinel.defenses.engine.security.output.filter import detect_sensitive_info

# ---------------------- 工具输入参数严格定义 ----------------------
class CheckSensitiveInfoInput(BaseModel):
    text: str = Field(description="待检测的文本内容")

class SimpleVulnScanInput(BaseModel):
    url: str = Field(description="待扫描的完整URL地址")

class SqlInjectionCheckInput(BaseModel):
    content: str = Field(description="待检测的SQL语句/URL/用户输入内容")

# ---------------------- 工具定义（去掉RAG工具，保留4个安全工具） ----------------------
@tool(args_schema=CheckSensitiveInfoInput)
def check_sensitive_information(text: str) -> str:
    """
    【用途】检测文本中的敏感信息
    【调用场景】用户要求检测手机号、身份证、银行卡、API密钥等隐私内容
    """
    has_risk, result = detect_sensitive_info(text)
    return result

@tool
def detect_pdf_sensitive_info() -> str:
    """
    【用途】检测已加载PDF文档中的敏感信息
    【调用场景】用户询问上传的PDF里有没有敏感信息、隐私内容
    【注意】此工具仅用于命令行，网页端会直接在Agent里处理
    """
    from pathlib import Path

    from redsentinel.defenses.engine.config import DEFAULT_TEST_PDF

    if not Path(DEFAULT_TEST_PDF).exists():
        return "[SEARCH_FAIL] No default PDF is available. Upload a PDF before running this check."

    from redsentinel.defenses.engine.rag.retriever import init_rag_retriever

    default_retriever = init_rag_retriever()
    all_docs = default_retriever.get("docs", [])
    full_text = "\n".join(getattr(doc, "page_content", "") for doc in all_docs)
    if not full_text.strip():
        return "[SEARCH_FAIL] The loaded PDF did not contain extractable text."
    has_risk, result = detect_sensitive_info(full_text)
    return result

@tool(args_schema=SimpleVulnScanInput)
def simple_vuln_scan(url: str) -> str:
    """
    【用途】扫描URL的常见Web基础漏洞
    【调用场景】用户要求扫描网站、检测URL漏洞、做安全扫描
    """
    # 清理参数
    url = url.strip().replace('"', '').replace("'", "").replace("url=", "").strip()
    report = f"【简易漏洞扫描报告】\n目标URL：{url}\n\n"
    
    # 自动补全URL
    if not url.startswith(("http://", "https://")):
        if "." in url:
            url = f"https://{url}"
            report += f"[i] 自动补全URL为：{url}\n\n"
        else:
            return "[X] 格式错误：请输入以 http:// 或 https:// 开头的有效URL"
    
    # 漏洞规则检测
    risk_count = 0
    if "?" in url:
        report += "[!] 风险点1：URL携带查询参数，存在SQL注入、XSS攻击风险\n"
        risk_count += 1
    if "login" in url.lower() or "signin" in url.lower():
        report += "[!] 风险点2：登录页面，需检查弱口令、暴力破解风险\n"
        risk_count += 1
    if "admin" in url.lower() or "manage" in url.lower():
        report += "[!] 风险点3：后台管理路径，需验证权限控制、未授权访问风险\n"
        risk_count += 1
    if "api" in url.lower():
        report += "[!] 风险点4：API接口，需检查越权访问、数据泄露风险\n"
        risk_count += 1
    
    if risk_count == 0:
        report += "[OK] 未检测到明显的基础风险点\n"
    
    report += f"\n[*] 扫描结果：共发现{risk_count}个潜在风险点"
    report += "\n\n注：本扫描为演示版规则检测，仅用于学习，不代表专业安全评估"
    return report

@tool(args_schema=SqlInjectionCheckInput)
def check_sql_injection(content: str) -> str:
    """
    【用途】检测内容中的SQL注入攻击风险
    【调用场景】用户要求检测SQL语句、URL参数、用户输入是否存在注入风险
    """
    # SQL注入特征库（覆盖主流注入payload）
    SQL_INJECTION_PATTERNS = [
        r"union\s+select", r"or\s+1=1", r"or\s+1=2", r"and\s+1=1", r"and\s+1=2",
        r"--", r";", r"#", r"/\*.*\*/", r"xp_cmdshell", r"exec\s+", r"execute\s+",
        r"drop\s+table", r"drop\s+database", r"insert\s+into", r"update\s+set",
        r"delete\s+from", r"alter\s+table", r"create\s+table", r"truncate\s+table",
        r"where\s+.*=\s*'", r"'\s+or\s+'", r"'\s+and\s+'", r"sleep\(", r"benchmark\("
    ]
    
    content_lower = content.lower()
    risk_list = []
    
    for pattern in SQL_INJECTION_PATTERNS:
        import re
        if re.search(pattern, content_lower):
            risk_list.append(f"检测到注入特征：{pattern.strip()}")
    
    report = f"【SQL注入检测报告】\n检测内容：{content[:100]}{'...' if len(content)>100 else ''}\n\n"
    if not risk_list:
        report += "[OK] 未检测到明显的SQL注入风险特征"
    else:
        report += "[X] 检测到SQL注入风险，风险特征如下：\n"
        report += "\n".join(risk_list)
        report += "\n\n[!] 该内容存在SQL注入攻击风险，禁止直接传入数据库执行"
    
    return report

# 工具列表（简化为4个安全工具，RAG直接集成到Agent里）
SEC_AGENT_TOOLS = [
    check_sensitive_information,
    detect_pdf_sensitive_info,
    simple_vuln_scan,
    check_sql_injection
]
