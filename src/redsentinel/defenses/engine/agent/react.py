from langchain_openai import ChatOpenAI
from redsentinel.defenses.engine.config import LLM_MODEL, LLM_API_BASE, LLM_API_KEY
from redsentinel.defenses.engine.tools.sec_tools import SEC_AGENT_TOOLS
from redsentinel.defenses.engine.rag.retriever import init_rag_retriever, rag_query
from redsentinel.defenses.engine.security.permission import check_tool_permission, DEFAULT_ROLE
from redsentinel.defenses.engine.security.firewall.input_guard import check_malicious_input
from redsentinel.defenses.engine.security.output.filter import mask_sensitive_info, check_output_compliance
from redsentinel.defenses.engine.security.audit import write_audit_log


class ConversationBufferMemory:
    """Minimal replacement for langchain.memory.ConversationBufferMemory (removed in langchain 1.x)."""
    def __init__(self, memory_key="chat_history", return_messages=True):
        self.memory_key = memory_key
        self.return_messages = return_messages
        self._history = []

    def save_context(self, inputs: dict, outputs: dict):
        self._history.append({"input": inputs, "output": outputs})

    def clear(self):
        self._history.clear()

def fact_check(answer: str, context: str, min_phrase_match_ratio: float = 0.05) -> str:
    """Verify answer is grounded in context. Uses Chinese character n-gram containment.
    Only blocks answers clearly disconnected from the context (very low phrase match)."""
    import re

    # Skip check for clearly negative answers, very short outputs, or fallback messages
    if "未找到" in answer or "未找到相关信息" in answer or len(answer) < 10:
        return answer

    def extract_key_phrases(text):
        clean = re.sub(r'[^一-鿿\w]', '', text)
        phrases = set()
        for length in [2, 3, 4]:
            for i in range(len(clean) - length + 1):
                phrases.add(clean[i:i+length])
        return phrases

    answer_phrases = extract_key_phrases(answer)
    if len(answer_phrases) < 8:
        return answer

    context_clean = re.sub(r'[^一-鿿\w]', '', context)

    matched = sum(1 for p in answer_phrases if p in context_clean)
    ratio = matched / len(answer_phrases) if answer_phrases else 1.0

    # Only block answers with extremely low phrase overlap (clear hallucination)
    if ratio < min_phrase_match_ratio:
        return "文档中未找到与该问题明确对应的内容。"
    return answer

# ===================== 大模型初始化（终极零随机配置） =====================
llm = ChatOpenAI(
    model=LLM_MODEL,
    temperature=0.0,
    max_tokens=1024,
    openai_api_base=LLM_API_BASE,
    openai_api_key=LLM_API_KEY
)

# 2. 全局对话记忆
memory = ConversationBufferMemory(
    memory_key="chat_history",
    return_messages=True
)

# 3. 工具映射
TOOL_MAP = {tool.name: tool for tool in SEC_AGENT_TOOLS}

# 4. 默认检索器（延迟加载，避免每次import都初始化embedding模型）
_default_retriever = None
_retriever_init_failed = False

def _get_default_retriever():
    global _default_retriever, _retriever_init_failed
    if _retriever_init_failed:
        return None
    if _default_retriever is None:
        try:
            _default_retriever = init_rag_retriever()
        except Exception as e:
            _retriever_init_failed = True
            print(f"[WARN] RAG retriever init failed: {e}")
            return None
    return _default_retriever

# 5. 修复版Agent
def agent_invoke(
    user_input: str,
    role: str = DEFAULT_ROLE,
    custom_memory=None,
    custom_retriever=None,
    user_id: str = "default"
) -> str:
    use_memory = custom_memory if custom_memory else memory
    use_retriever = custom_retriever if custom_retriever else _get_default_retriever()
    
    # 输入安全检测
    is_risk, risk_msg = check_malicious_input(user_input)
    if is_risk:
        write_audit_log(user_id, role, "安全拦截", user_input, risk_msg, "high")
        return risk_msg
    
    user_input_lower = user_input.lower()
    operation_type = "对话"
    
    # ---------------------- 智能路由：工具优先 -> RAG兜底 ----------------------
    tool_matched = False

    if any(keyword in user_input_lower for keyword in ["sql注入", "注入检测"]):
        tool_matched = True
        tool_to_call = "check_sql_injection"
        has_permission, permission_msg = check_tool_permission(tool_to_call, role)
        if not has_permission:
            write_audit_log(user_id, role, "权限拒绝", user_input, permission_msg, "low")
            return permission_msg
        try:
            tool_result = TOOL_MAP[tool_to_call].invoke({"content": user_input})
            final_answer = llm.invoke(f"整理成简洁专业的回答：\n{tool_result}").content
        except Exception as e:
            final_answer = f"工具调用出错：{str(e)}"

    elif any(keyword in user_input_lower for keyword in ["扫描", "漏洞"]):
        tool_matched = True
        tool_to_call = "simple_vuln_scan"
        has_permission, permission_msg = check_tool_permission(tool_to_call, role)
        if not has_permission:
            write_audit_log(user_id, role, "权限拒绝", user_input, permission_msg, "low")
            return permission_msg
        import re
        url_match = re.search(r"https?://[^\s]+", user_input)
        if not url_match:
            final_answer = "请提供完整URL"
        else:
            try:
                tool_result = TOOL_MAP[tool_to_call].invoke({"url": url_match.group()})
                final_answer = llm.invoke(f"整理成简洁专业的回答：\n{tool_result}").content
            except Exception as e:
                final_answer = f"工具调用出错：{str(e)}"

    elif any(keyword in user_input_lower for keyword in ["检测敏感", "隐私"]):
        tool_matched = True
        if any(keyword in user_input_lower for keyword in ["pdf", "文档"]):
            all_docs = use_retriever["bm25"].invoke("")
            full_text = "\n".join([doc.page_content for doc in all_docs])
            from redsentinel.defenses.engine.security.output.filter import detect_sensitive_info
            has_risk, result = detect_sensitive_info(full_text)
            final_answer = llm.invoke(f"整理成简洁专业的回答：\n{result}").content
        else:
            tool_to_call = "check_sensitive_information"
            has_permission, permission_msg = check_tool_permission(tool_to_call, role)
            if not has_permission:
                write_audit_log(user_id, role, "权限拒绝", user_input, permission_msg, "low")
                return permission_msg
            try:
                tool_result = TOOL_MAP[tool_to_call].invoke({"text": user_input})
                final_answer = llm.invoke(f"整理成简洁专业的回答：\n{tool_result}").content
            except Exception as e:
                final_answer = f"工具调用出错：{str(e)}"

    # RAG兜底：retriever有文档且非工具查询 -> 自动走RAG
    if not tool_matched:
        has_docs = use_retriever and use_retriever.get("docs")
        if has_docs:
            context, source_docs = rag_query(use_retriever, user_input)

            # 检查检索返回是否有效（非空且非"未找到"）
            if source_docs and "未找到" not in context:
                prompt = f"""你是文档分析助手。请根据【参考内容】回答用户问题。

参考内容来自PDF表格提取，数据格式说明：
- 表格的列值（如分类、类型、状态）通常出现在每行描述的末尾（最后2-4个字）
- 例如"xxx内容违规"中"内容违规"是类型值，"xxx答案问题"中"答案问题"是类型值
- 提示区的【可能分类/类型值】列出了文档中提取到的候选类型
- 区分"类型/分类的固定枚举值"和"具体的条目描述"

规则：
1. 先看提示区了解文档有哪些分类/类型，再到原文中找对应条目的描述
2. 只能根据参考内容回答，不编造。找不到时回答「文档中未找到相关信息」
3. 简洁回答，先概括再补充细节

【参考内容】
{context}

用户问题：{user_input}
"""

                try:
                    llm_response = llm.invoke(prompt)
                    if hasattr(llm_response, 'content') and llm_response.content:
                        final_answer = llm_response.content if isinstance(llm_response.content, str) else str(llm_response.content)
                    else:
                        final_answer = "文档中未找到相关信息。"
                except Exception:
                    final_answer = "文档中未找到相关信息。"

                final_answer = fact_check(final_answer, context)

                if source_docs and "未找到" not in final_answer:
                    final_answer += "\n\n---\n[*] 引用来源：\n"
                    for doc in source_docs:
                        final_answer += f"[{doc['id']}] {doc['file_name']} 第{doc['page']}页\n"

                operation_type = "RAG知识库问答"
            else:
                final_answer = "我是AI安全智能助手，支持：\n1. PDF文档问答（直接问我文档内容即可）\n2. 敏感信息检测（如：帮我检测敏感信息）\n3. SQL注入检测（如：帮我检测SQL注入）\n4. 网站漏洞扫描（如：帮我扫描 https://example.com）\n\n请提出相关问题。"
        else:
            final_answer = "我是AI安全智能助手，目前没有加载知识库文档。请上传PDF文档后提问，或使用以下功能：\n1. 敏感信息检测\n2. SQL注入检测\n3. 网站漏洞扫描\n\n请提出相关问题。"
    
    # 输出校验 -- RAG场景使用宽松规则，允许安全文档中的描述性安全术语
    is_compliance, compliance_msg = check_output_compliance(
        final_answer, is_rag_context=(operation_type == "RAG知识库问答")
    )
    if not is_compliance:
        write_audit_log(user_id, role, "输出拦截", user_input, compliance_msg, "high")
        return compliance_msg
    
    final_answer = mask_sensitive_info(final_answer)
    
    # 保存记忆
    use_memory.save_context({"input": user_input}, {"output": final_answer})
    write_audit_log(user_id, role, operation_type, user_input, final_answer, "normal")
    
    return final_answer