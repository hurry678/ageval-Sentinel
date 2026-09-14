"""
LangGraph-based Agent — replaces the procedural agent_invoke() with a StateGraph.

Architecture:
  START -> guardrail -> agent <=> tools -> output_filter -> finalize -> END
"""

import contextvars
import operator
import re
import sqlite3
from typing import Annotated, Optional, TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.checkpoint.sqlite import SqliteSaver

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI

from redsentinel.defenses.engine.config import LLM_MODEL, LLM_API_BASE, LLM_API_KEY, CHECKPOINT_DIR, CHECKPOINT_DB
from redsentinel.defenses.engine.tools.sec_tools import SEC_AGENT_TOOLS
from redsentinel.defenses.engine.rag.retriever import rag_query
from redsentinel.defenses.engine.security.permission import get_allowed_tools, DEFAULT_ROLE
from redsentinel.defenses.engine.security.output.filter import mask_sensitive_info
from redsentinel.defenses.engine.security.audit import write_audit_log
from redsentinel.defenses.engine.security.firewall.classifier import classify_with_old_fallback, classify_with_context

# ContextVar lets the RAG tool access the session's retriever without
# putting non-serializable objects in LangGraph state.
_current_retriever: contextvars.ContextVar = contextvars.ContextVar('current_retriever', default=None)


@tool
def search_document(query: str) -> str:
    """Search the uploaded PDF document for information. Use when the user asks
    about document content, policies, rules, or specific topics in the uploaded file.
    If no results found, try different keywords — shorter queries, synonyms,
    or terms that are more likely to appear in the document."""
    retriever = _current_retriever.get()
    if not retriever or not retriever.get("docs"):
        return "[SEARCH_FAIL] No document is currently loaded. Ask the user to upload a PDF first."

    context, source_docs = rag_query(retriever, query)
    # Security: scan retrieved chunks for poisoned content
    if source_docs:
        try:
            from redsentinel.defenses.engine.security.ingest.doc_scanner import scan_retrieved_chunks
            ctxs = [s.get("content", "") for s in source_docs]
            scans = scan_retrieved_chunks(ctxs)
            if scans:
                poisoned = [s for s in scans if s.get("should_filter")]
                safe = [s for s in scans if not s.get("should_filter")]
                if poisoned:
                    context += (f"\n\n[SEC] {len(poisoned)}/{len(scans)} 个检索片段"
                                f"含可疑投毒内容，已过滤。安全片段: {len(safe)}")
        except ImportError:
            pass
    if not source_docs or "未找到" in context:
        return (
            f"[SEARCH_RETRY] No results for '{query[:100]}'. "
            f"Try: (1) shorter keywords (2) synonyms (3) terms that likely appear in the document. "
            f"Call search_document again with a different query."
        )

    result = context
    if source_docs:
        result += "\n\n---\n[*] Reference sources:\n"
        for doc in source_docs[:5]:
            result += f"[{doc['id']}] {doc['file_name']} page {doc['page']}\n"
    return result


# Global tool name -> function mapping (tool_node needs it independent of role filtering)
_ALL_TOOLS_BY_NAME = {t.name: t for t in SEC_AGENT_TOOLS}
_ALL_TOOLS_BY_NAME["search_document"] = search_document
_DANGEROUS_TOOL_NAMES: set[str] = set()
try:
    from redsentinel.defenses.engine.tools.dangerous import DANGEROUS_TOOLS
    for _tool in DANGEROUS_TOOLS:
        _ALL_TOOLS_BY_NAME[_tool.name] = _tool
        _DANGEROUS_TOOL_NAMES.add(_tool.name)
except ImportError:
    DANGEROUS_TOOLS = []


_llm = None


def _get_llm():
    global _llm
    if _llm is None:
        _llm = ChatOpenAI(
            model=LLM_MODEL,
            temperature=0.0,
            max_tokens=1024,
            openai_api_base=LLM_API_BASE,
            openai_api_key=LLM_API_KEY
        )
    return _llm


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    user_role: str
    security_blocked: bool
    audit_entries: Annotated[list, operator.add]
    tool_call_count: int
    conversation_summary: str
    guardrail_category: str
    guardrail_score: int


RETRY_LIMIT = 3
MAX_TOOL_RESULT = 2000


def _summarize_tool_result(tool_name: str, full_content: str) -> str:
    """Summarize long tool output via LLM instead of blind truncation."""
    prompt = f"""Summarize this tool output concisely. Keep ALL specific data (numbers, URLs, IPs, names, findings, risk levels, file paths). Only remove redundancy. Output in Chinese, ~600 chars max.

Tool: {tool_name}
Output ({len(full_content)} chars):
{full_content[:4000]}

Concise summary:"""

    try:
        response = _get_llm().invoke(prompt)
        return response.content.strip() if hasattr(response, 'content') else full_content[:MAX_TOOL_RESULT] + "..."
    except Exception:
        return full_content[:MAX_TOOL_RESULT] + f"\n...[truncated, {len(full_content)} chars total]"


def guardrail_node(state: AgentState) -> dict:
    messages = state["messages"]
    last_msg = messages[-1]
    user_input = last_msg.content if hasattr(last_msg, 'content') else str(last_msg)

    # Extract prior user messages for multi-turn context detection
    prior_user_msgs = []
    for m in messages[:-1]:
        if hasattr(m, 'content'):
            content = m.content if isinstance(m.content, str) else str(m.content)
            # Only collect user messages (not system or AI)
            if hasattr(m, 'type') and m.type == 'human':
                prior_user_msgs.append(content)

    # Use context-aware classification if prior messages exist
    if prior_user_msgs:
        is_risk, risk_msg, detail = classify_with_context(user_input, prior_user_msgs)
    else:
        is_risk, risk_msg, detail = classify_with_old_fallback(user_input)

    if is_risk:
        return {
            "security_blocked": True,
            "messages": [AIMessage(content=risk_msg)],
            "audit_entries": [
                f"SEC_BLOCK | {state['user_role']} | "
                f"cat={detail.get('category','?')} | "
                f"score={detail.get('risk_score','?')} | "
                f"layer={detail.get('layer','?')} | "
                f"reason={detail.get('reasoning','?')[:50]} | "
                f"input={user_input[:60]}"
            ],
            "guardrail_category": detail.get("category", ""),
            "guardrail_score": detail.get("risk_score", 0),
        }
    return {
        "security_blocked": False,
        "guardrail_category": "normal",
        "guardrail_score": detail.get("risk_score", 0),
    }


def agent_node(state: AgentState) -> dict:
    role = state.get("user_role", DEFAULT_ROLE)
    retriever = _current_retriever.get()
    count = state.get("tool_call_count", 0)

    allowed_names = get_allowed_tools(role)
    available_tools = [t for t in SEC_AGENT_TOOLS if t.name in allowed_names]

    if retriever and retriever.get("docs") and "search_knowledge_base" in allowed_names:
        available_tools.append(search_document)

    # Admin gets dangerous simulated tools for policy demo.
    if role == "admin":
        available_tools.extend(DANGEROUS_TOOLS)

    role_labels = {
        "guest": "Guest (knowledge base only)",
        "user": "User (KB + sensitive info detection)",
        "admin": "Admin (all security tools)"
    }

    summary = state.get("conversation_summary", "")
    summary_block = f"[Prior conversation context]\n{summary}\n\n" if summary else ""

    tool_desc = ", ".join(t.name for t in available_tools) if available_tools else "none"
    system_prompt = f"""{summary_block}You are an AI security assistant. Answer in Chinese.

User role: {role_labels.get(role, role)}
Available tools: {tool_desc}
Tools used this turn: {count}/{RETRY_LIMIT}

Rules:
- Use tools when the user asks for scanning, detection, or document search
- When the user asks for MULTIPLE independent tasks at once (e.g. scan a URL AND check SQL injection), call all relevant tools simultaneously in one response
- If the user asks something unrelated to your tools, answer directly
- Be concise and professional

Keyword retry for document search:
- If search_document returns [SEARCH_RETRY], reformulate the query: use shorter keywords, try synonyms, or guess terms likely in the document
- Call search_document again with the new query. Up to 2 retries
- Only tell the user "not found" after 2 search attempts with different keywords

Self-healing on tool errors:
- If a tool returns [TOOL_ERROR], read the Error, Hint, and Called-with fields
- Fix the obvious issue yourself: missing http:// prefix, empty parameter, wrong argument name, etc.
- Retry with the fixed parameters. If it fails again, explain the issue to the user
- If the fix isn't obvious from the error, explain to the user what's needed"""

    full_messages = [SystemMessage(content=system_prompt)] + list(state["messages"])
    llm = _get_llm()

    if count >= RETRY_LIMIT:
        response = llm.invoke(full_messages)
    else:
        model = llm.bind_tools(available_tools) if available_tools else llm
        response = model.invoke(full_messages)
    return {"messages": [response]}


def output_filter_node(state: AgentState) -> dict:
    messages = state["messages"]
    last_msg = messages[-1]
    answer = last_msg.content if hasattr(last_msg, 'content') else str(last_msg)

    # Minimal filter: as a security education tool, discussing attack techniques
    # in an educational context is expected. Only block actual executable payloads.
    import re as _re
    EXEC_PATTERNS = [
        r'xp_cmdshell', r'exec\s+master\.', r'execute\s+sp_',
        r'shell_exec\(', r'passthru\(', r'popen\(', r'system\(',
    ]
    blocked = any(_re.search(p, answer.lower()) for p in EXEC_PATTERNS)
    if blocked:
        return {
            "messages": [AIMessage(content="[!] 输出内容包含可执行高危代码，已拦截")],
            "audit_entries": ["OUT_BLOCK"]
        }

    # Fact-check RAG answers against retrieved context
    if len(answer) > 50:
        try:
            from redsentinel.defenses.engine.agent.react import fact_check
            context_for_check = ""
            for m in reversed(messages):
                if isinstance(m, ToolMessage):
                    content = m.content if hasattr(m, 'content') else str(m)
                    if content and len(content) > len(context_for_check):
                        context_for_check = content
            if context_for_check:
                verified = fact_check(answer, context_for_check, min_phrase_match_ratio=0.02)
                if verified != answer:
                    return {
                        "messages": [AIMessage(content=verified)],
                        "audit_entries": ["FACT_CHECK: answer not grounded in retrieved context"],
                    }
        except ImportError:
            pass

    masked = mask_sensitive_info(answer)
    if masked != answer:
        return {"messages": [AIMessage(content=masked)]}
    return {}


def finalize_node(state: AgentState, config: RunnableConfig) -> dict:
    user_id = config.get("configurable", {}).get("user_id", "default")
    role = state.get("user_role", DEFAULT_ROLE)
    messages = state["messages"]

    user_input = ""
    for m in messages:
        if isinstance(m, HumanMessage):
            user_input = m.content if hasattr(m, 'content') else str(m)

    final_answer = ""
    for m in reversed(messages):
        if isinstance(m, AIMessage) and not (hasattr(m, 'tool_calls') and m.tool_calls):
            final_answer = m.content if hasattr(m, 'content') else str(m)
            break

    has_tool = any(
        isinstance(m, AIMessage) and hasattr(m, 'tool_calls') and m.tool_calls
        for m in messages
    )
    op_type = "Agent工具调用" if has_tool else "对话"
    if any("search_document" in str(m) for m in messages):
        op_type = "RAG知识库问答"

    write_audit_log(user_id, role, op_type, user_input, final_answer, "normal")

    for entry in state.get("audit_entries", []):
        write_audit_log(user_id, role, "审计", entry[:200], "", "high" if "BLOCK" in entry else "low")

    return {}


def route_after_guardrail(state: AgentState) -> str:
    return "finalize" if state.get("security_blocked") else "agent"


def route_after_agent(state: AgentState) -> str:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, 'tool_calls') and last_msg.tool_calls:
        return "tools"
    return "output_filter"


def _format_tool_error(tool_name: str, args: dict, error: Exception) -> str:
    """Build a structured error message that helps the LLM self-heal."""
    import json as _json
    err_type = type(error).__name__
    err_str = str(error)

    hints = {
        "simple_vuln_scan": "Check that 'url' starts with http:// or https:// and contains a valid domain.",
        "check_sql_injection": "Ensure 'content' is a non-empty string with SQL-like patterns.",
        "check_sensitive_information": "Ensure 'text' is provided as a non-empty string.",
        "search_document": "Make sure a PDF document has been uploaded first. The query should be a clear question.",
    }

    hint = hints.get(tool_name, "Check the parameter types and try again.")
    return (
        f"[TOOL_ERROR] Tool '{tool_name}' failed.\n"
        f"Error: {err_type}: {err_str}\n"
        f"Called with: {_json.dumps(args, ensure_ascii=False)}\n"
        f"Hint: {hint}\n"
        f"Please fix the parameters and call the tool again."
    )


def _tool_allowed_for_role(tool_name: str, role: str) -> bool:
    allowed_names = set(get_allowed_tools(role))
    if tool_name == "search_document":
        return "search_knowledge_base" in allowed_names
    if tool_name in allowed_names:
        return True
    return role == "admin" and tool_name in _DANGEROUS_TOOL_NAMES


def tool_node(state: AgentState) -> dict:
    messages = state["messages"]
    last_msg = messages[-1]
    if not hasattr(last_msg, "tool_calls") or not last_msg.tool_calls:
        return {}

    count = state.get("tool_call_count", 0)
    tool_messages = []
    role = state.get("user_role", DEFAULT_ROLE)

    for tc in last_msg.tool_calls:
        tool_name = tc["name"]
        tool_args = tc["args"]
        count += 1

        if not _tool_allowed_for_role(tool_name, role):
            tool_messages.append(ToolMessage(
                content=f"[TOOL_PERMISSION_BLOCK] Role '{role}' cannot use tool '{tool_name}'.",
                tool_call_id=tc["id"],
            ))
            continue

        tool_fn = _ALL_TOOLS_BY_NAME.get(tool_name)
        if not tool_fn:
            tool_messages.append(ToolMessage(
                content=f"Tool '{tool_name}' not available.", tool_call_id=tc["id"]
            ))
            continue

        # Tool Policy Engine check.
        try:
            from redsentinel.defenses.engine.security.policy.engine import check_policy, write_policy_audit
            allowed, reason, detail = check_policy(tool_name, tool_args, state)
            if not allowed:
                tool_messages.append(ToolMessage(
                    content=f"[TOOL_POLICY_BLOCK] {reason}",
                    tool_call_id=tc["id"]
                ))
                write_policy_audit(tool_name, tool_args, False, detail,
                                   role=state.get("user_role", "user"))
                continue
        except ImportError:
            pass

        try:
            result = tool_fn.invoke(tool_args)
            content_str = str(result)
            if len(content_str) > MAX_TOOL_RESULT:
                content_str = _summarize_tool_result(tool_name, content_str)
            tool_messages.append(ToolMessage(content=content_str, tool_call_id=tc["id"]))
        except Exception as e:
            error_msg = _format_tool_error(tool_name, tool_args, e)
            tool_messages.append(ToolMessage(content=error_msg, tool_call_id=tc["id"]))

    return {"messages": tool_messages, "tool_call_count": count}


def _build_graph(checkpointer=None):
    builder = StateGraph(AgentState)

    builder.add_node("guardrail", guardrail_node)
    builder.add_node("agent", agent_node)
    builder.add_node("tools", tool_node)
    builder.add_node("output_filter", output_filter_node)
    builder.add_node("finalize", finalize_node)

    builder.add_edge(START, "guardrail")
    builder.add_conditional_edges("guardrail", route_after_guardrail, {
        "agent": "agent",
        "finalize": "finalize"
    })
    builder.add_conditional_edges("agent", route_after_agent, {
        "tools": "tools",
        "output_filter": "output_filter"
    })
    builder.add_edge("tools", "agent")
    builder.add_edge("output_filter", "finalize")
    builder.add_edge("finalize", END)

    return builder.compile(checkpointer=checkpointer)


_graph = None
_checkpointer = None


def _get_graph():
    global _graph, _checkpointer
    if _graph is None:
        CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(CHECKPOINT_DB), check_same_thread=False)
        _checkpointer = SqliteSaver(conn)
        _graph = _build_graph(checkpointer=_checkpointer)
    return _graph


def clear_history(thread_id: str) -> bool:
    """Delete checkpoint state for a given thread_id."""
    global _checkpointer
    _get_graph()  # ensure initialized
    if _checkpointer is None:
        return False
    try:
        _checkpointer.delete_thread(thread_id)
        return True
    except Exception:
        return False


def get_thread_messages(thread_id: str) -> list:
    """Return UI-friendly message dicts from checkpointed thread state.
    Returns [{"role": "user"|"assistant", "content": "..."}, ...]"""
    graph = _get_graph()
    config = {"configurable": {"thread_id": thread_id}}
    saved = graph.get_state(config)
    if not saved or not saved.values:
        return []
    messages = saved.values.get("messages", [])
    result = []
    for m in messages:
        if hasattr(m, 'tool_calls') and m.tool_calls:
            continue  # skip intermediate tool-call messages
        if isinstance(m, HumanMessage):
            result.append({"role": "user", "content": m.content})
        elif isinstance(m, AIMessage):
            result.append({"role": "assistant", "content": m.content})
    return result


FORGET_PATTERN = re.compile(r"(?:忘掉|忘记|forget|删除.*(?:记录|记忆|对话))[：:\s]*(.+)", re.IGNORECASE)


def _generate_summary(messages: list) -> str:
    """Compress old conversation messages into a 2-3 sentence Chinese summary."""
    if not messages:
        return ""
    lines = []
    for m in messages:
        role = "用户" if isinstance(m, HumanMessage) else "助手"
        content = m.content if hasattr(m, 'content') else str(m)
        lines.append(f"[{role}]: {content[:300]}")
    text = "\n".join(lines)

    prompt = f"""Summarize the key context from this conversation in 2-3 Chinese sentences.
Focus on: who the user is, what they are working on, any important facts or decisions.
Do NOT re-execute or continue the conversation — only summarize the existing content.

Conversation:
{text}

Summary (2-3 sentences in Chinese):"""

    try:
        response = _get_llm().invoke(prompt)
        return response.content.strip() if hasattr(response, 'content') else ""
    except Exception:
        return ""


def graph_invoke(
    user_input: str,
    role: str = DEFAULT_ROLE,
    retriever: Optional[dict] = None,
    user_id: str = "default",
    chat_history: Optional[list] = None,
    max_history: int = 20,
    thread_id: str = None,
) -> str:
    _current_retriever.set(retriever)
    graph = _get_graph()

    # When chat_history is provided (Streamlit), caller manages state.
    # Use a unique per-call thread_id to avoid merging with prior checkpoint.
    # When chat_history is None (CLI), rely entirely on checkpointer.
    has_caller_history = chat_history is not None
    if has_caller_history:
        history = list(chat_history)
        tid = f"{thread_id or user_id}_{hash(tuple())}"  # unique per call
        saved_summary = ""
        # Each call gets a fresh checkpoint ID to avoid message duplication
        import uuid
        tid = f"{thread_id or user_id}_{uuid.uuid4().hex[:8]}"
    else:
        history = []
        tid = thread_id or user_id
        saved = graph.get_state({"configurable": {"thread_id": tid}})
        if saved and saved.values:
            history = list(saved.values.get("messages", []))
            saved_summary = saved.values.get("conversation_summary", "")
        else:
            saved_summary = ""

    config = {"configurable": {"thread_id": tid, "user_id": user_id}}

    # Precise forgetting: user says "forget X" -> remove matching messages
    forget_match = FORGET_PATTERN.search(user_input)
    if forget_match:
        target = forget_match.group(1).strip()
        tokens = [t for t in re.split(r'[\s,，。]+', target) if len(t) >= 4]
        tokens.append(target)
        new_history = []
        for m in history:
            content = m.content if hasattr(m, 'content') else str(m)
            if any(t in content for t in tokens):
                continue
            new_history.append(m)
        removed = len(history) - len(new_history)
        if has_caller_history:
            chat_history.clear()
            chat_history.extend(new_history)
        return f"已遗忘 {removed} 条与「{target}」相关的对话记录。"

    # Summary generation: compress old messages when exceeding max_history
    summary = saved_summary
    if len(history) > max_history:
        old = history[:-max_history]
        history = history[-max_history:]
        summary = _generate_summary(old)
        if has_caller_history:
            chat_history.clear()
            chat_history.extend(history)

    # Build state messages:
    # - Caller-managed: pass full history + new msg (no checkpoint merge risk with unique tid)
    # - Checkpointer-managed: pass only new msg (add_messages appends to checkpoint)
    if has_caller_history:
        state_messages = history + [HumanMessage(content=user_input)]
    else:
        state_messages = [HumanMessage(content=user_input)]

    state = {
        "messages": state_messages,
        "user_role": role,
        "security_blocked": False,
        "audit_entries": [],
        "tool_call_count": 0,
        "conversation_summary": summary,
        "guardrail_category": "",
        "guardrail_score": 0,
    }

    result = graph.invoke(state, config)

    result_messages = result["messages"]
    for m in reversed(result_messages):
        if isinstance(m, AIMessage) and not (hasattr(m, 'tool_calls') and m.tool_calls):
            return m.content

    return "Agent did not produce a response."
