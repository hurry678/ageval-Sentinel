"""文档安全扫描器 — L1规则扫描 + L2级联LLM分类。

L1（入库+检索时）：纯规则，零API调用，微秒级。检测7类投毒特征。
L2（检索时）：级联策略——仅L1标记可疑的chunk调LLM classify()，~14s/条。

复用 classifier._normalize_input, classifier.COMPOUND_PAIRS, classifier._check_compound_pairs,
     classifier.classify, security.input_check.check_malicious_input
"""

import re
import unicodedata

# Reuse existing firewall components
from redsentinel.defenses.engine.security.firewall.classifier import (
    _normalize_input, _check_compound_pairs, classify
)
from redsentinel.defenses.engine.security.firewall.input_guard import check_malicious_input

# ---------------------------------------------------------------------------
# L1: Rule-based chunk scanning (7 checks, no API calls)
# ---------------------------------------------------------------------------

# Zero-width and invisible characters
ZERO_WIDTH_CHARS = re.compile(r'[​‌‍﻿‎‏‪‫‬‭‮]')

# Base64 pattern: 40+ base64 chars, possibly with = padding
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

# Decode-related keywords suggesting base64 should be decoded
DECODE_HINTS = re.compile(r'(解码|解密|base64|decode|执行.{0,10}指令|反转|reverse|从右向左)',
                          re.IGNORECASE)

# Suspicious metadata field names
SUSPICIOUS_META_FIELDS = re.compile(
    r'(忽略|忘记|无视|DAN|越狱|解除限制|无限制|系统提示|prompt|指令|注入)',
    re.IGNORECASE
)

# Unicode script ranges for homoglyph detection
MIXED_SCRIPT_THRESHOLD = 0.05  # if >5% chars from "unusual" scripts, flag


def _count_zero_width(text: str) -> tuple[int, int]:
    """Count zero-width characters in text. Returns (zero_width_count, total_chars)."""
    total = len(text)
    if total == 0:
        return 0, 0
    zw_count = len(ZERO_WIDTH_CHARS.findall(text))
    return zw_count, total


def _detect_mixed_script(text: str) -> bool:
    """Detect if text mixes Latin with visually-confusable non-Latin scripts."""
    confusable = 0
    total = 0
    for ch in text:
        if ch.isalpha():
            total += 1
            name = unicodedata.name(ch, '')
            # Cyrillic, Greek, Mathematical Alphanumerics look like Latin
            if any(tag in name for tag in ('CYRILLIC', 'GREEK', 'MATHEMATICAL')):
                confusable += 1
    if total == 0:
        return False
    return (confusable / total) > MIXED_SCRIPT_THRESHOLD


def _detect_base64_encoding(text: str) -> bool:
    """Check if text contains Base64-encoded payload with decode hint."""
    has_b64 = bool(BASE64_PATTERN.search(text))
    has_hint = bool(DECODE_HINTS.search(text))
    return has_b64 and has_hint


def _char_ratio_anomaly(text: str) -> bool:
    """Check if visible/total char ratio is suspiciously low (< 0.3)."""
    total = len(text)
    if total == 0:
        return False
    visible = len(text.strip())
    return (visible / total) < 0.3


def _detect_hidden_text_per_line(text: str) -> bool:
    """Check if any line has mostly invisible content but long total length."""
    for line in text.split('\n'):
        stripped = line.strip()
        if len(stripped) < 3 and len(line) > 100:
            return True
    return False


def _check_metadata_fields(metadata: dict) -> tuple[bool, list[str]]:
    """Scan metadata values for suspicious keywords."""
    if not metadata:
        return False, []
    flags = []
    for key, value in metadata.items():
        if not value:
            continue
        blocked, msg = check_malicious_input(str(value))
        if blocked:
            flags.append(f"metadata_{key}")
        elif SUSPICIOUS_META_FIELDS.search(str(value)):
            flags.append(f"metadata_{key}_suspicious")
    return len(flags) > 0, flags


def _detect_html_hidden_text(text: str) -> bool:
    """Rule 8: HTML hidden text via CSS — display:none, visibility:hidden, font-size:0, opacity:0."""
    hidden_patterns = [
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
        r"font-size\s*:\s*0",
        r"opacity\s*:\s*0",
        r"<noscript>",
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in hidden_patterns)


def _detect_link_lure(text: str) -> bool:
    """Rule 9: Link lure — <a href="evil.com"> but text suggests safe destination."""
    # Find all <a> tags where href contains external-looking domain
    import re as _re
    links = _re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>', text, re.IGNORECASE)
    suspicious_domains = ["evil", "exfil", "steal", "hack", "attack", "malware", "phish"]
    for href, link_text in links:
        if any(d in href.lower() for d in suspicious_domains):
            # Link text doesn't match — possible lure
            if not any(d in link_text.lower() for d in suspicious_domains):
                return True
    return False


def _detect_forged_urgency(text: str) -> bool:
    """Rule 10: Forged email urgency — X-Priority: 1 + executive action verbs."""
    has_urgent_header = bool(re.search(r"X-Priority\s*:\s*1", text, re.IGNORECASE))
    has_exec_verbs = bool(re.search(
        r"(立即|马上|紧急|务必|尽快|立刻|immediately|urgent|mandatory)",
        text, re.IGNORECASE,
    ))
    has_action = bool(re.search(
        r"(执行|删除|运行|调用|写入|发送|execute|delete|run|call|write|send)",
        text, re.IGNORECASE,
    ))
    return has_urgent_header and has_exec_verbs and has_action


def _detect_markdown_html_injection(text: str) -> bool:
    """Rule 11: Markdown HTML injection — <div style>, <script> embedded in .md files."""
    script_tag = bool(re.search(r"<script[^>]*>", text, re.IGNORECASE))
    hidden_div = bool(re.search(r"<div[^>]*style\s*=\s*[\"'][^\"']*display\s*:\s*none", text, re.IGNORECASE))
    return script_tag or hidden_div


def scan_chunk_l1(text: str, metadata: dict = None) -> dict:
    """L1 rule-based chunk scan. Returns {is_suspicious, risk_score, flags[], sanitized_text}.

    Checks 11 attack vectors:
    1. Zero-width character ratio > 5%
    2. Mixed-script / homoglyph detection
    3. Base64 encoding + decode hint
    4. Compound keyword pairs (reuse classifier.COMPOUND_PAIRS)
    5. Character ratio anomaly (invisible/visible)
    6. Hidden text per line
    7. Metadata field poisoning
    """
    flags = []
    risk_score = 0

    # Pre-normalize for keyword matching
    normalized = _normalize_input(text)

    # 1. Zero-width character check
    zw_count, total_chars = _count_zero_width(text)
    if total_chars > 0 and (zw_count / total_chars) > 0.05:
        flags.append("zero_width_obfuscation")
        risk_score = max(risk_score, 75)

    # 2. Mixed-script / homoglyph check
    if _detect_mixed_script(normalized):
        flags.append("homoglyph_obfuscation")
        risk_score = max(risk_score, 70)

    # 3. Base64 encoding check
    if _detect_base64_encoding(normalized):
        flags.append("encoding_bypass")
        risk_score = max(risk_score, 80)

    # 4. Compound keyword pairs (reuse classifier)
    compound_result = _check_compound_pairs(normalized.lower())
    if compound_result:
        flags.append("suspicious_keyword_pair")
        risk_score = max(risk_score, compound_result.get("risk_score", 80))

    # 5. Character ratio anomaly
    if _char_ratio_anomaly(text):
        flags.append("hidden_text_suspected")
        risk_score = max(risk_score, 60)

    # 6. Hidden text per line
    if _detect_hidden_text_per_line(text):
        flags.append("white_text_suspected")
        risk_score = max(risk_score, 65)

    # 7. Metadata check
    meta_flagged, meta_flags = _check_metadata_fields(metadata)
    if meta_flagged:
        flags.extend(meta_flags)
        risk_score = max(risk_score, 75)

    # 8. HTML hidden text (CSS display:none, visibility:hidden, font-size:0)
    if _detect_html_hidden_text(text):
        flags.append("html_hidden_text")
        risk_score = max(risk_score, 80)

    # 9. Link lure detection (<a> with text != href target domain)
    if _detect_link_lure(text):
        flags.append("link_lure")
        risk_score = max(risk_score, 65)

    # 10. Forged email urgent headers (X-Priority + executive action verbs)
    if _detect_forged_urgency(text):
        flags.append("forged_urgency")
        risk_score = max(risk_score, 70)

    # 11. Markdown inline HTML injection (<div style>, <script> in .md)
    if _detect_markdown_html_injection(text):
        flags.append("markdown_html_injection")
        risk_score = max(risk_score, 75)

    return {
        "is_suspicious": len(flags) > 0,
        "risk_score": risk_score,
        "flags": flags,
        "sanitized_text": normalized,
    }


# ---------------------------------------------------------------------------
# L2: Cascading chunk scan (L1 pre-filter -> LLM classify on suspicious only)
# ---------------------------------------------------------------------------

def scan_retrieved_chunks(chunks: list, threshold: int = 50) -> list[dict]:
    """Cascading scan of retrieved chunks: L1 on all -> L2 (LLM) only on L1-flagged.

    Args:
        chunks: list of chunk text strings, or list of {text, metadata} dicts
        threshold: risk_score threshold for LLM escalation (default 50)

    Returns:
        list of [{chunk_index, text, risk_score, category, should_filter, reasoning, layer}]
    """
    results = []
    for i, chunk in enumerate(chunks):
        if isinstance(chunk, dict):
            text = chunk.get("text", chunk.get("page_content", ""))
            metadata = chunk.get("metadata", None)
        else:
            text = str(chunk)
            metadata = None

        # Stage 1: L1 rule scan (fast, microseconds)
        l1_result = scan_chunk_l1(text, metadata)

        if l1_result["is_suspicious"] and l1_result["risk_score"] >= threshold:
            # Stage 2: LLM semantic classification (slow, ~14s)
            try:
                l2_result = classify(text)
                results.append({
                    "chunk_index": i,
                    "text_preview": text[:200],
                    "risk_score": l2_result.get("risk_score", l1_result["risk_score"]),
                    "category": l2_result.get("category", "unknown"),
                    "should_filter": l2_result.get("should_block", False),
                    "reasoning": l2_result.get("reasoning", ""),
                    "layer": 2,
                    "l1_flags": l1_result["flags"],
                })
            except Exception:
                # LLM call failed; fall back to L1 decision
                results.append({
                    "chunk_index": i,
                    "text_preview": text[:200],
                    "risk_score": l1_result["risk_score"],
                    "category": "l1_fallback",
                    "should_filter": l1_result["risk_score"] >= threshold,
                    "reasoning": f"L2 classify() failed, L1 risk={l1_result['risk_score']} flags={l1_result['flags']}",
                    "layer": 1,
                    "l1_flags": l1_result["flags"],
                })
        else:
            # Clean or low-risk: pass through
            results.append({
                "chunk_index": i,
                "text_preview": text[:200],
                "risk_score": l1_result["risk_score"],
                "category": "clean",
                "should_filter": False,
                "reasoning": "L1 clean" + (f", flags={l1_result['flags']}" if l1_result['flags'] else ""),
                "layer": 1,
                "l1_flags": l1_result["flags"],
            })

    return results


# ---------------------------------------------------------------------------
# Ingestion-time sanitization
# ---------------------------------------------------------------------------

def sanitize_splits(splits: list) -> tuple[list, list[dict]]:
    """Sanitize document chunks at ingestion time. Returns (clean_splits, scan_reports).

    All chunks are kept in the index (removing them would break ingestion when
    all chunks are flagged). Instead, suspicious chunks are:
    1. Normalized (zero-width stripped, Unicode normalized)
    2. Tagged with poison scan metadata for L2 retrieval-time filtering

    The final block/allow decision happens at retrieval time via scan_retrieved_chunks().
    """
    clean_splits = []
    reports = []
    for split in splits:
        text = split.page_content if hasattr(split, 'page_content') else str(split)
        metadata = split.metadata if hasattr(split, 'metadata') else {}
        result = scan_chunk_l1(text, metadata)

        result["chunk_id"] = metadata.get("source", "unknown")
        reports.append(result)

        # Sanitize text (strip zero-width, normalize unicode)
        if hasattr(split, 'page_content'):
            split.page_content = result["sanitized_text"]
        # Tag metadata with scan results for retrieval-time use
        if hasattr(split, 'metadata'):
            split.metadata["_ps_risk"] = result["risk_score"]
            split.metadata["_ps_suspicious"] = result["is_suspicious"]
            split.metadata["_ps_flags"] = ",".join(result["flags"]) if result["flags"] else ""

        clean_splits.append(split)  # Keep all chunks

    return clean_splits, reports
