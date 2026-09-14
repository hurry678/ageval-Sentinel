from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""全量基准测试 — API限额自动切换 + 增量保存CSV

运行方式: python data/run_full_benchmark.py
输出: data/benchmarks/benchmark_YYYYMMDD_HHMMSS.csv
"""

import os
import csv
import time
from datetime import datetime


# ============================================================
# API 双key配置 + 自动切换
# ============================================================
API_POOL = [
    {
        "name": "ModelScope",
        "base": os.getenv("MODELSCOPE_API_BASE", "https://api-inference.modelscope.cn/v1"),
        "key": os.getenv("MODELSCOPE_API_KEY", os.getenv("LLM_API_KEY", "")),
    },
    {
        "name": "SiliconFlow",
        "base": os.getenv("SILICONFLOW_API_BASE", "https://api.siliconflow.cn"),
        "key": os.getenv("SILICONFLOW_API_KEY", ""),
    },
]
ACTIVE = 0  # index into API_POOL
MAX_RETRIES_PER_TEST = 3


def switch_api():
    global ACTIVE
    ACTIVE = (ACTIVE + 1) % len(API_POOL)
    api = API_POOL[ACTIVE]
    # 动态更新 config 模块中的值
    import redsentinel.defenses.engine.config as cfg
    cfg.LLM_API_BASE = api["base"]
    cfg.LLM_API_KEY = api["key"]
    print(f"\n  [API切换] -> {api['name']} ({api['base'][:35]}...)")
    return api


def current_api():
    return API_POOL[ACTIVE]


def apply_current_api():
    api = API_POOL[ACTIVE]
    import redsentinel.defenses.engine.config as cfg
    cfg.LLM_API_BASE = api["base"]
    cfg.LLM_API_KEY = api["key"]


# ============================================================
# 测试样本加载
# ============================================================
from redsentinel.evaluation.engine.benchmarks.benchmark import HACKAPROMPT_SAMPLES, GARAK_STYLE_PROBES

ALL_TESTS = []
for s in HACKAPROMPT_SAMPLES:
    s = dict(s)
    s["source"] = "HackAPrompt"
    ALL_TESTS.append(s)
for s in GARAK_STYLE_PROBES:
    s = dict(s)
    s["source"] = "Garak"
    s["level"] = 0
    s["expected_block"] = True  # all Garak probes are attacks
    ALL_TESTS.append(s)

TOTAL = len(ALL_TESTS)
print(f"全量基准测试: {TOTAL} 条 (HackAPrompt 30 + Garak 20)")

# ============================================================
# 输出文件准备
# ============================================================
OUTPUT_DIR = os.path.join(str(Path(__file__).resolve().parents[2]), 'data', 'benchmarks')
os.makedirs(OUTPUT_DIR, exist_ok=True)
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
CSV_PATH = os.path.join(OUTPUT_DIR, f"benchmark_{TIMESTAMP}.csv")

with open(CSV_PATH, "w", encoding="utf-8-sig", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["序号", "来源", "ID", "类别", "等级", "输入内容", "防火墙输出", "风险分",
                     "检测层", "检测类别", "期望拦截", "实际拦截", "是否合格", "延迟ms",
                     "API来源", "备注"])
print(f"输出文件: {CSV_PATH}")

# ============================================================
# 运行并增量保存
# ============================================================
apply_current_api()
api = current_api()
print(f"初始API: {api['name']} ({api['base'][:35]}...)")
print(f"{'='*70}")

def clear_classifier_cache():
    """清除 classifier 模块的 LLM 缓存，强制下次调用使用新 API 配置"""
    import redsentinel.defenses.engine.security.firewall.classifier as clf
    clf._classifier_llm = None


PASS = 0
FAIL = 0
ERRORS = 0

with open(CSV_PATH, "a", encoding="utf-8-sig", newline="") as f:
    writer = csv.writer(f)

    for idx, sample in enumerate(ALL_TESTS):
        sid = sample["id"]
        cat = sample.get("category", "?")
        lvl = sample.get("level", 0)
        content = sample["content"]
        expected = sample.get("expected_block", True)
        source = sample["source"]

        # --- 逐条测试 ---
        blocked = False
        risk_score = 0
        layer = "?"
        detected_cat = "?"
        latency_ms = 0
        note = ""
        api_used = current_api()["name"]

        for attempt in range(MAX_RETRIES_PER_TEST):
            try:
                apply_current_api()
                clear_classifier_cache()
                from redsentinel.defenses.engine.security.firewall.classifier import classify as classify_fn

                t0 = time.time()
                result = classify_fn(content)
                latency_ms = round((time.time() - t0) * 1000, 1)

                blocked = result.get("should_block", False)
                risk_score = result.get("risk_score", 0)
                layer = result.get("layer", "?")
                detected_cat = result.get("category", "?")
                break  # success

            except Exception as e:
                err_msg = str(e)[:200]
                if "429" in err_msg or "rate" in err_msg.lower() or "limit" in err_msg.lower():
                    print(f"  [WARN] {sid}: 限流 (attempt {attempt+1})")
                    switch_api()
                    api_used = current_api()["name"]
                    time.sleep(2)
                    continue
                elif "401" in err_msg or "403" in err_msg or "auth" in err_msg.lower():
                    print(f"  [WARN] {sid}: 认证失败, 切换API")
                    switch_api()
                    api_used = current_api()["name"]
                    time.sleep(1)
                    continue
                else:
                    note = f"API错误: {err_msg[:100]}"
                    ERRORS += 1
                    break
        else:
            note = f"重试{MAX_RETRIES_PER_TEST}次均失败"
            blocked = None
            ERRORS += 1

        # --- 判定是否合格 ---
        if blocked is None:
            qualified = "ERROR"
        elif blocked == expected:
            qualified = "PASS"
            PASS += 1
        else:
            qualified = "FAIL"
            FAIL += 1

        # --- 实时打印 ---
        icon = {"PASS": "[PASS]", "FAIL": "[FAIL]", "ERROR": "[ERR!]"}[qualified]
        status = "BLOCK" if blocked else "ALLOW"
        print(f"  {idx+1:03d}/{TOTAL} {icon} {sid:<12} L{lvl} {cat:<20} {status:<6} "
              f"risk={risk_score} layer={layer} {latency_ms}ms {api_used[:8]}")

        # --- 增量写入CSV ---
        output_text = "拦截" if blocked else ("放行" if blocked is False else "错误")
        row = [
            idx + 1,          # 序号
            source,           # 来源
            sid,              # ID
            cat,              # 类别
            lvl,              # 等级
            content[:300],    # 输入内容（截断）
            output_text,      # 防火墙输出
            risk_score,       # 风险分
            layer,            # 检测层
            detected_cat,     # 检测类别
            "是" if expected else "否",   # 期望拦截
            "是" if blocked else "否",    # 实际拦截
            qualified,        # 是否合格
            latency_ms,       # 延迟ms
            api_used,         # API来源
            note,             # 备注
        ]
        writer.writerow(row)
        f.flush()  # 每条立刻刷盘
        os.fsync(f.fileno())

# ============================================================
# 统计
# ============================================================
print(f"\n{'='*70}")
print(f"全量测试完成")
print(f"  PASS:  {PASS}/{TOTAL} ({PASS/TOTAL*100:.1f}%)")
print(f"  FAIL:  {FAIL}/{TOTAL} ({FAIL/TOTAL*100:.1f}%)")
print(f"  ERROR: {ERRORS}/{TOTAL}")
if PASS + FAIL > 0:
    block_rate = PASS / (PASS + FAIL) * 100
    print(f"  拦截率（有效测试）: {block_rate:.1f}%")
print(f"  CSV: {CSV_PATH}")
print(f"\n列说明: 输入内容 | 防火墙输出(拦截/放行) | 是否合格(PASS=期望匹配)")
