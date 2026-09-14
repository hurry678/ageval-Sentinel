from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""对 garak测试数据.xlsx 跑防火墙, 填写拦截/风险分/是否合格"""

import os, time, pandas as pd


# 从 SiliconFlow 结果继续（已有 400 行）— 只补未填充的行
USE_EXISTING = "data/benchmarks/garak测试数据_SiliconFlow结果.xlsx"
if os.path.exists(USE_EXISTING):
    EXCEL_PATH = USE_EXISTING
    print(f"从已有结果续跑: {EXCEL_PATH}")
else:
    EXCEL_PATH = "data/benchmarks/garak测试数据.xlsx"
OUT_PATH = "data/benchmarks/garak测试数据_ModelScope结果.xlsx"

MAX_RETRIES = 1  # 减少重试, 避免connection超时累计

# API config (after midnight reset, back to ModelScope)
CURRENT_API = {
    "name": "ModelScope",
    "base": os.getenv("LLM_API_BASE", "https://api-inference.modelscope.cn/v1"),
    "key": os.getenv("LLM_API_KEY", ""),
}

def apply_api():
    import redsentinel.defenses.engine.config as cfg
    cfg.LLM_API_BASE = CURRENT_API["base"]
    cfg.LLM_API_KEY = CURRENT_API["key"]
    import redsentinel.defenses.engine.security.firewall.classifier as clf
    clf._classifier_llm = None

def call_classifier(content):
    global CURRENT_API
    for attempt in range(MAX_RETRIES):
        try:
            apply_api()
            from redsentinel.defenses.engine.security.firewall.classifier import classify
            return classify(content), None
        except Exception as e:
            err = str(e)[:300]
            if any(kw in err.lower() for kw in ["429", "rate limit", "quota", "limit exceeded"]):
                return None, f"RATE_LIMITED"
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.5)
                continue
            return None, f"ERR"
    return None, "ERR"

# ============================================================
print("Loading Excel...")
df = pd.read_excel(EXCEL_PATH)
print(f"Total rows: {len(df)}")
print(f"Columns: {list(df.columns)}")

# Track progress
RATE_LIMITED = False
TOTAL = len(df)
done = 0
pass_count = 0
fail_count = 0
error_count = 0

# Process each row
for idx in range(TOTAL):
    row = df.iloc[idx]

    # Skip if already has results
    if pd.notna(row.get("防火墙输出")) and pd.notna(row.get("风险分")):
        continue

    content = str(row["输入内容"])
    expected_block = bool(row.get("expected_block", True))

    t0 = time.time()
    result, error = call_classifier(content)
    latency_ms = round((time.time() - t0) * 1000, 1)

    if error and "RATE_LIMITED" in error:
        print(f"\n  [!] Rate limited at row {idx+1}/{TOTAL}, saving...")
        df.to_excel(OUT_PATH, index=False)
        print(f"  Saved partial results to {OUT_PATH}")
        RATE_LIMITED = True
        break

    if error:
        df.at[idx, "防火墙输出"] = "错误"
        df.at[idx, "风险分"] = 0
        df.at[idx, "延迟ms"] = 0
        df.at[idx, "备注"] = error
        error_count += 1
    else:
        blocked = result.get("should_block", False)
        risk_score = result.get("risk_score", 0)
        layer = result.get("layer", "?")
        detected_cat = result.get("category", "?")

        df.at[idx, "防火墙输出"] = "拦截" if blocked else "放行"
        df.at[idx, "风险分"] = risk_score
        df.at[idx, "检测层"] = layer
        df.at[idx, "延迟ms"] = latency_ms

        # PASS/FAIL
        if blocked == expected_block:
            qualified = "PASS"
            pass_count += 1
        else:
            qualified = "FAIL"
            fail_count += 1
        df.at[idx, "是否合格"] = qualified

    done += 1
    if done % 50 == 0:
        print(f"  Progress: {done}/{TOTAL} (PASS={pass_count}, FAIL={fail_count}, ERR={error_count})")
        df.to_excel(OUT_PATH, index=False)

# Final save
if not RATE_LIMITED:
    df.to_excel(OUT_PATH, index=False)
    print(f"\n{'='*70}")
    print(f"Complete! {done}/{TOTAL} evaluated")
    print(f"  PASS: {pass_count}, FAIL: {fail_count}, ERROR: {error_count}")
    print(f"  Output: {OUT_PATH}")
