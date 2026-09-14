from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""HackAPrompt 分层抽样基准 — 每Level 100条, 限流即停+午夜续跑

数据: HuggingFace hackaprompt/hackaprompt-dataset
每Level抽100条 unique successful attack

运行: python data/run_full_hackaprompt.py
"""

import os, csv, time, json, random
from datetime import datetime


OUTPUT_DIR = os.path.join(str(Path(__file__).resolve().parents[2]), 'data', 'benchmarks')
CHECKPOINT_FILE = os.path.join(OUTPUT_DIR, ".hackaprompt_checkpoint.json")
DONE_FILE = os.path.join(OUTPUT_DIR, ".hackaprompt_done")
SAMPLE_CACHE = os.path.join(OUTPUT_DIR, ".hackaprompt_samples.pkl")
SAMPLES_PER_LEVEL = 100
MAX_RETRIES = 2
PARQUET_PATH = "C:/Users/Lenovo/.cache/huggingface/hub/datasets--hackaprompt--hackaprompt-dataset/snapshots/25b87fbedfb86840abaf8cd09af7a029208a971a/hackaprompt.parquet"
RATE_LIMITED = False


def load_samples():
    import pandas as pd

    if os.path.exists(SAMPLE_CACHE):
        import pickle
        with open(SAMPLE_CACHE, "rb") as f:
            samples = pickle.load(f)
        print(f"[*] 从缓存加载: {len(samples)} 条样本")
        return samples

    print(f"[*] 从 Parquet 分层抽样 (每Level {SAMPLES_PER_LEVEL})...")
    df = pd.read_parquet(PARQUET_PATH)
    correct = df[df['correct'] == True]

    samples = []
    random.seed(42)
    for lvl in sorted(correct['level'].unique()):
        subset = correct[correct['level'] == lvl]
        unique = list(subset['user_input'].dropna().unique())
        random.shuffle(unique)
        taken = unique[:SAMPLES_PER_LEVEL]
        for inp in taken:
            samples.append({
                "level": int(lvl),
                "content": str(inp).strip(),
                "expected_block": True,
            })
        print(f"  Level {int(lvl)}: {len(unique)} unique -> {len(taken)} sampled")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    import pickle
    with open(SAMPLE_CACHE, "wb") as f:
        pickle.dump(samples, f)
    print(f"总抽样: {len(samples)} 条")
    return samples


def call_classifier(content):
    global RATE_LIMITED
    import redsentinel.defenses.engine.security.firewall.classifier as clf

    last_error = ""
    for attempt in range(MAX_RETRIES):
        try:
            clf._classifier_llm = None
            from redsentinel.defenses.engine.security.firewall.classifier import classify
            return classify(content), None
        except Exception as e:
            err = str(e)[:300]
            last_error = err
            if any(kw in err.lower() for kw in [
                "429", "rate limit", "too many", "quota", "limit exceeded",
                "401", "403", "unauthorized",
            ]):
                RATE_LIMITED = True
                return None, f"RATE_LIMITED: {err[:100]}"
            time.sleep(1)
    return None, f"Error: {last_error[:80]}"


def save_checkpoint(idx, total, p, f, e, csv_file):
    cp = {"next_index": idx, "total": total,
          "pass_count": p, "fail_count": f, "error_count": e,
          "csv_file": csv_file, "last_update": datetime.now().isoformat()}
    with open(CHECKPOINT_FILE, "w") as fh:
        json.dump(cp, fh, ensure_ascii=False, indent=2)


def main():
    global RATE_LIMITED
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if os.path.exists(DONE_FILE):
        print(f"[*] HackAPrompt 已完成 ({open(DONE_FILE).read().strip()})")
        return

    samples = load_samples()
    TOTAL = len(samples)

    # Resume or fresh
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE) as f:
            chk = json.load(f)
        if chk["next_index"] > 0:
            start_idx = chk["next_index"]
            pass_count = chk["pass_count"]
            fail_count = chk["fail_count"]
            error_count = chk["error_count"]
            csv_path = os.path.join(OUTPUT_DIR, chk["csv_file"])
        else:
            start_idx = pass_count = fail_count = error_count = 0
    else:
        start_idx = pass_count = fail_count = error_count = 0

    if start_idx == 0:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join(OUTPUT_DIR, f"hackaprompt_{ts}.csv")
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["序号", "Level", "输入内容", "防火墙输出", "风险分",
                        "检测层", "检测类别", "是否合格", "延迟ms", "备注"])
        save_checkpoint(0, TOTAL, 0, 0, 0, os.path.basename(csv_path))

    print(f"\n{'='*70}")
    print(f"HackAPrompt 分层抽样 (每Level {SAMPLES_PER_LEVEL}条)")
    print(f"  总计: {TOTAL} | 起始: #{start_idx+1} | CSV: {os.path.basename(csv_path)}")
    print(f"{'='*70}")

    with open(csv_path, "a", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)

        for idx in range(start_idx, TOTAL):
            s = samples[idx]
            content, lvl = s["content"], s["level"]

            t0 = time.time()
            result, error = call_classifier(content)
            latency_ms = round((time.time() - t0) * 1000, 1)

            if error and RATE_LIMITED:
                print(f"\n  [!] 限流于 #{idx+1}/{TOTAL} (Level={lvl})")
                save_checkpoint(idx, TOTAL, pass_count, fail_count, error_count,
                               os.path.basename(csv_path))
                return

            if result is None:
                blocked, risk, layer, cat, note = None, 0, "?", "?", error
                error_count += 1; qualified = "ERROR"
            else:
                blocked = result.get("should_block", False)
                risk = result.get("risk_score", 0)
                layer = result.get("layer", "?")
                cat = result.get("category", "?")
                note = ""
                if blocked: qualified, pass_count = "PASS", pass_count + 1
                else: qualified, fail_count = "FAIL", fail_count + 1

            out = "拦截" if blocked else ("放行" if blocked is False else "错误")
            w.writerow([idx+1, lvl, content[:300], out, risk,
                        layer, cat, qualified, latency_ms, note])

            if (idx+1) % 50 == 0 or qualified != "PASS":
                icon = {"PASS":"[PASS]","FAIL":"[FAIL]","ERROR":"[ERR!]"}[qualified]
                st = "BLOCK" if blocked else "ALLOW"
                print(f"  {idx+1:04d}/{TOTAL} {icon} L{lvl} {st:<6} risk={risk} L{layer} {latency_ms}ms")

            if (idx+1) % 50 == 0:
                f.flush(); os.fsync(f.fileno())
                save_checkpoint(idx+1, TOTAL, pass_count, fail_count, error_count,
                               os.path.basename(csv_path))

    # Done
    for fpath in [CHECKPOINT_FILE, SAMPLE_CACHE]:
        if os.path.exists(fpath): os.remove(fpath)
    with open(DONE_FILE, "w") as f:
        f.write(datetime.now().isoformat())
    print(f"\n{'='*70}")
    print(f"HackAPrompt 完成! PASS={pass_count} FAIL={fail_count} ERR={error_count}")
    if pass_count + fail_count > 0:
        print(f"拦截率: {pass_count/(pass_count+fail_count)*100:.1f}%")


if __name__ == "__main__":
    import warnings; warnings.filterwarnings("ignore")
    main()
