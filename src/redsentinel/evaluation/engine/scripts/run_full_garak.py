from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""Garak全量基准 — 限流即停 + 午夜自动续跑 + 断点续传

运行: python data/run_full_garak.py
遇限流自动停止, 00:05 自动恢复, 所有结果在同一CSV
"""

import os, csv, time, json, importlib
from datetime import datetime


# ============================================================
# 配置
# ============================================================
OUTPUT_DIR = os.path.join(str(Path(__file__).resolve().parents[2]), 'data', 'benchmarks')
CHECKPOINT_FILE = os.path.join(OUTPUT_DIR, ".garak_checkpoint.json")
MAX_RETRIES_PER_TEST = 2

# ============================================================
# 提取所有 Garak prompts (只在首次运行时执行)
# ============================================================
def extract_all_garak_prompts():
    from garak._plugins import enumerate_plugins

    all_tests = []
    total_probes = 0
    skipped = 0

    for name, active in enumerate_plugins('probes'):
        total_probes += 1
        if not active:
            skipped += 1
            continue
        parts = name.split('.')
        module_path = 'garak.' + '.'.join(parts[:-1])
        cls_name = parts[-1]
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, cls_name)
            p = cls()
            if not hasattr(p, 'prompts') or not isinstance(p.prompts, list) or len(p.prompts) == 0:
                continue
            for i, prompt in enumerate(p.prompts):
                prompt_str = str(prompt).strip()
                if len(prompt_str) < 5:
                    continue
                all_tests.append({
                    "source": "Garak",
                    "probe_class": cls_name,
                    "probe_path": name,
                    "prompt_index": i,
                    "content": prompt_str,
                    "expected_block": True,
                })
        except Exception:
            pass

    print(f"Garak 探针类: {total_probes} (active: {total_probes-skipped})")
    print(f"提取 prompts: {len(all_tests)}")
    return all_tests


# ============================================================
# 加载进度（断点续跑）
# ============================================================
def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "r") as f:
            cp = json.load(f)
        print(f"[*] 发现断点: 已完成 {cp['next_index']}/{cp['total']}, "
              f"PASS={cp.get('pass_count',0)}, FAIL={cp.get('fail_count',0)}")
        return cp
    return None


def save_checkpoint(next_index, total, pass_count, fail_count, error_count, api_count):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    cp = {
        "next_index": next_index,
        "total": total,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "error_count": error_count,
        "api_call_count": api_count,
        "last_update": datetime.now().isoformat(),
    }
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(cp, f, ensure_ascii=False, indent=2)


def clear_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        os.remove(CHECKPOINT_FILE)
        print("[*] 断点已清除(全部完成)")


# ============================================================
# 分类器调用（带限流检测）
# ============================================================
RATE_LIMITED = False  # 全局标记


def call_classifier(content):
    """调用防火墙分类, 返回 (result_dict, error_string).
    如果遇到限流, 设置 RATE_LIMITED = True."""
    global RATE_LIMITED
    import redsentinel.defenses.engine.security.firewall.classifier as clf

    for attempt in range(MAX_RETRIES_PER_TEST):
        try:
            clf._classifier_llm = None  # 每次刷新配置
            from redsentinel.defenses.engine.security.firewall.classifier import classify
            result = classify(content)
            return result, None
        except Exception as e:
            err = str(e)[:300]
            # 检测限流/认证错误 → 立即停止
            if any(kw in err.lower() for kw in ["429", "rate limit", "too many requests",
                                                  "quota", "limit exceeded"]):
                RATE_LIMITED = True
                return None, f"RATE_LIMITED: {err[:100]}"
            elif any(kw in err.lower() for kw in ["401", "403", "unauthorized"]):
                RATE_LIMITED = True
                return None, f"AUTH_ERROR: {err[:100]}"
            else:
                if attempt < MAX_RETRIES_PER_TEST - 1:
                    time.sleep(1)
                    continue
                return None, f"Error: {err[:80]}"

    return None, "Retry exhausted"


# ============================================================
# 主流程
# ============================================================
def main():
    global RATE_LIMITED

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 如果已经全部完成, 直接退出
    done_file = os.path.join(OUTPUT_DIR, ".garak_done")
    if os.path.exists(done_file):
        print("[*] Garak 全量测试已在之前完成, 无需续跑")
        print(f"    完成时间: {open(done_file).read().strip()}")
        return

    # 加载或创建测试集
    chk = load_checkpoint()
    if chk:
        # 从断点恢复
        ALL_TESTS = extract_all_garak_prompts()
        TOTAL = len(ALL_TESTS)
        start_idx = chk["next_index"]
        pass_count = chk["pass_count"]
        fail_count = chk["fail_count"]
        error_count = chk["error_count"]
        api_count = chk["api_call_count"]
        csv_path = os.path.join(OUTPUT_DIR, chk.get("csv_file", ""))
        if not os.path.exists(csv_path):
            print("[!] CSV文件丢失, 无法恢复")
            return
    else:
        # 全新开始
        ALL_TESTS = extract_all_garak_prompts()
        TOTAL = len(ALL_TESTS)
        start_idx = 0
        pass_count = 0
        fail_count = 0
        error_count = 0
        api_count = 0
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join(OUTPUT_DIR, f"garak_full_{timestamp}.csv")

        # 写CSV头
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["序号", "探针类", "prompt_idx", "输入内容", "防火墙输出",
                             "风险分", "检测层", "检测类别", "是否合格", "延迟ms", "备注"])

    # 保存 csv_path 到断点
    save_checkpoint(start_idx, TOTAL, pass_count, fail_count, error_count, api_count)
    # 手动修补 csv_file 字段
    cp = json.load(open(CHECKPOINT_FILE))
    cp["csv_file"] = os.path.basename(csv_path)
    json.dump(cp, open(CHECKPOINT_FILE, "w"), ensure_ascii=False, indent=2)

    print("=" * 70)
    print("Garak 全量基准测试 (限流即停 + 午夜续跑)")
    print(f"  总计: {TOTAL} prompts")
    print(f"  起始: #{start_idx+1}")
    print(f"  CSV:  {csv_path}")
    print("=" * 70)

    # 逐条测试
    with open(csv_path, "a", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)

        for idx in range(start_idx, TOTAL):
            sample = ALL_TESTS[idx]
            content = sample["content"]
            probe_cls = sample["probe_class"]
            expected = sample["expected_block"]

            t0 = time.time()
            result, error = call_classifier(content)
            latency_ms = round((time.time() - t0) * 1000, 1)
            api_count += 1

            if error and RATE_LIMITED:
                # 限流了 — 保存断点并退出
                print(f"\n  [!] 限流于 #{idx+1}/{TOTAL} {probe_cls}")
                print(f"  [!] 已保存断点, 等待午夜自动恢复")
                save_checkpoint(idx, TOTAL, pass_count, fail_count, error_count, api_count)
                return  # 退出, 由午夜定时任务恢复

            if error:
                # 非限流错误
                blocked = None
                risk_score = 0
                layer = "?"
                detected_cat = "?"
                note = error
                error_count += 1
                qualified = "ERROR"
            else:
                blocked = result.get("should_block", False)
                risk_score = result.get("risk_score", 0)
                layer = result.get("layer", "?")
                detected_cat = result.get("category", "?")
                note = ""

                if blocked == expected:
                    qualified = "PASS"
                    pass_count += 1
                else:
                    qualified = "FAIL"
                    fail_count += 1

            # 写入CSV
            output_text = "拦截" if blocked else ("放行" if blocked is False else "错误")
            row = [
                idx + 1, probe_cls, sample["prompt_index"],
                content[:300], output_text, risk_score,
                layer, detected_cat, qualified, latency_ms, note,
            ]
            writer.writerow(row)

            # 每10条刷盘
            if (idx + 1) % 10 == 0:
                f.flush()
                os.fsync(f.fileno())

            # 定期打印进度
            if (idx + 1) % 100 == 0 or qualified != "PASS":
                icon = {"PASS": "[PASS]", "FAIL": "[FAIL]", "ERROR": "[ERR!]"}[qualified]
                status = "BLOCK" if blocked else "ALLOW"
                print(f"  {idx+1:04d}/{TOTAL} {icon} {probe_cls:<25} {status:<6} "
                      f"risk={risk_score} L{layer} {latency_ms}ms")

            # 每200条保存一次断点（预防中途崩溃）
            if (idx + 1) % 200 == 0:
                save_checkpoint(idx + 1, TOTAL, pass_count, fail_count, error_count, api_count)

    # 全部完成
    clear_checkpoint()
    # 写入完成标记
    done_file = os.path.join(OUTPUT_DIR, ".garak_done")
    with open(done_file, "w") as f:
        f.write(datetime.now().isoformat())
    print(f"\n{'='*70}")
    print(f"Garak 全量测试完成!")
    print(f"  PASS:  {pass_count}/{TOTAL} ({pass_count/TOTAL*100:.1f}%)")
    print(f"  FAIL:  {fail_count}/{TOTAL} ({fail_count/TOTAL*100:.1f}%)")
    print(f"  ERROR: {error_count}/{TOTAL}")
    if pass_count + fail_count > 0:
        print(f"  拦截率: {pass_count/(pass_count+fail_count)*100:.1f}%")
    print(f"  API调用: {api_count}次")


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    main()
