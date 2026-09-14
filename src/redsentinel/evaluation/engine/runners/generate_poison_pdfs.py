from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""Batch generate all 12 poisoned PDFs into data/poison_pdfs/."""
import os
import json
from datetime import datetime

from redsentinel.attacks.engine.doc_poison import (
    generate_all_poison_pdfs, verify_payload_in_chunks, POISON_SCENARIOS
)

OUTPUT_DIR = os.path.join(str(Path(__file__).resolve().parents[2]), "data", "poison", "pdfs")


def main():
    print("=" * 70)
    print("RAG投毒攻击库 - PDF生成")
    print(f"输出目录: {OUTPUT_DIR}")
    print(f"场景数: {len(POISON_SCENARIOS)}")
    print("=" * 70)

    # Generate all PDFs
    print("\n[1/2] 生成毒化PDF...")
    results = generate_all_poison_pdfs(OUTPUT_DIR)
    print(f"\n已生成 {len(results)} 个毒化PDF")

    # Verify extraction
    print("\n[2/2] 验证载荷提取率...")
    verification = []
    for sc in POISON_SCENARIOS:
        pdf_path = results.get(sc["id"])
        if pdf_path:
            v = verify_payload_in_chunks(sc, pdf_path)
            verification.append(v)
            status = "OK" if v["payload_survived"] else "MISS"
            print(f"  [{status}] {v['scenario_id']} {sc['technique']:<15} "
                  f"chunks={v['total_chunks']:>2} body={v['payload_in_body_chunks']} meta={v['payload_in_metadata']}")

    # Summary
    survived = sum(1 for v in verification if v["payload_survived"])
    print(f"\n载荷提取率: {survived}/{len(verification)} ({survived/len(verification)*100:.0f}%)")

    # Save verification report
    report_path = os.path.join(os.path.dirname(OUTPUT_DIR), "poison_results", "payload_verification.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_scenarios": len(verification),
        "payload_survived_count": survived,
        "payload_survival_rate": survived / len(verification),
        "details": verification,
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"验证报告: {report_path}")


if __name__ == "__main__":
    main()
