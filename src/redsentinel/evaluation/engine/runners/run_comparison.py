from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""
RAG retrieval strategy comparison experiments.

Runs three experiment groups against the same test cases:
  A: Chunk size comparison (400 vs 800 vs 1200)
  B: Retrieval strategy comparison (vector-only, bm25-only, hybrid, hybrid+rerank)
  C: Top-K comparison (various top_k + rerank_top_n combos)

Saves raw results and a comparison summary to data/.
"""
import os
import json
import re
import time
from datetime import datetime


from redsentinel.defenses.engine.rag.retriever import init_rag_retriever, rag_query
from redsentinel.defenses.engine.agent.react import agent_invoke
from redsentinel.evaluation.engine.runners.test_cases import TEST_CASES

PDF_PATH = str(Path(__file__).resolve().parents[2] / "assets" / "pdfs" / "large_test.pdf")
REPORTS_DIR = str(Path(__file__).resolve().parents[2] / "data" / "experiments")


def _extract_phrases(text):
    """Extract Chinese character n-grams for hallucination scoring."""
    clean = re.sub(r'[^一-鿿\w]', '', text)
    phrases = set()
    for length in [2, 3, 4]:
        for i in range(len(clean) - length + 1):
            phrases.add(clean[i:i + length])
    return phrases


def evaluate_retriever(retriever, test_cases, label=""):
    """
    Run all test cases against a given retriever configuration.
    Returns per-case metrics list and aggregate summary dict.
    """
    results = []
    total_recall = 0.0
    total_precision = 0.0
    total_accuracy = 0.0
    total_hallucination = 0.0
    total_time = 0.0
    pass_count = 0

    for i, tc in enumerate(test_cases):
        query = tc["query"]
        expected_keywords = tc["expected_keywords"]

        start_time = time.time()

        # 1. Retrieval
        context, source_docs = rag_query(retriever, query)

        # Recall: fraction of expected keywords found in context
        found_keywords = [kw for kw in expected_keywords if kw in context]
        recall = len(found_keywords) / len(expected_keywords) if expected_keywords else 0.0

        # Precision: fraction of retrieved docs that contain >=1 expected keyword
        relevant_docs = sum(
            1 for doc in source_docs
            if any(kw in doc["content"] for kw in expected_keywords)
        )
        precision = relevant_docs / len(source_docs) if source_docs else 0.0

        # 2. Generation (using production agent pipeline)
        generated_answer = agent_invoke(
            user_input=query,
            role="admin",
            custom_retriever=retriever
        )
        total_elapsed = time.time() - start_time

        # Accuracy: fraction of expected keywords in generated answer
        answer_found = [kw for kw in expected_keywords if kw in generated_answer]
        accuracy = len(answer_found) / len(expected_keywords) if expected_keywords else 0.0

        # Hallucination rate
        hallucination_rate = 0.0
        if generated_answer and context:
            ans_phrases = _extract_phrases(generated_answer)
            ctx_clean = re.sub(r'[^一-鿿\w]', '', context)
            if ans_phrases:
                matched = sum(1 for p in ans_phrases if p in ctx_clean)
                hallucination_rate = max(0.0, 1.0 - matched / len(ans_phrases))

        passed = accuracy >= 0.8 and recall >= 0.7

        total_recall += recall
        total_precision += precision
        total_accuracy += accuracy
        total_hallucination += hallucination_rate
        total_time += total_elapsed
        pass_count += 1 if passed else 0

        print(f"  [{i+1}/{len(test_cases)}] {query[:40]}... "
              f"acc={accuracy:.2%} rec={recall:.2%} "
              f"{'PASS' if passed else 'FAIL'}")

        results.append({
            "query": query,
            "expected_keywords": expected_keywords,
            "found_keywords": found_keywords,
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "accuracy": round(accuracy, 4),
            "hallucination_rate": round(hallucination_rate, 4),
            "response_time_ms": round(total_elapsed * 1000, 2),
            "pass": passed
        })

    n = len(test_cases)
    summary = {
        "label": label,
        "test_count": n,
        "pass_count": pass_count,
        "pass_rate": round(pass_count / n, 4),
        "avg_recall": round(total_recall / n, 4),
        "avg_precision": round(total_precision / n, 4),
        "avg_accuracy": round(total_accuracy / n, 4),
        "avg_hallucination_rate": round(total_hallucination / n, 4),
        "avg_response_time_ms": round(total_time / n * 1000, 2),
        "detailed_results": results
    }
    return summary


def run_experiment_a():
    """Experiment A: Chunk size comparison."""
    print("\n" + "=" * 70)
    print("Experiment A: Chunk Size Comparison")
    print("=" * 70)

    configs = [
        ("A1: chunk=400 overlap=75", 400, 75),
        ("A2: chunk=800 overlap=150 (default)", 800, 150),
        ("A3: chunk=1200 overlap=200", 1200, 200),
    ]

    summaries = []
    for label, cs, co in configs:
        print(f"\n--- {label} ---")
        retriever = init_rag_retriever(
            PDF_PATH, force_reindex=True,
            chunk_size=cs, chunk_overlap=co
        )
        summary = evaluate_retriever(retriever, TEST_CASES, label)
        summaries.append(summary)
        print(f"  Summary: pass_rate={summary['pass_rate']:.2%} "
              f"acc={summary['avg_accuracy']:.2%} "
              f"rec={summary['avg_recall']:.2%} "
              f"hall={summary['avg_hallucination_rate']:.2%} "
              f"time={summary['avg_response_time_ms']:.0f}ms")

    return summaries


def run_experiment_b():
    """Experiment B: Retrieval strategy comparison."""
    print("\n" + "=" * 70)
    print("Experiment B: Retrieval Strategy Comparison")
    print("=" * 70)

    summaries = []

    # B1: Vector-only
    print("\n--- B1: Vector-only (MMR) ---")
    retriever = init_rag_retriever(PDF_PATH, force_reindex=True)
    retriever["strategy"] = "vector_only"
    summary = evaluate_retriever(retriever, TEST_CASES, "B1: Vector-only (MMR)")
    summaries.append(summary)
    print(f"  Summary: acc={summary['avg_accuracy']:.2%} rec={summary['avg_recall']:.2%}")

    # B2: BM25-only
    print("\n--- B2: BM25-only ---")
    retriever = init_rag_retriever(PDF_PATH, force_reindex=True)
    retriever["strategy"] = "bm25_only"
    summary = evaluate_retriever(retriever, TEST_CASES, "B2: BM25-only")
    summaries.append(summary)
    print(f"  Summary: acc={summary['avg_accuracy']:.2%} rec={summary['avg_recall']:.2%}")

    # B3: Hybrid (RRF), no rerank
    print("\n--- B3: Hybrid (RRF fusion, no rerank) ---")
    retriever = init_rag_retriever(PDF_PATH, force_reindex=True, enable_rerank=False)
    summary = evaluate_retriever(retriever, TEST_CASES, "B3: Hybrid RRF (no rerank)")
    summaries.append(summary)
    print(f"  Summary: acc={summary['avg_accuracy']:.2%} rec={summary['avg_recall']:.2%}")

    # B4: Hybrid + Rerank (production default)
    print("\n--- B4: Hybrid + Rerank (production) ---")
    retriever = init_rag_retriever(PDF_PATH, force_reindex=True, enable_rerank=True)
    summary = evaluate_retriever(retriever, TEST_CASES, "B4: Hybrid + Rerank")
    summaries.append(summary)
    print(f"  Summary: acc={summary['avg_accuracy']:.2%} rec={summary['avg_recall']:.2%}")

    return summaries


def run_experiment_c():
    """Experiment C: Top-K comparison."""
    print("\n" + "=" * 70)
    print("Experiment C: Top-K Comparison")
    print("=" * 70)

    configs = [
        ("C1: k=3 rerank=3", 3, 3),
        ("C2: k=5 rerank=3 (default)", 5, 3),
        ("C3: k=5 rerank=5", 5, 5),
        ("C4: k=8 rerank=5", 8, 5),
    ]

    summaries = []
    for label, vk, rn in configs:
        print(f"\n--- {label} ---")
        retriever = init_rag_retriever(
            PDF_PATH, force_reindex=True,
            vec_top_k=vk, rerank_top_n=rn
        )
        summary = evaluate_retriever(retriever, TEST_CASES, label)
        summaries.append(summary)
        print(f"  Summary: pass_rate={summary['pass_rate']:.2%} "
              f"acc={summary['avg_accuracy']:.2%} "
              f"rec={summary['avg_recall']:.2%} "
              f"hall={summary['avg_hallucination_rate']:.2%} "
              f"time={summary['avg_response_time_ms']:.0f}ms")

    return summaries


def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print("=" * 70)
    print("RAG Retrieval Strategy Comparison Suite")
    print(f"Test cases: {len(TEST_CASES)}")
    print(f"PDF: {PDF_PATH}")
    print(f"Started: {timestamp}")
    print("=" * 70)

    # Run all experiments
    results_a = run_experiment_a()
    results_b = run_experiment_b()
    results_c = run_experiment_c()

    # Build comparison summary
    all_summaries = results_a + results_b + results_c

    comparison = {
        "test_date": timestamp,
        "pdf_path": PDF_PATH,
        "test_case_count": len(TEST_CASES),
        "experiment_groups": {
            "A_chunk_size": results_a,
            "B_retrieval_strategy": results_b,
            "C_top_k": results_c,
        }
    }

    # Save raw data
    raw_path = os.path.join(REPORTS_DIR, f"comparison_summary_{timestamp}.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(comparison, f, ensure_ascii=False, indent=2)

    # Print final comparison table
    print("\n" + "=" * 70)
    print("FINAL COMPARISON TABLE")
    print("=" * 70)
    header = f"{'Config':<40} {'Pass':>6} {'Acc':>7} {'Rec':>7} {'Prec':>7} {'Hall':>7} {'Time':>7}"
    print(header)
    print("-" * len(header))
    for s in all_summaries:
        print(f"{s['label']:<40} {s['pass_rate']:>6.1%} {s['avg_accuracy']:>7.1%} "
              f"{s['avg_recall']:>7.1%} {s['avg_precision']:>7.1%} "
              f"{s['avg_hallucination_rate']:>7.1%} {s['avg_response_time_ms']:>6.0f}ms")

    print(f"\nReport saved to: {raw_path}")

    # Recommend best config
    best = max(all_summaries, key=lambda s: s['avg_accuracy'])
    print(f"\nBest configuration by accuracy: {best['label']} ({best['avg_accuracy']:.2%})")


if __name__ == "__main__":
    main()
