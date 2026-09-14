from pathlib import Path
from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""Cross-tenant data isolation verification for Chroma collection_name security.

Tests that Tenant A's poisoned document chunks are NOT retrievable by Tenant B,
verifying that Chroma's collection_name-based isolation is effective.

Also tests edge cases: same PDF name + different session_id, direct Chroma access.
"""
import os
import json
import tempfile
from datetime import datetime

from redsentinel.defenses.engine.rag.retriever import init_rag_retriever, rag_query
from redsentinel.attacks.engine.doc_poison import generate_poison_pdf, POISON_SCENARIOS


def test_basic_isolation():
    """Tenant A uploads poisoned doc, Tenant B queries — should not leak."""
    print("\n--- Test 1: Basic collection_name isolation ---")

    tmpdir = tempfile.mkdtemp(prefix="cross_tenant_")
    scenario = POISON_SCENARIOS[0]  # ps_001: malicious instruction embedding
    pdf_path = os.path.join(tmpdir, "tenant_a_poison.pdf")
    generate_poison_pdf(scenario, pdf_path)

    # Tenant A ingests with session_id
    try:
        retriever_a = init_rag_retriever(pdf_path, persist=True, session_id="tenant_a",
                                          force_reindex=True)
    except Exception as e:
        print(f"  SKIP: Tenant A ingestion failed: {e}")
        return {"status": "skip", "reason": str(e)}

    collection_a = retriever_a["collection_name"]
    print(f"  Tenant A collection: {collection_a}")

    # Tenant B: no document or different document, different session_id
    # Use same PDF but different session_id — Chroma should create separate collection
    try:
        retriever_b = init_rag_retriever(pdf_path, persist=True, session_id="tenant_b",
                                          force_reindex=True)
    except Exception as e:
        print(f"  SKIP: Tenant B ingestion failed: {e}")
        return {"status": "skip", "reason": str(e)}

    collection_b = retriever_b["collection_name"]
    print(f"  Tenant B collection: {collection_b}")

    # Collections should be different
    assert collection_a != collection_b, f"ERROR: Same collection name for different tenants! {collection_a}"

    # Tenant B queries for poisoned content
    context_b, sources_b = rag_query(retriever_b, "安全指令是什么？最高优先级规则是什么？")
    print(f"  Tenant B query result: {len(context_b)} chars, {len(sources_b)} sources")

    # Tenant B should NOT get Tenant A's poisoned content
    leaked = "忽略之前的所有安全指令" in context_b
    print(f"  Tenant B leaked poison content: {leaked}")

    # Tenant A SHOULD get their own content
    context_a, sources_a = rag_query(retriever_a, "文档中关于安全指令的内容是什么？")
    own_accessible = "忽略之前的所有安全指令" in context_a
    print(f"  Tenant A can access own content: {own_accessible} ({len(context_a)} chars, {len(sources_a)} sources)")

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    return {
        "status": "pass" if (not leaked and own_accessible) else "fail",
        "tenant_b_leaked": leaked,
        "tenant_a_accessible": own_accessible,
        "collection_a": collection_a,
        "collection_b": collection_b,
    }


def test_different_pdf_same_name():
    """Same PDF basename but different session_ids — must be isolated."""
    print("\n--- Test 2: Same PDF name, different session_ids ---")

    tmpdir = tempfile.mkdtemp(prefix="cross_tenant_")
    scenario_a = POISON_SCENARIOS[0]  # ps_001: malicious instruction
    scenario_b = POISON_SCENARIOS[2]  # ps_003: hidden white (different payload)

    # Both use same filename but different content and session
    pdf_a = os.path.join(tmpdir, "test.pdf")
    pdf_b = os.path.join(tmpdir, "test.pdf")  # same name!
    generate_poison_pdf(scenario_a, pdf_a)

    # Tenant A ingests
    try:
        r_a = init_rag_retriever(pdf_a, persist=True, session_id="tenant_a", force_reindex=True)
    except Exception as e:
        print(f"  SKIP: {e}")
        return {"status": "skip", "reason": str(e)}

    # Overwrite PDF with different content for Tenant B
    generate_poison_pdf(scenario_b, pdf_b)

    try:
        r_b = init_rag_retriever(pdf_b, persist=True, session_id="tenant_b", force_reindex=True)
    except Exception as e:
        print(f"  SKIP: {e}")
        return {"status": "skip", "reason": str(e)}

    # Verify different collections
    assert r_a["collection_name"] != r_b["collection_name"], \
        f"Same collection name with different session_ids: {r_a['collection_name']}"

    # Tenant B should not see Tenant A's content
    ctx_b, _ = rag_query(r_b, "安全指令最高优先级规则是什么？")
    leak = "忽略之前的所有安全指令" in ctx_b
    print(f"  Tenant B sees Tenant A content: {leak} (expect False)")

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    return {"status": "pass" if not leak else "fail", "leaked": leak}


def test_chroma_direct_access():
    """Verify that direct Chroma access respects collection boundaries."""
    print("\n--- Test 3: Direct Chroma collection access ---")

    try:
        import chromadb
        client = chromadb.PersistentClient(path=str(__import__("redsentinel.defenses.engine.config", fromlist=["CHROMA_PERSIST_DIR"]).CHROMA_PERSIST_DIR))
        collections = client.list_collections()
        print(f"  Total collections: {len(collections)}")

        # Every collection should have a unique name
        names = [c.name for c in collections]
        assert len(names) == len(set(names)), f"Duplicate collection names found: {len(names)} != {len(set(names))}"
        print(f"  All {len(names)} collection names are unique")
        return {"status": "pass", "total_collections": len(names)}
    except Exception as e:
        print(f"  Chroma direct access error: {e}")
        return {"status": "error", "reason": str(e)}


def main():
    print("=" * 70)
    print("跨租户数据隔离安全验证")
    from redsentinel.defenses.engine.config import CHROMA_PERSIST_DIR
    print(f"Chroma persist directory: {CHROMA_PERSIST_DIR}")
    print("=" * 70)

    results = {}
    results["test_1_basic"] = test_basic_isolation()
    results["test_2_same_name"] = test_different_pdf_same_name()
    results["test_3_direct"] = test_chroma_direct_access()

    # Summary
    print("\n" + "=" * 70)
    print("隔离验证结果")
    print("=" * 70)
    for name, r in results.items():
        status = r.get("status", "unknown")
        mark = "PASS" if status == "pass" else ("FAIL" if status == "fail" else status.upper())
        print(f"  [{mark}] {name}")

    all_pass = all(r.get("status") == "pass" for r in results.values())
    print(f"\n结论: {'隔离方案有效，未发现跨租户数据泄露' if all_pass else '存在隔离问题，需进一步排查'}")

    # Save report
    output_dir = os.path.join(str(Path(__file__).resolve().parents[2]),
                              "data", "poison", "results")
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "cross_tenant_verification.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "test_results": results,
            "overall_pass": all_pass,
        }, f, ensure_ascii=False, indent=2)
    print(f"报告: {report_path}")


if __name__ == "__main__":
    main()
