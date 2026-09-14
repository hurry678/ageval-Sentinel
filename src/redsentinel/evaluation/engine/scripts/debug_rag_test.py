from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
import sys
import os

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 从 core.rag 导入你的函数（请根据实际函数名微调）
from redsentinel.defenses.engine.rag.retriever import init_rag_retriever, rerank_docs, rag_query, ENABLE_RERANK

def debug_rag(retriever_dict, query, gold_keyword):
    bm25_ret = retriever_dict["bm25"]
    vec_ret  = retriever_dict["vector"]

    bm25_docs = bm25_ret.invoke(query)
    vec_docs  = vec_ret.invoke(query)

    print(f"\n{'='*50}\n查询: {query}\n期待关键词: {gold_keyword}\n{'='*50}")

    # 1. BM25 结果
    print("\n▶ BM25 检索结果（前5）：")
    for i, doc in enumerate(bm25_docs):
        page = doc.metadata.get('page', '?')
        print(f"  {i+1}. [页{page}] {doc.page_content[:120]}...")

    # 2. 向量结果
    print("\n▶ 向量检索结果（前5）：")
    for i, doc in enumerate(vec_docs):
        page = doc.metadata.get('page', '?')
        print(f"  {i+1}. [页{page}] {doc.page_content[:120]}...")

    # 3. 合并去重逻辑（模拟 rag_query 中的操作）
    all_docs = []
    seen_ids = set()
    for doc in vec_docs + bm25_docs:
        doc_id = f"{doc.metadata['page']}_{doc.page_content[:50]}"
        if doc_id not in seen_ids:
            all_docs.append(doc)
            seen_ids.add(doc_id)

    print(f"\n▶ 合并去重后文档数: {len(all_docs)}")
    for i, doc in enumerate(all_docs):
        print(f"  {i+1}. [页{doc.metadata.get('page','?')}] {doc.page_content[:120]}...")

    # 4. 重排序
    ranked = rerank_docs(query, all_docs)
    print(f"\n▶ 重排序后（启用重排: {ENABLE_RERANK}）")
    for i, doc in enumerate(ranked):
        print(f"  {i+1}. [页{doc.metadata.get('page','?')}] {doc.page_content[:120]}...")

    # 5. 最终上下文
    context, sources = rag_query(retriever_dict, query)
    print(f"\n▶ 最终上下文（前400字）:\n{context[:400]}...")
    print("\n▶ 来源引用：")
    for s in sources:
        print(f"  [{s['id']}] 文件:{s['file_name']} 页码:{s['page']}")

    # 6. 关键词检查
    found = gold_keyword in context
    print(f"\n★★★ 关键词'{gold_keyword}'是否出现在最终上下文中？ {'✅ 是' if found else '❌ 否'}")
    if not found:
        print("   → 请向上查看中间结果，定位在哪个环节丢失。")
    return found

if __name__ == "__main__":
    print("正在初始化 RAG 检索器（加载模型可能需要几秒）...")
    # 注意路径：这里假设从项目根目录运行，所以 PDF 路径为 "docs/test.pdf"
    from redsentinel.defenses.engine.config import DEFAULT_TEST_PDF
    ret_dict = init_rag_retriever(DEFAULT_TEST_PDF)
    print("初始化完成。\n")

    # 替换为你的真实测试问题
    test_queries = [
        ("服务问题的数量有几条", "三条"),
        ("投诉类型有哪几类", "答案错误，答案问题，内容违规，服务问题，其他问题"),   # 示例，请根据你的 PDF 内容修改
    ]

    for query, keyword in test_queries:
        debug_rag(ret_dict, query, keyword)
        print("\n" + "-"*50)