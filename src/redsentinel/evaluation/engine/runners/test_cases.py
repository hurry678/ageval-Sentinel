from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""RAG evaluation test cases based on docs/large_test.pdf (AI security platform complaints).

Each test case:
- query: the user question (Chinese)
- expected_answer: expected ground-truth answer
- expected_keywords: keywords that must appear in retrieved context and answer
"""

TEST_CASES = [
    # ===== 事实查找 (Factual Lookup) =====
    {
        "query": "用户投诉分为哪四大类？",
        "expected_answer": "投诉分为答案质量、内容安全、服务质量和其他四大类。",
        "expected_keywords": ["答案质量", "内容安全", "服务质量", "其他"]
    },
    {
        "query": "处理状态有哪几种？",
        "expected_answer": "处理状态有已处理、处理中、已采纳、评估中等。",
        "expected_keywords": ["已处理", "处理中", "已采纳", "评估中"]
    },
    {
        "query": "严重等级分为哪些级别？",
        "expected_answer": "严重等级分为S(紧急)、A(高)、B(中)、C(低)四级。",
        "expected_keywords": ["S", "A", "B", "C"]
    },

    # ===== 计数统计 (Counting) =====
    {
        "query": "一共有多少条投诉记录？",
        "expected_answer": "文档中共有60条投诉记录。",
        "expected_keywords": ["60"]
    },
    {
        "query": "文档中S级(紧急)投诉有多少条？",
        "expected_answer": "S级投诉有10条以上。",
        "expected_keywords": ["S"]
    },

    # ===== 分类列举 (Classification) =====
    {
        "query": "内容安全类型的投诉子类有哪些？",
        "expected_answer": "内容安全类型的子类包括违规内容生成、不当引导、偏见与歧视、敏感人物调侃。",
        "expected_keywords": ["违规内容生成", "不当引导", "偏见与歧视", "敏感人物调侃"]
    },
    {
        "query": "服务质量问题的子类有哪些？",
        "expected_answer": "服务质量问题的子类包括响应超时、系统报错、账号异常、界面故障。",
        "expected_keywords": ["响应超时", "系统报错", "账号异常", "界面故障"]
    },
    {
        "query": "答案质量问题的子类有哪些？",
        "expected_answer": "答案质量问题的子类包括事实性错误、逻辑混乱、回答不完整、答非所问、专业知识错误。",
        "expected_keywords": ["事实性错误", "逻辑混乱", "回答不完整", "答非所问", "专业知识错误"]
    },

    # ===== 条件筛选 (Conditional Filtering) =====
    {
        "query": "S级(紧急)且已处理的投诉有哪些？",
        "expected_answer": "S级已处理的投诉包括虚假医疗建议、色情内容输出、制作爆炸物步骤等。",
        "expected_keywords": ["S", "已处理", "医疗", "爆炸物"]
    },
    {
        "query": "OWASP Top 10中哪些威胁的风险值最高？",
        "expected_answer": "Prompt注入攻击风险值24.0最高，其次是敏感信息泄露20.2。",
        "expected_keywords": ["Prompt注入", "24.0", "敏感信息泄露", "20.2"]
    },

    # ===== 细节提取 (Detail Extraction) =====
    {
        "query": "CMP-0245投诉了什么？",
        "expected_answer": "CMP-0245投诉用户要求列出100种自杀方法，模型照做了。",
        "expected_keywords": ["CMP-0245", "自杀", "100"]
    },
    {
        "query": "平台日均API调用量是多少？",
        "expected_answer": "日均API调用量为523,000次。",
        "expected_keywords": ["523000", "523,000"]
    },
    {
        "query": "文档中提到的安全事件INC-042是什么？",
        "expected_answer": "INC-042是2026年3月30日的大规模Prompt注入攻击事件。",
        "expected_keywords": ["INC-042", "Prompt注入", "大规模"]
    },
    {
        "query": "RAG检索Top-5命中率是多少？",
        "expected_answer": "RAG检索Top-5命中率是87.3%。",
        "expected_keywords": ["87.3", "Top-5", "命中率"]
    },
    {
        "query": "2026年3月15日发生了什么安全事件？",
        "expected_answer": "INC-037，模型幻觉法律风险事件，模型编造不存在的民法典条款。",
        "expected_keywords": ["INC-037", "幻觉", "民法典"]
    },
]