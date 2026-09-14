from redsentinel.defenses.engine.rag.retriever import init_rag_retriever, rag_query
from langchain_openai import ChatOpenAI
from redsentinel.defenses.engine.config import LLM_MODEL, LLM_API_BASE, LLM_API_KEY, DEFAULT_TEST_PDF
import json
import re
import time
from typing import List, Dict

class RAGEvaluator:
    def __init__(self, pdf_path: str = None):
        if pdf_path is None:
            pdf_path = DEFAULT_TEST_PDF
        # 初始化RAG系统和大模型
        self.retriever = init_rag_retriever(pdf_path)
        self.llm = ChatOpenAI(
            model=LLM_MODEL, temperature=0.0,
            openai_api_base=LLM_API_BASE, openai_api_key=LLM_API_KEY
        )
        self.pdf_name = pdf_path.split("/")[-1]
        
    def run_single_test(self, test_case: Dict) -> Dict:
        """运行单个测试用例"""
        query = test_case["query"]
        expected_answer = test_case["expected_answer"]
        expected_keywords = test_case["expected_keywords"]
        
        start_time = time.time()
        
        # 1. 检索环节评估
        context, source_docs = rag_query(self.retriever, query)
        retrieval_time = time.time() - start_time
        
        # 计算召回率：期望关键词在检索上下文中的出现比例
        found_keywords = [kw for kw in expected_keywords if kw in context]
        recall = len(found_keywords) / len(expected_keywords) if expected_keywords else 0.0
        
        # 计算精准度：检索到的文档中相关文档的比例
        relevant_docs = 0
        for doc in source_docs:
            if any(kw in doc["content"] for kw in expected_keywords):
                relevant_docs += 1
        precision = relevant_docs / len(source_docs) if source_docs else 0.0
        
        # 2. 生成环节评估 — 使用与生产环境相同的 agent_invoke pipeline
        generation_start = time.time()
        from redsentinel.defenses.engine.agent.react import agent_invoke
        generated_answer = agent_invoke(
            user_input=query,
            role="admin",
            custom_retriever=self.retriever
        )
        generation_time = time.time() - generation_start
        total_time = time.time() - start_time

        # 计算生成准确率：期望关键词在生成回答中的出现比例
        answer_found = [kw for kw in expected_keywords if kw in generated_answer]
        accuracy = len(answer_found) / len(expected_keywords) if expected_keywords else 0.0

        # 计算幻觉率：用中文短语重叠度检测（与 fact_check 一致的指标）
        def _extract_phrases(text):
            clean = re.sub(r'[^一-鿿\w]', '', text)
            phrases = set()
            for length in [2, 3, 4]:
                for i in range(len(clean) - length + 1):
                    phrases.add(clean[i:i+length])
            return phrases

        hallucination_rate = 0.0
        if generated_answer and context:
            ans_phrases = _extract_phrases(generated_answer)
            ctx_clean = re.sub(r'[^一-鿿\w]', '', context)
            if ans_phrases:
                matched = sum(1 for p in ans_phrases if p in ctx_clean)
                phrase_match_ratio = matched / len(ans_phrases)
                hallucination_rate = max(0.0, 1.0 - phrase_match_ratio)
        
        return {
            "query": query,
            "expected_answer": expected_answer,
            "generated_answer": generated_answer,
            "expected_keywords": expected_keywords,
            "found_keywords": found_keywords,
            "retrieval": {
                "recall": round(recall, 4),
                "precision": round(precision, 4),
                "source_count": len(source_docs),
                "time_ms": round(retrieval_time * 1000, 2)
            },
            "generation": {
                "accuracy": round(accuracy, 4),
                "hallucination_rate": round(hallucination_rate, 4),
                "time_ms": round(generation_time * 1000, 2)
            },
            "total_time_ms": round(total_time * 1000, 2),
            "pass": accuracy >= 0.8 and recall >= 0.7
        }
    
    def run_batch_test(self, test_cases: List[Dict], save_report: bool = True) -> Dict:
        """运行批量测试，生成完整评估报告"""
        print(f"[START] 开始RAG效果评估，共 {len(test_cases)} 个测试用例")
        print("="*80)
        
        results = []
        total_recall = 0.0
        total_precision = 0.0
        total_accuracy = 0.0
        total_hallucination = 0.0
        total_time = 0.0
        pass_count = 0
        
        for i, test_case in enumerate(test_cases):
            print(f"[{i+1}/{len(test_cases)}] 测试问题：{test_case['query']}")
            result = self.run_single_test(test_case)
            results.append(result)
            
            total_recall += result["retrieval"]["recall"]
            total_precision += result["retrieval"]["precision"]
            total_accuracy += result["generation"]["accuracy"]
            total_hallucination += result["generation"]["hallucination_rate"]
            total_time += result["total_time_ms"]
            
            if result["pass"]:
                pass_count += 1
                print(f"[PASS] 通过 | 准确率：{result['generation']['accuracy']:.2%} | 召回率：{result['retrieval']['recall']:.2%}")
            else:
                print(f"[FAIL] 失败 | 准确率：{result['generation']['accuracy']:.2%} | 召回率：{result['retrieval']['recall']:.2%}")
            print("-"*80)
        
        # 计算整体指标
        avg_recall = total_recall / len(test_cases)
        avg_precision = total_precision / len(test_cases)
        avg_accuracy = total_accuracy / len(test_cases)
        avg_hallucination = total_hallucination / len(test_cases)
        avg_time = total_time / len(test_cases)
        pass_rate = pass_count / len(test_cases)
        
        report = {
            "test_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pdf_name": self.pdf_name,
            "total_test_cases": len(test_cases),
            "pass_count": pass_count,
            "pass_rate": round(pass_rate, 4),
            "overall": {
                "avg_recall": round(avg_recall, 4),
                "avg_precision": round(avg_precision, 4),
                "avg_accuracy": round(avg_accuracy, 4),
                "avg_hallucination_rate": round(avg_hallucination, 4),
                "avg_response_time_ms": round(avg_time, 2)
            },
            "detailed_results": results
        }
        
        # 保存报告到文件
        if save_report:
            report_filename = f"rag_evaluation_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_filename, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"[SAVED] 评估报告已保存到：{report_filename}")
        
        return report
    
    def print_summary(self, report: Dict):
        """打印评估总结"""
        print("\n" + "="*80)
        print("[REPORT] RAG效果评估总结报告")
        print("="*80)
        print(f"测试文档：{report['pdf_name']}")
        print(f"测试时间：{report['test_time']}")
        print(f"总测试用例：{report['total_test_cases']}")
        print(f"通过用例：{report['pass_count']}")
        print(f"通过率：{report['pass_rate']:.2%}")
        print("-"*80)
        print(f"平均召回率：{report['overall']['avg_recall']:.2%}")
        print(f"平均精准度：{report['overall']['avg_precision']:.2%}")
        print(f"平均生成准确率：{report['overall']['avg_accuracy']:.2%}")
        print(f"平均幻觉率：{report['overall']['avg_hallucination_rate']:.2%}")
        print(f"平均响应时间：{report['overall']['avg_response_time_ms']:.2f} ms")
        print("="*80)
        
        # 优化建议
        print("\n[TIPS] 优化建议：")
        if report['overall']['avg_recall'] < 0.7:
            print("[WARN] 召回率偏低，建议优化检索环节：")
            print("   - 增加TOP_K召回数量")
            print("   - 优化分块策略，使用语义分块")
            print("   - 启用BM25+向量混合检索")
        elif report['overall']['avg_accuracy'] < 0.8:
            print("[WARN] 生成准确率偏低，建议优化生成环节：")
            print("   - 加强Prompt约束")
            print("   - 启用上下文压缩")
            print("   - 降低大模型温度")
        elif report['overall']['avg_hallucination_rate'] > 0.2:
            print("[WARN] 幻觉率偏高，建议加强幻觉治理：")
            print("   - 强制大模型只基于参考内容回答")
            print("   - 增加引用溯源")
            print("   - 启用事实校验")
        else:
            print("[OK] RAG系统表现良好！")
        print("="*80)