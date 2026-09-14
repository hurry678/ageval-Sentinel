import os
from pathlib import Path


# 模型配置
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-zh-v1.5")
LLM_MODEL = os.getenv("LLM_MODEL", "Qwen/Qwen3.5-35B-A3B")

# OpenAI-compatible API endpoint. Secrets must come from the environment.
LLM_API_BASE = os.getenv("LLM_API_BASE", "https://api-inference.modelscope.cn/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")

# RAG
CHUNK_SIZE = 800
CHUNK_OVERLAP = 150
TOP_K = 5
# RAG重排序配置
RERANK_TOP_N = 3

# Project paths (config lives in redsentinel.defenses.engine/src/redsentinel.defenses.engine/)
PROJECT_ROOT = Path(os.getenv("AI_SYSTEM_ROOT", Path(__file__).resolve().parents[3]))
DEFENSE_ROOT = PROJECT_ROOT / "redsentinel.defenses.engine"
STORAGE_DIR = PROJECT_ROOT / "storage"
CHROMA_PERSIST_DIR = STORAGE_DIR / "chroma_db"
CHECKPOINT_DIR = STORAGE_DIR / "checkpoints"
CHECKPOINT_DB = CHECKPOINT_DIR / "graph_state.db"
AUDIT_LOG_PATH = STORAGE_DIR / "logs" / "audit.log"
ASSETS_PDFS_DIR = DEFENSE_ROOT / "assets" / "pdfs"
DATA_DIR = DEFENSE_ROOT / "data"
DEFAULT_TEST_PDF = str(ASSETS_PDFS_DIR / "test.pdf")
DEFAULT_LARGE_PDF = str(ASSETS_PDFS_DIR / "large_test.pdf")

for _d in (STORAGE_DIR, CHROMA_PERSIST_DIR, CHECKPOINT_DIR, AUDIT_LOG_PATH.parent):
    _d.mkdir(parents=True, exist_ok=True)
