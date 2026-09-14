from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""RAG evaluation entry point. Runs full comparison suite."""
from redsentinel.evaluation.engine.runners.run_comparison import main

if __name__ == "__main__":
    main()
