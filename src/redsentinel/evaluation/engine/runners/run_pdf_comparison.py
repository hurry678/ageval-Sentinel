from redsentinel.evaluation.engine.bootstrap import setup_paths  # noqa: F401
"""PDF parser comparison entry point. Compares PyMuPDF vs PyPDF extraction accuracy with security focus."""
from redsentinel.evaluation.engine.runners.pdf_parser_comparison import main

if __name__ == "__main__":
    main()
