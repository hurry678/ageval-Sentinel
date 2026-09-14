"""Command-line entry point for traceable research analysis."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from redsentinel.research.analysis import analyze_files, write_analysis_artifacts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate multi-seed research JSON and render paper artifacts.")
    parser.add_argument("inputs", nargs="+", type=Path, help="Raw experiment-run-v1 or baseline-comparison-v1 JSON.")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--svg", action="store_true", help="Use the standard-library SVG fallback.")
    args = parser.parse_args(argv)

    artifacts = write_analysis_artifacts(
        analyze_files(args.inputs),
        args.output_dir,
        prefer_matplotlib=not args.svg,
    )
    for name, path in sorted(artifacts.items()):
        print(f"{name.upper()}={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
