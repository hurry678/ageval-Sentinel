from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from redsentinel.datasets.loader import load_dataset_manifest


def main(argv: Sequence[str] | None = None) -> int:
    """Verify one dataset manifest and print a machine-readable summary."""
    parser = argparse.ArgumentParser(description="Verify RedSentinel dataset files against their manifest hashes.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--expected-version", default=None)
    args = parser.parse_args(argv)

    manifest = load_dataset_manifest(
        args.manifest,
        repo_root=args.repo_root,
        expected_version=args.expected_version,
    )
    print(
        json.dumps(
            {
                "dataset_id": manifest.dataset_id,
                "file_count": len(manifest.files),
                "generation": manifest.generation,
                "status": "verified",
                "version": manifest.version,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
