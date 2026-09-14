from __future__ import annotations

import argparse
import json
from pathlib import Path

from redsentinel.profiling.manifest import load_agent_config
from redsentinel.profiling.validation import validate_agent_config
from redsentinel.profiling.builder import build_agent_security_profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate RedSentinel agent onboarding configs.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate a redsentinel.yaml config.")
    validate_parser.add_argument("config", type=Path)

    profile_parser = subparsers.add_parser("profile", help="Generate an AgentSecurityProfile JSON file.")
    profile_parser.add_argument("config", type=Path)
    profile_parser.add_argument("--output", type=Path, required=True)

    args = parser.parse_args(argv)
    config = load_agent_config(args.config)
    validate_agent_config(config, config_path=args.config)

    if args.command == "validate":
        print("CONFIG_VALID=true")
        print(f"NODES={len(config.nodes)}")
        print("ATTACK_ENTRIES=" + ",".join(config.evaluation.attack_entries))
        return 0

    if args.command == "profile":
        profile = build_agent_security_profile(config)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(profile.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        print(f"PROFILE_PATH={args.output}")
        print(f"NODES={len(profile.nodes)}")
        print("ATTACK_ENTRIES=" + ",".join(profile.attack_entries))
        return 0

    raise ValueError(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
