from __future__ import annotations

from dataclasses import asdict
from typing import Any

from redsentinel.adapters.engine.openmanus_agent.adapter import OpenManusAdapter, build_default_adapter


def run_normal_business_demo(adapter: OpenManusAdapter | None = None) -> dict[str, Any]:
    active_adapter = adapter or build_default_adapter()
    result = active_adapter.call_tool(
        "send_email",
        {
            "to": "ops@company.com",
            "subject": "Order workflow check",
            "body": "The supervised OpenManus business tool demo completed.",
        },
    )
    return {
        "agent": "openmanus",
        "mode": "no_defense_demo",
        "tool_call": asdict(active_adapter.call_history[-1]),
        "result": result,
        "registered_tools": sorted(active_adapter.tools),
    }


def main() -> int:
    import json

    print(json.dumps(run_normal_business_demo(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
