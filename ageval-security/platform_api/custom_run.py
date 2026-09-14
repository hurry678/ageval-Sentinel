"""Generic custom-suite task runner."""

from __future__ import annotations

import sys
from pathlib import Path

from ageval_sdk import RunContext, RunTerminal

_SHARED = Path(__file__).resolve().parents[5] / "sentinel-ecommerce" / "shared"
if str(_SHARED.parent) not in sys.path:
    sys.path.insert(0, str(_SHARED.parent))

from shared.ecommerce import load_scenario, profile_and_turns, replay


async def run(ctx: RunContext) -> RunTerminal:
    scenario = load_scenario(ctx.workspace_root)
    profile_id, max_turns = profile_and_turns(ctx)
    async with ctx.agent.session(profile_id, max_turns=max_turns) as session:
        clean = await replay(session, scenario.get("clean_steps") or [], phase="clean")
        controlled = await replay(session, scenario.get("controlled_steps") or [], phase="controlled")
    ctx.publish_json("clean", clean)
    ctx.publish_json("controlled", controlled)
    return RunTerminal.completed(str(scenario.get("scenario_id") or ctx.task_id))
