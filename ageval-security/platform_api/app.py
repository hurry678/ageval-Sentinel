"""HTTP surface of the platform.

Deliberately thin: every route delegates to one of the four modules. No auth and
no tenancy — this binds to localhost and drives a local ageval checkout, so adding
either would be ceremony without a threat it defends against.

Seven capabilities, one router:

    targets   onboard the Agent under test        /api/targets
    suites    pick what to throw at it            /api/suites
    runs      launch it                           /api/runs
    stream    watch it live                       /api/runs/{id}/events   (SSE)
    replay    read the evidence chain             /api/runs/{id}/replay/{task}
    report    the graded verdict                  /api/runs/{id}/report
    compare   several Agents side by side         /api/compare
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from platform_api import PLATFORM_VERSION
from platform_api.attack_path import build_attack_path
from platform_api.config import WEB_DIST, ensure_state
from platform_api.custom_suites import validate_custom_suite, write_custom_suite
from platform_api.probe import probe
from platform_api.reports import build_report, compare, replay, report_markdown
from platform_api.runs import cancel_run, events_since, list_runs, load_run, start_run
from platform_api.suites import get_suite, list_suites, pipeline_nodes, scenario_payload
from platform_api.targets import (
    INPROC_AGENTS,
    KINDS,
    delete_target,
    get_target,
    load_targets,
    upsert_target,
    validate,
)

STREAM_INTERVAL = 0.4


def create_app() -> FastAPI:
    ensure_state()
    app = FastAPI(title="Sentinel Agent Detection Platform", version=PLATFORM_VERSION)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5174", "http://localhost:5174"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---------------------------------------------------------------- meta

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "version": PLATFORM_VERSION,
            "target_kinds": list(KINDS),
            "inproc_agents": list(INPROC_AGENTS),
            "pipeline_nodes": pipeline_nodes(),
        }

    # ------------------------------------------------------------- targets

    @app.get("/api/targets")
    def targets() -> dict[str, Any]:
        return {"targets": [item.as_dict() for item in load_targets()]}

    @app.post("/api/targets")
    def create_target(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        target, reason = validate(payload)
        if target is None:
            raise HTTPException(status_code=422, detail=reason)
        return upsert_target(target).as_dict()

    @app.get("/api/targets/{target_id}")
    def read_target(target_id: str) -> dict[str, Any]:
        target = get_target(target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="target not found")
        return target.as_dict()

    @app.delete("/api/targets/{target_id}")
    def remove_target(target_id: str) -> dict[str, Any]:
        if not delete_target(target_id):
            raise HTTPException(status_code=404, detail="target not found")
        return {"deleted": target_id}

    @app.post("/api/targets/{target_id}/probe")
    def probe_target(target_id: str) -> dict[str, Any]:
        target = get_target(target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="target not found")
        return probe(target)

    # -------------------------------------------------------------- suites

    @app.get("/api/suites")
    def suites() -> dict[str, Any]:
        return {"suites": list_suites()}

    @app.get("/api/suites/{suite_id}")
    def suite(suite_id: str) -> dict[str, Any]:
        found = get_suite(suite_id)
        if found is None:
            raise HTTPException(status_code=404, detail="suite not found")
        return found

    @app.get("/api/suites/{suite_id}/tasks/{task_id}")
    def scenario(suite_id: str, task_id: str) -> dict[str, Any]:
        found = scenario_payload(suite_id, task_id)
        if found is None:
            raise HTTPException(status_code=404, detail="scenario not found")
        return found

    @app.post("/api/custom-suites/validate")
    def check_custom_suite(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        found, reason = validate_custom_suite(payload)
        if found is None:
            raise HTTPException(status_code=422, detail=reason)
        return {"ok": True, "suite": found}

    @app.post("/api/custom-suites")
    def create_custom_suite(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        found, reason = write_custom_suite(payload)
        if found is None:
            raise HTTPException(status_code=422, detail=reason)
        return found

    # ---------------------------------------------------------------- runs

    @app.get("/api/runs")
    def runs() -> dict[str, Any]:
        return {"runs": list_runs()}

    @app.post("/api/runs")
    def create_run(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        record, reason = start_run(
            target_id=str(payload.get("target_id") or ""),
            suite_id=str(payload.get("suite_id") or ""),
            n_attempts=int(payload.get("n_attempts") or 1),
            max_concurrent=int(payload.get("max_concurrent") or 4),
        )
        if record is None:
            raise HTTPException(status_code=422, detail=reason)
        return record.summary()

    @app.get("/api/runs/{run_id}")
    def read_run(run_id: str) -> dict[str, Any]:
        record = load_run(run_id)
        if record is None:
            raise HTTPException(status_code=404, detail="run not found")
        return record.summary()

    @app.get("/api/runs/{run_id}/attack-path")
    def read_attack_path(run_id: str) -> dict[str, Any]:
        found = build_attack_path(run_id)
        if found is None:
            raise HTTPException(status_code=404, detail="run not found")
        return found

    @app.post("/api/runs/{run_id}/cancel")
    def stop_run(run_id: str) -> dict[str, Any]:
        ok, reason = cancel_run(run_id)
        if not ok:
            raise HTTPException(status_code=409, detail=reason)
        return {"cancelled": run_id}

    @app.get("/api/runs/{run_id}/events")
    async def stream(run_id: str, cursor: int = Query(0, ge=0)) -> StreamingResponse:
        if load_run(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")

        async def pump() -> Any:
            position = cursor
            while True:
                batch, finished = events_since(run_id, position)
                for event in batch:
                    position = int(event["seq"]) + 1
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                if finished and not batch:
                    yield "event: end\ndata: {}\n\n"
                    return
                await asyncio.sleep(STREAM_INTERVAL)

        return StreamingResponse(
            pump(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ------------------------------------------------------ report / replay

    @app.get("/api/runs/{run_id}/report")
    def report(run_id: str, required_nodes: int | None = Query(None, ge=1)) -> dict[str, Any]:
        found = build_report(run_id, required_nodes=required_nodes)
        if found is None:
            raise HTTPException(status_code=409, detail="报告尚未就绪：运行未完成或没有产出 summary")
        return found

    @app.get("/api/runs/{run_id}/report.md", response_class=PlainTextResponse)
    def report_md(run_id: str, required_nodes: int | None = Query(None, ge=1)) -> str:
        text = report_markdown(run_id, required_nodes=required_nodes)
        if text is None:
            raise HTTPException(status_code=409, detail="报告尚未就绪")
        return text

    @app.get("/api/runs/{run_id}/replay/{task_id}")
    def read_replay(run_id: str, task_id: str, attempt: int = Query(0, ge=0)) -> dict[str, Any]:
        found = replay(run_id, task_id, attempt=attempt)
        if found is None:
            raise HTTPException(status_code=404, detail="没有可回放的产物")
        return found

    @app.post("/api/compare")
    def read_compare(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        run_ids = [str(item) for item in payload.get("run_ids") or []]
        if not run_ids:
            raise HTTPException(status_code=422, detail="run_ids 不能为空")
        return compare(run_ids, required_nodes=payload.get("required_nodes"))

    # ----------------------------------------------------------- built web

    if WEB_DIST.is_dir():
        app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(WEB_DIST / "index.html")

    return app


app = create_app()
