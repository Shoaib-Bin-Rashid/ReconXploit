"""
ReconXploit API — Scheduler router

Endpoints:
  GET   /api/v1/scheduler/status          All targets with schedule info
  POST  /api/v1/scheduler/run-now         Force immediate scan of a target
  POST  /api/v1/scheduler/targets         Add target to scheduler
  PATCH /api/v1/scheduler/targets/{domain}  Update schedule settings
"""

import logging
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.modules.scheduler import SchedulerState, load_targets_from_file, _interval_for_score

logger = logging.getLogger(__name__)
router = APIRouter()

# Module-level state shared with the daemon (if running)
_state = SchedulerState()


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────

class SchedulerTargetOut(BaseModel):
    domain: str
    mode: str
    status: str
    interval_h: int
    last_run: Optional[str]
    next_run: Optional[str]
    last_score: int
    run_count: int
    eta: Optional[str]


class SchedulerSummary(BaseModel):
    total_targets: int
    running: int
    idle: int
    error: int
    total_runs: int
    scheduler_started: str


class RunNowRequest(BaseModel):
    domain: str
    mode: str = Field("full", description="full|passive|quick|deep")


class AddScheduleTarget(BaseModel):
    domain: str
    mode: str = Field("full")
    interval_h: int = Field(24, ge=1, le=8760)


class UpdateScheduleTarget(BaseModel):
    mode: Optional[str] = None
    interval_h: Optional[int] = Field(None, ge=1, le=8760)
    status: Optional[str] = Field(None, description="idle|error")


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@router.get("/status", response_model=SchedulerSummary, summary="Scheduler summary")
def scheduler_summary():
    return SchedulerSummary(**_state.summary())


@router.get("/targets", response_model=List[SchedulerTargetOut], summary="All scheduled targets")
def list_scheduled_targets():
    from datetime import timedelta
    from backend.modules.scheduler import _humanize

    rows = []
    now  = datetime.utcnow()
    for domain, info in sorted(_state.all_targets().items()):
        next_run = info.get("next_run")
        eta = None
        if next_run:
            try:
                delta = datetime.fromisoformat(next_run) - now
                eta = _humanize(delta)
            except ValueError:
                eta = None

        rows.append(SchedulerTargetOut(
            domain     = domain,
            mode       = info.get("mode", "full"),
            status     = info.get("status", "idle"),
            interval_h = info.get("interval_h", 24),
            last_run   = info.get("last_run"),
            next_run   = next_run,
            last_score = info.get("last_score", 0),
            run_count  = info.get("run_count", 0),
            eta        = eta,
        ))
    return rows


@router.post("/run-now", status_code=202, summary="Force immediate scan")
def run_now(body: RunNowRequest):
    """Trigger an immediate scan for a target regardless of its scheduled time."""
    t = _state.get_target(body.domain)
    if not t:
        # Auto-register it
        _state.upsert_target(body.domain, mode=body.mode, interval_h=24)

    if _state.get_target(body.domain).get("status") == "running":
        raise HTTPException(409, f"'{body.domain}' is already running")

    # Reset next_run to trigger immediately
    _state.upsert_target(body.domain, next_run=None)
    logger.info(f"[API] run-now queued for {body.domain}")
    return {"queued": True, "domain": body.domain, "mode": body.mode}


@router.post("/targets", status_code=201, summary="Add target to scheduler")
def add_scheduler_target(body: AddScheduleTarget):
    existing = _state.get_target(body.domain)
    if existing:
        raise HTTPException(409, f"'{body.domain}' already in scheduler")
    _state.upsert_target(body.domain, mode=body.mode, interval_h=body.interval_h)
    logger.info(f"[API] Scheduler target added: {body.domain}")
    return {"added": True, "domain": body.domain}


@router.patch("/targets/{domain}", summary="Update schedule settings")
def update_scheduler_target(domain: str, body: UpdateScheduleTarget):
    t = _state.get_target(domain)
    if not t:
        raise HTTPException(404, f"'{domain}' not in scheduler")
    updates = {}
    if body.mode       is not None: updates["mode"]       = body.mode
    if body.interval_h is not None: updates["interval_h"] = body.interval_h
    if body.status     is not None: updates["status"]     = body.status
    _state.upsert_target(domain, **updates)
    return {"updated": True, "domain": domain, **updates}
