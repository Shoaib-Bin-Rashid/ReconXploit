"""
ReconXploit API — Subdomains router

Endpoints:
  GET  /api/v1/subdomains                      List subdomains (filterable)
  GET  /api/v1/subdomains/target/{domain}      All subdomains for a target
  GET  /api/v1/subdomains/target/{domain}/live  Only live subdomains
"""

import logging
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.models.database import get_db_context
from backend.models.models import Subdomain, LiveHost, Target

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────

class SubdomainOut(BaseModel):
    id: str
    subdomain: str
    source: Optional[str]
    ip_address: Optional[str]
    is_active: Optional[bool]
    discovered_at: Optional[datetime]

    class Config:
        from_attributes = True


class LiveHostOut(BaseModel):
    id: str
    url: str
    status_code: Optional[int]
    title: Optional[str]
    server: Optional[str]
    waf: Optional[str]
    cdn: Optional[str]
    ip_address: Optional[str]
    content_length: Optional[int]
    probed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@router.get("", response_model=List[SubdomainOut], summary="List all subdomains")
def list_subdomains(
    domain: Optional[str] = Query(None, description="Filter by target domain"),
    source: Optional[str] = Query(None, description="Filter by discovery source"),
    limit:  int           = Query(200, ge=1, le=1000),
    offset: int           = Query(0, ge=0),
):
    with get_db_context() as db:
        q = db.query(Subdomain)
        if domain:
            target = db.query(Target).filter(Target.domain == domain).first()
            if target:
                q = q.filter(Subdomain.target_id == target.id)
            else:
                return []
        if source:
            q = q.filter(Subdomain.source == source)
        subs = q.order_by(Subdomain.first_seen.desc()).offset(offset).limit(limit).all()
        return [_sub_out(s) for s in subs]


@router.get("/target/{domain}", response_model=List[SubdomainOut], summary="Subdomains for a target")
def subdomains_for_target(
    domain: str,
    limit:  int = Query(500, ge=1, le=5000),
):
    with get_db_context() as db:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            raise HTTPException(404, f"Target '{domain}' not found")
        subs = db.query(Subdomain)\
                 .filter(Subdomain.target_id == target.id)\
                 .order_by(Subdomain.first_seen.desc())\
                 .limit(limit).all()
        return [_sub_out(s) for s in subs]


@router.get("/target/{domain}/live", response_model=List[LiveHostOut], summary="Live hosts for a target")
def live_hosts_for_target(
    domain:      str,
    status_code: Optional[int] = Query(None, description="Filter by HTTP status code"),
    limit:       int           = Query(200, ge=1, le=1000),
):
    """Return all live hosts (HTTP-responding) discovered for this target."""
    with get_db_context() as db:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            raise HTTPException(404, f"Target '{domain}' not found")
        q = db.query(LiveHost).filter(LiveHost.target_id == target.id)
        if status_code:
            q = q.filter(LiveHost.status_code == status_code)
        hosts = q.order_by(LiveHost.first_seen.desc()).limit(limit).all()
        return [_host_out(h) for h in hosts]


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _sub_out(s: Subdomain) -> SubdomainOut:
    return SubdomainOut(
        id            = s.id,
        subdomain     = s.subdomain,
        source        = getattr(s, "source", None),
        ip_address    = getattr(s, "ip_address", None),
        is_active     = getattr(s, "is_active", None),
        discovered_at = getattr(s, "discovered_at", None),
    )


def _host_out(h: LiveHost) -> LiveHostOut:
    return LiveHostOut(
        id             = h.id,
        url            = h.url,
        status_code    = h.status_code,
        title          = getattr(h, "title", None),
        server         = getattr(h, "server", None),
        waf            = getattr(h, "waf", None),
        cdn            = getattr(h, "cdn", None),
        ip_address     = getattr(h, "ip_address", None),
        content_length = getattr(h, "content_length", None),
        probed_at      = getattr(h, "probed_at", None),
    )
