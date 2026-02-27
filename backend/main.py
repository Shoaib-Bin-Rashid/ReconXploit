"""
ReconXploit - FastAPI Application Entry Point
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from contextlib import asynccontextmanager
import logging

from backend.core.config import settings
from backend.models.database import create_tables, check_connection

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("Starting ReconXploit API...")
    if check_connection():
        create_tables()
        logger.info("Database ready")
    else:
        logger.warning("Database not connected - running in limited mode")
    yield
    logger.info("Shutting down ReconXploit API")


app = FastAPI(
    title="ReconXploit API",
    description=(
        "## Ultimate Automated Recon Platform\n\n"
        "REST API for managing targets, viewing scan results, "
        "vulnerabilities, and controlling the scheduler.\n\n"
        "### Quick start\n"
        "1. `POST /api/v1/targets` — add a target\n"
        "2. `POST /api/v1/scans` — trigger a scan\n"
        "3. `GET /api/v1/dashboard/overview` — view summary\n"
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Exception Handlers
# ─────────────────────────────────────────────

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Consistent JSON shape for all HTTP errors."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error":   True,
            "status":  exc.status_code,
            "message": exc.detail,
            "path":    str(request.url.path),
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return validation errors in a human-friendly structure."""
    errors = [
        {
            "field":   " → ".join(str(loc) for loc in err["loc"]),
            "message": err["msg"],
            "type":    err["type"],
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error":   True,
            "status":  422,
            "message": "Validation failed",
            "errors":  errors,
            "path":    str(request.url.path),
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catch-all: never leak tracebacks to clients."""
    logger.exception(f"Unhandled error on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error":   True,
            "status":  500,
            "message": "Internal server error",
            "path":    str(request.url.path),
        },
    )

# ─────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────

from backend.api.targets         import router as targets_router
from backend.api.scans           import router as scans_router
from backend.api.vulnerabilities import router as vulns_router
from backend.api.subdomains      import router as subdomains_router
from backend.api.scheduler       import router as scheduler_router
from backend.api.dashboard       import router as dashboard_router

API_PREFIX = "/api/v1"

app.include_router(targets_router,    prefix=f"{API_PREFIX}/targets",    tags=["Targets"])
app.include_router(scans_router,      prefix=f"{API_PREFIX}/scans",      tags=["Scans"])
app.include_router(vulns_router,      prefix=f"{API_PREFIX}/vulns",      tags=["Vulnerabilities"])
app.include_router(subdomains_router, prefix=f"{API_PREFIX}/subdomains", tags=["Subdomains"])
app.include_router(scheduler_router,  prefix=f"{API_PREFIX}/scheduler",  tags=["Scheduler"])
app.include_router(dashboard_router,  prefix=f"{API_PREFIX}/dashboard",  tags=["Dashboard"])


# ─────────────────────────────────────────────
# Core routes
# ─────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health():
    """Health check — returns DB connectivity status."""
    db_ok = check_connection()
    return JSONResponse(
        status_code=200 if db_ok else 503,
        content={
            "status":   "ok" if db_ok else "degraded",
            "version":  "0.1.0",
            "database": db_ok,
        },
    )


@app.get("/", tags=["System"])
def root():
    return {
        "name":      "ReconXploit API",
        "version":   "0.1.0",
        "docs":      "/docs",
        "redoc":     "/redoc",
        "endpoints": {
            "targets":     f"{API_PREFIX}/targets",
            "scans":       f"{API_PREFIX}/scans",
            "vulns":       f"{API_PREFIX}/vulns",
            "subdomains":  f"{API_PREFIX}/subdomains",
            "scheduler":   f"{API_PREFIX}/scheduler/status",
            "dashboard":   f"{API_PREFIX}/dashboard/overview",
        },
    }

