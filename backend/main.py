"""
ReconXploit - FastAPI Application Entry Point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from backend.core.config import settings
from backend.models.database import create_tables, check_connection

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    logger.info("Starting ReconXploit API...")
    if check_connection():
        create_tables()
        logger.info("Database ready")
    else:
        logger.warning("Database not connected - some features unavailable")
    yield
    # Shutdown
    logger.info("Shutting down ReconXploit API")


app = FastAPI(
    title="ReconXploit API",
    description="Ultimate Automated Recon Platform - REST API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "database": check_connection(),
    }


@app.get("/")
def root():
    return {
        "name": "ReconXploit API",
        "version": "0.1.0",
        "docs": "/docs",
    }


# Routers will be added here as modules are built:
# from backend.api import targets, scans, vulnerabilities
# app.include_router(targets.router, prefix="/api/v1/targets", tags=["targets"])
