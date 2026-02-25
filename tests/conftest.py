"""
Shared pytest fixtures for ReconXploit tests.

Unit tests:     Use in-memory SQLite or mocks — no real DB/tools needed.
Integration:    Use a real PostgreSQL test database.
"""

import os
import uuid
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

# ── Point config at test env before any imports ──────────────────────────────
os.environ.setdefault("RECON_DB_NAME", "reconxploit_test")
os.environ.setdefault("RECON_DB_PASSWORD", "postgres")
os.environ.setdefault("RECON_DEBUG", "false")
os.environ.setdefault("RECON_SECRET_KEY", "test-secret-key")

# ── SQLAlchemy in-memory SQLite for unit tests ───────────────────────────────
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models.models import Base


@pytest.fixture(scope="session")
def sqlite_engine():
    """In-memory SQLite engine (no PostgreSQL required)."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="function")
def sqlite_session(sqlite_engine):
    """Isolated SQLite session per test (rolled back after each test)."""
    connection = sqlite_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# ── Sample data factories ────────────────────────────────────────────────────

@pytest.fixture
def sample_target_data():
    return {
        "domain": "example.com",
        "organization": "Example Corp",
        "description": "Test target",
        "status": "active",
    }


@pytest.fixture
def sample_scan_data():
    return {
        "scan_type": "full",
        "status": "pending",
    }


@pytest.fixture
def mock_subprocess_success():
    """Mock subprocess.run returning successful output."""
    with patch("subprocess.run") as mock_run:
        result = MagicMock()
        result.returncode = 0
        result.stdout = "sub1.example.com\nsub2.example.com\nsub3.example.com\n"
        result.stderr = ""
        mock_run.return_value = result
        yield mock_run


@pytest.fixture
def mock_subprocess_failure():
    """Mock subprocess.run simulating tool not found."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("tool not found")
        yield mock_run


@pytest.fixture
def mock_db_session():
    """Simple mock DB session for unit tests."""
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    session.query.return_value.filter.return_value.all.return_value = []
    session.query.return_value.filter.return_value.count.return_value = 0
    return session
