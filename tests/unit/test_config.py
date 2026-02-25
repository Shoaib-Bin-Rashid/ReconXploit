"""
Unit tests for backend/core/config.py

Tests settings loading from YAML, env vars, and property methods.
No external dependencies required.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open


@pytest.mark.unit
class TestSettingsDefaults:
    """Settings should have sane defaults even without config file."""

    def setup_method(self):
        # Clear the lru_cache so each test gets a fresh Settings instance
        from backend.core.config import get_settings
        get_settings.cache_clear()

    def test_app_name_default(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.app_name == "ReconXploit"

    def test_app_version(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.app_version == "0.1.0"

    def test_db_defaults(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.db_host == "localhost"
        assert s.db_port == 5432
        assert s.db_name in ("reconxploit", "reconxploit_test")  # test env override

    def test_redis_defaults(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.redis_host == "localhost"
        assert s.redis_port == 6379

    def test_api_defaults(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.api_host == "0.0.0.0"
        assert s.api_port == 8000

    def test_cors_origins_is_list(self):
        from backend.core.config import Settings
        s = Settings()
        assert isinstance(s.cors_origins, list)
        assert len(s.cors_origins) >= 1

    def test_max_concurrent_scans_positive(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.max_concurrent_scans > 0

    def test_default_scan_timeout_positive(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.default_scan_timeout > 0

    def test_tool_names_are_strings(self):
        from backend.core.config import Settings
        s = Settings()
        for attr in ["tool_subfinder", "tool_httpx", "tool_nmap", "tool_nuclei"]:
            assert isinstance(getattr(s, attr), str)
            assert len(getattr(s, attr)) > 0


@pytest.mark.unit
class TestSettingsProperties:
    """Test computed property methods on Settings."""

    def setup_method(self):
        from backend.core.config import get_settings
        get_settings.cache_clear()

    def test_redis_url_no_password(self):
        from backend.core.config import Settings
        s = Settings()
        s.redis_password = None
        url = s.redis_url
        assert url.startswith("redis://")
        assert str(s.redis_host) in url
        assert str(s.redis_port) in url
        assert "@" not in url  # no password in URL

    def test_redis_url_with_password(self):
        from backend.core.config import Settings
        s = Settings()
        s.redis_password = "mysecret"
        url = s.redis_url
        assert "mysecret" in url
        assert "@" in url

    def test_celery_broker_matches_redis_url(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.celery_broker_url == s.redis_url

    def test_celery_backend_matches_redis_url(self):
        from backend.core.config import Settings
        s = Settings()
        assert s.celery_result_backend == s.redis_url

    def test_screenshots_path_is_path_object(self):
        from backend.core.config import Settings
        s = Settings()
        assert isinstance(s.screenshots_path, Path)

    def test_outputs_path_is_path_object(self):
        from backend.core.config import Settings
        s = Settings()
        assert isinstance(s.outputs_path, Path)

    def test_screenshots_path_contains_screenshots(self):
        from backend.core.config import Settings
        s = Settings()
        assert "screenshots" in str(s.screenshots_path)


@pytest.mark.unit
class TestSettingsEnvOverride:
    """Environment variables should override yaml/defaults."""

    def setup_method(self):
        from backend.core.config import get_settings
        get_settings.cache_clear()

    def teardown_method(self):
        from backend.core.config import get_settings
        get_settings.cache_clear()

    def test_env_overrides_db_host(self):
        from backend.core.config import Settings
        with patch.dict(os.environ, {"RECON_DB_HOST": "custom-db-host"}):
            s = Settings()
            assert s.db_host == "custom-db-host"

    def test_env_overrides_db_port(self):
        from backend.core.config import Settings
        with patch.dict(os.environ, {"RECON_DB_PORT": "5433"}):
            s = Settings()
            assert s.db_port == 5433

    def test_env_overrides_debug(self):
        from backend.core.config import Settings
        with patch.dict(os.environ, {"RECON_DEBUG": "true"}):
            s = Settings()
            assert s.debug is True

    def test_env_overrides_secret_key(self):
        from backend.core.config import Settings
        with patch.dict(os.environ, {"RECON_SECRET_KEY": "super-secret-456"}):
            s = Settings()
            assert s.secret_key == "super-secret-456"
