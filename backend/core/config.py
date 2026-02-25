"""
ReconXploit - Configuration Management
Loads settings from config/settings.yaml and environment variables
"""

import os
import yaml
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Optional
from functools import lru_cache

# Project root
BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONFIG_FILE = BASE_DIR / "config" / "settings.yaml"


def _load_yaml() -> dict:
    """Load YAML config file."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f) or {}
    return {}


_yaml = _load_yaml()


class Settings(BaseSettings):
    """
    Application settings.
    Values can be overridden via environment variables (uppercase, prefixed with RECON_).
    E.g., RECON_DB_PASSWORD=secret
    """

    # App
    app_name: str = "ReconXploit"
    app_version: str = "0.1.0"
    debug: bool = Field(default=False)

    # Database
    db_host: str = Field(default=_yaml.get("database", {}).get("host", "localhost"))
    db_port: int = Field(default=_yaml.get("database", {}).get("port", 5432))
    db_name: str = Field(default=_yaml.get("database", {}).get("name", "reconxploit"))
    db_user: str = Field(default=_yaml.get("database", {}).get("user", "postgres"))
    db_password: str = Field(default=_yaml.get("database", {}).get("password", ""))
    db_pool_size: int = Field(default=20)
    db_max_overflow: int = Field(default=40)

    # Redis
    redis_host: str = Field(default=_yaml.get("redis", {}).get("host", "localhost"))
    redis_port: int = Field(default=_yaml.get("redis", {}).get("port", 6379))
    redis_db: int = Field(default=_yaml.get("redis", {}).get("db", 0))
    redis_password: Optional[str] = Field(default=None)

    @property
    def redis_url(self) -> str:
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # Celery
    @property
    def celery_broker_url(self) -> str:
        return self.redis_url

    @property
    def celery_result_backend(self) -> str:
        return self.redis_url

    # API
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    cors_origins: List[str] = Field(default=["http://localhost:3000", "http://localhost:5173"])
    secret_key: str = Field(default="change-this-to-a-random-secret-key-in-production")

    # Telegram
    telegram_enabled: bool = Field(
        default=_yaml.get("notifications", {}).get("telegram", {}).get("enabled", False)
    )
    telegram_bot_token: Optional[str] = Field(
        default=_yaml.get("notifications", {}).get("telegram", {}).get("bot_token")
    )
    telegram_chat_id: Optional[str] = Field(
        default=_yaml.get("notifications", {}).get("telegram", {}).get("chat_id")
    )

    # Scanning
    max_concurrent_scans: int = Field(
        default=_yaml.get("scanning", {}).get("max_concurrent_scans", 3)
    )
    default_scan_timeout: int = Field(
        default=_yaml.get("scanning", {}).get("default_timeout", 3600)
    )

    # Storage paths (relative to BASE_DIR)
    screenshots_dir: str = Field(default="data/screenshots")
    outputs_dir: str = Field(default="data/outputs")
    temp_dir: str = Field(default="data/temp")
    wordlists_dir: str = Field(default="data/wordlists")

    @property
    def screenshots_path(self) -> Path:
        return BASE_DIR / self.screenshots_dir

    @property
    def outputs_path(self) -> Path:
        return BASE_DIR / self.outputs_dir

    @property
    def temp_path(self) -> Path:
        return BASE_DIR / self.temp_dir

    # Tool binaries (will use PATH if just a name)
    tool_subfinder: str = Field(default="subfinder")
    tool_assetfinder: str = Field(default="assetfinder")
    tool_amass: str = Field(default="amass")
    tool_findomain: str = Field(default="findomain")
    tool_httpx: str = Field(default="httpx")
    tool_gowitness: str = Field(default="gowitness")
    tool_naabu: str = Field(default="naabu")
    tool_nmap: str = Field(default="nmap")
    tool_nuclei: str = Field(default="nuclei")
    tool_waybackurls: str = Field(default="waybackurls")
    tool_gau: str = Field(default="gau")
    tool_dnsx: str = Field(default="dnsx")

    class Config:
        env_prefix = "RECON_"
        env_file = BASE_DIR / ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


# Global settings instance
settings = get_settings()
