"""
ForgeLens configuration manager.

Loads settings in priority order:
  1. Environment variables (highest priority)
  2. .env file (project root)
  3. configs/settings.yaml (defaults)

Usage:
    from core.config import settings
    print(settings.app.name)
    print(settings.evidence.base_path)
"""

from __future__ import annotations

from pathlib import Path

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Locate project root ───────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT_DIR / ".env"
SETTINGS_FILE = ROOT_DIR / "backend" / "configs" / "settings.yaml"


# ── Sub-models ────────────────────────────────────────────────────────────────


class AppConfig(BaseModel):
    name: str = "ForgeLens"
    version: str = "0.1.0"
    debug: bool = False
    timezone: str = "Asia/Kolkata"   # IST — change to "UTC" for UTC


class EvidenceConfig(BaseModel):
    base_path: Path = ROOT_DIR / "evidence"
    hash_algorithm: str = "sha256"


class LoggingConfig(BaseModel):
    level: str = "INFO"
    log_dir: Path = ROOT_DIR / "backend" / "logs"


class AcquisitionConfig(BaseModel):
    block_size: int = 4096
    threads: int = 4


class FeaturesConfig(BaseModel):
    disabled: list[str] = Field(default_factory=list)


# ── Main settings class ───────────────────────────────────────────────────────


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",  # e.g. APP__DEBUG=true maps to app.debug
        extra="ignore",
    )

    app: AppConfig = Field(default_factory=AppConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    acquisition: AcquisitionConfig = Field(default_factory=AcquisitionConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)


    # Flat env-var overrides (e.g. SECRET_KEY in .env)
    secret_key: str = "change_me_before_use"
    db_path: Path = ROOT_DIR / "evidence" / "forgelens.db"
    app_env: str = "development"

    @classmethod
    def from_yaml(cls) -> Settings:
        """Load defaults from settings.yaml, then overlay env vars."""
        load_dotenv(ENV_FILE)
        yaml_data: dict = {}
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f) or {}
        return cls(**yaml_data)


# ── Singleton ─────────────────────────────────────────────────────────────────
settings: Settings = Settings.from_yaml()
