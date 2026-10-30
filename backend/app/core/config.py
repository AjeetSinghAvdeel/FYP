from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "Risk-Guided Adaptive Pentest Platform"
    app_version: str = "0.1.0"
    environment: str = "development"
    database_url: str = f"sqlite:///{BASE_DIR / 'data' / 'pentest.db'}"
    secret_key: str = "dev-secret-key-change-me"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24
    allow_public_targets: bool = False

    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", case_sensitive=False)


@lru_cache
def get_settings() -> Settings:
    return Settings()
