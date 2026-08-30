import json
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "DEEPTRACE"
    PROJECT_DESCRIPTION: str = "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform"
    TEAM_NAME: str = "DEEP thinkers"
    PROBLEM_STATEMENT: str = "SIH26106"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    APP_ENV: str = "development"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    SECRET_KEY: str = "deeptrace-sih2026-super-secret-key-change-in-production"
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./deeptrace.db"

    # Storage
    UPLOAD_DIR: str = "./uploads"
    REPORTS_DIR: str = "./reports"
    MAX_UPLOAD_SIZE_MB: int = 25

    # Optional Intelligence APIs & Provider Settings
    INTELLIGENCE_MODE: str = "offline"  # "offline" or "live"
    DNS_TIMEOUT_SECONDS: float = 3.0
    HTTP_INTEL_TIMEOUT_SECONDS: float = 5.0
    CACHE_TTL_HOURS: int = 24

    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    IPINFO_TOKEN: str = ""
    SHODAN_API_KEY: str = ""


    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, str) and v.startswith("["):
            try:
                return json.loads(v)
            except Exception:
                return [v]
        return v


settings = Settings()
