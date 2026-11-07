import json
from typing import List, Union
from pydantic import field_validator, model_validator
import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "DEEPTRACE"
    PROJECT_DESCRIPTION: str = "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform"
    TEAM_NAME: str = "DEEP thinkers"
    PROBLEM_STATEMENT: str = "SIH26106"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    APP_ENV: str = "development"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    SECRET_KEY: str = ""
    ACCESS_TOKEN_MINUTES: int = 30
    TOKEN_ISSUER: str = "mailspectra"
    LOGIN_ATTEMPT_LIMIT: int = 10
    LOGIN_WINDOW_SECONDS: int = 300
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
    VERIFY_AUTHENTICATION_DNS: bool = False
    TRUSTED_RECEIVERS: List[str] = []
    DNS_TIMEOUT_SECONDS: float = 3.0
    HTTP_INTEL_TIMEOUT_SECONDS: float = 5.0
    CACHE_TTL_HOURS: int = 24

    CORRELATION_MATCH_THRESHOLD: float = 0.35
    CORRELATION_CLUSTER_THRESHOLD: float = 0.60
    CORRELATION_WINDOW_DAYS: int = 90

    # Alerting & Thresholds
    ALERT_THRESHOLD_SCORE: float = 60.0  # Threshold for generating high alerts
    CRITICAL_ALERT_SCORE: float = 80.0   # Threshold for critical alerts
    DEFAULT_DATA_RETENTION_DAYS: int = 90
    PRIVACY_MASKING_ENABLED: bool = False

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

    @model_validator(mode="after")
    def secure_configuration(self):
        if self.APP_ENV == "production":
            if len(self.SECRET_KEY) < 32 or len(set(self.SECRET_KEY)) < 16:
                raise ValueError("Production requires a random SECRET_KEY of at least 32 characters")
            if self.DEBUG or "*" in self.CORS_ORIGINS:
                raise ValueError("Production requires DEBUG=false and explicit CORS origins")
        elif not self.SECRET_KEY:
            # Development sessions intentionally expire on restart without a configured key.
            self.SECRET_KEY = secrets.token_urlsafe(48)
        return self

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
