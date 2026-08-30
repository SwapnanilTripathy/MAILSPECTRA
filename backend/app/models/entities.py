from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.base import Base, TimestampMixin


class UserRecord(Base, TimestampMixin):
    """User account model for SOC analyst authentication."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    role: Mapped[str] = mapped_column(String(64), default="SOC Analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class CaseRecord(Base, TimestampMixin):
    """Stores analyzed email case metadata, observables, and threat results."""
    __tablename__ = "cases"

    case_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), default="")
    from_address: Mapped[str] = mapped_column(String(255), default="", index=True)
    sender_domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    origin_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    classification: Mapped[str] = mapped_column(String(64), default="LEGITIMATE", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)  # OPEN, INVESTIGATING, RESOLVED, ARCHIVED
    priority: Mapped[str] = mapped_column(String(32), default="MEDIUM", index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    assigned_to: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    sha256: Mapped[str] = mapped_column(String(64), default="", index=True)
    full_analysis_json: Mapped[str] = mapped_column(Text, default="{}")

    # Forensic report integrity fields
    report_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    report_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    report_generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    observables: Mapped[List["ObservableRecord"]] = relationship(
        "ObservableRecord", back_populates="case", cascade="all, delete-orphan"
    )
    timeline_events: Mapped[List["TimelineEventRecord"]] = relationship(
        "TimelineEventRecord", back_populates="case", cascade="all, delete-orphan"
    )


class ObservableRecord(Base, TimestampMixin):
    """Stores discrete forensic observables (IPs, domains, URLs, mail servers) for graph and correlation."""
    __tablename__ = "observables"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    observable_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # IP, DOMAIN, URL, MAIL_SERVER, SENDER
    value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    defanged_value: Mapped[str] = mapped_column(String(512), default="")
    source: Mapped[str] = mapped_column(String(64), default="EMAIL_HEADER")
    extra_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    case: Mapped["CaseRecord"] = relationship("CaseRecord", back_populates="observables")


class TimelineEventRecord(Base, TimestampMixin):
    """Stores chronological investigative and forensic timeline events for a case."""
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("cases.case_id"), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), default="SYSTEM")
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    case: Mapped["CaseRecord"] = relationship("CaseRecord", back_populates="timeline_events")


class AuditLogRecord(Base, TimestampMixin):
    """Stores audit trail of user and system security actions."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(128), default="Analyst")
    details: Mapped[str] = mapped_column(Text, default="")
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class CampaignRecord(Base, TimestampMixin):
    """Stores correlated threat campaigns linking multiple cases sharing infrastructure."""
    __tablename__ = "campaigns"

    campaign_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="Uncategorized Campaign")
    primary_threat_type: Mapped[str] = mapped_column(String(64), default="PHISHING")
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    member_case_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    shared_indicators_json: Mapped[str] = mapped_column(Text, default="[]")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class IntelligenceCacheRecord(Base, TimestampMixin):
    """Caches external IP, DNS, and WHOIS lookups to prevent rate limiting."""
    __tablename__ = "intelligence_cache"

    cache_key: Mapped[str] = mapped_column(String(255), primary_key=True, index=True)
    provider: Mapped[str] = mapped_column(String(64), default="default")
    response_json: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(32), default="SUCCESS")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
