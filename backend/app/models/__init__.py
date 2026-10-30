from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(30), default="security_operator", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    targets: Mapped[list["Target"]] = relationship(back_populates="owner")
    assessments: Mapped[list["Assessment"]] = relationship(back_populates="owner")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    target_url: Mapped[str] = mapped_column(String(255), nullable=False)
    network_range: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[str] = mapped_column(Text, default="allowlisted")
    allowed_tools: Mapped[str] = mapped_column(Text, default="nmap,ffuf,gobuster,nikto")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="registered")

    owner: Mapped[User] = relationship(back_populates="targets")
    assessments: Mapped[list["Assessment"]] = relationship(back_populates="target")


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="new")
    budget: Mapped[int] = mapped_column(Integer, default=8)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_action: Mapped[str | None] = mapped_column(String(120), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    graph_snapshot: Mapped[str | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    current_phase: Mapped[str] = mapped_column(String(40), default="draft")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    requests_used: Mapped[int] = mapped_column(Integer, default=0)
    job_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    owner: Mapped[User] = relationship(back_populates="assessments")
    target: Mapped[Target] = relationship(back_populates="assessments")
    findings: Mapped[list["Finding"]] = relationship(back_populates="assessment")
    tool_executions: Mapped[list["ToolExecution"]] = relationship(back_populates="assessment")
    audit_events: Mapped[list["AuditEvent"]] = relationship(back_populates="assessment")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), nullable=False)
    source_tool: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(150), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    confidence: Mapped[int] = mapped_column(Integer, default=1)
    asset: Mapped[str] = mapped_column(String(120), default="host")
    vector: Mapped[str] = mapped_column(String(200), default="")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="observed")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_breakdown: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    observations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    assessment: Mapped[Assessment] = relationship(back_populates="findings")


class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), nullable=False, index=True)
    tool: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default="real")
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    return_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    requests_made: Mapped[int | None] = mapped_column(Integer, nullable=True)
    observations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    assessment: Mapped[Assessment] = relationship(back_populates="tool_executions")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey("assessments.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    action: Mapped[str | None] = mapped_column(String(120), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(40), nullable=True)
    outcome: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    previous_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    current_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    assessment: Mapped[Assessment | None] = relationship(back_populates="audit_events")


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    scenario: Mapped[str] = mapped_column(String(120), nullable=False)
    configuration: Mapped[str] = mapped_column(String(20), nullable=False)
    seed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parameters: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    results: Mapped[list["EvaluationResult"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class EvaluationResult(Base):
    __tablename__ = "evaluation_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("evaluation_runs.id"), nullable=False)
    metric: Mapped[str] = mapped_column(String(60), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    run: Mapped[EvaluationRun] = relationship(back_populates="results")
