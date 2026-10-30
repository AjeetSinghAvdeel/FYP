from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AssessmentCreate(BaseModel):
    name: str = Field(..., min_length=3)
    target_id: int
    budget: int = 8


class FindingOut(BaseModel):
    id: int
    source_tool: str
    title: str
    severity: str
    confidence: int
    asset: str
    vector: str
    evidence: str | None = None
    status: str


class AssessmentOut(BaseModel):
    id: int
    name: str
    status: str
    budget: int
    target_id: int
    summary: str | None = None
    next_action: str | None = None
    risk_score: float
    graph_snapshot: Any | None = None
    findings: list[FindingOut] = []
    created_at: datetime
    current_phase: str = "draft"
    progress: int = 0
    requests_used: int = 0
    job_id: str | None = None
    last_error: str | None = None


class AssessmentStep(BaseModel):
    assessment_id: int
    tool: str
    recommendation: str
    threat_score: float
    authorization: str
    score_breakdown: dict[str, float] = {}
