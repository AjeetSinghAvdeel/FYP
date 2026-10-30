from typing import Any

from pydantic import BaseModel, Field


class EvaluationRequest(BaseModel):
    scenario: str = Field(..., min_length=2)
    configuration: str = Field("C", pattern="^[ABC]$")
    ground_truth: dict[str, Any]
    observed: dict[str, Any]
    seed: int | None = None
    ablations: list[str] = []


class EvaluationExecutionRequest(BaseModel):
    scenario: str = Field(..., min_length=2)
    configuration: str = Field("C", pattern="^[ABC]$")
    target_url: str
    allowed_tools: str = "nmap,ffuf,gobuster,nikto"
    target_scope: str = "allowlisted"
    ground_truth: dict[str, Any]
    mode: str = Field("mock", pattern="^(mock|real)$")
    budget: int = Field(4, ge=1, le=20)