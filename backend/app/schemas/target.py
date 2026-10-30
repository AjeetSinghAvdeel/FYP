from __future__ import annotations

from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    target_url: str = Field(..., min_length=4)
    network_range: str | None = None
    description: str | None = None
    scope: str = "allowlisted"
    allowed_tools: str = "nmap,ffuf,gobuster,nikto"


class TargetRead(TargetCreate):
    id: int
    status: str
    owner_id: int
