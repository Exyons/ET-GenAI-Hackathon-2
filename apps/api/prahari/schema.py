from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

EventType = Literal["network_flow", "auth", "process"]
Criticality = Literal["low", "medium", "high", "critical", "unknown"]


class CanonicalEvent(BaseModel):
    timestamp: datetime
    event_type: EventType
    source_entity: str | None = None
    dest_entity: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_host: str | None = None
    dst_host: str | None = None
    action: str | None = None
    outcome: str | None = None
    bytes: int | None = None
    duration: float | None = None
    src_internal: bool | None = None
    asset_criticality: Criticality = "unknown"
    source: str
    labels: list[str] = Field(default_factory=list)
    raw: str
