from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class EventView(BaseModel):
    timestamp: datetime
    event_type: str
    phase: str
    source: str
    actor: str | None = None
    detail: str
    dst_ip: str | None = None


class TechniqueView(BaseModel):
    id: str
    name: str
    tactic: str


class AttributionView(BaseModel):
    technique_ids: list[str]
    techniques: list[TechniqueView]
    explanation: str
    grounded: bool
    predicted_next: str


class IncidentSummary(BaseModel):
    id: str
    entity: str
    compound_score: float
    high_confidence: bool
    is_true_positive: bool
    phase_count: int
    source_count: int
    event_count: int
    start: datetime
    end: datetime
    phases: list[str]   # ordered by first occurrence in the timeline
    sources: list[str]


class IncidentDetail(BaseModel):
    summary: IncidentSummary
    timeline: list[EventView]
    attribution: AttributionView


class MetricsView(BaseModel):
    behavioural_recall: float
    signature_recall: float
    mttd_seconds: int
    attack_techniques: int
    false_positive_rate: float
