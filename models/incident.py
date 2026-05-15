# models/incident.py

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


VALID_STATUSES = {
    "new",
    "triage",
    "investigating",
    "escalated",
    "contained",
    "closed",
}

VALID_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Incident:
    """
    Core SOC Incident model.

    Represents a correlated security case built from alerts/events.
    """

    incident_id: str
    title: str
    severity: str = "low"
    status: str = "new"

    description: str = ""

    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    assigned_analyst: Optional[str] = None

    rule_name: Optional[str] = None
    attack_stage: Optional[str] = None

    risk_score: int = 0

    entities: Dict[str, Any] = field(default_factory=dict)

    source_alerts: List[Dict[str, Any]] = field(default_factory=list)

    evidence: List[Dict[str, Any]] = field(default_factory=list)

    timeline: List[Dict[str, Any]] = field(default_factory=list)

    notes: List[Dict[str, Any]] = field(default_factory=list)

    tags: List[str] = field(default_factory=list)

    related_event_count: int = 0

    # =========================================================
    # STATE UPDATES
    # =========================================================

    def update_timestamp(self) -> None:
        self.updated_at = utc_now()

    def set_status(self, status: str) -> None:
        status = status.lower().strip()
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        self.status = status
        self.update_timestamp()

    def set_severity(self, severity: str) -> None:
        severity = severity.lower().strip()
        if severity not in VALID_SEVERITIES:
            severity = "low"

        self.severity = severity
        self.update_timestamp()

    def assign(self, analyst: str) -> None:
        self.assigned_analyst = analyst
        self.update_timestamp()

    def add_note(self, analyst: str, note: str) -> None:
        self.notes.append(
            {
                "timestamp": utc_now(),
                "analyst": analyst,
                "note": note.strip(),
            }
        )
        self.update_timestamp()

    def add_tag(self, tag: str) -> None:
        tag = tag.strip().lower()
        if tag not in self.tags:
            self.tags.append(tag)
            self.update_timestamp()

    def add_alert(self, alert: Dict[str, Any]) -> None:
        self.source_alerts.append(alert)
        self.update_timestamp()

    def add_evidence(self, evidence: List[Dict[str, Any]]) -> None:
        self.evidence.extend(evidence)
        self.update_timestamp()

    def add_timeline(self, timeline: List[Dict[str, Any]]) -> None:
        self.timeline.extend(timeline)
        self.update_timestamp()

    def increment_event_count(self, count: int) -> None:
        self.related_event_count += count
        self.update_timestamp()

    # =========================================================
    # SERIALIZATION
    # =========================================================

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "assigned_analyst": self.assigned_analyst,
            "rule_name": self.rule_name,
            "attack_stage": self.attack_stage,
            "risk_score": self.risk_score,
            "entities": self.entities,
            "source_alerts": self.source_alerts,
            "evidence": self.evidence,
            "timeline": self.timeline,
            "notes": self.notes,
            "tags": self.tags,
            "related_event_count": self.related_event_count,
        }