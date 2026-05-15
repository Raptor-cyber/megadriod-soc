# models/event.py

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Event:
    """
    Core SOC Event model.

    Represents a single security telemetry record
    flowing through the SIEM pipeline.
    """

    event_id: str

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    source: str = "custom"  # endpoint | firewall | auth | dns | network | syslog

    event_type: str = "unknown"

    severity: str = "low"

    user: str = "unknown"

    host: str = "unknown"

    ip: str = "0.0.0.0"

    message: str = ""

    tags: List[str] = field(default_factory=list)

    raw_event: Dict[str, Any] = field(default_factory=dict)

    # enrichment fields
    network_zone: str = "unknown"
    severity_score: int = 0
    threat_tags: List[str] = field(default_factory=list)

    entities: Dict[str, str] = field(
        default_factory=lambda: {
            "user": "unknown",
            "host": "unknown",
            "ip": "0.0.0.0",
        }
    )

    # =========================================================
    # UPDATE METHODS
    # =========================================================

    def add_tag(self, tag: str) -> None:
        tag = tag.strip().lower()
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def set_severity(self, severity: str) -> None:
        self.severity = severity.strip().lower()

    def update_message(self, message: str) -> None:
        self.message = message.strip()

    def add_threat_tag(self, tag: str) -> None:
        tag = tag.strip().lower()
        if tag and tag not in self.threat_tags:
            self.threat_tags.append(tag)

    def set_enrichment(
        self,
        network_zone: str,
        severity_score: int,
        threat_tags: List[str],
    ) -> None:
        self.network_zone = network_zone
        self.severity_score = max(0, min(100, severity_score))
        self.threat_tags = list(
            {t.strip().lower() for t in threat_tags if t}
        )

    # =========================================================
    # SERIALIZATION
    # =========================================================

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "user": self.user,
            "host": self.host,
            "ip": self.ip,
            "message": self.message,
            "tags": self.tags,
            "raw_event": self.raw_event,
            "network_zone": self.network_zone,
            "severity_score": self.severity_score,
            "threat_tags": self.threat_tags,
            "entities": self.entities,
        }