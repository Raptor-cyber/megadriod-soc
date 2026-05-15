# services/incident_manager.py

from __future__ import annotations

import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class IncidentManager:
    """
    Enterprise SOC incident management engine.

    Responsibilities:
    - incident creation
    - alert grouping
    - evidence chaining
    - workflow lifecycle
    - analyst operations
    """

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

    def __init__(self) -> None:

        self.lock = threading.Lock()

        self.incidents: List[Dict[str, Any]] = []

        self.incident_index: Dict[str, Dict[str, Any]] = {}

        self.entity_map = defaultdict(list)

    # =========================================================
    # INCIDENT CREATION
    # =========================================================

    def create_incident_from_alert(
        self,
        alert: Dict[str, Any],
    ) -> Dict[str, Any]:

        incident = {
            "id": self._generate_incident_id(),
            "title": alert.get(
                "title",
                "Security Incident",
            ),
            "description": alert.get(
                "description",
                "",
            ),
            "severity": self._normalize_severity(
                alert.get("severity")
            ),
            "status": "new",
            "created_at": self._utc_now(),
            "updated_at": self._utc_now(),
            "assigned_analyst": None,
            "rule_name": alert.get(
                "rule_name"
            ),
            "attack_stage": alert.get(
                "attack_stage"
            ),
            "risk_score": alert.get(
                "risk_score",
                0,
            ),
            "entities": alert.get(
                "entities",
                {},
            ),
            "source_alerts": [
                alert
            ],
            "evidence": self._build_evidence(
                alert
            ),
            "timeline": self._build_timeline(
                alert
            ),
            "notes": [],
            "tags": [],
            "related_event_count": alert.get(
                "source_event_count",
                0,
            ),
        }

        self._store_incident(incident)

        return incident

    # =========================================================
    # INCIDENT RETRIEVAL
    # =========================================================

    def get_all_incidents(
        self,
    ) -> List[Dict[str, Any]]:

        with self.lock:
            return list(self.incidents)

    def get_incident_by_id(
        self,
        incident_id: str,
    ) -> Optional[Dict[str, Any]]:

        return self.incident_index.get(
            incident_id
        )

    def get_incidents_by_status(
        self,
        status: str,
    ) -> List[Dict[str, Any]]:

        status = status.lower()

        with self.lock:

            return [
                incident
                for incident in self.incidents
                if incident["status"] == status
            ]

    def get_incidents_by_severity(
        self,
        severity: str,
    ) -> List[Dict[str, Any]]:

        severity = severity.lower()

        with self.lock:

            return [
                incident
                for incident in self.incidents
                if incident["severity"] == severity
            ]

    def get_incidents_by_entity(
        self,
        entity_value: str,
    ) -> List[Dict[str, Any]]:

        return self.entity_map.get(
            entity_value,
            [],
        )

    # =========================================================
    # INCIDENT OPERATIONS
    # =========================================================

    def assign_incident(
        self,
        incident_id: str,
        analyst: str,
    ) -> Dict[str, Any]:

        incident = self._require_incident(
            incident_id
        )

        with self.lock:

            incident[
                "assigned_analyst"
            ] = analyst

            incident[
                "updated_at"
            ] = self._utc_now()

        return incident

    def update_status(
        self,
        incident_id: str,
        status: str,
    ) -> Dict[str, Any]:

        status = status.lower()

        if status not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid status: {status}"
            )

        incident = self._require_incident(
            incident_id
        )

        with self.lock:

            incident["status"] = status

            incident[
                "updated_at"
            ] = self._utc_now()

        return incident

    def add_note(
        self,
        incident_id: str,
        analyst: str,
        note: str,
    ) -> Dict[str, Any]:

        incident = self._require_incident(
            incident_id
        )

        note_entry = {
            "timestamp": self._utc_now(),
            "analyst": analyst,
            "note": note.strip(),
        }

        with self.lock:

            incident["notes"].append(
                note_entry
            )

            incident[
                "updated_at"
            ] = self._utc_now()

        return incident

    def add_tag(
        self,
        incident_id: str,
        tag: str,
    ) -> Dict[str, Any]:

        incident = self._require_incident(
            incident_id
        )

        normalized_tag = (
            tag.strip().lower()
        )

        with self.lock:

            if normalized_tag not in incident[
                "tags"
            ]:
                incident["tags"].append(
                    normalized_tag
                )

            incident[
                "updated_at"
            ] = self._utc_now()

        return incident

    def link_alert(
        self,
        incident_id: str,
        alert: Dict[str, Any],
    ) -> Dict[str, Any]:

        incident = self._require_incident(
            incident_id
        )

        evidence = self._build_evidence(
            alert
        )

        timeline = self._build_timeline(
            alert
        )

        with self.lock:

            incident[
                "source_alerts"
            ].append(alert)

            incident[
                "evidence"
            ].extend(evidence)

            incident[
                "timeline"
            ].extend(timeline)

            incident[
                "related_event_count"
            ] += alert.get(
                "source_event_count",
                0,
            )

            incident[
                "updated_at"
            ] = self._utc_now()

        return incident

    # =========================================================
    # INCIDENT ANALYTICS
    # =========================================================

    def get_summary(
        self,
    ) -> Dict[str, Any]:

        with self.lock:

            summary = {
                "total_incidents": len(
                    self.incidents
                ),
                "by_status": {},
                "by_severity": {},
            }

            for status in self.VALID_STATUSES:

                summary["by_status"][
                    status
                ] = len(
                    [
                        i
                        for i in self.incidents
                        if i["status"] == status
                    ]
                )

            for severity in self.VALID_SEVERITIES:

                summary["by_severity"][
                    severity
                ] = len(
                    [
                        i
                        for i in self.incidents
                        if i["severity"] == severity
                    ]
                )

            return summary

    # =========================================================
    # INTERNAL STORAGE
    # =========================================================

    def _store_incident(
        self,
        incident: Dict[str, Any],
    ) -> None:

        with self.lock:

            self.incidents.append(
                incident
            )

            self.incident_index[
                incident["id"]
            ] = incident

            self._index_entities(
                incident
            )

    def _index_entities(
        self,
        incident: Dict[str, Any],
    ) -> None:

        entities = incident.get(
            "entities",
            {},
        )

        for _, value in entities.items():

            if not value:
                continue

            self.entity_map[
                value
            ].append(incident)

    # =========================================================
    # EVIDENCE + TIMELINE
    # =========================================================

    def _build_evidence(
        self,
        alert: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        evidence = []

        source_events = alert.get(
            "source_events",
            [],
        )

        for event in source_events:

            evidence.append(
                {
                    "event_id": event.get(
                        "id"
                    ),
                    "timestamp": event.get(
                        "timestamp"
                    ),
                    "event_type": event.get(
                        "event_type"
                    ),
                    "source": event.get(
                        "source"
                    ),
                    "host": event.get(
                        "host"
                    ),
                    "user": event.get(
                        "user"
                    ),
                    "ip": event.get(
                        "ip"
                    ),
                    "severity": event.get(
                        "severity"
                    ),
                    "message": event.get(
                        "message"
                    ),
                }
            )

        return evidence

    def _build_timeline(
        self,
        alert: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        timeline = []

        source_events = alert.get(
            "source_events",
            [],
        )

        sorted_events = sorted(
            source_events,
            key=lambda event: event.get(
                "timestamp",
                "",
            ),
        )

        for event in sorted_events:

            timeline.append(
                {
                    "timestamp": event.get(
                        "timestamp"
                    ),
                    "event_type": event.get(
                        "event_type"
                    ),
                    "host": event.get(
                        "host"
                    ),
                    "user": event.get(
                        "user"
                    ),
                    "ip": event.get(
                        "ip"
                    ),
                    "message": event.get(
                        "message"
                    ),
                }
            )

        return timeline

    # =========================================================
    # HELPERS
    # =========================================================

    def _require_incident(
        self,
        incident_id: str,
    ) -> Dict[str, Any]:

        incident = self.get_incident_by_id(
            incident_id
        )

        if not incident:
            raise ValueError(
                f"Incident not found: {incident_id}"
            )

        return incident

    def _generate_incident_id(
        self,
    ) -> str:

        return f"INC-{uuid.uuid4().hex[:12].upper()}"

    def _normalize_severity(
        self,
        severity: Optional[str],
    ) -> str:

        if not severity:
            return "low"

        severity = (
            str(severity)
            .strip()
            .lower()
        )

        if severity not in self.VALID_SEVERITIES:
            return "low"

        return severity

    def _utc_now(
        self,
    ) -> str:

        return (
            datetime.now(timezone.utc)
            .isoformat()
        )