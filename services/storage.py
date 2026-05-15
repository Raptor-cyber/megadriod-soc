# services/storage.py

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class InMemoryStorage:
    """
    Lightweight SOC storage layer (NO DATABASE).

    Responsibilities:
    - persist events (memory only)
    - persist alerts
    - persist incidents snapshots
    - simple replay / export
    """

    def __init__(self, max_events: int = 20000) -> None:
        self.lock = threading.Lock()

        self.max_events = max_events

        self.events: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.incidents: List[Dict[str, Any]] = []

    # =========================================================
    # EVENTS
    # =========================================================

    def store_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:

            self.events.append(event)

            if len(self.events) > self.max_events:
                self.events = self.events[-self.max_events :]

        return event

    def get_events(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.events)

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for e in reversed(self.events):
                if e.get("id") == event_id:
                    return e
        return None

    # =========================================================
    # ALERTS
    # =========================================================

    def store_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            self.alerts.append(alert)
        return alert

    def get_alerts(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.alerts)

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for a in reversed(self.alerts):
                if a.get("id") == alert_id:
                    return a
        return None

    # =========================================================
    # INCIDENTS
    # =========================================================

    def store_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            self.incidents.append(incident)
        return incident

    def get_incidents(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.incidents)

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for i in reversed(self.incidents):
                if i.get("id") == incident_id:
                    return i
        return None

    # =========================================================
    # EXPORT / REPLAY
    # =========================================================

    def export_all(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "events": self.events,
                "alerts": self.alerts,
                "incidents": self.incidents,
                "exported_at": self._utc_now(),
            }

    def export_json(self) -> str:
        return json.dumps(self.export_all(), indent=2)

    def clear_all(self) -> None:
        with self.lock:
            self.events.clear()
            self.alerts.clear()
            self.incidents.clear()

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "event_count": len(self.events),
                "alert_count": len(self.alerts),
                "incident_count": len(self.incidents),
                "max_events": self.max_events,
            }

    # =========================================================
    # UTIL
    # =========================================================

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()