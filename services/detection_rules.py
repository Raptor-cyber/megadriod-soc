# services/detection_rules.py

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List
import uuid


class DetectionRulesEngine:
    """
    Lightweight SIEM rule engine.

    Responsibilities:
    - rule evaluation
    - threshold detection
    - time-window logic
    - rule output standardization
    """

    def __init__(self) -> None:
        self.enabled_rules = {
            "failed_login_spike": True,
            "multi_host_login": True,
            "rapid_fire_events": True,
            "external_access_anomaly": True,
        }

    # =========================================================
    # ENTRY POINT
    # =========================================================

    def evaluate(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        alerts: List[Dict[str, Any]] = []

        if self.enabled_rules["failed_login_spike"]:
            alerts.extend(self._failed_login_spike(events))

        if self.enabled_rules["multi_host_login"]:
            alerts.extend(self._multi_host_login(events))

        if self.enabled_rules["rapid_fire_events"]:
            alerts.extend(self._rapid_fire_events(events))

        if self.enabled_rules["external_access_anomaly"]:
            alerts.extend(self._external_access_anomaly(events))

        return alerts

    # =========================================================
    # RULE 1: FAILED LOGIN SPIKE
    # =========================================================

    def _failed_login_spike(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        grouped = {}

        for e in events:

            if e.get("event_type") != "failed_login":
                continue

            key = (e.get("user"), e.get("ip"))

            grouped.setdefault(key, []).append(e)

        alerts = []

        for (user, ip), items in grouped.items():

            if len(items) >= 5:

                alerts.append(
                    self._build_alert(
                        title="Failed Login Spike Detected",
                        severity="high",
                        description=(
                            f"{len(items)} failed login attempts "
                            f"for user {user} from {ip}"
                        ),
                        events=items,
                        entities={"user": user, "ip": ip},
                        rule="failed_login_spike",
                    )
                )

        return alerts

    # =========================================================
    # RULE 2: MULTI HOST LOGIN
    # =========================================================

    def _multi_host_login(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        user_hosts = {}

        for e in events:

            if e.get("event_type") != "successful_login":
                continue

            user = e.get("user")
            host = e.get("host")

            user_hosts.setdefault(user, set()).add(host)

        alerts = []

        for user, hosts in user_hosts.items():

            if len(hosts) >= 3:

                related = [
                    e
                    for e in events
                    if e.get("user") == user
                    and e.get("event_type") == "successful_login"
                ]

                alerts.append(
                    self._build_alert(
                        title="Multi-Host Login Detected",
                        severity="medium",
                        description=(
                            f"User {user} logged into "
                            f"{len(hosts)} different hosts"
                        ),
                        events=related,
                        entities={"user": user},
                        rule="multi_host_login",
                    )
                )

        return alerts

    # =========================================================
    # RULE 3: RAPID FIRE EVENTS
    # =========================================================

    def _rapid_fire_events(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        sorted_events = sorted(
            events,
            key=lambda e: e.get("timestamp", ""),
        )

        alerts = []

        window = timedelta(seconds=10)

        for i in range(len(sorted_events)):

            base = sorted_events[i]

            base_time = self._parse_time(base.get("timestamp"))

            burst = []

            for j in range(i, len(sorted_events)):

                current = sorted_events[j]

                current_time = self._parse_time(
                    current.get("timestamp")
                )

                if current_time - base_time <= window:
                    burst.append(current)
                else:
                    break

            if len(burst) >= 10:

                alerts.append(
                    self._build_alert(
                        title="Rapid Event Burst Detected",
                        severity="medium",
                        description=(
                            f"{len(burst)} events in 10 seconds"
                        ),
                        events=burst,
                        entities={},
                        rule="rapid_fire_events",
                    )
                )

        return alerts

    # =========================================================
    # RULE 4: EXTERNAL ACCESS ANOMALY
    # =========================================================

    def _external_access_anomaly(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        alerts = []

        external_logins = [
            e
            for e in events
            if e.get("event_type") == "successful_login"
            and e.get("ip_type") == "external"
        ]

        if len(external_logins) >= 3:

            alerts.append(
                self._build_alert(
                    title="External Access Anomaly",
                    severity="high",
                    description=(
                        "Multiple successful logins from external IPs"
                    ),
                    events=external_logins,
                    entities={},
                    rule="external_access_anomaly",
                )
            )

        return alerts

    # =========================================================
    # ALERT BUILDER
    # =========================================================

    def _build_alert(
        self,
        title: str,
        severity: str,
        description: str,
        events: List[Dict[str, Any]],
        entities: Dict[str, Any],
        rule: str,
    ) -> Dict[str, Any]:

        return {
            "id": self._generate_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "title": title,
            "severity": severity,
            "description": description,
            "rule": rule,
            "event_count": len(events),
            "events": events,
            "entities": entities,
        }

    # =========================================================
    # HELPERS
    # =========================================================

    def _generate_id(self) -> str:
        return str(uuid.uuid4())

    def _parse_time(self, ts: str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.utcnow()