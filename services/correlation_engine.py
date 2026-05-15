# services/correlation_engine.py

from __future__ import annotations

import threading
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


class CorrelationEngine:
    """
    Enterprise-style SIEM correlation engine.

    Responsibilities:
    - rule-based detections
    - temporal correlation
    - entity correlation
    - attack chain reconstruction
    - alert generation
    """

    def __init__(self) -> None:

        self.lock = threading.Lock()

        self.alerts: List[Dict[str, Any]] = []

        self.alert_index: Dict[str, Dict[str, Any]] = {}

        self.enabled_rules = {
            "brute_force_detection": True,
            "privilege_escalation_detection": True,
            "lateral_movement_detection": True,
            "network_scan_detection": True,
            "malware_activity_detection": True,
            "credential_abuse_detection": True,
            "beaconing_detection": True,
        }

    # =========================================================
    # PUBLIC API
    # =========================================================

    def process_events(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Main correlation pipeline.
        """

        detections = []

        if not events:
            return detections

        if self.enabled_rules["brute_force_detection"]:
            detections.extend(
                self._detect_brute_force(events)
            )

        if self.enabled_rules["privilege_escalation_detection"]:
            detections.extend(
                self._detect_privilege_escalation(events)
            )

        if self.enabled_rules["lateral_movement_detection"]:
            detections.extend(
                self._detect_lateral_movement(events)
            )

        if self.enabled_rules["network_scan_detection"]:
            detections.extend(
                self._detect_network_scans(events)
            )

        if self.enabled_rules["malware_activity_detection"]:
            detections.extend(
                self._detect_malware_activity(events)
            )

        if self.enabled_rules["credential_abuse_detection"]:
            detections.extend(
                self._detect_credential_abuse(events)
            )

        if self.enabled_rules["beaconing_detection"]:
            detections.extend(
                self._detect_beaconing(events)
            )

        for detection in detections:
            self._store_alert(detection)

        return detections

    def get_all_alerts(self) -> List[Dict[str, Any]]:

        with self.lock:
            return list(self.alerts)

    def get_alert_by_id(
        self,
        alert_id: str,
    ) -> Optional[Dict[str, Any]]:

        return self.alert_index.get(alert_id)

    def get_alerts_by_severity(
        self,
        severity: str,
    ) -> List[Dict[str, Any]]:

        with self.lock:

            return [
                alert
                for alert in self.alerts
                if alert["severity"] == severity
            ]

    def enable_rule(
        self,
        rule_name: str,
    ) -> None:

        if rule_name in self.enabled_rules:
            self.enabled_rules[rule_name] = True

    def disable_rule(
        self,
        rule_name: str,
    ) -> None:

        if rule_name in self.enabled_rules:
            self.enabled_rules[rule_name] = False

    # =========================================================
    # DETECTION RULES
    # =========================================================

    def _detect_brute_force(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        detections = []

        grouped = defaultdict(list)

        for event in events:

            if event["event_type"] == "failed_login":

                key = (
                    event["user"],
                    event["ip"],
                )

                grouped[key].append(event)

        for (
            user,
            ip,
        ), failed_events in grouped.items():

            recent_events = self._filter_recent_events(
                failed_events,
                minutes=5,
            )

            if len(recent_events) >= 5:

                detections.append(
                    self._build_alert(
                        rule_name="Brute Force Detection",
                        severity="high",
                        title=f"Multiple failed logins detected for user {user}",
                        description=(
                            f"{len(recent_events)} failed "
                            f"login attempts from IP {ip}"
                        ),
                        source_events=recent_events,
                        entities={
                            "user": user,
                            "ip": ip,
                        },
                        attack_stage="credential_access",
                    )
                )

        return detections

    def _detect_privilege_escalation(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        detections = []

        escalation_keywords = {
            "privilege_escalation",
            "sudo_abuse",
            "admin_access",
            "token_manipulation",
        }

        for event in events:

            if event["event_type"] in escalation_keywords:

                detections.append(
                    self._build_alert(
                        rule_name="Privilege Escalation Detection",
                        severity="critical",
                        title="Privilege escalation activity detected",
                        description=(
                            f"Suspicious privilege activity "
                            f"on host {event['host']}"
                        ),
                        source_events=[event],
                        entities=event["entities"],
                        attack_stage="privilege_escalation",
                    )
                )

        return detections

    def _detect_lateral_movement(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        detections = []

        grouped = defaultdict(set)

        for event in events:

            if event["event_type"] in {
                "remote_login",
                "remote_execution",
                "smb_access",
                "rdp_connection",
            }:

                grouped[event["user"]].add(
                    event["host"]
                )

        for user, hosts in grouped.items():

            if len(hosts) >= 3:

                related_events = [
                    event
                    for event in events
                    if event["user"] == user
                ]

                detections.append(
                    self._build_alert(
                        rule_name="Lateral Movement Detection",
                        severity="high",
                        title="Potential lateral movement detected",
                        description=(
                            f"User {user} accessed "
                            f"multiple hosts"
                        ),
                        source_events=related_events,
                        entities={
                            "user": user,
                        },
                        attack_stage="lateral_movement",
                    )
                )

        return detections

    def _detect_network_scans(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        detections = []

        grouped = defaultdict(set)

        for event in events:

            if event["event_type"] == "network_connection":

                grouped[event["ip"]].add(
                    event["host"]
                )

        for ip, hosts in grouped.items():

            if len(hosts) >= 10:

                related_events = [
                    event
                    for event in events
                    if event["ip"] == ip
                ]

                detections.append(
                    self._build_alert(
                        rule_name="Network Scan Detection",
                        severity="medium",
                        title="Potential network scan detected",
                        description=(
                            f"IP {ip} connected "
                            f"to multiple hosts"
                        ),
                        source_events=related_events,
                        entities={
                            "ip": ip,
                        },
                        attack_stage="reconnaissance",
                    )
                )

        return detections

    def _detect_malware_activity(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        detections = []

        malware_keywords = {
            "malware_detected",
            "malicious_execution",
            "persistence_created",
            "payload_execution",
        }

        for event in events:

            if event["event_type"] in malware_keywords:

                detections.append(
                    self._build_alert(
                        rule_name="Malware Activity Detection",
                        severity="critical",
                        title="Malware activity detected",
                        description=(
                            f"Malicious activity on "
                            f"host {event['host']}"
                        ),
                        source_events=[event],
                        entities=event["entities"],
                        attack_stage="execution",
                    )
                )

        return detections

    def _detect_credential_abuse(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        detections = []

        failed_logins = defaultdict(list)
        successful_logins = defaultdict(list)

        for event in events:

            key = (
                event["user"],
                event["ip"],
            )

            if event["event_type"] == "failed_login":
                failed_logins[key].append(event)

            if event["event_type"] == "successful_login":
                successful_logins[key].append(event)

        for key, failures in failed_logins.items():

            if key in successful_logins:

                if len(failures) >= 3:

                    related_events = (
                        failures +
                        successful_logins[key]
                    )

                    detections.append(
                        self._build_alert(
                            rule_name="Credential Abuse Detection",
                            severity="high",
                            title="Credential abuse suspected",
                            description=(
                                "Failed logins followed "
                                "by successful authentication"
                            ),
                            source_events=related_events,
                            entities={
                                "user": key[0],
                                "ip": key[1],
                            },
                            attack_stage="credential_access",
                        )
                    )

        return detections

    def _detect_beaconing(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        detections = []

        grouped = defaultdict(list)

        for event in events:

            if event["event_type"] == "outbound_connection":

                grouped[event["ip"]].append(event)

        for ip, connections in grouped.items():

            if len(connections) < 5:
                continue

            timestamps = sorted([
                self._parse_time(
                    event["timestamp"]
                )
                for event in connections
            ])

            intervals = []

            for index in range(
                1,
                len(timestamps),
            ):

                delta = (
                    timestamps[index] -
                    timestamps[index - 1]
                ).total_seconds()

                intervals.append(delta)

            if not intervals:
                continue

            average_interval = (
                sum(intervals) / len(intervals)
            )

            consistent = all(
                abs(i - average_interval) < 10
                for i in intervals
            )

            if consistent:

                detections.append(
                    self._build_alert(
                        rule_name="Beaconing Detection",
                        severity="critical",
                        title="Potential beaconing detected",
                        description=(
                            f"Consistent outbound "
                            f"traffic from IP {ip}"
                        ),
                        source_events=connections,
                        entities={
                            "ip": ip,
                        },
                        attack_stage="command_and_control",
                    )
                )

        return detections

    # =========================================================
    # ALERT MANAGEMENT
    # =========================================================

    def _build_alert(
        self,
        rule_name: str,
        severity: str,
        title: str,
        description: str,
        source_events: List[Dict[str, Any]],
        entities: Dict[str, str],
        attack_stage: str,
    ) -> Dict[str, Any]:

        alert_id = str(uuid.uuid4())

        return {
            "id": alert_id,
            "timestamp": (
                datetime.now(timezone.utc)
                .isoformat()
            ),
            "rule_name": rule_name,
            "severity": severity,
            "title": title,
            "description": description,
            "status": "new",
            "attack_stage": attack_stage,
            "entities": entities,
            "source_event_count": len(source_events),
            "source_events": source_events,
            "risk_score": self._calculate_risk_score(
                severity,
                len(source_events),
            ),
        }

    def _store_alert(
        self,
        alert: Dict[str, Any],
    ) -> None:

        with self.lock:

            self.alerts.append(alert)

            self.alert_index[
                alert["id"]
            ] = alert

    # =========================================================
    # HELPERS
    # =========================================================

    def _filter_recent_events(
        self,
        events: List[Dict[str, Any]],
        minutes: int,
    ) -> List[Dict[str, Any]]:

        now = datetime.now(timezone.utc)

        cutoff = now - timedelta(
            minutes=minutes
        )

        recent = []

        for event in events:

            event_time = self._parse_time(
                event["timestamp"]
            )

            if event_time >= cutoff:
                recent.append(event)

        return recent

    def _parse_time(
        self,
        timestamp: str,
    ) -> datetime:

        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    def _calculate_risk_score(
        self,
        severity: str,
        event_count: int,
    ) -> int:

        severity_base = {
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 100,
        }

        score = (
            severity_base.get(severity, 0)
            + min(event_count * 2, 25)
        )

        return min(score, 100)