# services/threat_hunting.py

from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
import threading


class ThreatHuntingEngine:
    """
    SOC Threat Hunting Layer (no DB, no external tools).
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()

    # =========================================================
    # CORE HUNTING ENTRY
    # =========================================================

    def hunt(
        self,
        events: List[Dict[str, Any]],
        incidents: List[Dict[str, Any]],
        user: Optional[str] = None,
        host: Optional[str] = None,
        ip: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:

        filtered_events = self._filter_events(
            events,
            user=user,
            host=host,
            ip=ip,
            event_type=event_type,
            severity=severity,
            start_time=start_time,
            end_time=end_time,
        )

        related_incidents = self._match_incidents(
            incidents,
            user=user,
            host=host,
            ip=ip,
        )

        timeline = self._build_timeline(filtered_events)

        entities = self._extract_entities(filtered_events)

        patterns = self._detect_patterns(filtered_events)

        return {
            "query": {
                "user": user,
                "host": host,
                "ip": ip,
                "event_type": event_type,
                "severity": severity,
                "start_time": start_time,
                "end_time": end_time,
            },
            "summary": {
                "total_events": len(filtered_events),
                "total_incidents": len(related_incidents),
            },
            "events": filtered_events,
            "incidents": related_incidents,
            "timeline": timeline,
            "entities": entities,
            "patterns": patterns,
        }

    # =========================================================
    # EVENT FILTERING
    # =========================================================

    def _filter_events(
        self,
        events: List[Dict[str, Any]],
        user: Optional[str],
        host: Optional[str],
        ip: Optional[str],
        event_type: Optional[str],
        severity: Optional[str],
        start_time: Optional[str],
        end_time: Optional[str],
    ) -> List[Dict[str, Any]]:

        results = []

        start_dt = self._parse_time(start_time) if start_time else None
        end_dt = self._parse_time(end_time) if end_time else None

        for event in events:

            if user and event.get("user") != user:
                continue

            if host and event.get("host") != host:
                continue

            if ip and event.get("ip") != ip:
                continue

            if event_type and event.get("event_type") != event_type:
                continue

            if severity and event.get("severity") != severity:
                continue

            if start_dt or end_dt:
                try:
                    event_time = self._parse_time(event.get("timestamp"))
                    if start_dt and event_time < start_dt:
                        continue
                    if end_dt and event_time > end_dt:
                        continue
                except Exception:
                    pass

            results.append(event)

        return results

    # =========================================================
    # INCIDENT MATCHING
    # =========================================================

    def _match_incidents(
        self,
        incidents: List[Dict[str, Any]],
        user: Optional[str],
        host: Optional[str],
        ip: Optional[str],
    ) -> List[Dict[str, Any]]:

        matches = []

        for incident in incidents:

            entities = incident.get("entities", {})

            if user and entities.get("user") == user:
                matches.append(incident)
                continue

            if host and entities.get("host") == host:
                matches.append(incident)
                continue

            if ip and entities.get("ip") == ip:
                matches.append(incident)

        return matches

    # =========================================================
    # TIMELINE BUILDING
    # =========================================================

    def _build_timeline(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        sorted_events = sorted(
            events,
            key=lambda e: e.get("timestamp", ""),
        )

        timeline = []

        for e in sorted_events:

            timeline.append(
                {
                    "timestamp": e.get("timestamp"),
                    "event_type": e.get("event_type"),
                    "user": e.get("user"),
                    "host": e.get("host"),
                    "ip": e.get("ip"),
                    "severity": e.get("severity"),
                }
            )

        return timeline

    # =========================================================
    # ENTITY EXTRACTION
    # =========================================================

    def _extract_entities(
        self,
        events: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:

        users = set()
        hosts = set()
        ips = set()

        for e in events:
            if e.get("user") and e.get("user") != "unknown":
                users.add(e.get("user"))
            if e.get("host") and e.get("host") != "unknown":
                hosts.add(e.get("host"))
            if e.get("ip") and e.get("ip") != "0.0.0.0":
                ips.add(e.get("ip"))

        return {
            "users": sorted(list(users)),
            "hosts": sorted(list(hosts)),
            "ips": sorted(list(ips)),
        }

    # =========================================================
    # PATTERN DETECTION (LIGHTWEIGHT BEHAVIORAL SIGNALS)
    # =========================================================

    def _detect_patterns(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        patterns = []

        failed_logins = 0
        successful_logins = 0
        scans = 0

        for e in events:
            if "failed_login" in e.get("event_type", ""):
                failed_logins += 1
            elif "successful_login" in e.get("event_type", ""):
                successful_logins += 1
            elif "scan" in e.get("event_type", ""):
                scans += 1

        if failed_logins >= 5:
            patterns.append({
                "name": "Brute Force Attempt",
                "severity": "high",
                "count": failed_logins
            })

        if successful_logins > 0 and failed_logins > 0:
            patterns.append({
                "name": "Failed Then Successful Login",
                "severity": "medium",
                "description": "Unusual login pattern detected"
            })

        if scans >= 3:
            patterns.append({
                "name": "Network Scanning Activity",
                "severity": "high",
                "count": scans
            })

        return patterns

    # =========================================================
    # TIME PARSING
    # =========================================================

    def _parse_time(self, ts: Optional[str]) -> datetime:
        if not ts:
            return datetime.min
        
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.min