# services/event_processor.py

from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
from collections import deque
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class EventProcessor:
    """
    Core SOC event processing engine.

    Responsibilities:
    - schema validation
    - normalization
    - enrichment
    - deduplication
    - severity mapping
    - entity extraction
    - in-memory storage
    """

    VALID_SOURCES = {
        "endpoint",
        "firewall",
        "authentication",
        "dns",
        "network",
        "web",
        "vpn",
        "proxy",
        "syslog",
        "custom",
    }

    VALID_SEVERITIES = {
        "low",
        "medium",
        "high",
        "critical",
    }

    INTERNAL_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]

    def __init__(
        self,
        max_events: int = 10000,
        dedup_window_seconds: int = 30,
    ) -> None:

        self.max_events = max_events
        self.dedup_window_seconds = dedup_window_seconds

        self.events = deque(maxlen=max_events)

        self.event_index: Dict[str, Dict[str, Any]] = {}

        self.dedup_cache: Dict[str, datetime] = {}

        self.lock = threading.Lock()

    # =========================================================
    # PUBLIC API
    # =========================================================

    def process_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main event processing pipeline.
        """

        validated = self._validate_event(raw_event)

        normalized = self._normalize_event(validated)

        enriched = self._enrich_event(normalized)

        if self._is_duplicate(enriched):
            raise ValueError("Duplicate event detected")

        stored = self._store_event(enriched)

        return stored

    def get_all_events(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.events)

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        return self.event_index.get(event_id)

    def search_events(
        self,
        user: Optional[str] = None,
        host: Optional[str] = None,
        ip: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[Dict[str, Any]]:

        results = []

        with self.lock:

            for event in reversed(self.events):

                if user and event["user"] != user:
                    continue

                if host and event["host"] != host:
                    continue

                if ip and event["ip"] != ip:
                    continue

                if event_type and event["event_type"] != event_type:
                    continue

                if severity and event["severity"] != severity:
                    continue

                if source and event["source"] != source:
                    continue

                results.append(event)

        return results

    def get_events_by_time_window(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> List[Dict[str, Any]]:

        results = []

        with self.lock:

            for event in self.events:

                event_time = datetime.fromisoformat(
                    event["timestamp"]
                )

                if start_time <= event_time <= end_time:
                    results.append(event)

        return results

    def get_stats(self) -> Dict[str, Any]:

        with self.lock:

            total_events = len(self.events)

            severity_breakdown = {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
            }

            source_breakdown: Dict[str, int] = {}

            for event in self.events:

                severity_breakdown[
                    event["severity"]
                ] += 1

                source = event["source"]

                source_breakdown[source] = (
                    source_breakdown.get(source, 0) + 1
                )

            return {
                "total_events": total_events,
                "severity_breakdown": severity_breakdown,
                "source_breakdown": source_breakdown,
            }

    # =========================================================
    # VALIDATION
    # =========================================================

    def _validate_event(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not isinstance(event, dict):
            raise ValueError("Event must be a dictionary")

        required_fields = [
            "source",
            "event_type",
        ]

        for field in required_fields:

            if field not in event:
                raise ValueError(
                    f"Missing required field: {field}"
                )

        source = str(event["source"]).lower()

        if source not in self.VALID_SOURCES:
            raise ValueError(
                f"Invalid source: {source}"
            )

        return deepcopy(event)

    # =========================================================
    # NORMALIZATION
    # =========================================================

    def _normalize_event(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        normalized = {}

        normalized["id"] = self._generate_event_id(event)

        normalized["timestamp"] = (
            self._normalize_timestamp(
                event.get("timestamp")
            )
        )

        normalized["source"] = (
            str(event.get("source", "custom"))
            .strip()
            .lower()
        )

        normalized["event_type"] = (
            str(event.get("event_type", "unknown"))
            .strip()
            .lower()
        )

        normalized["severity"] = (
            self._normalize_severity(
                event.get("severity")
            )
        )

        normalized["user"] = (
            str(event.get("user", "unknown"))
            .strip()
        )

        normalized["host"] = (
            str(event.get("host", "unknown"))
            .strip()
        )

        normalized["ip"] = (
            self._normalize_ip(
                event.get("ip", "0.0.0.0")
            )
        )

        normalized["message"] = (
            str(event.get("message", ""))
            .strip()
        )

        normalized["tags"] = (
            self._normalize_tags(
                event.get("tags", [])
            )
        )

        normalized["raw_event"] = deepcopy(event)

        return normalized

    # =========================================================
    # ENRICHMENT
    # =========================================================

    def _enrich_event(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        event["network_zone"] = (
            self._classify_ip(event["ip"])
        )

        event["severity_score"] = (
            self._severity_score(
                event["severity"]
            )
        )

        event["threat_tags"] = (
            self._generate_threat_tags(event)
        )

        event["entities"] = (
            self._extract_entities(event)
        )

        return event

    # =========================================================
    # DEDUPLICATION
    # =========================================================

    def _is_duplicate(
        self,
        event: Dict[str, Any],
    ) -> bool:

        dedup_key = self._generate_dedup_key(event)

        now = datetime.now(timezone.utc)

        existing = self.dedup_cache.get(dedup_key)

        if existing:

            delta = (
                now - existing
            ).total_seconds()

            if delta <= self.dedup_window_seconds:
                return True

        self.dedup_cache[dedup_key] = now

        return False

    # =========================================================
    # STORAGE
    # =========================================================

    def _store_event(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        with self.lock:

            self.events.append(event)

            self.event_index[
                event["id"]
            ] = event

        return event

    # =========================================================
    # HELPERS
    # =========================================================

    def _generate_event_id(
        self,
        event: Dict[str, Any],
    ) -> str:

        payload = json.dumps(
            event,
            sort_keys=True,
        )

        return hashlib.sha256(
            payload.encode()
        ).hexdigest()[:16]

    def _generate_dedup_key(
        self,
        event: Dict[str, Any],
    ) -> str:

        dedup_fields = [
            event["source"],
            event["event_type"],
            event["user"],
            event["host"],
            event["ip"],
            event["message"],
        ]

        payload = "|".join(dedup_fields)

        return hashlib.md5(
            payload.encode()
        ).hexdigest()

    def _normalize_timestamp(
        self,
        timestamp: Optional[str],
    ) -> str:

        if not timestamp:

            return (
                datetime.now(timezone.utc)
                .isoformat()
            )

        try:

            parsed = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            return parsed.isoformat()

        except Exception:

            return (
                datetime.now(timezone.utc)
                .isoformat()
            )

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

    def _normalize_ip(
        self,
        ip: str,
    ) -> str:

        try:

            ipaddress.ip_address(ip)

            return ip

        except Exception:

            return "0.0.0.0"

    def _normalize_tags(
        self,
        tags: Any,
    ) -> List[str]:

        if not isinstance(tags, list):
            return []

        normalized = []

        for tag in tags:

            normalized.append(
                str(tag).strip().lower()
            )

        return normalized

    def _classify_ip(
        self,
        ip: str,
    ) -> str:

        try:

            parsed_ip = ipaddress.ip_address(ip)

            for network in self.INTERNAL_NETWORKS:

                if parsed_ip in network:
                    return "internal"

            return "external"

        except Exception:

            return "unknown"

    def _severity_score(
        self,
        severity: str,
    ) -> int:

        mapping = {
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 100,
        }

        return mapping.get(severity, 0)

    def _generate_threat_tags(
        self,
        event: Dict[str, Any],
    ) -> List[str]:

        tags = []

        event_type = event["event_type"]

        if "login" in event_type:
            tags.append("authentication")

        if "failed" in event_type:
            tags.append("failure")

        if "malware" in event_type:
            tags.append("malware")

        if "scan" in event_type:
            tags.append("reconnaissance")

        if event["severity"] in {
            "high",
            "critical",
        }:
            tags.append("high_priority")

        return tags

    def _extract_entities(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, str]:

        return {
            "user": event["user"],
            "host": event["host"],
            "ip": event["ip"],
        }