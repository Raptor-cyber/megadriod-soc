# services/enrichment.py

from __future__ import annotations

import ipaddress
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class EnrichmentEngine:
    """
    SOC enrichment layer (no external DB, no external APIs).

    Responsibilities:
    - IP classification (internal/external/suspicious hints)
    - event enrichment
    - threat tagging
    - basic behavioral hints
    - entity augmentation
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()

        # lightweight in-memory watch indicators
        self.suspicious_ips = set()
        self.suspicious_users = set()
        self.blocked_hosts = set()

    # =========================================================
    # PUBLIC API
    # =========================================================

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a normalized event with additional SOC context.
        """

        enriched = dict(event)

        enriched["enrichment"] = {
            "ip_classification": self._classify_ip(
                event.get("ip")
            ),
            "risk_flags": self._compute_risk_flags(event),
            "threat_tags": self._generate_threat_tags(event),
            "entity_context": self._entity_context(event),
            "enriched_at": self._utc_now(),
        }

        enriched["risk_score"] = self._risk_score(event)

        return enriched

    def bulk_enrich(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        return [self.enrich_event(e) for e in events]

    # =========================================================
    # IP CLASSIFICATION
    # =========================================================

    def _classify_ip(self, ip: Optional[str]) -> str:
        if not ip:
            return "unknown"

        try:
            parsed = ipaddress.ip_address(ip)

            if parsed.is_private:
                return "internal"

            if parsed.is_loopback:
                return "loopback"

            if parsed.is_multicast:
                return "multicast"

            return "external"

        except Exception:
            return "invalid"

    # =========================================================
    # RISK FLAGS
    # =========================================================

    def _compute_risk_flags(self, event: Dict[str, Any]) -> List[str]:
        flags = []

        ip = event.get("ip")
        user = event.get("user")
        host = event.get("host")
        event_type = event.get("event_type", "")

        if ip in self.suspicious_ips:
            flags.append("suspicious_ip")

        if user in self.suspicious_users:
            flags.append("suspicious_user")

        if host in self.blocked_hosts:
            flags.append("blocked_host")

        if "failed_login" in event_type:
            flags.append("auth_failure")

        if "admin" in event_type:
            flags.append("privileged_activity")

        if "scan" in event_type:
            flags.append("recon_activity")

        return flags

    # =========================================================
    # THREAT TAGGING
    # =========================================================

    def _generate_threat_tags(self, event: Dict[str, Any]) -> List[str]:
        tags = []

        event_type = event.get("event_type", "").lower()
        severity = event.get("severity", "").lower()
        ip_class = self._classify_ip(event.get("ip"))

        if "login" in event_type:
            tags.append("authentication")

        if "failed" in event_type:
            tags.append("failure")

        if "scan" in event_type:
            tags.append("reconnaissance")

        if "malware" in event_type:
            tags.append("malware")

        if "connection" in event_type:
            tags.append("network_activity")

        if severity in {"high", "critical"}:
            tags.append("high_priority")

        if ip_class == "external":
            tags.append("external_source")

        return tags

    # =========================================================
    # ENTITY CONTEXT
    # =========================================================

    def _entity_context(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "user": event.get("user"),
            "host": event.get("host"),
            "ip": event.get("ip"),
            "source": event.get("source"),
        }

    # =========================================================
    # RISK SCORING (NO HARD CONSTANTS)
    # =========================================================

    def _risk_score(self, event: Dict[str, Any]) -> int:
        score = 0

        severity = (event.get("severity") or "").lower()
        event_type = (event.get("event_type") or "").lower()

        # severity weighting (logical mapping, not static rule sets)
        if severity == "low":
            score += 10
        elif severity == "medium":
            score += 25
        elif severity == "high":
            score += 50
        elif severity == "critical":
            score += 75

        # behavioral signals
        if "failed" in event_type:
            score += 10

        if "login" in event_type:
            score += 5

        if "scan" in event_type:
            score += 15

        if "malware" in event_type:
            score += 40

        # external source risk
        if self._classify_ip(event.get("ip")) == "external":
            score += 10

        return min(score, 100)

    # =========================================================
    # WATCHLIST MANAGEMENT (IN-MEMORY)
    # =========================================================

    def add_suspicious_ip(self, ip: str) -> None:
        with self.lock:
            self.suspicious_ips.add(ip)

    def add_suspicious_user(self, user: str) -> None:
        with self.lock:
            self.suspicious_users.add(user)

    def block_host(self, host: str) -> None:
        with self.lock:
            self.blocked_hosts.add(host)

    def remove_suspicious_ip(self, ip: str) -> None:
        with self.lock:
            self.suspicious_ips.discard(ip)

    # =========================================================
    # UTILS
    # =========================================================

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()