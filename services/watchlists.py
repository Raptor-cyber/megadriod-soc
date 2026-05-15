# services/watchlists.py

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class WatchlistManager:
    """
    In-memory SOC watchlist system.

    Responsibilities:
    - track suspicious entities (IP, user, host)
    - match events against watchlists
    - generate risk signals for correlation layer
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()

        self.ip_watchlist: Dict[str, Dict[str, Any]] = {}
        self.user_watchlist: Dict[str, Dict[str, Any]] = {}
        self.host_watchlist: Dict[str, Dict[str, Any]] = {}

    # =========================================================
    # ADD TO WATCHLIST
    # =========================================================

    def add_ip(
        self,
        ip: str,
        reason: str = "",
        severity: str = "medium",
    ) -> Dict[str, Any]:

        entry = self._build_entry(ip, reason, severity, "ip")

        with self.lock:
            self.ip_watchlist[ip] = entry

        return entry

    def add_user(
        self,
        user: str,
        reason: str = "",
        severity: str = "medium",
    ) -> Dict[str, Any]:

        entry = self._build_entry(user, reason, severity, "user")

        with self.lock:
            self.user_watchlist[user] = entry

        return entry

    def add_host(
        self,
        host: str,
        reason: str = "",
        severity: str = "medium",
    ) -> Dict[str, Any]:

        entry = self._build_entry(host, reason, severity, "host")

        with self.lock:
            self.host_watchlist[host] = entry

        return entry

    # =========================================================
    # REMOVE FROM WATCHLIST
    # =========================================================

    def remove_ip(self, ip: str) -> None:
        with self.lock:
            self.ip_watchlist.pop(ip, None)

    def remove_user(self, user: str) -> None:
        with self.lock:
            self.user_watchlist.pop(user, None)

    def remove_host(self, host: str) -> None:
        with self.lock:
            self.host_watchlist.pop(host, None)

    # =========================================================
    # MATCHING ENGINE
    # =========================================================

    def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check if event matches any watchlist entry.
        Returns risk signals.
        """

        signals = []

        ip = event.get("ip")
        user = event.get("user")
        host = event.get("host")

        if ip and ip in self.ip_watchlist:
            signals.append(
                self._build_signal(
                    entity=ip,
                    entity_type="ip",
                    entry=self.ip_watchlist[ip],
                    event=event,
                )
            )

        if user and user in self.user_watchlist:
            signals.append(
                self._build_signal(
                    entity=user,
                    entity_type="user",
                    entry=self.user_watchlist[user],
                    event=event,
                )
            )

        if host and host in self.host_watchlist:
            signals.append(
                self._build_signal(
                    entity=host,
                    entity_type="host",
                    entry=self.host_watchlist[host],
                    event=event,
                )
            )

        return signals

    # =========================================================
    # LIST WATCHLISTS
    # =========================================================

    def get_all(self) -> Dict[str, List[Dict[str, Any]]]:

        with self.lock:
            return {
                "ip": list(self.ip_watchlist.values()),
                "user": list(self.user_watchlist.values()),
                "host": list(self.host_watchlist.values()),
            }

    # =========================================================
    # CORE BUILDERS
    # =========================================================

    def _build_entry(
        self,
        entity: str,
        reason: str,
        severity: str,
        entity_type: str,
    ) -> Dict[str, Any]:

        return {
            "entity": entity,
            "type": entity_type,
            "reason": reason,
            "severity": severity,
            "added_at": self._utc_now(),
        }

    def _build_signal(
        self,
        entity: str,
        entity_type: str,
        entry: Dict[str, Any],
        event: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "entity": entity,
            "entity_type": entity_type,
            "watchlist_reason": entry.get("reason"),
            "watchlist_severity": entry.get("severity"),
            "event": event,
            "timestamp": self._utc_now(),
            "risk_flag": True,
        }

    # =========================================================
    # UTIL
    # =========================================================

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()