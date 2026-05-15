# models/rule.py

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Rule:
    """
    Core SIEM Detection Rule model.

    Represents a reusable detection logic unit.
    """

    rule_id: str
    name: str

    description: str = ""

    severity: str = "low"

    enabled: bool = True

    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    tags: List[str] = field(default_factory=list)

    # rule logic is callable (pluggable engine style)
    matcher: Optional[Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]] = None

    metadata: Dict[str, Any] = field(default_factory=dict)

    # =========================================================
    # STATE
    # =========================================================

    def enable(self) -> None:
        self.enabled = True
        self._touch()

    def disable(self) -> None:
        self.enabled = False
        self._touch()

    def set_severity(self, severity: str) -> None:
        self.severity = severity.lower().strip()
        self._touch()

    def add_tag(self, tag: str) -> None:
        tag = tag.strip().lower()
        if tag and tag not in self.tags:
            self.tags.append(tag)
            self._touch()

    def update_metadata(self, key: str, value: Any) -> None:
        self.metadata[key] = value
        self._touch()

    # =========================================================
    # EXECUTION
    # =========================================================

    def evaluate(
        self,
        events: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Execute rule logic if enabled.
        """

        if not self.enabled:
            return []

        if not self.matcher:
            return []

        return self.matcher(events)

    # =========================================================
    # INTERNAL
    # =========================================================

    def _touch(self) -> None:
        self.updated_at = utc_now()

    # =========================================================
    # SERIALIZATION
    # =========================================================

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": self.tags,
            "metadata": self.metadata,
        }