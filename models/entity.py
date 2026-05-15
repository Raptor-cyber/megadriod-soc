# models/entity.py

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Entity:
    """
    Core SOC entity model.

    Represents:
    - user
    - host
    - ip
    - system object participating in events/incidents
    """

    entity_id: str
    entity_type: str  # user | host | ip | process | session
    value: str

    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    risk_score: int = 0
    tags: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    def update_seen(self, timestamp: Optional[str] = None) -> None:
        self.last_seen = timestamp or datetime.now(timezone.utc).isoformat()

    def add_tag(self, tag: str) -> None:
        tag = tag.strip().lower()
        if tag not in self.tags:
            self.tags.append(tag)

    def set_risk(self, score: int) -> None:
        self.risk_score = max(0, min(100, score))


class EntityStore:
    """
    In-memory entity registry (NO DATABASE).
    """

    def __init__(self) -> None:
        self.entities: Dict[str, Entity] = {}

    def get_or_create(
        self,
        entity_type: str,
        value: str,
    ) -> Entity:

        key = self._make_key(entity_type, value)

        if key not in self.entities:
            self.entities[key] = Entity(
                entity_id=key,
                entity_type=entity_type,
                value=value,
            )

        return self.entities[key]

    def update_entity(
        self,
        entity_type: str,
        value: str,
        risk_score: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> Entity:

        entity = self.get_or_create(entity_type, value)

        entity.update_seen()

        if risk_score is not None:
            entity.set_risk(risk_score)

        if tags:
            for t in tags:
                entity.add_tag(t)

        return entity

    def get_all(self) -> List[Entity]:
        return list(self.entities.values())

    def get_by_type(self, entity_type: str) -> List[Entity]:
        return [
            e for e in self.entities.values()
            if e.entity_type == entity_type
        ]

    def get_high_risk(self, threshold: int = 70) -> List[Entity]:
        return [
            e for e in self.entities.values()
            if e.risk_score >= threshold
        ]

    def _make_key(self, entity_type: str, value: str) -> str:
        return f"{entity_type}:{value}".lower()