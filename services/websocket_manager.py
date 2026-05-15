# services/websocket_manager.py

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Dict, Set


class WebSocketManager:
    """
    Real-time SOC event distribution layer.

    Responsibilities:
    - manage active websocket connections
    - broadcast events
    - broadcast alerts/incidents
    - keep live SOC dashboard synced
    """

    def __init__(self) -> None:
        self.active_connections: Set[Any] = set()
        self.lock = threading.Lock()

    # =========================================================
    # CONNECTION MANAGEMENT
    # =========================================================

    async def connect(self, websocket: Any) -> None:
        """
        Register a new websocket connection.
        """
        await websocket.accept()

        with self.lock:
            self.active_connections.add(websocket)

    def disconnect(self, websocket: Any) -> None:
        """
        Remove a websocket connection.
        """
        with self.lock:
            self.active_connections.discard(websocket)

    # =========================================================
    # BROADCAST CORE
    # =========================================================

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """
        Broadcast message to all connected clients.
        """

        payload = json.dumps(message)

        disconnected = []

        with self.lock:
            connections = list(self.active_connections)

        for connection in connections:
            try:
                await connection.send_text(payload)
            except Exception:
                disconnected.append(connection)

        # cleanup dead connections
        if disconnected:
            with self.lock:
                for d in disconnected:
                    self.active_connections.discard(d)

    # =========================================================
    # SOC-SPECIFIC BROADCASTS
    # =========================================================

    async def broadcast_event(self, event: Dict[str, Any]) -> None:
        await self.broadcast(
            {
                "type": "event",
                "data": event,
            }
        )

    async def broadcast_alert(self, alert: Dict[str, Any]) -> None:
        await self.broadcast(
            {
                "type": "alert",
                "data": alert,
            }
        )

    async def broadcast_incident(
        self,
        incident: Dict[str, Any],
    ) -> None:
        await self.broadcast(
            {
                "type": "incident",
                "data": incident,
            }
        )

    async def broadcast_stats(self, stats: Dict[str, Any]) -> None:
        await self.broadcast(
            {
                "type": "stats",
                "data": stats,
            }
        )

    # =========================================================
    # CONTROL MESSAGES
    # =========================================================

    async def send_to_all(self, message_type: str, data: Dict[str, Any]) -> None:
        await self.broadcast(
            {
                "type": message_type,
                "data": data,
            }
        )

    def get_connection_count(self) -> int:
        with self.lock:
            return len(self.active_connections)