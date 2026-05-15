from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
import os

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

# =========================
# SERVICES
# =========================

from services.storage import InMemoryStorage
from services.watchlists import WatchlistManager
from services.detection_rules import DetectionRulesEngine
from services.incident_manager import IncidentManager
from services.event_processor import EventProcessor
from services.correlation_engine import CorrelationEngine
from services.threat_hunting import ThreatHuntingEngine

# =========================
# APP INIT
# =========================

app = FastAPI(title="Megadriod SOC Lab")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Fix: Use absolute path and ensure directory exists
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# =========================
# CORE SINGLETONS
# =========================

storage = InMemoryStorage()
watchlists = WatchlistManager()
rules_engine = DetectionRulesEngine()
incident_manager = IncidentManager()
event_processor = EventProcessor()
correlation_engine = CorrelationEngine()
threat_hunting = ThreatHuntingEngine()
# active websocket clients
active_connections: List[WebSocket] = []

# =========================
# UTILITIES
# =========================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def generate_id(prefix: str = "evt") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# =========================
# NORMALIZATION (LIGHT SIEM LAYER)
# =========================

def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts raw input into a unified SOC event schema.
    """

    event = {
        "id": raw.get("id", generate_id()),
        "timestamp": raw.get("timestamp", utc_now()),
        "source": raw.get("source", "api"),
        "event_type": raw.get("event_type", "unknown"),
        "severity": raw.get("severity", "low"),
        "user": raw.get("user", "unknown"),
        "host": raw.get("host", "unknown"),
        "ip": raw.get("ip", "0.0.0.0"),
        "message": raw.get("message", ""),
        "raw": raw,
    }

    return event


# =========================
# CORRELATION (LIGHT ENGINE)
# =========================

def correlate(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Runs detection rules over events.
    """
    alerts = rules_engine.evaluate(events)
    return alerts


# =========================
# WEBSOCKET MANAGER
# =========================

async def broadcast(payload: Dict[str, Any]):
    dead = []

    for conn in active_connections:
        try:
            await conn.send_json(payload)
        except Exception:
            dead.append(conn)

    for d in dead:
        active_connections.remove(d)


# =========================
# ROUTES - UI
# =========================

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    try:
        template = templates.get_template("dashboard.html")
        return template.render(request=request)
    except Exception as e:
        print(f"Template error: {e}")
        return "<h1>Dashboard Loading...</h1><p>Templates failed to load. Check templates/ folder.</p>"


@app.get("/incidents", response_class=HTMLResponse)
async def incidents_page(request: Request):
    try:
        template = templates.get_template("incidents.html")
        return template.render(request=request)
    except Exception as e:
        print(f"Template error: {e}")
        return "<h1>Incidents Page</h1><p>Templates failed to load.</p>"


@app.get("/investigation", response_class=HTMLResponse)
async def investigation_page(request: Request):
    try:
        template = templates.get_template("investigation.html")
        return template.render(request=request)
    except Exception as e:
        print(f"Template error: {e}")
        return "<h1>Investigation Page</h1><p>Templates failed to load.</p>"


# =========================
# INGESTION API (REAL EVENT INPUT)
# =========================

@app.post("/ingest")
async def ingest_event(payload: Dict[str, Any]):
    """
    Entry point for REAL logs (endpoint agents, syslog, firewall, auth logs).
    """

    event = normalize_event(payload)

    # store
    storage.store_event(event)

    # watchlist check
    watch_signals = watchlists.match_event(event)

    # detection rules (simple correlation window = last N events)
    recent_events = storage.get_events()[-50:]
    alerts = correlate(recent_events)

    # broadcast event
    await broadcast({"type": "event", "data": event})

    # broadcast alerts
    for alert in alerts:
        storage.store_alert(alert)
        await broadcast({"type": "alert", "data": alert})

    # watchlist signals
    for signal in watch_signals:
        await broadcast({"type": "alert", "data": signal})

    return {"status": "ingested", "event_id": event["id"]}


# =========================
# INCIDENT ENDPOINT (LIGHTWEIGHT CASE CREATION)
# =========================

@app.post("/incident/create")
async def create_incident(payload: Dict[str, Any]):
    incident = {
        "id": generate_id("inc"),
        "title": payload.get("title", "Untitled Incident"),
        "severity": payload.get("severity", "low"),
        "status": "new",
        "risk_score": payload.get("risk_score", 0),
        "evidence": payload.get("evidence", []),
        "notes": [],
        "created_at": utc_now(),
    }

    storage.store_incident(incident)

    await broadcast({"type": "incident", "data": incident})

    return incident


# =========================
# LIVE DATA API
# =========================

@app.get("/api/events")
async def get_events(limit: int = 100):
    """Return recent events from storage"""
    events = storage.get_events()
    return events[-limit:] if events else []


@app.get("/api/incidents")
async def get_incidents(limit: int = 10):
    """Return recent incidents from storage"""
    incidents = storage.get_incidents()
    return incidents[-limit:] if incidents else []


@app.get("/api/incident/{incident_id}")
async def get_incident(incident_id: str):
    """Return specific incident by ID"""
    incidents = storage.get_incidents()
    for inc in incidents:
        if inc.get("id") == incident_id:
            return inc
    return {"error": "Incident not found"}


@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    """Return recent alerts from storage"""
    alerts = storage.get_alerts()
    return alerts[-limit:] if alerts else []


# =========================
# WEBSOCKET STREAM
# =========================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            data = await websocket.receive_text()

            # heartbeat or client messages
            if data:
                await websocket.send_json(
                    {
                        "type": "message",
                        "data": {
                            "status": "alive",
                            "server_time": utc_now(),
                        },
                    }
                )

    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)


# =========================
# THREAT HUNTING API
# =========================

@app.get("/api/hunt")
async def hunt_entities(
    user: str = None,
    host: str = None,
    ip: str = None,
    event_type: str = None,
    severity: str = None,
    start_time: str = None,
    end_time: str = None,
):
    """
    Entity pivoting and threat hunting endpoint.
    Returns events, incidents, timeline, entities, and patterns.
    """
    events = storage.get_events()
    incidents = storage.get_incidents()

    result = threat_hunting.hunt(
        events=events,
        incidents=incidents,
        user=user,
        host=host,
        ip=ip,
        event_type=event_type,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
    )

    return result


# =========================
# HEALTH CHECK
# =========================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "time": utc_now(),
        "events": len(storage.get_events()),
        "alerts": len(storage.get_alerts()),
        "incidents": len(storage.get_incidents()),
    }

# =========================
# LOCAL RUN ENTRY (UVICORN)
# =========================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )