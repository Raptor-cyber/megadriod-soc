// static/app.js

/* =========================================================
   Megadriod SOC Lab - Frontend Live SOC Controller
   Vanilla JS real-time dashboard engine (no frameworks)
========================================================= */

class SOCApp {
    constructor() {
        this.events = [];
        this.alerts = [];
        this.incidents = [];

        this.ws = null;
        this.connected = false;

        this.filters = {
            search: "",
            severity: "all",
            event_type: "all",
            user: "",
            host: "",
            ip: ""
        };

        this.init();
    }

    // =========================================================
    // INIT
    // =========================================================

    init() {
        this.bindUI();
        this.connectWebSocket();
        this.loadInitialData();
        this.startHeartbeat();
    }

    // NEW: Load initial data from backend
    loadInitialData() {
        Promise.all([
            fetch("/api/events?limit=100").then(r => r.json()),
            fetch("/api/alerts?limit=50").then(r => r.json()),
            fetch("/api/incidents?limit=50").then(r => r.json())
        ])
        .then(([events, alerts, incidents]) => {
            this.events = events || [];
            this.alerts = alerts || [];
            this.incidents = incidents || [];
            this.renderEvents();
            this.renderAlerts();
            this.renderIncidents();
        })
        .catch(err => console.error("Failed to load initial data:", err));
    }

    bindUI() {
        const searchInput = document.getElementById("search");
        const severityFilter = document.getElementById("severityFilter");

        if (searchInput) {
            searchInput.addEventListener("input", (e) => {
                this.filters.search = e.target.value.toLowerCase();
                this.renderEvents();
            });
        }

        if (severityFilter) {
            severityFilter.addEventListener("change", (e) => {
                this.filters.severity = e.target.value;
                this.renderEvents();
            });
        }
    }

    // =========================================================
    // WEBSOCKET
    // =========================================================

    connectWebSocket() {
        try {
            const protocol = window.location.protocol === "https:" ? "wss" : "ws";
            this.ws = new WebSocket(`${protocol}://${window.location.host}/ws`);

            this.ws.onopen = () => {
                this.connected = true;
                this.updateConnectionStatus(true);
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            };

            this.ws.onclose = () => {
                this.connected = false;
                this.updateConnectionStatus(false);
                setTimeout(() => this.connectWebSocket(), 3000);
            };

            this.ws.onerror = () => {
                this.connected = false;
                this.updateConnectionStatus(false);
            };
        } catch (err) {
            console.error("WebSocket error:", err);
        }
    }

    handleMessage(msg) {
        switch (msg.type) {
            case "event":
                this.addEvent(msg.data);
                break;

            case "alert":
                this.addAlert(msg.data);
                break;

            case "incident":
                this.addIncident(msg.data);
                break;

            case "stats":
                this.updateStats(msg.data);
                break;
        }
    }

    // =========================================================
    // DATA HANDLERS
    // =========================================================

    addEvent(event) {
        this.events.unshift(event);

        if (this.events.length > 5000) {
            this.events = this.events.slice(0, 5000);
        }

        this.renderEvents();
    }

    addAlert(alert) {
        this.alerts.unshift(alert);

        if (this.alerts.length > 1000) {
            this.alerts = this.alerts.slice(0, 1000);
        }

        this.renderAlerts();
    }

    addIncident(incident) {
        this.incidents.unshift(incident);

        if (this.incidents.length > 1000) {
            this.incidents = this.incidents.slice(0, 1000);
        }

        this.renderIncidents();
    }

    updateStats(stats) {
        const el = document.getElementById("stats");
        if (!el) return;

        el.innerHTML = `
            <div class="stat">Events: ${stats.event_count}</div>
            <div class="stat">Alerts: ${stats.alert_count}</div>
            <div class="stat">Incidents: ${stats.incident_count}</div>
        `;
    }

    // =========================================================
    // FILTERING
    // =========================================================

    applyFilters(items) {
        return items.filter(item => {
            if (this.filters.search) {
                const search = this.filters.search;
                const text = JSON.stringify(item).toLowerCase();
                if (!text.includes(search)) return false;
            }

            if (this.filters.severity !== "all") {
                if (item.severity !== this.filters.severity) return false;
            }

            return true;
        });
    }

    // =========================================================
    // RENDER EVENTS
    // =========================================================

    renderEvents() {
        const container = document.getElementById("events");
        if (!container) return;

        const filtered = this.applyFilters(this.events);

        container.innerHTML = filtered.slice(0, 100).map(e => `
            <div class="event severity-${e.severity || "low"}">
                <div class="event-header">
                    <span>${e.timestamp}</span>
                    <span>${e.event_type}</span>
                    <span>${e.severity}</span>
                </div>
                <div class="event-body">
                    <strong>User:</strong> ${e.user} |
                    <strong>Host:</strong> ${e.host} |
                    <strong>IP:</strong> ${e.ip}
                </div>
            </div>
        `).join("");
    }

    // =========================================================
    // RENDER ALERTS
    // =========================================================

    renderAlerts() {
        const container = document.getElementById("alerts");
        if (!container) return;

        container.innerHTML = this.alerts.slice(0, 50).map(a => `
            <div class="alert severity-${a.severity}">
                <div class="alert-title">${a.title}</div>
                <div class="alert-desc">${a.description}</div>
            </div>
        `).join("");
    }

    // =========================================================
    // RENDER INCIDENTS
    // =========================================================

    renderIncidents() {
        const container = document.getElementById("incidents");
        if (!container) return;

        container.innerHTML = this.incidents.slice(0, 50).map(i => `
            <div class="incident severity-${i.severity}" style="cursor:pointer;" onclick="window.location.href='/investigation?id=${i.id}'">
                <div class="incident-title">${i.title}</div>
                <div class="incident-meta">
                    Status: ${i.status} | Risk: ${i.risk_score}
                </div>
            </div>
        `).join("");
    }

    // =========================================================
    // CONNECTION STATUS
    // =========================================================

    updateConnectionStatus(state) {
        const el = document.getElementById("connectionStatus");
        if (!el) return;

        el.innerText = state ? "CONNECTED" : "DISCONNECTED";
        el.className = state ? "status ok" : "status bad";
    }

    // =========================================================
    // HEARTBEAT
    // =========================================================

    startHeartbeat() {
        setInterval(() => {
            if (this.ws && this.connected) {
                this.ws.send(JSON.stringify({ type: "heartbeat" }));
            }
        }, 10000);
    }
}

// =========================================================
// BOOTSTRAP
// =========================================================

window.addEventListener("DOMContentLoaded", () => {
    window.socApp = new SOCApp();
});