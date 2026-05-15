// static/investigation.js

/* =========================================================
   Megadriod SOC Lab - Investigation Workspace Engine
   Handles drill-down, timeline reconstruction, case view
========================================================= */

class SOCInvestigation {
    constructor() {
        this.currentIncident = null;
        this.currentEvents = [];

        this.filters = {
            entity: null,
            timeRange: null,
            severity: null
        };

        this.init();
    }

    // =========================================================
    // INIT
    // =========================================================

    init() {
        this.bindUI();
        this.loadInitialData();
        this.setupWebSocketListeners();
    }

    bindUI() {
        const searchBtn = document.getElementById("investigateBtn");

        if (searchBtn) {
            searchBtn.addEventListener("click", () => {
                this.runInvestigation();
            });
        }
    }

    // NEW: Load incident from URL or fetch latest
    loadInitialData() {
        const params = new URLSearchParams(window.location.search);
        const incidentId = params.get("id");

        if (incidentId) {
            fetch(`/api/incident/${incidentId}`)
                .then(r => r.json())
                .then(data => this.loadIncident(data))
                .catch(err => console.error("Failed to load incident:", err));
        } else {
            // Load latest incident if none specified
            fetch(`/api/incidents?limit=1`)
                .then(r => r.json())
                .then(data => {
                    if (data.length > 0) {
                        this.loadIncident(data[0]);
                    }
                })
                .catch(err => console.error("Failed to load incidents:", err));
        }
    }

    // NEW: Listen for WebSocket updates
    setupWebSocketListeners() {
        if (window.SOCWS) {
            window.SOCWS.on("incident", (data) => {
                if (this.currentIncident && data.id === this.currentIncident.id) {
                    this.loadIncident(data);
                }
            });
        }
    }

    // =========================================================
    // LOAD INCIDENT
    // =========================================================

    loadIncident(incident) {
        this.currentIncident = incident;
        this.currentEvents = incident.evidence || [];

        this.renderIncidentHeader();
        this.renderTimeline();
        this.renderEvidence();
        this.renderNotes();
    }

    // =========================================================
    // INVESTIGATION QUERY
    // =========================================================

    runInvestigation() {
        const entityInput = document.getElementById("entityInput");
        const value = entityInput ? entityInput.value : null;

        if (!value) return;

        this.filters.entity = value.toLowerCase();

        // Call threat hunting API instead of filtering locally
        this.fetchHuntResults(value);
    }

    async fetchHuntResults(query) {
        try {
            // Parse query (e.g., "user=admin" or just "admin")
            let params = new URLSearchParams();

            if (query.includes("=")) {
                const [key, val] = query.split("=").map(s => s.trim());
                params.set(key, val);
            } else {
                // Try to match as user, host, or IP
                params.set("user", query);
            }

            const res = await fetch(`/api/hunt?${params.toString()}`);
            const result = await res.json();

            this.renderFilteredEvents(result.events);
            this.renderTimeline(result.timeline || result.events);
            
            if (result.patterns && result.patterns.length > 0) {
                console.log("Detected patterns:", result.patterns);
            }
        } catch (err) {
            console.error("Hunt query failed:", err);
        }
    }

    filterEvents() {
        // This is now handled by fetchHuntResults
    }

    // =========================================================
    // RENDER INCIDENT HEADER
    // =========================================================

    renderIncidentHeader() {
        const el = document.getElementById("incidentHeader");
        if (!el || !this.currentIncident) return;

        const i = this.currentIncident;

        el.innerHTML = `
            <div class="incident-title">${i.title}</div>
            <div class="incident-meta">
                Severity: ${i.severity} |
                Status: ${i.status} |
                Risk Score: ${i.risk_score}
            </div>
        `;
    }

    // =========================================================
    // TIMELINE
    // =========================================================

    renderTimeline() {
        const el = document.getElementById("investigationTimeline");
        if (!el || !this.currentIncident) return;

        const events = this.currentEvents;

        el.innerHTML = events.map(e => `
            <div class="timeline-event severity-${e.severity || "low"}">
                <div class="time">${e.timestamp}</div>
                <div class="details">
                    <b>${e.event_type}</b><br/>
                    User: ${e.user} | Host: ${e.host} | IP: ${e.ip}
                </div>
            </div>
        `).join("");
    }

    // =========================================================
    // EVIDENCE PANEL
    // =========================================================

    renderEvidence() {
        const el = document.getElementById("evidencePanel");
        if (!el || !this.currentIncident) return;

        const evidence = this.currentIncident.evidence || [];

        el.innerHTML = evidence.map(e => `
            <div class="evidence-item">
                <div><b>${e.event_type || "event"}</b></div>
                <div>${e.timestamp}</div>
                <div>User: ${e.user} | IP: ${e.ip}</div>
                <div>${e.message || ""}</div>
            </div>
        `).join("");
    }

    // =========================================================
    // NOTES
    // =========================================================

    renderNotes() {
        const el = document.getElementById("notesPanel");
        if (!el || !this.currentIncident) return;

        const notes = this.currentIncident.notes || [];

        el.innerHTML = notes.map(n => `
            <div class="note">
                <div class="note-meta">
                    ${n.timestamp} - ${n.analyst}
                </div>
                <div class="note-body">
                    ${n.note}
                </div>
            </div>
        `).join("");
    }

    // =========================================================
    // FILTERED VIEW
    // =========================================================

    renderFilteredEvents(events) {
        const el = document.getElementById("filteredEvents");
        if (!el) return;

        el.innerHTML = events.map(e => `
            <div class="filtered-event">
                <div>${e.event_type}</div>
                <div>${e.timestamp}</div>
                <div>${e.user} | ${e.host} | ${e.ip}</div>
            </div>
        `).join("");
    }

    // =========================================================
    // ADD NOTE
    // =========================================================

    addNote(analyst, noteText) {
        if (!this.currentIncident) return;

        const note = {
            timestamp: new Date().toISOString(),
            analyst,
            note: noteText
        };

        this.currentIncident.notes.push(note);
        this.renderNotes();
    }

    // =========================================================
    // STATUS UPDATE
    // =========================================================

    updateStatus(status) {
        if (!this.currentIncident) return;

        this.currentIncident.status = status;
        this.renderIncidentHeader();
    }
}

// =========================================================
// BOOTSTRAP
// =========================================================

window.addEventListener("DOMContentLoaded", () => {
    window.socInvestigation = new SOCInvestigation();
});