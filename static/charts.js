// static/charts.js

/* =========================================================
   Megadriod SOC Lab - Lightweight Visualization Layer
   Vanilla JS charts (no external frameworks required)
========================================================= */

class SOCCharts {
    constructor() {
        this.timelineCanvas = null;
        this.ctx = null;

        this.data = {
            events: [],
            alerts: [],
            incidents: []
        };

        this.init();
    }

    // =========================================================
    // INIT
    // =========================================================

    init() {
        this.timelineCanvas = document.getElementById("timelineChart");

        if (this.timelineCanvas) {
            this.ctx = this.timelineCanvas.getContext("2d");
        }

        this.startRenderLoop();
    }

    // =========================================================
    // UPDATE DATA
    // =========================================================

    update(data) {
        if (!data) return;

        if (data.events) this.data.events = data.events;
        if (data.alerts) this.data.alerts = data.alerts;
        if (data.incidents) this.data.incidents = data.incidents;
    }

    // =========================================================
    // TIMELINE RENDERING (EVENT ACTIVITY GRAPH)
    // =========================================================

    renderTimeline() {
        if (!this.ctx || !this.timelineCanvas) return;

        const ctx = this.ctx;
        const canvas = this.timelineCanvas;

        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const width = canvas.width;
        const height = canvas.height;

        const events = this.data.events.slice(0, 200);

        if (events.length === 0) return;

        const max = events.length;

        const stepX = width / max;

        ctx.beginPath();
        ctx.strokeStyle = "#002366";
        ctx.lineWidth = 2;

        events.forEach((e, i) => {
            const severity = this.getSeverityValue(e.severity);

            const x = i * stepX;
            const y = height - (severity / 100) * height;

            if (i === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });

        ctx.stroke();

        // points
        events.forEach((e, i) => {
            const severity = this.getSeverityValue(e.severity);

            const x = i * stepX;
            const y = height - (severity / 100) * height;

            ctx.fillStyle = this.getSeverityColor(e.severity);

            ctx.beginPath();
            ctx.arc(x, y, 2, 0, Math.PI * 2);
            ctx.fill();
        });
    }

    // =========================================================
    // INCIDENT SEVERITY DISTRIBUTION
    // =========================================================

    renderIncidentDistribution() {
        const el = document.getElementById("incidentChart");
        if (!el) return;

        const counts = {
            low: 0,
            medium: 0,
            high: 0,
            critical: 0
        };

        this.data.incidents.forEach(i => {
            if (counts[i.severity] !== undefined) {
                counts[i.severity]++;
            }
        });

        el.innerHTML = `
            <div class="chart-bars">
                ${Object.keys(counts).map(key => `
                    <div class="bar-group">
                        <div class="bar-label">${key}</div>
                        <div class="bar" style="height:${counts[key] * 10}px"></div>
                        <div class="bar-value">${counts[key]}</div>
                    </div>
                `).join("")}
            </div>
        `;
    }

    // =========================================================
    // ALERT HEATMAP (SIMPLIFIED)
    // =========================================================

    renderAlertHeatmap() {
        const el = document.getElementById("alertHeatmap");
        if (!el) return;

        const heat = {};

        this.data.alerts.forEach(a => {
            const key = a.rule_name || "unknown";
            heat[key] = (heat[key] || 0) + 1;
        });

        el.innerHTML = Object.keys(heat).map(k => `
            <div class="heat-item">
                <span>${k}</span>
                <span>${heat[k]}</span>
            </div>
        `).join("");
    }

    // =========================================================
    // UTILITIES
    // =========================================================

    getSeverityValue(severity) {
        switch ((severity || "").toLowerCase()) {
            case "low": return 25;
            case "medium": return 50;
            case "high": return 75;
            case "critical": return 100;
            default: return 10;
        }
    }

    getSeverityColor(severity) {
        switch ((severity || "").toLowerCase()) {
            case "low": return "#22c55e";
            case "medium": return "#facc15";
            case "high": return "#f97316";
            case "critical": return "#ef4444";
            default: return "#64748b";
        }
    }

    // =========================================================
    // MAIN LOOP
    // =========================================================

    startRenderLoop() {
        setInterval(() => {
            this.renderTimeline();
            this.renderIncidentDistribution();
            this.renderAlertHeatmap();
        }, 1000);
    }
}

// =========================================================
// BOOTSTRAP
// =========================================================

window.addEventListener("DOMContentLoaded", () => {
    window.socCharts = new SOCCharts();
});