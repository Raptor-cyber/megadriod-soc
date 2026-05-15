// static/websocket.js

/* =========================================================
   Megadriod SOC Lab - WebSocket Utility Layer
   Shared real-time connection handler for frontend modules
========================================================= */

class SOCWebSocketClient {
    constructor(url = null) {
        this.url = url || this.buildURL();
        this.socket = null;

        this.connected = false;
        this.reconnectInterval = 3000;
        this.shouldReconnect = true;

        this.listeners = {
            event: [],
            alert: [],
            incident: [],
            stats: [],
            message: []
        };

        this.init();
    }

    // =========================================================
    // INIT
    // =========================================================

    init() {
        this.connect();
    }

    buildURL() {
        const protocol = window.location.protocol === "https:" ? "wss" : "ws";
        return `${protocol}://${window.location.host}/ws`;
    }

    // =========================================================
    // CONNECTION
    // =========================================================

    connect() {
        try {
            this.socket = new WebSocket(this.url);

            this.socket.onopen = () => {
                this.connected = true;
                this.emit("message", { type: "connection", status: "connected" });
            };

            this.socket.onmessage = (event) => {
                this.handleMessage(event.data);
            };

            this.socket.onclose = () => {
                this.connected = false;
                this.emit("message", { type: "connection", status: "disconnected" });

                if (this.shouldReconnect) {
                    setTimeout(() => this.connect(), this.reconnectInterval);
                }
            };

            this.socket.onerror = () => {
                this.connected = false;
            };

        } catch (err) {
            console.error("WebSocket connection error:", err);
        }
    }

    // =========================================================
    // MESSAGE HANDLING
    // =========================================================

    handleMessage(raw) {
        let msg = null;

        try {
            msg = JSON.parse(raw);
        } catch (e) {
            console.error("Invalid WS message:", raw);
            return;
        }

        if (!msg.type) return;

        this.emit(msg.type, msg.data);
    }

    // =========================================================
    // SEND
    // =========================================================

    send(data) {
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;

        this.socket.send(JSON.stringify(data));
    }

    sendHeartbeat() {
        this.send({ type: "heartbeat", timestamp: Date.now() });
    }

    // =========================================================
    // EVENT SYSTEM
    // =========================================================

    on(type, callback) {
        if (!this.listeners[type]) {
            this.listeners[type] = [];
        }

        this.listeners[type].push(callback);
    }

    emit(type, data) {
        const handlers = this.listeners[type] || [];

        handlers.forEach(fn => {
            try {
                fn(data);
            } catch (err) {
                console.error("Listener error:", err);
            }
        });
    }

    // =========================================================
    // CONTROL
    // =========================================================

    disconnect() {
        this.shouldReconnect = false;

        if (this.socket) {
            this.socket.close();
        }
    }

    reconnect() {
        this.shouldReconnect = true;
        this.connect();
    }

    isConnected() {
        return this.connected;
    }
}

// =========================================================
// GLOBAL INSTANCE
// =========================================================

window.SOCWS = new SOCWebSocketClient();

// Optional heartbeat
setInterval(() => {
    if (window.SOCWS.isConnected()) {
        window.SOCWS.sendHeartbeat();
    }
}, 10000);