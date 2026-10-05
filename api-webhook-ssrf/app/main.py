from flask import Flask, request, jsonify, render_template
import os, uuid, json, time, threading
import requests as req_lib

FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def init_lab():
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)
    flag_value = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag_value)

def read_flag():
    try:
        return open(FLAG_PATH).read().strip()
    except Exception:
        return "KX{ERROR_NO_FLAG}"

# ---------------------------------------------------------------------------
# INTERNAL service -- binds to 127.0.0.1:5001 only (not reachable from kali)
# ---------------------------------------------------------------------------
internal_app = Flask("internal")

@internal_app.route("/")
def internal_root():
    return "Internal metadata service -- restricted access."

@internal_app.route("/internal/secrets")
def internal_secrets():
    return jsonify({
        "service": "InternalMetadata",
        "flag": read_flag(),
        "credentials": {
            "db_host": "postgres-internal.corp.local",
            "db_user": "svc_notifyhub",
            "db_pass": "N0t1fyS3cr3t!2024",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        "internal_endpoints": [
            "/internal/secrets",
            "/internal/health",
            "/internal/admin/users",
        ],
    })

@internal_app.route("/internal/health")
def internal_health():
    return jsonify({"status": "ok", "uptime": "47d 12h 33m"})

def run_internal_server():
    internal_app.run(host="127.0.0.1", port=5001, use_reloader=False, debug=False)

# ---------------------------------------------------------------------------
# EXTERNAL app -- binds to 0.0.0.0:5000 (reachable from kali)
# ---------------------------------------------------------------------------
app = Flask(__name__)

# In-memory data stores
WEBHOOKS = {}       # {id: {"callback_url": url, "events": ["order.created"], "created_at": ts}}
DELIVERIES = {}     # {webhook_id: [{"event": "...", "response_status": N, "response_body": "...", "timestamp": ts}]}
WEBHOOK_COUNTER = [1]


def summarize_delivery(delivery):
    return {
        "webhook_id": delivery["webhook_id"],
        "event": delivery["event"],
        "callback_url": delivery["callback_url"],
        "response_status": delivery["response_status"],
        "timestamp": delivery["timestamp"],
    }

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/webhooks", methods=["POST"])
def register_webhook():
    """
    VULNERABILITY (API7:2023 -- Server-Side Request Forgery):
    Accepts any callback_url without validation or filtering.
    When an event is triggered the server will fetch this URL server-side,
    allowing an attacker to reach internal services (127.0.0.1:5001).
    """
    data = request.get_json(silent=True) or {}
    callback_url = data.get("callback_url", "").strip()
    events = data.get("events", [])

    if not callback_url:
        return jsonify({"error": "callback_url is required"}), 400
    if not events or not isinstance(events, list):
        return jsonify({"error": "events must be a non-empty list"}), 400

    valid_events = [
        "order.created", "order.updated", "order.cancelled",
        "user.signup", "payment.completed",
    ]
    for ev in events:
        if ev not in valid_events:
            return jsonify({
                "error": f"Invalid event type: {ev}",
                "valid_events": valid_events,
            }), 400

    wh_id = WEBHOOK_COUNTER[0]
    WEBHOOK_COUNTER[0] += 1

    WEBHOOKS[wh_id] = {
        "id": wh_id,
        "callback_url": callback_url,       # NO validation -- SSRF vector
        "events": events,
        "created_at": time.time(),
    }
    DELIVERIES[wh_id] = []

    return jsonify({
        "message": "Webhook registered successfully",
        "webhook": WEBHOOKS[wh_id],
    }), 201


@app.route("/api/webhooks", methods=["GET"])
def list_webhooks():
    return jsonify({"webhooks": list(WEBHOOKS.values())})


@app.route("/api/webhooks/<int:wh_id>", methods=["GET"])
def get_webhook(wh_id):
    wh = WEBHOOKS.get(wh_id)
    if not wh:
        return jsonify({"error": "Webhook not found"}), 404
    return jsonify({"webhook": wh})


@app.route("/api/events", methods=["POST"])
def trigger_event():
    """
    VULNERABILITY (API10:2023 -- Unsafe Consumption of APIs):
    When an event fires, the server fetches each subscribed webhook's
    callback_url using requests.get() with NO URL filtering.  The full
    response body is stored and can be retrieved via the deliveries endpoint.
    """
    data = request.get_json(silent=True) or {}
    event_type = data.get("type", "").strip()
    event_data = data.get("data", {})

    if not event_type:
        return jsonify({"error": "type is required"}), 400

    deliveries_made = []

    for wh_id, wh in WEBHOOKS.items():
        if event_type in wh["events"]:
            callback_url = wh["callback_url"]
            try:
                # VULNERABLE: fetches attacker-controlled URL with no restrictions
                resp = req_lib.get(callback_url, timeout=5)
                delivery = {
                    "webhook_id": wh_id,
                    "event": event_type,
                    "callback_url": callback_url,
                    "response_status": resp.status_code,
                    "response_body": resp.text[:8192],
                    "timestamp": time.time(),
                }
            except Exception as e:
                delivery = {
                    "webhook_id": wh_id,
                    "event": event_type,
                    "callback_url": callback_url,
                    "response_status": 0,
                    "response_body": f"Delivery failed: {str(e)}",
                    "timestamp": time.time(),
                }

            DELIVERIES.setdefault(wh_id, []).append(delivery)
            deliveries_made.append(summarize_delivery(delivery))

    return jsonify({
        "message": f"Event '{event_type}' processed",
        "deliveries": len(deliveries_made),
        "details": deliveries_made,
    })


@app.route("/api/webhooks/<int:wh_id>/deliveries", methods=["GET"])
def get_deliveries(wh_id):
    """
    Returns full delivery history including response bodies.
    THIS is where the attacker reads the SSRF response containing the flag.
    """
    if wh_id not in WEBHOOKS:
        return jsonify({"error": "Webhook not found"}), 404
    return jsonify({"deliveries": DELIVERIES.get(wh_id, [])})


@app.route("/api/docs", methods=["GET"])
def api_docs():
    return jsonify({
        "service": "NotifyHub API",
        "version": "1.0",
        "description": "Webhook notification service for event-driven integrations",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/webhooks",
                "description": "Register a new webhook",
                "body": {
                    "callback_url": "string (URL that will be called when events fire)",
                    "events": "list of event types to subscribe to",
                },
                "example": {
                    "callback_url": "https://example.com/my-webhook",
                    "events": ["order.created"],
                },
            },
            {
                "method": "GET",
                "path": "/api/webhooks",
                "description": "List all registered webhooks",
            },
            {
                "method": "GET",
                "path": "/api/webhooks/<id>",
                "description": "Get details for a specific webhook",
            },
            {
                "method": "POST",
                "path": "/api/events",
                "description": "Trigger an event (server will call all subscribed webhook URLs)",
                "body": {
                    "type": "string (event type)",
                    "data": "object (event payload)",
                },
                "example": {
                    "type": "order.created",
                    "data": {"order_id": 12345, "total": 99.99},
                },
                "note": "The server fetches each webhook's callback_url and stores the full response. Use /api/webhooks/<id>/deliveries to inspect the response body.",
            },
            {
                "method": "GET",
                "path": "/api/webhooks/<id>/deliveries",
                "description": "View delivery history for a webhook (includes response bodies)",
            },
            {
                "method": "GET",
                "path": "/api/docs",
                "description": "This documentation endpoint",
            },
            {
                "method": "GET",
                "path": "/api/hint",
                "description": "Get hints about the challenge",
            },
        ],
        "valid_event_types": [
            "order.created",
            "order.updated",
            "order.cancelled",
            "user.signup",
            "payment.completed",
        ],
    })


@app.route("/api/hint", methods=["GET"])
def hint():
    return jsonify({
        "hints": [
            "Webhook callback URLs are fetched server-side when events fire.",
            "There is no validation or filtering on the callback_url field.",
            "What internal services might be running on localhost?",
            "Try registering a webhook with a callback_url pointing to 127.0.0.1.",
            "After triggering an event, check the delivery history for the response body.",
        ]
    })


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_lab()
    # Start internal metadata service in a background thread
    t = threading.Thread(target=run_internal_server, daemon=True)
    t.start()
    # Start external-facing app
    app.run(host="0.0.0.0", port=5000, debug=False)
