from flask import Flask, request, jsonify, render_template, session, redirect
import os, uuid, json
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = os.urandom(24)

FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")

# In-memory log — populated at startup and on each request
ACCESS_LOG = []

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def read_flag():
    try:
        return open(FLAG_PATH).read().strip()
    except Exception:
        return "KX{ERROR_NO_FLAG}"

def init_lab():
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)
    flag_value = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag_value)

    flag = read_flag()

    # VULNERABILITY (A09:2025 – Security Logging and Alerting Failures):
    # The application logs sensitive data — including the admin's API key which
    # IS the flag — in plain text.  These logs are accessible via a forgotten
    # debug endpoint that should have been removed before production deployment.
    # There is no alerting when this debug endpoint is accessed by non-admins.
    ACCESS_LOG.extend([
        {
            "ts":      "2025-02-20T08:00:01Z",
            "level":   "INFO",
            "source":  "app",
            "message": "Application started successfully. Environment: production."
        },
        {
            "ts":      "2025-02-20T08:01:15Z",
            "level":   "INFO",
            "source":  "auth",
            "message": "Admin login: POST /api/auth/login body={\"username\":\"admin\",\"api_key\":\"" + flag + "\"}"
        },
        {
            "ts":      "2025-02-20T08:01:16Z",
            "level":   "INFO",
            "source":  "auth",
            "message": "Admin authenticated. Session created for user=admin role=superadmin."
        },
        {
            "ts":      "2025-02-20T08:05:00Z",
            "level":   "INFO",
            "source":  "health",
            "message": "Healthcheck OK — uptime 4m59s"
        },
    ])

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /api/v1/debug\n"       # Hints at debug path
    ), 200, {"Content-Type": "text/plain"}

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "")
    api_key  = data.get("api_key", "")

    # Log the request (including the api_key!) — that's how it ends up in logs
    ACCESS_LOG.append({
        "ts":      datetime.now(timezone.utc).isoformat(),
        "level":   "INFO",
        "source":  "auth",
        "message": f"Login attempt: POST /api/auth/login body={json.dumps({'username': username, 'api_key': api_key})}"
    })

    if username == "admin" and api_key == read_flag():
        session["admin"] = True
        return jsonify({"message": "Authenticated", "role": "superadmin"})
    return jsonify({"error": "Unauthorized"}), 401

@app.route("/admin")
def admin():
    if not session.get("admin"):
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"message": "Admin panel", "flag": read_flag()})

# ---------------------------------------------------------------------------
# MISCONFIGURATION — unauthenticated debug log endpoint
# ---------------------------------------------------------------------------
@app.route("/api/v1/debug/logs")
def debug_logs():
    """
    VULNERABILITY: This debug endpoint was never removed from production.
    It exposes the full application log — which contains the admin's
    api_key in plain text — with no authentication or alerting.
    """
    return jsonify({"count": len(ACCESS_LOG), "logs": ACCESS_LOG})

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
