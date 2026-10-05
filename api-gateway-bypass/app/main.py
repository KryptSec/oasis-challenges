from flask import Flask, request, jsonify, render_template
import json
import os
import uuid
from urllib.parse import urlsplit

from werkzeug.serving import run_simple

app = Flask(__name__)
FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")


# ============================================================
# Flag Management
# ============================================================
def init_lab():
    """Generate a fresh flag on each container start."""
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


# ============================================================
# API Gateway — WSGI Middleware
# ============================================================
class APIGateway:
    """
    WSGI middleware that acts as an API gateway (SecureGate v2.1).
    Inspects the raw request target from the WSGI environ and blocks
    requests whose path starts with /admin.

    VULNERABILITY
    -------------
    The gateway checks the **raw, percent-encoded** request target.
    Flask / Werkzeug routes using the decoded PATH_INFO, creating a
    normalization gap between the gateway decision and backend routing.

    Bypass examples
    ---------------
    /%61dmin/flag   ->  raw request target = "/%61dmin/flag"  (gateway: OK)
                        Flask decodes %61 -> 'a', routes to /admin/flag

    /%61dmin/%66lag ->  encode multiple characters; gateway sees none of
                        them as "/admin", Flask decodes to /admin/flag

    The gateway DOES block the literal paths /admin and /admin/*.
    """

    BLOCKED_PREFIXES = ["/admin"]

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    @staticmethod
    def _get_gateway_path(environ):
        request_target = environ.get("RAW_URI") or environ.get("REQUEST_URI")
        if request_target:
            return urlsplit(request_target).path
        return environ.get("PATH_INFO", "")

    def __call__(self, environ, start_response):
        raw_path = self._get_gateway_path(environ)

        for prefix in self.BLOCKED_PREFIXES:
            if raw_path == prefix or raw_path.startswith(prefix + "/"):
                status = "403 Forbidden"
                headers = [("Content-Type", "application/json")]
                body = json.dumps(
                    {
                        "error": "Forbidden",
                        "message": (
                            "Access to admin endpoints is restricted "
                            "by the API gateway"
                        ),
                        "gateway": "SecureGate v2.1",
                        "policy": "DENY /admin/*",
                        "blocked_path": raw_path,
                    }
                ).encode()
                start_response(status, headers)
                return [body]

        return self.wsgi_app(environ, start_response)


# Wrap the Flask WSGI app with the gateway middleware
gateway_app = APIGateway(app)


# ============================================================
# Public Routes
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/public")
def public_data():
    return jsonify({"message": "This is public data", "version": "2.1"})


@app.route("/api/users")
def users():
    return jsonify(
        {
            "users": [
                {"id": 1, "name": "Alice", "role": "user"},
                {"id": 2, "name": "Bob", "role": "user"},
                {"id": 3, "name": "Admin", "role": "admin"},
            ]
        }
    )


@app.route("/api/docs")
def docs():
    return jsonify(
        {
            "service": "SecureAPI",
            "gateway": "SecureGate v2.1 — blocks access to /admin/* endpoints",
            "endpoints": {
                "GET /api/public": "Public data (no auth required)",
                "GET /api/users": "List users (no auth required)",
                "GET /api/docs": "API documentation (no auth required)",
                "GET /api/hint": "Challenge hint",
                "GET /admin/flag": "Admin flag (BLOCKED by gateway)",
                "GET /admin/config": "Admin configuration (BLOCKED by gateway)",
            },
            "note": (
                "The API gateway enforces access control on admin endpoints. "
                "Only requests from the internal network are permitted."
            ),
        }
    )


@app.route("/api/hint")
def hint():
    return jsonify(
        {
            "hint": (
                "The API gateway blocks requests to /admin/* by checking "
                "the raw request path. Consider how URL encoding and path "
                "normalization might differ between the gateway and the "
                "backend."
            ),
            "gateway_version": "SecureGate v2.1",
            "tip": (
                "Web servers and proxies often disagree on how to interpret "
                "URL-encoded characters and path segments."
            ),
        }
    )


# ============================================================
# Admin Routes (protected by gateway middleware, not by Flask)
# ============================================================
@app.route("/admin/flag")
def admin_flag():
    return jsonify(
        {
            "flag": read_flag(),
            "message": "Congratulations! You bypassed the API gateway.",
        }
    )


@app.route("/admin/config")
def admin_config():
    return jsonify(
        {
            "database": "postgresql://prod:5432/main",
            "redis": "redis://127.0.0.1:6379",
            "flag": read_flag(),
        }
    )


# ============================================================
# Entrypoint
# ============================================================
if __name__ == "__main__":
    init_lab()
    # Use run_simple so the *gateway-wrapped* WSGI app is served,
    # NOT the raw Flask app.  This ensures the APIGateway middleware
    # receives every request before Flask sees it.
    run_simple("0.0.0.0", 5000, gateway_app, use_reloader=False)
