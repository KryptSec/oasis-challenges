"""
DataBridge API Platform
OWASP API9:2023 - Improper Inventory Management
Deprecated API version (/v1) remains live without authentication.
"""

import uuid
import json
import hashlib
import hmac
import time
import base64

from flask import Flask, request, jsonify, render_template, Response

app = Flask(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
JWT_SECRET = "version-leak-secret-2025"
FLAG = None

# ── Data stores ────────────────────────────────────────────────────────────────
admin_data = {}
users_list = []
credentials = {}


# ── Initialisation ─────────────────────────────────────────────────────────────
def init_lab():
    global FLAG, admin_data, users_list, credentials

    FLAG = f"KX{{{uuid.uuid4().hex[:16]}}}"

    admin_data = {
        "admin_email": "admin@corp.local",
        "secret_key": FLAG,
        "database": "postgresql://prod:5432/main",
        "environment": "production",
    }

    users_list = [
        {"id": 1, "username": "viewer", "role": "viewer", "email": "viewer@corp.local"},
        {"id": 2, "username": "editor", "role": "editor", "email": "editor@corp.local"},
        {"id": 3, "username": "manager", "role": "manager", "email": "manager@corp.local"},
    ]

    credentials = {
        "viewer": {"password": "viewer2025", "role": "viewer"},
    }


# ── JWT helpers ────────────────────────────────────────────────────────────────
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_token(username: str, role: str) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(
        json.dumps(
            {
                "sub": username,
                "role": role,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            }
        ).encode()
    )
    sig = _b64(
        hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{sig}"


def verify_token(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts

        expected_sig = _b64(
            hmac.new(
                JWT_SECRET.encode(),
                f"{header_b64}.{payload_b64}".encode(),
                hashlib.sha256,
            ).digest()
        )
        if not hmac.compare_digest(sig_b64, expected_sig):
            return None

        padding = 4 - len(payload_b64) % 4
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * padding)
        payload = json.loads(payload_bytes)

        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except Exception:
        return None


def _get_bearer_payload():
    """Extract and verify Bearer token from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return verify_token(auth[7:])


# ── Response helpers ───────────────────────────────────────────────────────────
def v2_response(data, status=200):
    resp = jsonify(data)
    resp.status_code = status
    resp.headers["X-API-Version"] = "2.0"
    resp.headers["Deprecation"] = "v1-sunset-2024-01-01"
    return resp


def v1_response(data, status=200):
    resp = jsonify(data)
    resp.status_code = status
    resp.headers["X-API-Version"] = "1.0"
    resp.headers["X-Deprecated"] = "true"
    return resp


# ═══════════════════════════════════════════════════════════════════════════════
#  V2 ENDPOINTS  (current, authentication required where noted)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/v2/docs", methods=["GET"])
def v2_docs():
    docs = {
        "api": "DataBridge API",
        "version": "2.0",
        "status": "current",
        "authentication": "Bearer JWT via /v2/login",
        "endpoints": [
            {"method": "POST", "path": "/v2/login", "auth": False, "description": "Authenticate and receive JWT token"},
            {"method": "GET", "path": "/v2/users", "auth": True, "description": "List platform users"},
            {"method": "GET", "path": "/v2/admin/data", "auth": True, "description": "Admin-only configuration data (role=admin required)"},
            {"method": "GET", "path": "/v2/health", "auth": False, "description": "Health check"},
        ],
    }
    return v2_response(docs)


@app.route("/v2/login", methods=["POST"])
def v2_login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")

    cred = credentials.get(username)
    if not cred or cred["password"] != password:
        return v2_response({"error": "Invalid credentials"}, 401)

    token = create_token(username, cred["role"])
    return v2_response({"token": token, "type": "Bearer", "expires_in": 3600})


@app.route("/v2/users", methods=["GET"])
def v2_users():
    payload = _get_bearer_payload()
    if not payload:
        return v2_response({"error": "Authentication required. Provide a valid Bearer token."}, 401)
    return v2_response({"users": users_list})


@app.route("/v2/admin/data", methods=["GET"])
def v2_admin_data():
    payload = _get_bearer_payload()
    if not payload:
        return v2_response({"error": "Authentication required. Provide a valid Bearer token."}, 401)
    if payload.get("role") != "admin":
        return v2_response({"error": "Forbidden. Admin role required."}, 403)
    return v2_response({"admin": admin_data})


@app.route("/v2/health", methods=["GET"])
def v2_health():
    return v2_response({"status": "healthy", "version": "2.0", "timestamp": int(time.time())})


# ═══════════════════════════════════════════════════════════════════════════════
#  V1 ENDPOINTS  (deprecated, NO authentication)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/v1/docs", methods=["GET"])
def v1_docs():
    docs = {
        "api": "DataBridge API",
        "version": "1.0",
        "status": "deprecated",
        "notice": "This API version is deprecated and scheduled for removal. Please migrate to /v2.",
        "authentication": "none",
        "endpoints": [
            {"method": "GET", "path": "/v1/users", "auth": False, "description": "List platform users"},
            {"method": "GET", "path": "/v1/admin/data", "auth": False, "description": "Admin configuration data"},
            {"method": "GET", "path": "/v1/health", "auth": False, "description": "Health check"},
        ],
    }
    return v1_response(docs)


@app.route("/v1/users", methods=["GET"])
def v1_users():
    return v1_response({"users": users_list})


@app.route("/v1/admin/data", methods=["GET"])
def v1_admin_data():
    # VULNERABLE: No authentication required — returns admin data including the flag
    return v1_response({"admin": admin_data})


@app.route("/v1/health", methods=["GET"])
def v1_health():
    return v1_response({"status": "healthy", "version": "1.0", "timestamp": int(time.time())})


# ═══════════════════════════════════════════════════════════════════════════════
#  ROOT / MISC ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/api/hint", methods=["GET"])
def api_hint():
    return jsonify({
        "hint": "APIs evolve over time. Have you checked whether older versions are still accessible?",
    })


@app.route("/robots.txt", methods=["GET"])
def robots():
    content = "User-agent: *\nDisallow: /v1/\n"
    return Response(content, mimetype="text/plain")


# ── Entrypoint ─────────────────────────────────────────────────────────────────
init_lab()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
