"""
StaffHub API -- Employee Management System
OWASP API5:2023 - Broken Function Level Authorization (BFLA)

Vulnerability:
    Admin endpoints at /api/admin/* only verify that the caller has a
    valid JWT (i.e. is authenticated).  They never check whether the
    caller's role is actually "admin".  Any authenticated user --
    including a regular employee -- can invoke admin functions such as
    listing all users, reading system config (which contains the flag),
    or deleting users.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import uuid

from flask import Flask, jsonify, render_template, request

# ---------------------------------------------------------------------------
# App & constants
# ---------------------------------------------------------------------------
app = Flask(__name__)

JWT_SECRET = "bfla-role-secret-2025"
FLAG = None
USERS = {}
SYSTEM_CONFIG = {}

# ---------------------------------------------------------------------------
# JWT helpers  (compact HS256, same pattern as mass-assignment challenge)
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    """URL-safe base64 encode, strip padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode, re-add padding."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def create_token(payload: dict) -> str:
    """Create an HS256 JWT."""
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_with_exp = {**payload, "iat": int(time.time()), "exp": int(time.time()) + 3600}
    body = _b64(json.dumps(payload_with_exp).encode())
    sig = _b64(
        hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{body}.{sig}"


def verify_token(token: str) -> dict | None:
    """Verify an HS256 JWT.  Returns the payload dict or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, body_b64, sig_b64 = parts
        expected_sig = _b64(
            hmac.new(
                JWT_SECRET.encode(), f"{header_b64}.{body_b64}".encode(), hashlib.sha256
            ).digest()
        )
        if not hmac.compare_digest(sig_b64, expected_sig):
            return None
        payload = json.loads(_b64_decode(body_b64))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def get_token_from_request() -> dict | None:
    """Extract and verify the Bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return verify_token(auth[7:])


# ---------------------------------------------------------------------------
# Lab initialisation
# ---------------------------------------------------------------------------

def init_lab():
    """Generate the flag, seed users, build system config."""
    global FLAG, USERS, SYSTEM_CONFIG

    FLAG = f"KX{{{uuid.uuid4().hex[:16]}}}"

    # Admin gets a random, unguessable password
    admin_password = uuid.uuid4().hex

    USERS = {
        1: {
            "id": 1,
            "username": "employee",
            "password": "emp2025",
            "role": "employee",
            "department": "engineering",
        },
        2: {
            "id": 2,
            "username": "manager",
            "password": "mgr2025",
            "role": "manager",
            "department": "sales",
        },
        3: {
            "id": 3,
            "username": "admin",
            "password": admin_password,
            "role": "admin",
            "department": "executive",
        },
    }

    SYSTEM_CONFIG = {
        "app_name": "StaffHub API",
        "version": "2.4.1",
        "environment": "production",
        "debug": False,
        "jwt_algorithm": "HS256",
        "flag": FLAG,
        "allowed_origins": ["https://staffhub.internal"],
        "rate_limit": "100/hour",
    }


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/login", methods=["POST"])
def login():
    """Authenticate a user and return a JWT."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    for user in USERS.values():
        if user["username"] == username and user["password"] == password:
            token = create_token(
                {"sub": user["id"], "username": user["username"], "role": user["role"]}
            )
            return jsonify(
                {
                    "message": "Login successful",
                    "token": token,
                    "user": {
                        "id": user["id"],
                        "username": user["username"],
                        "role": user["role"],
                    },
                }
            )

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/profile", methods=["GET"])
def profile():
    """Return the authenticated user's profile."""
    payload = get_token_from_request()
    if payload is None:
        return jsonify({"error": "Authentication required"}), 401

    user = USERS.get(payload.get("sub"))
    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify(
        {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "department": user["department"],
        }
    )


@app.route("/api/docs", methods=["GET"])
def api_docs():
    """Return API documentation -- mentions admin endpoints."""
    return jsonify(
        {
            "api": "StaffHub API",
            "version": "2.4.1",
            "endpoints": {
                "POST /api/login": {
                    "description": "Authenticate and receive a JWT",
                    "body": {"username": "string", "password": "string"},
                },
                "GET /api/profile": {
                    "description": "Get your own profile (requires Bearer token)",
                },
                "GET /api/docs": {
                    "description": "This documentation page",
                },
                "GET /api/admin/users": {
                    "description": "List all users (requires admin access)",
                },
                "GET /api/admin/config": {
                    "description": "View system configuration (requires admin access)",
                },
                "DELETE /api/admin/users/<id>": {
                    "description": "Delete a user by ID (requires admin access)",
                },
                "GET /api/hint": {
                    "description": "Get a hint for this challenge",
                },
            },
        }
    )


# ---------------------------------------------------------------------------
# ADMIN endpoints  --  VULNERABLE: check authentication but NOT role
# ---------------------------------------------------------------------------

@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    """List all users.  VULNERABLE -- no role check."""
    payload = get_token_from_request()
    if payload is None:
        return jsonify({"error": "Authentication required"}), 401

    # BUG: should verify payload["role"] == "admin" but does not
    safe_users = [
        {
            "id": u["id"],
            "username": u["username"],
            "role": u["role"],
            "department": u["department"],
        }
        for u in USERS.values()
    ]
    return jsonify({"users": safe_users})


@app.route("/api/admin/config", methods=["GET"])
def admin_config():
    """Return system configuration including the flag.  VULNERABLE -- no role check."""
    payload = get_token_from_request()
    if payload is None:
        return jsonify({"error": "Authentication required"}), 401

    # BUG: should verify payload["role"] == "admin" but does not
    return jsonify({"config": SYSTEM_CONFIG})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
def admin_delete_user(user_id):
    """Delete a user.  VULNERABLE -- no role check."""
    payload = get_token_from_request()
    if payload is None:
        return jsonify({"error": "Authentication required"}), 401

    # BUG: should verify payload["role"] == "admin" but does not
    if user_id not in USERS:
        return jsonify({"error": "User not found"}), 404

    deleted = USERS.pop(user_id)
    return jsonify(
        {"message": f"User '{deleted['username']}' (id={user_id}) deleted"}
    )


# ---------------------------------------------------------------------------
# Hints
# ---------------------------------------------------------------------------

@app.route("/api/hint", methods=["GET"])
def hint():
    return jsonify(
        {
            "hints": [
                "The /api/docs endpoint reveals all available routes, including admin ones.",
                "Admin endpoints check if you are authenticated, but do they check your role?",
                "Try accessing /api/admin/config with a non-admin token.",
                "Broken Function Level Authorization means the server trusts the authentication but ignores the authorization level.",
            ]
        }
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

init_lab()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
