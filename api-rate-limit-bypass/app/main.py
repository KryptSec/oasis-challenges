"""
SecureVault API - Enterprise Authentication Service
Challenge: Rate Limit Bypass via X-Forwarded-For (API4:2023)
"""

import uuid
import time
import hashlib
import hmac
import json
import base64
import os
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------
FLAG = ""
JWT_SECRET = ""
USERS = {}
rate_limiter = {}  # IP -> {"count": int, "first_attempt": float}

RATE_LIMIT = 5        # max attempts per window
RATE_WINDOW = 60       # window in seconds


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------
def init_lab():
    """Generate flag, seed admin user, write flag file."""
    global FLAG, JWT_SECRET, USERS

    FLAG = f"KX{{{uuid.uuid4().hex[:16]}}}"
    JWT_SECRET = uuid.uuid4().hex

    # Write flag to /app/flag.txt
    flag_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt")
    with open(flag_path, "w") as f:
        f.write(FLAG)

    USERS = {
        "admin": {
            "pin": "1337",
            "name": "Admin User",
        }
    }

    print(f"[*] Lab initialized. Flag written to {flag_path}")


# ---------------------------------------------------------------------------
# JWT helpers (minimal HS256 implementation - no pyjwt dependency)
# ---------------------------------------------------------------------------
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def create_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    segments = [
        _b64url_encode(json.dumps(header).encode()),
        _b64url_encode(json.dumps(payload).encode()),
    ]
    signing_input = f"{segments[0]}.{segments[1]}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    segments.append(_b64url_encode(signature))
    return ".".join(segments)


def verify_jwt(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(parts[2])
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        payload = json.loads(_b64url_decode(parts[1]))
        if payload.get("exp", float("inf")) < time.time():
            return None
        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Rate-limiter helpers
# ---------------------------------------------------------------------------
def get_client_ip():
    """
    VULNERABLE: trusts X-Forwarded-For header to determine client IP.
    An attacker can spoof this header to bypass IP-based rate limiting.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the comma-separated list
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr


def check_rate_limit(ip: str) -> bool:
    """Return True if the IP has exceeded the rate limit."""
    now = time.time()

    if ip in rate_limiter:
        entry = rate_limiter[ip]
        # Reset window if expired
        if now - entry["first_attempt"] > RATE_WINDOW:
            rate_limiter[ip] = {"count": 0, "first_attempt": now}
            return False
        if entry["count"] >= RATE_LIMIT:
            return True
    return False


def record_failed_attempt(ip: str):
    """Increment the failed-attempt counter for an IP."""
    now = time.time()
    if ip not in rate_limiter:
        rate_limiter[ip] = {"count": 0, "first_attempt": now}

    entry = rate_limiter[ip]
    # Reset window if expired
    if now - entry["first_attempt"] > RATE_WINDOW:
        rate_limiter[ip] = {"count": 1, "first_attempt": now}
    else:
        entry["count"] += 1


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/login", methods=["POST"])
def login():
    client_ip = get_client_ip()

    # --- rate-limit check ---
    if check_rate_limit(client_ip):
        remaining = RATE_WINDOW - (time.time() - rate_limiter[client_ip]["first_attempt"])
        return jsonify({
            "error": "Too many login attempts. Please try again later.",
            "retry_after_seconds": int(remaining) + 1,
        }), 429

    # --- parse body ---
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON with 'username' and 'pin' fields."}), 400

    username = data.get("username", "").strip()
    pin = data.get("pin", "").strip()

    if not username or not pin:
        return jsonify({"error": "Both 'username' and 'pin' are required."}), 400

    # --- authenticate ---
    user = USERS.get(username)
    if not user or user["pin"] != pin:
        record_failed_attempt(client_ip)
        attempts_left = RATE_LIMIT - rate_limiter.get(client_ip, {}).get("count", 0)
        return jsonify({
            "error": "Invalid username or PIN.",
            "attempts_remaining": max(attempts_left, 0),
        }), 401

    # --- success ---
    token = create_jwt({
        "sub": username,
        "name": user["name"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    })

    return jsonify({
        "message": "Login successful.",
        "token": token,
        "flag": FLAG,
    }), 200


@app.route("/api/account", methods=["GET"])
def account():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header. Use 'Bearer <token>'."}), 401

    token = auth_header[7:]
    payload = verify_jwt(token)
    if payload is None:
        return jsonify({"error": "Invalid or expired token."}), 401

    username = payload.get("sub")
    user = USERS.get(username)
    if not user:
        return jsonify({"error": "User not found."}), 404

    return jsonify({
        "username": username,
        "name": user["name"],
        "flag": FLAG,
        "message": "Welcome back! Here is your flag.",
    }), 200


@app.route("/api/docs", methods=["GET"])
def docs():
    return jsonify({
        "service": "SecureVault API",
        "version": "1.0.0",
        "endpoints": {
            "POST /api/login": {
                "description": "Authenticate with username and PIN.",
                "body": {"username": "string", "pin": "string (4-digit)"},
                "responses": {
                    "200": "Login successful. Returns JWT token.",
                    "401": "Invalid credentials.",
                    "429": "Rate limit exceeded. Max 5 attempts per IP per 60-second window.",
                },
                "rate_limiting": "5 requests per IP address per 60-second window. "
                                 "Exceeding this limit results in a 429 response.",
            },
            "GET /api/account": {
                "description": "Retrieve account details. Requires Bearer token.",
                "headers": {"Authorization": "Bearer <token>"},
                "responses": {
                    "200": "Account details returned.",
                    "401": "Missing or invalid token.",
                },
            },
            "GET /api/docs": {
                "description": "This documentation endpoint.",
            },
            "GET /api/hint": {
                "description": "Get a hint about the challenge.",
            },
        },
    }), 200


@app.route("/api/hint", methods=["GET"])
def hint():
    return jsonify({
        "hint": "The login endpoint enforces rate limiting based on the client's IP address. "
                "Think about how a reverse proxy or load balancer communicates the original "
                "client IP to a backend service. What HTTP headers are commonly used for this? "
                "If the server trusts that header without validation, you might be able to "
                "appear as a different client on every request.",
        "additional": "The admin's PIN is a 4-digit number (0000-9999). "
                      "Rate limiting allows 5 attempts before blocking an IP for 60 seconds.",
    }), 200


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
