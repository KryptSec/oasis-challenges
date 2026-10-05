from flask import Flask, render_template, request, jsonify
import os, uuid, json, hashlib, hmac, time, base64

app = Flask(__name__)

FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")
JWT_SECRET = "property-exposure-secret-2025"

# ---------------------------------------------------------------------------
# In-memory data store
# ---------------------------------------------------------------------------
USERS = {}  # id -> {id, username, password_hash, is_admin, role, department, api_key, internal_notes}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_token(payload: dict) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_copy = dict(payload)
    payload_copy["iat"] = int(time.time())
    payload_copy["exp"] = int(time.time()) + 86400
    body = _b64(json.dumps(payload_copy).encode())
    sig = _b64(hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def verify_token(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        expected = _b64(hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def get_token_from_request() -> dict | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return verify_token(auth[7:])
    return None

# ---------------------------------------------------------------------------
# Initialisation - seed users & write flag
# ---------------------------------------------------------------------------

def init_lab():
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)

    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

    # --- Users ---------------------------------------------------------------
    users = [
        {
            "id": 1,
            "username": "admin",
            "password_hash": _hash_pw("sup3rS3cur3"),
            "is_admin": True,
            "role": "admin",
            "department": "executive",
            "api_key": flag,
            "internal_notes": "System administrator — DO NOT expose API key",
        },
        {
            "id": 2,
            "username": "guest",
            "password_hash": _hash_pw("guest123"),
            "is_admin": False,
            "role": "user",
            "department": "general",
            "api_key": "gst-xxxx",
            "internal_notes": "Guest test account",
        },
        {
            "id": 3,
            "username": "alice",
            "password_hash": _hash_pw("alice2025"),
            "is_admin": False,
            "role": "user",
            "department": "engineering",
            "api_key": "eng-xxxx",
            "internal_notes": "Frontend developer",
        },
        {
            "id": 4,
            "username": "bob",
            "password_hash": _hash_pw("bob2025"),
            "is_admin": False,
            "role": "user",
            "department": "marketing",
            "api_key": "mkt-xxxx",
            "internal_notes": "Marketing analyst",
        },
        {
            "id": 5,
            "username": "carol",
            "password_hash": _hash_pw("carol2025"),
            "is_admin": False,
            "role": "manager",
            "department": "engineering",
            "api_key": "mgr-xxxx",
            "internal_notes": "Team lead",
        },
    ]
    for u in users:
        USERS[u["id"]] = u

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    for u in USERS.values():
        if u["username"] == username and u["password_hash"] == _hash_pw(password):
            token = create_token({"sub": u["id"], "username": u["username"], "role": u["role"]})
            return jsonify({
                "token": token,
                "user": {"id": u["id"], "username": u["username"], "role": u["role"]},
            })

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/users", methods=["GET"])
def list_users():
    """Return a filtered list of users — only safe public fields."""
    claims = get_token_from_request()
    if not claims:
        return jsonify({"error": "Authentication required. Send Authorization: Bearer <token>"}), 401

    safe_users = []
    for u in USERS.values():
        safe_users.append({
            "id": u["id"],
            "username": u["username"],
            "department": u["department"],
            "role": u["role"],
        })
    return jsonify({"users": safe_users})


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    """
    VULNERABILITY: Returns ALL user fields without any property-level
    filtering. This exposes password_hash, is_admin, api_key, and
    internal_notes — a classic Broken Object Property Level Authorization
    flaw (OWASP API3:2023). The /api/users list endpoint is properly
    filtered, but this detail endpoint leaks everything.
    """
    claims = get_token_from_request()
    if not claims:
        return jsonify({"error": "Authentication required. Send Authorization: Bearer <token>"}), 401

    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # BUG: no field filtering — returns the entire user dict including
    # password_hash, is_admin, api_key, internal_notes
    return jsonify({"user": user})


@app.route("/api/me", methods=["GET"])
def api_me():
    """Return info about the currently authenticated user from the JWT."""
    claims = get_token_from_request()
    if not claims:
        return jsonify({"error": "Authentication required. Send Authorization: Bearer <token>"}), 401

    return jsonify({"user": claims})


@app.route("/api/docs", methods=["GET"])
def api_docs():
    return jsonify({
        "api": "CorpDirectory API v1.0",
        "description": "Employee Directory Service",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/login",
                "description": "Authenticate with username/password. Returns a JWT.",
                "body": {"username": "string", "password": "string"},
            },
            {
                "method": "GET",
                "path": "/api/users",
                "description": "List all employees with basic public info (id, username, department, role). Requires Bearer token.",
            },
            {
                "method": "GET",
                "path": "/api/users/{id}",
                "description": "Get full profile for a specific employee by ID. Requires Bearer token.",
            },
            {
                "method": "GET",
                "path": "/api/me",
                "description": "Get current authenticated user info from JWT. Requires Bearer token.",
            },
        ],
        "authentication": "JWT Bearer token in Authorization header",
        "test_credentials": {"username": "guest", "password": "guest123"},
    })


@app.route("/api/hint", methods=["GET"])
def api_hint():
    return jsonify({
        "hint": "The /api/users list endpoint returns only public fields, "
                "but does the /api/users/{id} detail endpoint apply the same "
                "filtering? Compare the response fields carefully. "
                "Some users hold more valuable keys than others...",
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
