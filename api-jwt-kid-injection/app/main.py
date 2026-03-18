from flask import Flask, render_template, request, jsonify
import json, base64, hmac, hashlib, os, uuid, time, sqlite3

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "keys.db")
FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")

# ---------------------------------------------------------------------------
# In-memory user store
# ---------------------------------------------------------------------------
USERS = {}  # username -> {id, username, password_hash, role}


def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_lab():
    """Generate flag, create SQLite key DB, seed users."""
    # --- Flag ----------------------------------------------------------------
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)
    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

    # --- SQLite key store ----------------------------------------------------
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE jwt_keys (kid TEXT, key_value TEXT)")
    signing_secret = uuid.uuid4().hex  # random 32-char hex — unguessable
    c.execute("INSERT INTO jwt_keys (kid, key_value) VALUES (?, ?)",
              ("default-key-001", signing_secret))
    conn.commit()
    conn.close()

    # --- Users ---------------------------------------------------------------
    admin_pw = uuid.uuid4().hex[:16]
    users = [
        {"id": 1, "username": "guest", "password_hash": _hash_pw("guest2025"), "role": "user"},
        {"id": 2, "username": "admin", "password_hash": _hash_pw(admin_pw),    "role": "admin"},
    ]
    for u in users:
        USERS[u["username"]] = u


def read_flag():
    if os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, "r") as f:
            return f.read().strip()
    return "KX{ERROR_NO_FLAG}"


# ---------------------------------------------------------------------------
# JWT helpers (manual — no pyjwt library)
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _get_signing_key(kid: str) -> str:
    """Look up the signing key for a given kid from the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Read the key from DB using the provided kid
    result = c.execute(f"SELECT key_value FROM jwt_keys WHERE kid = '{kid}'").fetchone()
    conn.close()
    if result:
        return result[0]
    return None


def create_jwt(payload: dict, kid: str = "default-key-001") -> str:
    """Create a JWT signed with the key identified by *kid*."""
    key = _get_signing_key(kid)
    if key is None:
        raise ValueError(f"Unknown kid: {kid}")

    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(key.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    s = b64url_encode(sig)
    return f"{h}.{p}.{s}"


def verify_jwt(token: str):
    """
    Verify a JWT token.

    VULNERABILITY: The kid from the JWT header is interpolated directly into
    a SQL query via string concatenation, enabling SQL injection. An attacker
    can inject a UNION SELECT to supply their own signing key value, then
    forge a token signed with that attacker-controlled key.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, "Invalid token format"

        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))

        kid = header.get("kid", "")

        # ------------------------------------------------------------------
        # VULNERABLE QUERY — kid is user-controlled and concatenated directly
        # ------------------------------------------------------------------
        key = _get_signing_key(kid)
        if key is None:
            return None, "Unknown signing key"

        # Verify HMAC-SHA256 signature
        expected_sig = hmac.new(
            key.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256
        ).digest()
        actual_sig = b64url_decode(parts[2])

        if hmac.compare_digest(expected_sig, actual_sig):
            if payload.get("exp", 0) < time.time():
                return None, "Token expired"
            return payload, None
        else:
            return None, "Invalid signature"

    except Exception as e:
        return None, f"Token error: {str(e)}"


def _require_token():
    """Extract and verify a Bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "Authorization header required. Use: Authorization: Bearer <token>"}), 401)
    token = auth[7:]
    payload, err = verify_jwt(token)
    if err:
        return None, (jsonify({"error": err}), 401)
    return payload, None


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

    user = USERS.get(username)
    if not user or user["password_hash"] != _hash_pw(password):
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400,
    }
    token = create_jwt(payload, kid="default-key-001")
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
    })


@app.route("/api/me", methods=["GET"])
def api_me():
    payload, err_resp = _require_token()
    if payload is None:
        return err_resp
    return jsonify({
        "user": payload.get("username"),
        "role": payload.get("role"),
        "claims": payload,
    })


@app.route("/api/admin/flag", methods=["GET"])
def api_admin_flag():
    payload, err_resp = _require_token()
    if payload is None:
        return err_resp

    if payload.get("role") != "admin":
        return jsonify({
            "error": "Admin role required",
            "your_role": payload.get("role"),
        }), 403

    return jsonify({
        "message": "Admin access granted",
        "flag": read_flag(),
    })


@app.route("/api/docs", methods=["GET"])
def api_docs():
    return jsonify({
        "api": "KeyVault IAM API v1.0",
        "description": "Identity & Access Management service using JWT-based authentication with key-id (kid) key lookup.",
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/login",
                "description": "Authenticate with username and password. Returns a signed JWT.",
                "body": {"username": "string", "password": "string"},
            },
            {
                "method": "GET",
                "path": "/api/me",
                "description": "Returns the authenticated user's profile and JWT claims. Requires Bearer token.",
            },
            {
                "method": "GET",
                "path": "/api/admin/flag",
                "description": "Admin-only endpoint. Returns the secret flag. Requires Bearer token with admin role.",
            },
            {
                "method": "GET",
                "path": "/api/docs",
                "description": "This documentation endpoint.",
            },
            {
                "method": "GET",
                "path": "/api/hint",
                "description": "Hints for solving the challenge.",
            },
        ],
        "authentication": "JWT Bearer token in the Authorization header. Tokens are signed with HMAC-SHA256 and include a 'kid' (Key ID) in the JWT header to identify which signing key was used.",
        "test_credentials": {"username": "guest", "password": "guest2025"},
    })


@app.route("/api/hint", methods=["GET"])
def api_hint():
    return jsonify({
        "hints": [
            "Login as guest and inspect the JWT you receive. Decode the header — what fields are present?",
            "The JWT header contains a 'kid' (Key ID) parameter. The server uses it to look up the signing key from a database.",
            "How does the server query the database for the key? Is the kid value sanitized before the query?",
            "Think about what happens if you can control the key the server uses to verify your signature...",
        ],
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
