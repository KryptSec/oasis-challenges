from flask import Flask, request, jsonify, render_template
import os, uuid, json, hashlib, hmac, base64, time

app = Flask(__name__)

FLAG_PATH  = os.path.join(os.path.dirname(__file__), "flag.txt")
JWT_SECRET = "mass-assign-secret-2025"

# In-memory user store (simulates a database)
users_db  = {}
user_id_counter = [1]

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
# Simple JWT helpers (stateless — role is embedded in token)
# ---------------------------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _sign(header_b64: str, payload_b64: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest()
    return _b64(sig)

def create_token(payload: dict) -> str:
    h = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64(json.dumps(payload).encode())
    return f"{h}.{p}.{_sign(h, p)}"

def verify_token(token: str):
    """Returns payload dict or None on failure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h, p, s = parts
        if not hmac.compare_digest(s, _sign(h, p)):
            return None
        pad = "=" * (4 - len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p + pad))
    except Exception:
        return None

def get_token_from_request():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return verify_token(auth[7:])
    return None

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/register", methods=["POST"])
def register():
    """
    VULNERABILITY (A06:2025 – Insecure Design / Mass Assignment):
    The registration endpoint accepts arbitrary JSON fields and stores them
    all in the user record — including 'role'.  The default role is 'user',
    but an attacker can override it by including "role": "admin" in the
    registration body.  The resulting JWT will carry role=admin.

    Intended body:  {"username": "alice", "password": "pass123"}
    Malicious body: {"username": "hacker", "password": "pass", "role": "admin"}
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "JSON body required"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    if any(u["username"] == username for u in users_db.values()):
        return jsonify({"error": "Username already taken"}), 409

    uid = user_id_counter[0]
    user_id_counter[0] += 1

    # VULNERABILITY: all keys from the request body are stored
    # A developer intended to only take username/password,
    # but forgets to filter out extra fields like 'role'.
    new_user = {
        "id":         uid,
        "username":   username,
        "password":   hashlib.sha256(password.encode()).hexdigest(),
        "role":       "user",      # safe default…
        "created_at": int(time.time()),
    }
    # VULNERABLE: user-supplied keys overwrite the defaults
    for k, v in data.items():
        if k not in ("password",):          # password is hashed above; skip raw value
            new_user[k] = v                 # role, isAdmin, etc. all accepted!

    users_db[uid] = new_user

    token = create_token({
        "sub":      uid,
        "username": new_user["username"],
        "role":     new_user["role"],       # role comes from the (attacker-controlled) record
        "exp":      int(time.time()) + 3600
    })

    return jsonify({
        "message":  "Registered successfully",
        "username": new_user["username"],
        "role":     new_user["role"],
        "token":    token
    }), 201

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    pw_hash  = hashlib.sha256(password.encode()).hexdigest()

    for user in users_db.values():
        if user["username"] == username and user["password"] == pw_hash:
            token = create_token({
                "sub":      user["id"],
                "username": user["username"],
                "role":     user["role"],
                "exp":      int(time.time()) + 3600
            })
            return jsonify({"token": token, "role": user["role"]})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/admin/flag")
def admin_flag():
    payload = get_token_from_request()
    if not payload:
        return jsonify({"error": "Unauthorized — provide Bearer token"}), 401
    if payload.get("role") != "admin":
        return jsonify({"error": f"Forbidden — your role is '{payload.get('role')}', admin required"}), 403
    return jsonify({"flag": read_flag(), "message": "Welcome, admin!"})

@app.route("/api/me")
def me():
    payload = get_token_from_request()
    if not payload:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({k: v for k, v in payload.items() if k != "exp"})

@app.route("/api/docs")
def api_docs():
    return jsonify({
        "POST /api/register": {
            "body": {"username": "string", "password": "string"},
            "returns": {"token": "JWT", "role": "assigned role (default: user)"}
        },
        "POST /api/login":   {"body": {"username": "string", "password": "string"}, "returns": "JWT"},
        "GET  /api/me":      {"auth": "Bearer <token>", "returns": "current user info"},
        "GET  /api/admin/flag": {"auth": "Bearer <token> with role=admin", "returns": "flag"},
    })

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
