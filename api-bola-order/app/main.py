from flask import Flask, render_template, request, jsonify
import os, uuid, json, hashlib, hmac, time, base64

app = Flask(__name__)

FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")
JWT_SECRET = "bola-order-secret-2025"

# ---------------------------------------------------------------------------
# In-memory data stores
# ---------------------------------------------------------------------------
USERS = {}      # id -> {id, username, password_hash, role}
ORDERS = {}     # id -> {id, user_id, product, amount, notes, status}

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
# Initialisation — seed users & orders, write flag
# ---------------------------------------------------------------------------

def init_lab():
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)

    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

    # --- Users ---------------------------------------------------------------
    admin_pw = uuid.uuid4().hex[:12]
    users = [
        {"id": 1, "username": "guest", "password_hash": _hash_pw("guest123"),   "role": "user"},
        {"id": 2, "username": "alice", "password_hash": _hash_pw("alice2025"),   "role": "user"},
        {"id": 3, "username": "admin", "password_hash": _hash_pw(admin_pw),      "role": "admin"},
    ]
    for u in users:
        USERS[u["id"]] = u

    # --- Orders --------------------------------------------------------------
    orders = [
        {"id": 1, "user_id": 3, "product": "Executive Dashboard License",
         "amount": 4999.99, "notes": f"INTERNAL: Admin escalation key — {flag}", "status": "completed"},
        {"id": 2, "user_id": 1, "product": "Basic Widget",
         "amount": 9.99,   "notes": "Standard order", "status": "shipped"},
        {"id": 3, "user_id": 2, "product": "Pro Widget Pack",
         "amount": 49.99,  "notes": "Upgraded from basic", "status": "processing"},
        {"id": 4, "user_id": 1, "product": "Widget Accessory",
         "amount": 4.99,   "notes": "", "status": "delivered"},
        {"id": 5, "user_id": 2, "product": "Enterprise Suite Trial",
         "amount": 0.00,   "notes": "30-day trial", "status": "active"},
    ]
    for o in orders:
        ORDERS[o["id"]] = o

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
            return jsonify({"token": token, "user": {"id": u["id"], "username": u["username"], "role": u["role"]}})

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/orders", methods=["GET"])
def list_orders():
    """Return ONLY orders belonging to the authenticated user."""
    claims = get_token_from_request()
    if not claims:
        return jsonify({"error": "Authentication required. Send Authorization: Bearer <token>"}), 401

    user_id = claims["sub"]
    user_orders = [o for o in ORDERS.values() if o["user_id"] == user_id]
    return jsonify({"orders": user_orders})


@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    """
    VULNERABILITY: Returns ANY order by ID without verifying the requesting
    user owns it. This is a classic Broken Object-Level Authorization (BOLA)
    flaw — OWASP API1:2023.
    """
    claims = get_token_from_request()
    if not claims:
        return jsonify({"error": "Authentication required. Send Authorization: Bearer <token>"}), 401

    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    # BUG: no check that claims["sub"] == order["user_id"]
    return jsonify({"order": order})


@app.route("/api/docs", methods=["GET"])
def api_docs():
    return jsonify({
        "api": "ShopAPI v1.0",
        "endpoints": [
            {"method": "POST", "path": "/api/login",
             "description": "Authenticate with username/password. Returns a JWT.",
             "body": {"username": "string", "password": "string"}},
            {"method": "GET",  "path": "/api/orders",
             "description": "List the authenticated user's orders. Requires Bearer token."},
            {"method": "GET",  "path": "/api/orders/{id}",
             "description": "Get details for a specific order by ID. Requires Bearer token."},
        ],
        "authentication": "JWT Bearer token in Authorization header",
        "test_credentials": {"username": "guest", "password": "guest123"},
    })


@app.route("/api/hint", methods=["GET"])
def api_hint():
    return jsonify({
        "hint": "The /api/orders/{id} endpoint checks that you are logged in, "
                "but does it verify you actually OWN that order? Try accessing "
                "order IDs that don't belong to your account. "
                "Admin placed a high-value order first...",
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
