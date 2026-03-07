from flask import Flask, request, jsonify, render_template, session
import os, uuid, re

app = Flask(__name__)
app.secret_key = os.urandom(24)

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
# Simulated document store (mimics MongoDB in-memory)
# ---------------------------------------------------------------------------
USERS = [
    {"_id": 1, "username": "admin",   "password": "Sup3rS3cr3t!Adm1n", "role": "admin"},
    {"_id": 2, "username": "alice",   "password": "al1cePass2025",      "role": "user"},
    {"_id": 3, "username": "charlie", "password": "ch4rl1epass",        "role": "user"},
]

def mongo_find_one(collection, query):
    """
    VULNERABILITY (A05:2025 – Injection / NoSQL Injection):
    This function mimics MongoDB's find() and processes operator-based queries
    ($ne, $gt, $regex, $exists) that are passed directly from user input
    without sanitisation.

    Attack: {"username": "admin", "password": {"$ne": ""}}
    → password field: "$ne" operator means 'not equal to empty string'
    → Since admin's password is not "", the operator matches → auth bypass.
    """
    for doc in collection:
        if _matches(doc, query):
            return doc
    return None

def _matches(doc, query):
    for key, value in query.items():
        if isinstance(value, dict):
            # Operator-based comparison
            for op, operand in value.items():
                field_val = doc.get(key)
                if op == "$ne":
                    if field_val == operand:
                        return False
                elif op == "$gt":
                    if not (isinstance(field_val, (int, float)) and field_val > operand):
                        return False
                elif op == "$lt":
                    if not (isinstance(field_val, (int, float)) and field_val < operand):
                        return False
                elif op == "$regex":
                    if not re.search(str(operand), str(field_val or "")):
                        return False
                elif op == "$exists":
                    if operand and key not in doc:
                        return False
                    elif not operand and key in doc:
                        return False
                # Unknown operators are silently ignored (like real MongoDB)
        else:
            if doc.get(key) != value:
                return False
    return True

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/auth/login", methods=["POST"])
def login():
    """
    Login accepts JSON. The username and password fields are passed directly
    into the NoSQL query — allowing operator injection from the request body.
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "JSON body required"}), 400

    username = data.get("username")
    password = data.get("password")

    if username is None or password is None:
        return jsonify({"error": "username and password required"}), 400

    # VULNERABLE: user-controlled values passed as query operators
    query = {"username": username, "password": password}
    user  = mongo_find_one(USERS, query)

    if user:
        session["user"] = user["username"]
        session["role"] = user["role"]
        return jsonify({
            "message":  "Login successful",
            "username": user["username"],
            "role":     user["role"]
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/admin/flag")
def admin_flag():
    if session.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    return jsonify({"flag": read_flag()})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route("/api/docs")
def api_docs():
    return jsonify({
        "endpoints": {
            "POST /api/auth/login":  {"body": {"username": "string", "password": "string"}, "returns": "JWT-like session"},
            "GET  /api/admin/flag":  {"auth": "session cookie with role=admin", "returns": "flag"},
        },
        "hint": "The API accepts standard JSON. Authentication checks username and password against the user store."
    })

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
