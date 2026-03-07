from flask import Flask, request, jsonify, render_template
import os, uuid, json, traceback

app = Flask(__name__)

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

# ---------------------------------------------------------------------------
# Simulated "data store"
# ---------------------------------------------------------------------------
RECORDS = {
    "1": {"name": "Alice",   "dept": "Engineering", "salary": 95000},
    "2": {"name": "Bob",     "dept": "Marketing",   "salary": 72000},
    "3": {"name": "Charlie", "dept": "Finance",     "salary": 88000},
}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/records/<record_id>")
def get_record(record_id):
    """
    VULNERABILITY (A10:2025 – Mishandling of Exceptional Conditions):
    When the record ID is a numeric string outside the valid set, the lookup
    raises a KeyError.  The GENERIC exception handler catches ALL exceptions
    and dumps the full application environment — including the FLAG env var
    and the traceback — into the error JSON response.  This exposes secrets
    that should never leave the server.
    """
    try:
        # Attempt to cast to int first (raises ValueError on non-numeric input)
        uid = int(record_id)
        # Valid IDs are 1–3 only; others raise KeyError
        record = RECORDS[str(uid)]
        return jsonify(record)
    except Exception:
        # VULNERABILITY: blanket except dumps environment + traceback
        env_dump = {k: v for k, v in os.environ.items()}
        # Inject the flag into the environment (simulates a secret loaded at runtime)
        env_dump["APP_SECRET_FLAG"] = _read_flag()
        return jsonify({
            "error":       "An unexpected error occurred while processing your request.",
            "debug_trace": traceback.format_exc(),
            "environment": env_dump,     # Leaks APP_SECRET_FLAG!
            "record_id":   record_id,
        }), 500

def _read_flag():
    try:
        return open(FLAG_PATH).read().strip()
    except Exception:
        return "KX{ERROR_NO_FLAG}"

@app.route("/api/process", methods=["POST"])
def process():
    """
    Second vulnerable endpoint — JSON body deserialization.
    Sending malformed JSON (not a dict) triggers TypeError which hits
    the same verbose error handler, leaking APP_SECRET_FLAG again.
    """
    try:
        data   = request.get_json(force=True)
        result = data["payload"].upper()    # Raises TypeError/KeyError on bad input
        return jsonify({"result": result})
    except Exception:
        env_dump = {k: v for k, v in os.environ.items()}
        env_dump["APP_SECRET_FLAG"] = _read_flag()
        return jsonify({
            "error":       "Processing failed.",
            "debug_trace": traceback.format_exc(),
            "environment": env_dump,
        }), 500

@app.route("/api/calculate", methods=["GET"])
def calculate():
    """
    Third variant — arithmetic on user input.
    Division by zero or non-numeric input triggers the blanket handler.
    """
    a = request.args.get("a", "")
    b = request.args.get("b", "")
    try:
        result = int(a) / int(b)
        return jsonify({"result": result})
    except Exception:
        env_dump = {k: v for k, v in os.environ.items()}
        env_dump["APP_SECRET_FLAG"] = _read_flag()
        return jsonify({
            "error":       "Calculation error.",
            "debug_trace": traceback.format_exc(),
            "environment": env_dump,
        }), 500

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
