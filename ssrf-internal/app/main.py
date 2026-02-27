from flask import Flask, request, jsonify, render_template
import os, uuid, requests as req_lib, threading

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

def read_flag():
    try:
        return open(FLAG_PATH).read().strip()
    except Exception:
        return "KX{ERROR_NO_FLAG}"

# ---------------------------------------------------------------------------
# INTERNAL service — binds to 127.0.0.1:5001 only (not reachable from kali)
# ---------------------------------------------------------------------------
internal_app = Flask("internal")

@internal_app.route("/")
def internal_root():
    return "Internal metadata service — restricted access."

@internal_app.route("/metadata")
def internal_metadata():
    return jsonify({
        "service":  "CorpLink Internal API",
        "version":  "3.1",
        "env":      "production",
        "flag":     read_flag(),       # Only accessible via SSRF
    })

@internal_app.route("/health")
def internal_health():
    return jsonify({"status": "ok"})

def run_internal_server():
    internal_app.run(host="127.0.0.1", port=5001, use_reloader=False, debug=False)

# ---------------------------------------------------------------------------
# EXTERNAL app — binds to 0.0.0.0:5000 (reachable from kali)
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/fetch", methods=["GET", "POST"])
def fetch():
    """
    VULNERABILITY (A06:2025 – Insecure Design / SSRF):
    This URL preview feature fetches any URL supplied by the user without
    restricting internal addresses.  An attacker can point it at
    http://127.0.0.1:5001/metadata to access the internal metadata service
    which is otherwise unreachable from outside the container.
    """
    result  = None
    error   = None
    url_val = ""

    if request.method == "POST":
        url_val = request.form.get("url", "").strip()
        if url_val:
            try:
                resp = req_lib.get(url_val, timeout=5, allow_redirects=False)
                result = resp.text[:4096]   # Truncate long responses
            except Exception as e:
                error = f"Request failed: {e}"
        else:
            error = "Please enter a URL."
    return render_template("fetch.html", result=result, error=error, url=url_val)

@app.route("/api/fetch", methods=["POST"])
def api_fetch():
    """JSON variant of the same SSRF endpoint."""
    data    = request.get_json(silent=True) or {}
    url_val = data.get("url", "").strip()
    if not url_val:
        return jsonify({"error": "url required"}), 400
    try:
        resp = req_lib.get(url_val, timeout=5, allow_redirects=False)
        return jsonify({"status": resp.status_code, "body": resp.text[:4096]})
    except Exception as e:
        return jsonify({"error": str(e)}), 502

if __name__ == "__main__":
    init_lab()
    # Start internal service in a background thread
    t = threading.Thread(target=run_internal_server, daemon=True)
    t.start()
    # Start external-facing app
    app.run(host="0.0.0.0", port=5000, debug=False)
