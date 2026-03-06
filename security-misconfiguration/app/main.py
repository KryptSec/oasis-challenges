from flask import Flask, request, jsonify, render_template, session, redirect
import os, uuid, json

app = Flask(__name__)
app.secret_key = "changeme-insecure-secret"

FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
ADMIN_PASSWORD = "admin"          # Default credential — never changed
DEBUG_API_KEY  = "debug-key-1234" # Hard-coded in source / exposed via /env

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
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "admin" and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/admin")
def admin():
    if not session.get("admin"):
        return redirect("/login")
    return render_template("admin.html", flag=read_flag())

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------------------------------------------------------------------
# MISCONFIGURATION 1 — Exposed environment / config dump (forgot to remove)
# ---------------------------------------------------------------------------
@app.route("/api/v1/debug/env")
def debug_env():
    """
    VULNERABILITY (Security Misconfiguration):
    This debug endpoint was left enabled in production. It exposes the full
    application configuration including the hard-coded admin password and
    debug API key. No authentication required.
    """
    return jsonify({
        "app": "CorpPortal v2.3",
        "environment": "production",          # Says production, acts like dev
        "admin_password": ADMIN_PASSWORD,     # Leaked!
        "debug_api_key":  DEBUG_API_KEY,
        "secret_key":     app.secret_key,
        "flag_path":      FLAG_PATH,
        "python_path":    os.environ.get("PATH", ""),
    })

# ---------------------------------------------------------------------------
# MISCONFIGURATION 2 — robots.txt reveals hidden endpoints
# ---------------------------------------------------------------------------
@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /api/v1/debug/env\n"   # Hint to attacker
        "Disallow: /api/v1/debug/logs\n"
    ), 200, {"Content-Type": "text/plain"}

# ---------------------------------------------------------------------------
# MISCONFIGURATION 3 — Directory listing on /static equivalent
# ---------------------------------------------------------------------------
@app.route("/api/v1/debug/logs")
def debug_logs():
    """Another forgotten endpoint — returns a hardcoded fake log that
    reconfirms the admin password in plain text (common in real breaches)."""
    logs = [
        {"ts": "2025-02-20T08:00:00Z", "level": "INFO",  "msg": "App started"},
        {"ts": "2025-02-20T08:01:12Z", "level": "DEBUG", "msg": f"Admin login OK — user=admin pass={ADMIN_PASSWORD}"},
        {"ts": "2025-02-20T08:05:00Z", "level": "INFO",  "msg": "Healthcheck passed"},
    ]
    return jsonify(logs)

if __name__ == "__main__":
    init_lab()
    # Keep verbose debug pages for training, but disable interactive debugger/reloader.
    app.run(host="0.0.0.0", port=5000, debug=True, use_debugger=False, use_reloader=False)
