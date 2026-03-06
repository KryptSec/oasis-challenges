from flask import Flask, request, render_template
import subprocess, os, uuid

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
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/ping", methods=["GET", "POST"])
def ping():
    """
    VULNERABILITY (A05:2025 – Injection / OS Command Injection):
    The host parameter is passed directly into a shell command via
    shell=True without any sanitisation.  An attacker can append
    shell metacharacters (;, &&, |, $()) to run arbitrary commands.

    Example: host=127.0.0.1; cat /app/flag.txt
    """
    output = None
    error  = None
    host   = ""
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        if host:
            try:
                # VULNERABLE: shell=True + unsanitised user input
                result = subprocess.run(
                    f"ping -c 2 {host}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                error = "Ping timed out."
            except Exception as e:
                error = str(e)
        else:
            error = "Please provide a host."
    return render_template("ping.html", output=output, error=error, host=host)

@app.route("/nslookup", methods=["POST"])
def nslookup():
    """Second vulnerable endpoint — nslookup with the same flaw."""
    domain = request.form.get("domain", "").strip()
    if not domain:
        return {"error": "domain required"}, 400
    try:
        result = subprocess.run(
            f"nslookup {domain}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return {"output": result.stdout + result.stderr}
    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
