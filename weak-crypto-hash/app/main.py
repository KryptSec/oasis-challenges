from flask import Flask, request, jsonify, render_template, session, redirect
import os, uuid, hashlib, time, sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)

FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")
DB_PATH   = os.path.join(os.path.dirname(__file__), "app.db")

# In-memory store for reset tokens: {token: (username, issued_at)}
reset_tokens = {}

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def init_lab():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)

    flag_value = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag_value)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)")
    # Admin password stored as plain MD5 (another crypto failure)
    admin_hash = hashlib.md5("password123".encode()).hexdigest()
    c.execute("INSERT INTO users VALUES (1,'admin',?,'admin')", (admin_hash,))
    c.execute("INSERT INTO users VALUES (2,'alice','alice_pass','user')")
    conn.commit()
    conn.close()

def read_flag():
    try:
        return open(FLAG_PATH).read().strip()
    except Exception:
        return "KX{ERROR_NO_FLAG}"

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row  # (id, username, password_hash, role)

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
        user = get_user(username)
        if user:
            stored_hash = user[2]
            # VULNERABILITY: passwords stored as plain MD5 (no salt)
            if hashlib.md5(password.encode()).hexdigest() == stored_hash:
                session["user"] = username
                session["role"] = user[3]
                return redirect("/dashboard")
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect("/login")
    flag = None
    if session.get("role") == "admin":
        flag = read_flag()
    return render_template("dashboard.html", user=session["user"],
                           role=session["role"], flag=flag)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """
    VULNERABILITY (A04:2025 – Cryptographic Failures):
    Reset tokens are generated as MD5(username + unix_timestamp).
    The timestamp is leaked directly in the JSON response, allowing an
    attacker to reproduce the token and reset any account's password.
    """
    msg = None
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        username = data.get("username", request.form.get("username", ""))
        user = get_user(username)
        if user:
            ts    = int(time.time())
            token = hashlib.md5(f"{username}{ts}".encode()).hexdigest()
            reset_tokens[token] = (username, ts)
            # VULNERABILITY: timestamp leaked in response
            return jsonify({
                "message": "Password reset token generated.",
                "hint":    f"Token valid for 5 minutes. Generated at unix timestamp: {ts}",
                "token_length": 32
            })
        return jsonify({"message": "If that account exists, a reset link was sent."}), 200
    return render_template("forgot.html", msg=msg)

@app.route("/reset-password", methods=["POST"])
def reset_password():
    """Use a valid reset token to change a password."""
    data = request.get_json(silent=True) or {}
    token       = data.get("token", "")
    new_password = data.get("password", "")

    if token not in reset_tokens:
        return jsonify({"error": "Invalid or expired token"}), 400

    username, issued_at = reset_tokens[token]
    if time.time() - issued_at > 300:   # 5-minute expiry
        del reset_tokens[token]
        return jsonify({"error": "Token expired"}), 400

    # Update password (still stored as MD5…)
    new_hash = hashlib.md5(new_password.encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET password=? WHERE username=?", (new_hash, username))
    conn.commit()
    conn.close()
    del reset_tokens[token]
    return jsonify({"message": f"Password for '{username}' updated successfully."})

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
