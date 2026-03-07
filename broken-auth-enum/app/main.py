from flask import Flask, request, jsonify, render_template, session, redirect
import os, uuid, sqlite3, time

app = Flask(__name__)
app.secret_key = os.urandom(24)

FLAG_PATH = os.path.join(os.path.dirname(__file__), "flag.txt")
DB_PATH   = os.path.join(os.path.dirname(__file__), "users.db")

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
    # Well-known admin account with a weak, guessable password
    c.execute("INSERT INTO users VALUES (1,'admin','admin2025','admin')")
    c.execute("INSERT INTO users VALUES (2,'alice','al1c3pass','user')")
    c.execute("INSERT INTO users VALUES (3,'bob','b0bpass','user')")
    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row

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
    """
    VULNERABILITY (A07:2025 – Authentication Failures):
    1. Username enumeration — different error messages for unknown username vs wrong password.
    2. No account lockout or rate-limiting — allows unlimited guessing.
    3. Weak / default password — admin uses 'admin2025'.
    """
    error  = None
    status = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = get_user_by_username(username)

        if not user:
            # VULNERABILITY: distinct message reveals the username does not exist
            error  = "User not found."
            status = "user_not_found"
        elif user[2] != password:
            # VULNERABILITY: distinct message confirms username is valid
            error  = "Incorrect password."
            status = "wrong_password"
        else:
            session["user"]     = username
            session["role"]     = user[3]
            return redirect("/dashboard")

    return render_template("login.html", error=error)

@app.route("/api/login", methods=["POST"])
def api_login():
    """JSON login — same vulnerability, easier to script."""
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    user     = get_user_by_username(username)

    if not user:
        return jsonify({"error": "User not found"}), 404          # Different HTTP status!
    if user[2] != password:
        return jsonify({"error": "Incorrect password"}), 401
    # Success
    session["user"] = username
    session["role"] = user[3]
    return jsonify({"message": "Login successful", "role": user[3]})

@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect("/login")
    flag = None
    if session.get("role") == "admin":
        flag = read_flag()
    return render_template("dashboard.html", user=session["user"],
                           role=session["role"], flag=flag)

@app.route("/api/users")
def api_users():
    """
    VULNERABILITY: Unauthenticated endpoint lists valid usernames (no auth required).
    Simulates a common misconfiguration where user-listing APIs lack access control.
    """
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    rows = c.execute("SELECT username, role FROM users").fetchall()
    conn.close()
    return jsonify([{"username": r[0], "role": r[1]} for r in rows])

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
