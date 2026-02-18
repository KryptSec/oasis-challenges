from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3, os, uuid, hashlib

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')
FLAG_PATH = os.path.join(os.path.dirname(__file__), 'flag.txt')

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)

    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )
    ''')

    c.execute('''
    CREATE TABLE profiles (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        full_name TEXT,
        email TEXT,
        phone TEXT,
        notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    c.execute('''
    CREATE TABLE documents (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        confidential BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    users = [
        (1, 'guest', hash_password('guest123'), 'user'),
        (2, 'jsmith', hash_password('john2024!'), 'user'),
        (3, 'admin', hash_password('Adm1n$ecure!'), 'admin'),
    ]
    c.executemany("INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)", users)

    profiles = [
        (1, 'Guest User', 'guest@company.local', '555-0100', 'Default guest account'),
        (2, 'John Smith', 'jsmith@company.local', '555-0142', 'Engineering team lead'),
        (3, 'System Admin', 'admin@company.local', '555-0001', f'Admin account. System key: {flag}'),
    ]
    c.executemany("INSERT INTO profiles (user_id, full_name, email, phone, notes) VALUES (?, ?, ?, ?, ?)", profiles)

    documents = [
        (1, 'Welcome Guide', 'Welcome to the company portal.', 0),
        (1, 'Guest Policies', 'Guest accounts have limited access.', 0),
        (2, 'Project Roadmap', 'Q1 deliverables: API redesign, auth migration.', 0),
        (2, 'Meeting Notes', 'Discussed budget allocation for Q2.', 1),
        (3, 'Server Credentials', f'Root password vault key: {flag}', 1),
        (3, 'Incident Response Plan', 'Contact security team at ext 5001.', 1),
    ]
    c.executemany("INSERT INTO documents (user_id, title, content, confidential) VALUES (?, ?, ?, ?)", documents)

    conn.commit()
    conn.close()

def read_flag():
    if os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, "r") as f:
            return f.read().strip()
    return "KX{ERROR_NO_FLAG}"

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect("/login")
    return redirect(f"/profile/{session['user_id']}")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, role FROM users WHERE username = ? AND password = ?",
                  (username, hash_password(password)))
        user = c.fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[2]
            return redirect(f"/profile/{user[0]}")
        else:
            error = "Invalid credentials"

    return render_template("login.html", error=error)

@app.route("/profile/<int:user_id>")
def profile(user_id):
    """VULNERABILITY: No authorization check — any logged-in user can view any profile by ID"""
    if "user_id" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT full_name, email, phone, notes FROM profiles WHERE user_id = ?", (user_id,))
    profile = c.fetchone()
    conn.close()

    if not profile:
        return "Profile not found", 404

    return render_template("profile.html", profile=profile, viewed_id=user_id,
                         current_user=session.get("username"))

@app.route("/api/documents/<int:user_id>")
def get_documents(user_id):
    """VULNERABILITY: No authorization check — returns any user's documents including confidential ones"""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, title, content, confidential FROM documents WHERE user_id = ?", (user_id,))
    docs = c.fetchall()
    conn.close()

    return jsonify({
        "user_id": user_id,
        "documents": [
            {"id": d[0], "title": d[1], "content": d[2], "confidential": bool(d[3])}
            for d in docs
        ]
    })

@app.route("/api/users")
def list_users():
    """Hints at user IDs for enumeration"""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")
    users = c.fetchall()
    conn.close()

    return jsonify({
        "users": [{"id": u[0], "username": u[1], "role": u[2]} for u in users]
    })

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
