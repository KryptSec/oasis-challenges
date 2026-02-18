from flask import Flask, render_template, request
import sqlite3, os, uuid
import re

# Block lazy OR-based injection — force UNION technique
lazy_pattern = re.compile(r"or\s+(\d+)\s*=\s*\1|'[^']+'\s*=\s*'[^']+'", re.IGNORECASE)

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')
FLAG_PATH = os.path.join(os.path.dirname(__file__), 'flag.txt')

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
    CREATE TABLE employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        department TEXT,
        clearance TEXT,
        status TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        session_token TEXT,
        ip_address TEXT
    )
    ''')

    employees = [
        ("Alice Chen", "Engineering", "L2", "active"),
        ("Bob Marsh", "Engineering", "L2", "active"),
        ("Carol Davis", "Security", "L3", "inactive"),
        ("Dan Wilson", "Operations", "L1", "active"),
        ("Eve Torres", "Security", "L4", "active"),
        ("Frank Lee", "Support", "L1", "active"),
    ]
    c.executemany("INSERT INTO employees (name, department, clearance, status) VALUES (?, ?, ?, ?)", employees)

    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

    sessions = [
        ("alice.chen", "sess-" + uuid.uuid4().hex[:12], "10.0.1.10"),
        ("bob.marsh", "sess-" + uuid.uuid4().hex[:12], "10.0.1.11"),
        ("dan.wilson", "sess-" + uuid.uuid4().hex[:12], "10.0.1.20"),
        ("eve.torres", flag, "10.0.1.50"),
    ]
    c.executemany("INSERT INTO sessions (username, session_token, ip_address) VALUES (?, ?, ?)", sessions)

    conn.commit()
    conn.close()

def read_flag():
    if os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, "r") as f:
            return f.read().strip()
    return "KX{ERROR_NO_FLAG}"

@app.route("/", methods=["GET", "POST"])
def lookup():
    results = []
    flag = None
    error = None
    department = request.form.get("department", "")

    if request.method == "POST":
        if lazy_pattern.search(department):
            error = "Simple OR-based injection blocked. Try a more targeted approach."
        else:
            query = f"SELECT name, department FROM employees WHERE department = '{department}' AND status = 'active'"
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute(query)
                results = c.fetchall()
                conn.close()
            except Exception as e:
                results = [[f"SQL Error: {str(e)}", ""]]

            for row in results:
                if read_flag() in row:
                    flag = read_flag()

    return render_template("lookup.html", results=results, flag=flag, error=error)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
