from flask import Flask, request, render_template, abort
import os, uuid

app = Flask(__name__)

BASE_DIR   = os.path.join(os.path.dirname(__file__), "docs")
FLAG_PATH  = os.path.join(os.path.dirname(__file__), "flag.txt")

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def init_lab():
    os.makedirs(BASE_DIR, exist_ok=True)

    # Public documents (legitimately viewable)
    public = {
        "welcome.txt":     "Welcome to DocuVault — your secure document portal.",
        "faq.txt":         "Q: How do I access my files?\nA: Use the /view?file= parameter.",
        "changelog.txt":   "v1.0 — Initial release\nv1.1 — Added user portal",
    }
    for name, content in public.items():
        with open(os.path.join(BASE_DIR, name), "w") as f:
            f.write(content)

    # Flag lives OUTSIDE the docs folder — must be reached via traversal
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
    docs = os.listdir(BASE_DIR)
    return render_template("index.html", docs=docs)

@app.route("/view")
def view():
    """
    VULNERABILITY (A01:2025 – Broken Access Control / Path Traversal):
    The 'file' parameter is concatenated directly with BASE_DIR without
    sanitisation.  An attacker can traverse to any readable file on the
    container filesystem by supplying ../../flag.txt or similar.
    """
    filename = request.args.get("file", "")
    if not filename:
        return "Missing ?file= parameter", 400
    if os.path.isabs(filename):
        return "Absolute paths are not allowed", 400

    # VULNERABLE: no path normalisation / jail check
    file_path = os.path.join(BASE_DIR, filename)

    try:
        with open(file_path, "r") as f:
            content = f.read()
        return render_template("view.html", filename=filename, content=content)
    except FileNotFoundError:
        abort(404)
    except PermissionError:
        abort(403)
    except Exception as e:
        return f"Error reading file: {e}", 500

@app.route("/api/file")
def api_file():
    """
    JSON-based variant of the same traversal — for curl-friendly exploitation.
    """
    filename = request.args.get("file", "")
    if not filename:
        return {"error": "Missing file parameter"}, 400
    if os.path.isabs(filename):
        return {"error": "Absolute paths are not allowed"}, 400

    file_path = os.path.join(BASE_DIR, filename)
    try:
        with open(file_path, "r") as f:
            content = f.read()
        return {"file": filename, "content": content}
    except FileNotFoundError:
        return {"error": "File not found"}, 404
    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
