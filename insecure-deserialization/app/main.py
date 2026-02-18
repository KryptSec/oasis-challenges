from flask import Flask, request, jsonify, render_template
import yaml, base64, os, uuid, subprocess

app = Flask(__name__)

FLAG_PATH = os.path.join(os.path.dirname(__file__), 'flag.txt')

def init_lab():
    if os.path.exists(FLAG_PATH):
        os.remove(FLAG_PATH)
    flag = f"KX{{{uuid.uuid4().hex[:16]}}}"
    with open(FLAG_PATH, "w") as f:
        f.write(flag)

def read_flag():
    if os.path.exists(FLAG_PATH):
        with open(FLAG_PATH, "r") as f:
            return f.read().strip()
    return "KX{ERROR_NO_FLAG}"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/config", methods=["POST"])
def load_config():
    """
    VULNERABILITY: Uses yaml.load() with FullLoader instead of yaml.safe_load().
    FullLoader allows instantiation of Python objects via YAML tags.
    Accepts both raw YAML and base64-encoded YAML.
    """
    content_type = request.content_type or ""
    raw_data = None

    if "application/json" in content_type:
        data = request.get_json()
        if not data:
            return jsonify({"error": "JSON body required"}), 400

        if "config_b64" in data:
            try:
                raw_data = base64.b64decode(data["config_b64"]).decode()
            except Exception:
                return jsonify({"error": "Invalid base64 encoding"}), 400
        elif "config" in data:
            raw_data = data["config"]
        else:
            return jsonify({"error": "Provide 'config' (raw YAML) or 'config_b64' (base64-encoded YAML)"}), 400
    else:
        raw_data = request.get_data(as_text=True)

    if not raw_data:
        return jsonify({"error": "Empty configuration"}), 400

    try:
        # VULNERABILITY: yaml.load with FullLoader allows object instantiation
        config = yaml.load(raw_data, Loader=yaml.FullLoader)

        return jsonify({
            "status": "Configuration loaded",
            "parsed": str(config),
            "type": str(type(config).__name__)
        })
    except yaml.YAMLError as e:
        return jsonify({"error": f"YAML parse error: {str(e)}"}), 400

@app.route("/api/healthcheck")
def healthcheck():
    return jsonify({
        "status": "healthy",
        "service": "config-loader",
        "version": "1.2.0",
        "yaml_version": yaml.__version__,
        "endpoints": [
            {"path": "/api/config", "method": "POST", "description": "Load YAML configuration"},
            {"path": "/api/read", "method": "GET", "description": "Read a configuration file"},
        ]
    })

@app.route("/api/read")
def read_file():
    """Read files from the config directory — intended for config files only"""
    filename = request.args.get("file", "")

    # Basic path traversal protection (but the real vuln is in /api/config)
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Invalid file path"}), 400

    allowed_extensions = [".yml", ".yaml", ".conf", ".cfg", ".txt"]
    if not any(filename.endswith(ext) for ext in allowed_extensions):
        return jsonify({"error": f"Only configuration files allowed: {allowed_extensions}"}), 400

    filepath = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return jsonify({"filename": filename, "content": f.read()})

    return jsonify({"error": "File not found"}), 404

if __name__ == "__main__":
    init_lab()
    app.run(host="0.0.0.0", port=5000, debug=False)
