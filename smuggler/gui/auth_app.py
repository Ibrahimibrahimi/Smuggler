"""
Auth Web UI
Flask-based authentication configuration interface.
Replaces the Tkinter GUI for broader compatibility.
"""

import threading
import webbrowser
from typing import Optional

from flask import Flask, render_template, request, jsonify

from smuggler.config.manager import AuthConfig, save_auth_config


app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

_auth_result: Optional[AuthConfig] = None
_existing_config: Optional[AuthConfig] = None


@app.route("/", methods=["GET"])
def index():
    prefill = {}
    if _existing_config:
        prefill = {
            "headers": _existing_config.headers,
            "cookies": _existing_config.cookies,
            "token": _existing_config.token,
            "token_type": _existing_config.token_type,
            "proxy_enabled": _existing_config.proxy_enabled,
            "proxy_url": _existing_config.proxy_url,
            "proxy_username": _existing_config.proxy_username,
            "proxy_password": _existing_config.proxy_password,
            "ssl_verify": _existing_config.ssl_verify,
        }
    return render_template("auth.html", config=prefill)


@app.route("/save", methods=["POST"])
def save():
    global _auth_result

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    headers = {}
    for h in data.get("headers", []):
        k = h.get("key", "").strip()
        v = h.get("value", "").strip()
        if k:
            headers[k] = v

    cookies = {}
    for c in data.get("cookies", []):
        k = c.get("key", "").strip()
        v = c.get("value", "").strip()
        if k:
            cookies[k] = v

    _auth_result = AuthConfig(
        headers=headers,
        cookies=cookies,
        token=data.get("token", "").strip(),
        token_type=data.get("token_type", "Bearer"),
        proxy_enabled=data.get("proxy_enabled", False),
        proxy_url=data.get("proxy_url", "").strip(),
        proxy_username=data.get("proxy_username", "").strip(),
        proxy_password=data.get("proxy_password", "").strip(),
        ssl_verify=data.get("ssl_verify", True),
    )

    save_auth_config(_auth_result)

    return jsonify({"status": "ok", "message": "Config saved"})


@app.route("/cancel", methods=["POST"])
def cancel():
    global _auth_result
    _auth_result = None
    return jsonify({"status": "ok"})


def launch_auth_web(existing_config: Optional[AuthConfig] = None, port: int = 5555) -> Optional[AuthConfig]:
    """
    Launch the Flask auth web UI and return the collected AuthConfig (or None if cancelled).
    Opens browser automatically.
    """
    global _auth_result, _existing_config

    _auth_result = None
    _existing_config = existing_config

    url = f"http://127.0.0.1:{port}"

    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open(url)

    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    print(f"\n  Auth Web UI running at: {url}")
    print(f"  Configure your authentication settings in the browser.")
    print(f"  Press Ctrl+C to cancel.\n")

    try:
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass

    return _auth_result
