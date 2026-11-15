"""Run this local Flask application with: python app.py"""
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.fernet import InvalidToken
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for

import security

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)  # new on each launch; not written to disk
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  MAX_CONTENT_LENGTH=20_000)
VAULT_FILE = Path(os.environ.get("PASSWORD_VAULT_FILE", Path(__file__).parent / "vault_data.json"))
LOCK_SECONDS = 30
IDLE_SECONDS = 15 * 60
# The signed browser cookie contains only an opaque token, never the vault key.
# Keys exist only in the memory of this single local Python process.
active_vaults = {}


def save_vault(data):
    VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = VAULT_FILE.with_name(VAULT_FILE.name + ".tmp")
    # Use restrictive permissions where the operating system supports them.
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        os.replace(temporary, VAULT_FILE)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_vault():
    with VAULT_FILE.open(encoding="utf-8") as file:
        return json.load(file)


def current_key():
    token = session.get("vault_token")
    record = active_vaults.get(token)
    if not record:
        return None
    if time.time() - record["last_active"] > IDLE_SECONDS:
        active_vaults.pop(token, None)
        session.pop("vault_token", None)
        return None
    record["last_active"] = time.time()
    return record["key"]


def unlock(key):
    old_token = session.pop("vault_token", None)
    active_vaults.pop(old_token, None)
    token = secrets.token_urlsafe(32)
    active_vaults[token] = {"key": key, "last_active": time.time()}
    session["vault_token"] = token


@app.before_request
def protect_local_forms():
    # Do not make the app available to other machines or arbitrary hostnames.
    if request.remote_addr not in ("127.0.0.1", "::1", None):
        abort(403)
    hostname = request.host.split(":", 1)[0].lower()
    if hostname not in ("127.0.0.1", "localhost"):
        abort(403)
    now = time.time()
    for token, record in list(active_vaults.items()):
        if now - record["last_active"] > IDLE_SECONDS:
            active_vaults.pop(token, None)
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
            abort(403)


@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'"
    return response


@app.context_processor
def template_helpers():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)
    return {"csrf_token": session["csrf_token"], "common_count": len(security.COMMON_PASSWORDS)}


@app.route("/", methods=["GET", "POST"])
def analyzer():
    result = None
    password = ""
    if request.method == "POST":
        password = request.form.get("password", "")
        try:
            result = security.analyze_password(password)
        except ValueError as error:
            flash(str(error), "error")
    return render_template("analyzer.html", result=result, password=password)


@app.route("/generator", methods=["GET", "POST"])
def generator():
    generated = None
    length = 20
    selected = list(security.CHARACTER_GROUPS)
    if request.method == "POST":
        selected = request.form.getlist("groups")
        try:
            length = int(request.form.get("length", "20"))
            generated = security.generate_password(length, selected)
        except (ValueError, TypeError) as error:
            flash(str(error) if isinstance(error, ValueError) and "literal" not in str(error)
                  else "Choose a whole-number length between 8 and 64.", "error")
    return render_template("generator.html", generated=generated, length=length, selected=selected)


@app.get("/demonstration")
def demonstration():
    weak = "password"
    strong = security.generate_password(20, list(security.CHARACTER_GROUPS))
    return render_template("demonstration.html", weak=weak, weak_result=security.analyze_password(weak),
                           strong=strong, strong_result=security.analyze_password(strong))


@app.get("/vault")
def vault():
    if not VAULT_FILE.exists():
        return render_template("vault.html", state="create")
    key = current_key()
    if not key:
        try:
            data = load_vault()
            remaining = max(0, int(data.get("locked_until", 0) - time.time() + 0.999))
        except (OSError, ValueError, KeyError):
            flash("The vault file could not be read. Restore a valid backup.", "error")
            remaining = 0
        return render_template("vault.html", state="locked", remaining=remaining)
    try:
        entries = security.decrypt_entries(load_vault()["ciphertext"], key)
    except (OSError, ValueError, KeyError, InvalidToken):
        flash("Could not open the vault. The encrypted file may be damaged.", "error")
        active_vaults.pop(session.pop("vault_token", None), None)
        return redirect(url_for("vault"))
    return render_template("vault.html", state="open", entries=entries)


@app.post("/vault/create")
def create_vault():
    if VAULT_FILE.exists():
        flash("A vault already exists. Unlock it instead.", "error")
        return redirect(url_for("vault"))
    master = request.form.get("master", "")
    confirm = request.form.get("confirm", "")
    if master != confirm:
        flash("The two master passwords do not match.", "error")
    elif not 12 <= len(master) <= 200:
        flash("Choose a master password between 12 and 200 characters.", "error")
    elif master.lower() in security.COMMON_RANK:
        flash("That master password appears on the common-password list.", "error")
    else:
        data, key = security.new_vault(master)
        save_vault(data)
        unlock(key)
        flash("Vault created and unlocked. Remember your master password.", "success")
    return redirect(url_for("vault"))


@app.post("/vault/login")
def login_vault():
    if not VAULT_FILE.exists():
        return redirect(url_for("vault"))
    try:
        data = load_vault()
        now = time.time()
        locked_until = data.get("locked_until", 0)
        if now < locked_until:
            remaining = int(locked_until - now + 0.999)
            flash(f"Too many attempts. Try again in {remaining} seconds.", "error")
            return redirect(url_for("vault"))
        if locked_until:
            data["locked_until"] = 0
            data["failed_attempts"] = 0
        master = request.form.get("master", "")
        if len(master) > 200 or not security.verify_master(master, data):
            data["failed_attempts"] = data.get("failed_attempts", 0) + 1
            if data["failed_attempts"] >= 3:
                data["locked_until"] = now + LOCK_SECONDS
                flash(f"Three incorrect attempts. Vault locked for {LOCK_SECONDS} seconds.", "error")
            else:
                remaining = 3 - data["failed_attempts"]
                flash(f"Incorrect master password. {remaining} attempt(s) before a temporary lock.", "error")
            save_vault(data)
            return redirect(url_for("vault"))
        key = security.vault_key(master, data)
        security.decrypt_entries(data["ciphertext"], key)  # authenticate before opening
        data["failed_attempts"] = 0
        data["locked_until"] = 0
        save_vault(data)
        unlock(key)
        flash("Vault unlocked.", "success")
    except (OSError, ValueError, KeyError, InvalidToken):
        flash("Could not open the vault. The encrypted file may be damaged.", "error")
    return redirect(url_for("vault"))


@app.post("/vault/add")
def add_entry():
    key = current_key()
    if not key:
        flash("Unlock the vault first.", "error")
        return redirect(url_for("vault"))
    site = request.form.get("site", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not site or not username or not password or len(site) > 120 or len(username) > 120 or len(password) > 256:
        flash("Enter a site, username, and password within the stated limits.", "error")
        return redirect(url_for("vault"))
    try:
        data = load_vault()
        entries = security.decrypt_entries(data["ciphertext"], key)
        entries.append({"id": secrets.token_hex(12), "site": site, "username": username, "password": password})
        data["ciphertext"] = security.encrypt_entries(entries, key)
        save_vault(data)
        flash("Credential saved inside the encrypted vault.", "success")
    except (OSError, ValueError, KeyError, InvalidToken):
        flash("Could not save the credential. Check the vault file.", "error")
    return redirect(url_for("vault"))


@app.post("/vault/delete")
def delete_entry():
    key = current_key()
    if not key:
        flash("Unlock the vault first.", "error")
        return redirect(url_for("vault"))
    try:
        data = load_vault()
        entries = security.decrypt_entries(data["ciphertext"], key)
        new_entries = [entry for entry in entries if entry["id"] != request.form.get("entry_id")]
        if len(entries) == len(new_entries):
            flash("Credential was not found.", "error")
        else:
            data["ciphertext"] = security.encrypt_entries(new_entries, key)
            save_vault(data)
            flash("Credential deleted.", "success")
    except (OSError, ValueError, KeyError, InvalidToken):
        flash("Could not update the vault.", "error")
    return redirect(url_for("vault"))


@app.post("/vault/lock")
def lock_vault():
    active_vaults.pop(session.pop("vault_token", None), None)
    flash("Vault locked.", "success")
    return redirect(url_for("vault"))


if __name__ == "__main__":
    print("Open http://127.0.0.1:5000 in your browser. Press Ctrl+C to stop.", flush=True)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=False)
