import sqlite3
import os
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import requests

# Token cache: {cache_key: {"token": str, "expires_at": float}}
_token_cache = {}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            company TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients(id)
        );
        CREATE TABLE IF NOT EXISTS qlik_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_url TEXT,
            client_id TEXT,
            client_secret TEXT,
            app_id TEXT,
            object_id TEXT,
            embed_type TEXT DEFAULT 'chart'
        );
    """)
    existing = cur.execute("SELECT id FROM users WHERE email = ?", ("veg@qlik.com",)).fetchone()
    if not existing:
        cur.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            ("veg@qlik.com", generate_password_hash("admin123")),
        )
        cur.executemany(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            [
                ("demoqlikfr1@gmail.com", generate_password_hash("demo123")),
                ("demoqlikfr2@gmail.com", generate_password_hash("demo123")),
                ("demoqlikfr3@gmail.com", generate_password_hash("demo123")),
                ("demoqlikfr4@gmail.com", generate_password_hash("demo123")),
                ("demoqlikfr5@gmail.com", generate_password_hash("demo123")),
                ("demoqlikfr6@gmail.com", generate_password_hash("demo123")),
            ],
        )
        cur.executemany(
            "INSERT INTO clients (name, email, company, status) VALUES (?, ?, ?, ?)",
            [
                ("Alice Dupont", "alice@example.com", "QlikTech", "active"),
                ("Bob Martin", "bob@example.com", "DataCorp", "active"),
                ("Claire Petit", "claire@example.com", "Analytics SA", "inactive"),
                ("David Leroy", "david@example.com", "CloudInc", "active"),
                ("Eve Moreau", "eve@example.com", "BI France", "active"),
            ],
        )
        cur.execute("INSERT INTO notes (client_id, content) VALUES (?, ?)", (1, "Premier contact le 10/06/2026"))
        cur.execute("INSERT INTO notes (client_id, content) VALUES (?, ?)", (2, "Démonstration prévue le 20/06"))
    settings = cur.execute("SELECT id FROM qlik_settings WHERE id = 1").fetchone()
    if not settings:
        cur.execute("""INSERT INTO qlik_settings (tenant_url, client_id, client_secret, app_id, object_id, embed_type)
            VALUES (NULL, NULL, NULL, NULL, NULL, 'chart')""")
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Veuillez vous connecter", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_qlik_admin_token(tenant_url, client_id, client_secret):
    resp = requests.post(
        f"{tenant_url}/oauth/token",
        json={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope": "admin.users",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def lookup_qlik_user_id(tenant_url, client_id, client_secret, email):
    try:
        admin_token = get_qlik_admin_token(tenant_url, client_id, client_secret)
        resp = requests.get(
            f"{tenant_url}/api/v1/users",
            params={"limit": 100},
            headers={"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        for user in resp.json().get("data", []):
            if user.get("email", "").lower() == email.lower():
                return user["id"]
        return None
    except Exception as e:
        print(f"Qlik user lookup error: {e}")
        return None


def get_qlik_impersonation_token(tenant_url, oauth_client_id, oauth_client_secret, user_email):
    cache_key = f"{tenant_url}|{oauth_client_id}|{user_email}"
    cached = _token_cache.get(cache_key)
    if cached and time.time() < cached["expires_at"] - 60:
        return cached["token"]
    try:
        user_id = lookup_qlik_user_id(tenant_url, oauth_client_id, oauth_client_secret, user_email)
        if not user_id:
            print(f"Qlik: user not found for email {user_email}")
            return None
        resp = requests.post(
            f"{tenant_url}/oauth/token",
            json={
                "client_id": oauth_client_id,
                "client_secret": oauth_client_secret,
                "grant_type": "urn:qlik:oauth:user-impersonation",
                "user_lookup": {
                    "field": "userId",
                    "value": user_id,
                },
                "scope": "user_default",
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        token = data.get("access_token")
        if token:
            _token_cache[cache_key] = {
                "token": token,
                "expires_at": time.time() + data.get("expires_in", 21600),
            }
        return token
    except Exception as e:
        print(f"Qlik token error: {e}")
        return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            flash("Connexion réussie", "success")
            return redirect(url_for("dashboard"))
        flash("Email ou mot de passe incorrect", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnexion réussie", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM clients").fetchone()["c"]
    active = conn.execute("SELECT COUNT(*) as c FROM clients WHERE status='active'").fetchone()["c"]
    recent = conn.execute(
        "SELECT * FROM clients ORDER BY created_at DESC LIMIT 5"
    ).fetchall()
    all_notes = conn.execute(
        "SELECT n.id, n.content, n.created_at, c.name FROM notes n JOIN clients c ON n.client_id = c.id ORDER BY n.created_at DESC"
    ).fetchall()
    qlik = conn.execute("SELECT * FROM qlik_settings WHERE id = 1").fetchone()
    conn.close()

    qlik_token = None
    if qlik and qlik["tenant_url"] and qlik["client_id"] and qlik["client_secret"]:
        qlik_token = get_qlik_impersonation_token(
            qlik["tenant_url"], qlik["client_id"], qlik["client_secret"], session["email"]
        )

    return render_template("dashboard.html",
        total=total, active=active, recent=recent, all_notes=all_notes,
        qlik=qlik, qlik_token=qlik_token)


@app.route("/kpi")
@login_required
def kpi():
    conn = get_db()
    qlik = conn.execute("SELECT * FROM qlik_settings WHERE id = 1").fetchone()
    conn.close()
    qlik_token = None
    if qlik and qlik["tenant_url"] and qlik["client_id"] and qlik["client_secret"]:
        qlik_token = get_qlik_impersonation_token(
            qlik["tenant_url"], qlik["client_id"], qlik["client_secret"], session["email"]
        )
    return render_template("kpi.html", qlik=qlik, qlik_token=qlik_token)


@app.route("/api/qlik-token")
@login_required
def qlik_token_api():
    conn = get_db()
    qlik = conn.execute("SELECT * FROM qlik_settings WHERE id = 1").fetchone()
    conn.close()
    if not qlik or not qlik["tenant_url"] or not qlik["client_id"] or not qlik["client_secret"]:
        return jsonify({"error": "Qlik not configured"}), 400
    token = get_qlik_impersonation_token(
        qlik["tenant_url"], qlik["client_id"], qlik["client_secret"], session["email"]
    )
    if token:
        cache_key = f"{qlik['tenant_url']}|{qlik['client_id']}|{session['email']}"
        cached = _token_cache.get(cache_key)
        return jsonify({
            "access_token": token,
            "expires_at": cached["expires_at"] if cached else time.time() + 21600,
        })
    return jsonify({"error": "Failed to get token"}), 500


@app.route("/clients")
@login_required
def clients():
    conn = get_db()
    rows = conn.execute("SELECT * FROM clients ORDER BY name").fetchall()
    conn.close()
    return render_template("clients.html", clients=rows)


@app.route("/clients/add", methods=["GET", "POST"])
@login_required
def add_client():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form.get("email", "").strip()
        company = request.form.get("company", "").strip()
        status = request.form.get("status", "active")
        if name:
            conn = get_db()
            conn.execute("INSERT INTO clients (name, email, company, status) VALUES (?, ?, ?, ?)",
                         (name, email, company, status))
            conn.commit()
            conn.close()
            flash("Client ajouté", "success")
            return redirect(url_for("clients"))
        flash("Le nom est requis", "danger")
    return render_template("add_client.html")


@app.route("/clients/<int:id>/delete", methods=["POST"])
@login_required
def delete_client(id):
    conn = get_db()
    conn.execute("DELETE FROM notes WHERE client_id = ?", (id,))
    conn.execute("DELETE FROM clients WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Client supprimé", "success")
    return redirect(url_for("clients"))


@app.route("/notes/add", methods=["POST"])
@login_required
def add_note():
    client_id = request.form.get("client_id")
    content = request.form.get("content", "").strip()
    if client_id and content:
        conn = get_db()
        conn.execute("INSERT INTO notes (client_id, content) VALUES (?, ?)", (client_id, content))
        conn.commit()
        conn.close()
        flash("Note ajoutée", "success")
    return redirect(url_for("dashboard"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    conn = get_db()
    if request.method == "POST":
        tenant_url = request.form.get("tenant_url", "").strip().rstrip("/")
        client_id = request.form.get("client_id", "").strip()
        client_secret = request.form.get("client_secret", "").strip()
        app_id = request.form.get("app_id", "").strip()
        object_id = request.form.get("object_id", "").strip()
        embed_type = request.form.get("embed_type", "chart")
        conn.execute("""UPDATE qlik_settings SET
            tenant_url=?, client_id=?, client_secret=?, app_id=?, object_id=?, embed_type=?
            WHERE id=1""",
            (tenant_url or None, client_id or None, client_secret or None,
             app_id or None, object_id or None, embed_type))
        conn.commit()
        flash("Configuration Qlik enregistrée", "success")
        return redirect(url_for("dashboard"))
    qlik = conn.execute("SELECT * FROM qlik_settings WHERE id = 1").fetchone()
    conn.close()
    return render_template("settings.html", qlik=qlik)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5051)
