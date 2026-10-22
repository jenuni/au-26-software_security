# app api running on http://localhost:8000

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests
import os
import sqlite3
import hashlib
import hmac
import secrets
import time

app = FastAPI(title="ADFMS Application API", version="1.0.0")

# Internal service URLs
MESSAGE_VAULT_URL = os.getenv("MESSAGE_VAULT_URL", "http://localhost:8001")
PROCESSING_WORKER_URL = os.getenv("PROCESSING_WORKER_URL", "http://localhost:8002")

# Identity store owned by the Application API (separate from the Message Vault's vault.db)
AUTH_DB_FILE = os.getenv("AUTH_DB_FILE", "auth.db")

# Accounts: two ordinary users and one admin
SEED_USERS = [
    ("pilot1", os.getenv("PILOT1_PASSWORD", "Drone@123"), "Operator"),
    ("pilot2", os.getenv("PILOT2_PASSWORD", "Drone@456"), "Operator"),
    ("admin", os.getenv("ADMIN_PASSWORD", "Admin@123"), "Admin"),
]

def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)

def init_auth_db():
    conn = sqlite3.connect(AUTH_DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            role TEXT NOT NULL
        )
    """)
    for username, password, role in SEED_USERS:
        salt = secrets.token_bytes(16)
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
            (username, hash_password(password, salt), salt, role)
        )
    conn.commit()
    conn.close()

init_auth_db()

# In-memory session store: token -> {username, role, expires_at}
ACTIVE_SESSIONS = {}

# Session validity period in seconds (default 15 minutes)
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "900"))

def require_session(authorization: str) -> dict:
    """Complete mediation: every protected request validates the session here.
    Rejects missing/unknown tokens and expired ones (fail-safe default)."""
    session = ACTIVE_SESSIONS.get(authorization)
    if session is None:
        raise HTTPException(status_code=403, detail="Unauthorized session")
    if time.time() >= session["expires_at"]:
        # Expired token: drop it and deny
        ACTIVE_SESSIONS.pop(authorization, None)
        raise HTTPException(status_code=401, detail="Session expired")
    return session

class LoginModel(BaseModel):
    username: str
    password: str

class MessageModel(BaseModel):
    recipient: str
    text: str

class ImportModel(BaseModel):
    backup: str  # base64-encoded serialized chat backup


@app.post("/login")
def login(creds: LoginModel):
    """Authenticates users against auth.db and issues a random session token."""
    conn = sqlite3.connect(AUTH_DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash, salt, role FROM users WHERE username = ?",
        (creds.username,)
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    password_hash, salt, role = row
    if not hmac.compare_digest(password_hash, hash_password(creds.password, salt)):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[token] = {
        "username": creds.username,
        "role": role,
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    return {"access_token": token, "role": role, "expires_in": SESSION_TTL_SECONDS}

@app.post("/messages")
def send_message(msg: MessageModel, authorization: str = Header(None)):
    """Coordinates sending a message through to the Message Vault."""
    user_info = require_session(authorization)

    # Forward the request to the Message Vault (Resource Service)
    payload = {
        "sender": user_info["username"],
        "recipient": msg.recipient,
        "content": msg.text
    }
    response = requests.post(f"{MESSAGE_VAULT_URL}/messages", json=payload)
    return response.json()

@app.post("/export")
def request_export(authorization: str = Header(None)):
    """Triggers the export job across all three components (API -> Worker -> Vault).
    Any authenticated user may export their own messages (export scopes to the caller)."""
    user_info = require_session(authorization)

    # Trigger the processing worker service for the caller's own messages
    response = requests.post(f"{PROCESSING_WORKER_URL}/run-export", json={"username": user_info["username"]})
    return response.json()

@app.post("/import")
def request_import(body: ImportModel, authorization: str = Header(None)):
    """Restores a chat backup across all three components (API -> Worker -> Vault).
    Restricted action: only the privileged Admin role may import a backup."""
    user_info = require_session(authorization)

    # Authorization check: import is an Admin-only action
    if user_info["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    # Hand the backup blob to the processing worker service
    response = requests.post(
        f"{PROCESSING_WORKER_URL}/import-backup",
        json={"username": user_info["username"], "backup": body.backup}
    )
    return response.json()

@app.get("/download")
def download_file(filename: str):
    """
    Vulnerable file download endpoint for documents like Terms of Service (tos.txt) or Privacy Policy (privacy.txt).
    """
    # --- VULNERABILITY: CWE-22 (Path Traversal) ---
    # Allows an attacker to use '../../' to read arbitrary files from the container.
    
    # Directory where safe documents are supposed to be stored
    target_dir = "./documents"
    
    # Unsafe path concatenation without proper sanitization or normalization checks
    file_path = os.path.join(target_dir, filename)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    return FileResponse(file_path)