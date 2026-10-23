"""Shared constants and helpers for the test suite.

Tests talk to the running stack over HTTP:
  - Application API   (default http://127.0.0.1:8000)
  - Message Vault     (default http://127.0.0.1:8001)
  - Processing Worker (default http://127.0.0.1:8002)
"""
import os
import json
import base64
import pickle

import requests

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
VAULT_URL = os.getenv("VAULT_URL", "http://127.0.0.1:8001")
WORKER_URL = os.getenv("WORKER_URL", "http://127.0.0.1:8002")

INTERNAL_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "adfms-internal-service-secret")

# Seeded synthetic accounts.
USERS = {
    "pilot1": os.getenv("PILOT1_PASSWORD", "Drone@123"),
    "pilot2": os.getenv("PILOT2_PASSWORD", "Drone@456"),
    "admin": os.getenv("ADMIN_PASSWORD", "Admin@123"),
}

# Wire format the Import feature expects for a backup blob:
#   code_vulnerable -> "pickle" (the planted CWE-502)
#   code_fixed      -> "json"   (safe deserialization)
# CI sets this per target directory; default matches the vulnerable build.
BACKUP_FORMAT = os.getenv("BACKUP_FORMAT", "pickle").lower()


def login(username, password=None):
    """Authenticate and return the session token (raises on failure)."""
    password = USERS[username] if password is None else password
    r = requests.post(f"{API_URL}/login", json={"username": username, "password": password})
    r.raise_for_status()
    return r.json()["access_token"]


def auth(token):
    """Build the Authorization header the API expects (raw token)."""
    return {"Authorization": token}


def send_message(token, recipient, text):
    """Send a message through the Application API."""
    return requests.post(
        f"{API_URL}/messages",
        headers=auth(token),
        json={"recipient": recipient, "text": text},
    )


def encode_backup(messages):
    """Encode a list of message dicts as a base64 backup blob in the format
    the current target expects (pickle for the vulnerable build, JSON for the
    fixed build)."""
    if BACKUP_FORMAT == "pickle":
        raw = pickle.dumps(messages)
    else:
        raw = json.dumps(messages).encode()
    return base64.b64encode(raw).decode()
