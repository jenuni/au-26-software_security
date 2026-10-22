"""Security tests for the planted vulnerabilities.

Each test asserts the SECURE behavior, so it:
  - FAILS on `code_vulnerable` (the exploit still works) -> documented evidence,
  - PASSES on `code_fixed`      (the vulnerability is remediated).

They are the behavioral counterpart to the static (Bandit) findings and are the
only checks that can catch the composition flaw, which no single-file static
rule can see.
"""
import os
import time
import uuid
import base64
import pickle
import urllib.parse

import pytest
import requests

from helpers import API_URL, VAULT_URL, WORKER_URL, auth, send_message

pytestmark = pytest.mark.security


# --- CWE-22: Path Traversal (Application API /download) ---

def test_download_legitimate_document():
    """The legitimate documents must still be served."""
    r = requests.get(f"{API_URL}/download", params={"filename": "privacy.txt"})
    assert r.status_code == 200


def test_download_path_traversal_blocked():
    """A '../' path must not escape the documents directory."""
    r = requests.get(f"{API_URL}/download", params={"filename": "../main.py"})
    assert r.status_code != 200, "Path traversal returned a file outside documents/"


# --- CWE-89: SQL Injection (Message Vault) ---

def test_sql_injection_does_not_dump_all(pilot1_token):
    """An injection in the recipient must not return rows for other recipients."""
    marker = f"sqlimark-{uuid.uuid4().hex}"
    assert send_message(pilot1_token, "pilot2", marker).status_code == 200

    injection = "no_such_recipient' OR '1'='1"
    url = f"{VAULT_URL}/messages/{urllib.parse.quote(injection, safe='')}"
    r = requests.get(url)

    body = r.json() if r.status_code == 200 else {}
    contents = [m.get("content", "") for m in body.get("messages", [])]
    assert marker not in contents, "SQL injection returned rows for a non-matching recipient"


# --- CWE-862 / composition: internal services must not trust unauthenticated callers ---

def test_worker_direct_access_blocked():
    """A direct, unauthenticated call to the Worker must be rejected."""
    r = requests.post(f"{WORKER_URL}/run-export", json={"username": "pilot2"})
    assert r.status_code in (401, 403), "Worker accepted an unauthenticated direct call"


def test_vault_direct_read_blocked():
    """A direct, unauthenticated read from the Vault must be rejected."""
    r = requests.get(f"{VAULT_URL}/messages/pilot2")
    assert r.status_code in (401, 403), "Vault served messages to an unauthenticated direct caller"


# --- CWE-502: Deserialization of Untrusted Data (Processing Worker import) ---

@pytest.mark.skipif(os.name != "posix", reason="RCE marker check uses a POSIX shell command")
def test_import_pickle_rce_blocked(admin_token):
    """A malicious pickle backup must not execute code during import."""
    marker = f"/tmp/pwned-{uuid.uuid4().hex}"

    class Exploit:
        def __reduce__(self):
            return (os.system, (f"touch {marker}",))

    payload = base64.b64encode(pickle.dumps(Exploit())).decode()
    requests.post(f"{API_URL}/import", headers=auth(admin_token), json={"backup": payload})
    time.sleep(1)

    assert not os.path.exists(marker), "Malicious pickle executed code in the Worker (CWE-502)"
