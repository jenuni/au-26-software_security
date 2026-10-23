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

from helpers import API_URL, VAULT_URL, WORKER_URL, INTERNAL_TOKEN, auth, send_message

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
    """An injection in the recipient must not return rows for other recipients.

    The call carries the internal token so it is authorized on the fixed build
    and actually reaches the query, proving the injection is neutralised at the
    SQL level.
    """
    marker = f"sqlimark-{uuid.uuid4().hex}"
    assert send_message(pilot1_token, "pilot2", marker).status_code == 200

    injection = "no_such_recipient' OR '1'='1"
    url = f"{VAULT_URL}/messages/{urllib.parse.quote(injection, safe='')}"
    r = requests.get(url, headers={"X-Internal-Token": INTERNAL_TOKEN})

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

def test_import_pickle_rce_blocked(admin_token):
    """A malicious pickle backup must not execute code during import.

    If the backup is deserialized with pickle, the payload runs a shell command
    inside the Worker that posts a sentinel message to the Vault (which the
    Worker can reach). We then check the Vault for that message over HTTP:
    present => code executed (vulnerability). 
    """
    rid = f"pwned-{uuid.uuid4().hex}"
    # Runs in the Worker: post {content: "RCE"} to whatever vault URL the Worker uses.
    code = (
        "import os,urllib.request,json;"
        "u=os.environ.get('MESSAGE_VAULT_URL','http://localhost:8001');"
        "d=json.dumps({'sender':'pwned','recipient':'%s','content':'RCE'}).encode();"
        "urllib.request.urlopen(urllib.request.Request("
        "u+'/messages',data=d,headers={'Content-Type':'application/json'}),timeout=5)"
    ) % rid
    cmd = 'python3 -c "%s"' % code

    class Exploit:
        def __reduce__(self):
            return (os.system, (cmd,))

    payload = base64.b64encode(pickle.dumps(Exploit())).decode()
    requests.post(f"{API_URL}/import", headers=auth(admin_token), json={"backup": payload})

    planted = False
    for _ in range(5):
        time.sleep(1)
        r = requests.get(f"{VAULT_URL}/messages/{rid}")
        if r.status_code == 200 and any(
            m.get("content") == "RCE" for m in r.json().get("messages", [])
        ):
            planted = True
            break

    assert not planted, "Malicious pickle executed code in the Worker (CWE-502)"
