"""Functional tests for the three application functionalities.

These assert the application does what it is supposed to do, and pass on both
the vulnerable and the fixed build.
"""
import pytest
import requests

from helpers import API_URL, USERS, auth, send_message, encode_backup

pytestmark = pytest.mark.functional


def test_login_all_seeded_users():
    """All three seeded accounts authenticate and receive a role."""
    for username in ("pilot1", "pilot2", "admin"):
        r = requests.post(f"{API_URL}/login", json={"username": username, "password": USERS[username]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["access_token"]
        assert body["role"] in ("Operator", "Admin")


def test_login_rejects_bad_password():
    r = requests.post(f"{API_URL}/login", json={"username": "pilot1", "password": "wrong"})
    assert r.status_code == 401


def test_send_message(pilot1_token):
    """Functionality 1: send a message (API -> Vault)."""
    r = send_message(pilot1_token, "pilot2", "hello pilot2")
    assert r.status_code == 200, r.text
    assert r.json().get("status") == "stored"


def test_export_full_flow(pilot1_token, pilot2_token):
    """Functionality 2: export spans all three components (API -> Worker ->
    Vault + chat_formatter). pilot1 messages pilot2, pilot2 exports their inbox."""
    text = "flow-check-message"
    assert send_message(pilot1_token, "pilot2", text).status_code == 200
    r = requests.post(f"{API_URL}/export", headers=auth(pilot2_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("export_format") == "markdown"
    assert text in body["exported_data"]


def test_admin_import(admin_token, pilot1_token):
    """Functionality 3: admin imports a backup (API -> Worker -> Vault); the
    restored message is then visible to its recipient via export."""
    messages = [{"sender": "admin", "recipient": "pilot1", "content": "imported-msg"}]
    r = requests.post(f"{API_URL}/import", headers=auth(admin_token), json={"backup": encode_backup(messages)})
    assert r.status_code == 200, r.text
    assert r.json().get("imported", 0) >= 1

    exp = requests.post(f"{API_URL}/export", headers=auth(pilot1_token))
    assert "imported-msg" in exp.json()["exported_data"]
