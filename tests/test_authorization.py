"""Authorization / access-control tests.

These assert the identity-and-authority rules the Application API is supposed to
enforce. They pass on both builds; the
cross-tier bypasses live in test_security.py.
"""
import os
import time

import pytest
import requests

from helpers import API_URL, auth, login, send_message, encode_backup

pytestmark = pytest.mark.authorization


def test_no_token_denied():
    """Fail-safe default: a protected endpoint rejects a request with no token."""
    r = requests.post(f"{API_URL}/export")
    assert r.status_code == 403


def test_invalid_token_denied():
    r = requests.post(f"{API_URL}/export", headers=auth("not-a-real-token"))
    assert r.status_code == 403


def test_ordinary_user_cannot_import(pilot1_token):
    """Least privilege: import is the Admin-only restricted action."""
    messages = [{"sender": "pilot1", "recipient": "pilot1", "content": "x"}]
    r = requests.post(f"{API_URL}/import", headers=auth(pilot1_token), json={"backup": encode_backup(messages)})
    assert r.status_code == 403


def test_admin_can_import(admin_token):
    messages = [{"sender": "admin", "recipient": "admin", "content": "x"}]
    r = requests.post(f"{API_URL}/import", headers=auth(admin_token), json={"backup": encode_backup(messages)})
    assert r.status_code == 200, r.text


def test_export_scoped_to_caller(pilot1_token, pilot2_token):
    """A user's export must contain only their own inbox, never another user's."""
    secret = "secret-for-pilot2-only"
    assert send_message(pilot1_token, "pilot2", secret).status_code == 200
    r = requests.post(f"{API_URL}/export", headers=auth(pilot1_token))
    assert r.status_code == 200
    assert secret not in r.json()["exported_data"]


@pytest.mark.skipif(
    int(os.getenv("SESSION_TTL_SECONDS", "900")) > 5,
    reason="Set SESSION_TTL_SECONDS<=5 on the API to exercise token expiry quickly",
)
def test_token_expires():
    """Validity period: a session token is rejected once its TTL elapses."""
    ttl = int(os.getenv("SESSION_TTL_SECONDS", "900"))
    token = login("pilot1")
    assert requests.post(f"{API_URL}/export", headers=auth(token)).status_code == 200
    time.sleep(ttl + 1)
    r = requests.post(f"{API_URL}/export", headers=auth(token))
    assert r.status_code == 401
