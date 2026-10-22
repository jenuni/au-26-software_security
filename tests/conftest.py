"""Pytest fixtures: wait for the stack, provide per-role session tokens."""
import time

import pytest
import requests

from helpers import API_URL, login


@pytest.fixture(scope="session", autouse=True)
def wait_for_services():
    """Block until the Application API is serving."""
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            if requests.get(f"{API_URL}/openapi.json", timeout=2).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    pytest.exit("Application API did not become ready", returncode=1)


@pytest.fixture
def pilot1_token():
    return login("pilot1")


@pytest.fixture
def pilot2_token():
    return login("pilot2")


@pytest.fixture
def admin_token():
    return login("admin")
