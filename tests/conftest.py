"""
Shared fixtures for Suplex integration tests.

Requirements:
  - A .env file at the repo root with api_url, api_key, and service_role set.
  - The Supabase project must have email confirmation DISABLED so that sign-up
    immediately returns a valid session (Auth > Settings > Email Confirmations).
  - service_role is required for admin operations (delete user, etc.).
"""

import os
import time
import uuid
import httpx
import pytest
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

# ---------------------------------------------------------------------------
# Request timing
# ---------------------------------------------------------------------------

_request_log: list[tuple[str, float]] = []


def _make_timing_client() -> httpx.Client:
    """Return an httpx.Client that records (label, elapsed_ms) for every request."""
    _start: dict[int, float] = {}

    def on_request(request: httpx.Request) -> None:
        _start[id(request)] = time.monotonic()

    def on_response(response: httpx.Response) -> None:
        elapsed = (time.monotonic() - _start.pop(id(response.request), time.monotonic())) * 1000
        label = f"{response.request.method} {response.request.url.path}"
        _request_log.append((label, elapsed))
        print(f"\n  [{elapsed:7.1f} ms] {label}")

    return httpx.Client(event_hooks={"request": [on_request], "response": [on_response]})


@pytest.fixture(scope="session")
def client() -> httpx.Client:
    with _make_timing_client() as c:
        yield c


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if not _request_log:
        return
    terminalreporter.write_sep("=", "request timing summary")
    for label, ms in _request_log:
        terminalreporter.write_line(f"  {ms:7.1f} ms  {label}")
    total = sum(ms for _, ms in _request_log)
    terminalreporter.write_line(f"  {'─' * 40}")
    terminalreporter.write_line(f"  {total:7.1f} ms  total ({len(_request_log)} requests)")


# ---------------------------------------------------------------------------
# Basic config fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def api_url() -> str:
    val = os.environ.get("api_url")
    if not val:
        pytest.skip("api_url not set in .env")
    return val


@pytest.fixture(scope="session")
def api_key() -> str:
    val = os.environ.get("api_key")
    if not val:
        pytest.skip("api_key not set in .env")
    return val


@pytest.fixture(scope="session")
def service_role() -> str:
    val = os.environ.get("service_role")
    if not val:
        pytest.skip("service_role not set in .env — skipping admin tests")
    return val


# ---------------------------------------------------------------------------
# Per-session test user state
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_credentials():
    """Unique email/password for this test run so reruns don't collide."""
    return {
        "email": f"suplex_test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "SupleXTest123!",
    }


@pytest.fixture(scope="session")
def session_state(api_url, api_key, test_credentials):
    """
    Mutable dict that carries live auth state (tokens, user_id) across the
    ordered tests in test_auth.py.  Tests populate it as they run.
    """
    return {
        "api_url": api_url,
        "api_key": api_key,
        "email": test_credentials["email"],
        "password": test_credentials["password"],
        "access_token": None,
        "refresh_token": None,
        "user_id": None,
    }


# ---------------------------------------------------------------------------
# Admin helper
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def admin_headers(api_url, api_key, service_role):
    return {
        "apikey": api_key,
        "Authorization": f"Bearer {service_role}",
        "Content-Type": "application/json",
    }
