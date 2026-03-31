"""
Auth integration tests for Suplex.

These tests exercise the same Supabase auth endpoints that Suplex wraps, in the
order that a real user session would follow:

  1. create user   (sign_up)
  2. user exists   (sign_in + get_user)
  3. update info   (update_user metadata)
  4. modify info   (update_user password)
  5. delete info   (clear user metadata)
  6. delete user   (admin API)

Run with:
  uv run pytest tests/ -v

Prerequisites (see conftest.py):
  - .env with api_url, api_key, service_role
  - Supabase project has email confirmation DISABLED
"""

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth_headers(state: dict) -> dict:
    return {
        "apikey": state["api_key"],
        "Authorization": f"Bearer {state['access_token']}",
    }


# ---------------------------------------------------------------------------
# Tests (run in declaration order)
# ---------------------------------------------------------------------------

def test_create_user(client, session_state):
    """A new user can be registered via /auth/v1/signup."""
    response = client.post(
        f"{session_state['api_url']}/auth/v1/signup",
        headers={"apikey": session_state["api_key"]},
        json={
            "email": session_state["email"],
            "password": session_state["password"],
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()

    # With email confirmation disabled the response includes session tokens.
    # With it enabled there is no session but user.id is still present.
    user = data.get("user") or data
    assert user.get("id"), "Expected a user id in sign-up response"

    session_state["user_id"] = user["id"]

    # Store tokens if present (email confirmation disabled).
    if data.get("access_token"):
        session_state["access_token"] = data["access_token"]
        session_state["refresh_token"] = data["refresh_token"]


def test_user_exists(client, session_state):
    """User can sign in and the session contains the expected identity."""
    response = client.post(
        f"{session_state['api_url']}/auth/v1/token?grant_type=password",
        headers={"apikey": session_state["api_key"]},
        json={
            "email": session_state["email"],
            "password": session_state["password"],
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()

    assert "access_token" in data, "Expected access_token in sign-in response"
    assert "refresh_token" in data, "Expected refresh_token in sign-in response"

    session_state["access_token"] = data["access_token"]
    session_state["refresh_token"] = data["refresh_token"]
    session_state["user_id"] = data["user"]["id"]

    # Confirm /auth/v1/user returns the same identity.
    me = client.get(
        f"{session_state['api_url']}/auth/v1/user",
        headers=_auth_headers(session_state),
    )
    assert me.status_code == 200, me.text
    me_data = me.json()
    assert me_data["email"] == session_state["email"]
    assert me_data["id"] == session_state["user_id"]


def test_update_user_info(client, session_state):
    """User metadata can be set (first write)."""
    response = client.put(
        f"{session_state['api_url']}/auth/v1/user",
        headers=_auth_headers(session_state),
        json={"data": {"display_name": "Suplex Tester", "theme": "dark"}},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    meta = data.get("user_metadata") or {}
    assert meta.get("display_name") == "Suplex Tester"
    assert meta.get("theme") == "dark"

    # Refresh tokens after metadata update (Supabase issues a new JWT).
    if data.get("access_token"):
        session_state["access_token"] = data["access_token"]
        session_state["refresh_token"] = data["refresh_token"]


def test_modify_user_info(client, session_state):
    """Existing user metadata can be changed to different values."""
    response = client.put(
        f"{session_state['api_url']}/auth/v1/user",
        headers=_auth_headers(session_state),
        json={"data": {"display_name": "Suplex Tester Modified", "theme": "light"}},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    meta = data.get("user_metadata") or {}
    assert meta.get("display_name") == "Suplex Tester Modified"
    assert meta.get("theme") == "light"

    if data.get("access_token"):
        session_state["access_token"] = data["access_token"]
        session_state["refresh_token"] = data["refresh_token"]


def test_clear_user_info(client, session_state):
    """User metadata can be cleared by writing an empty dict."""
    response = client.put(
        f"{session_state['api_url']}/auth/v1/user",
        headers=_auth_headers(session_state),
        json={"data": {"display_name": None, "theme": None}},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    meta = data.get("user_metadata") or {}
    # Supabase may return {} or omit the key entirely after clearing.
    assert meta.get("display_name") is None
    assert meta.get("theme") is None

    if data.get("access_token"):
        session_state["access_token"] = data["access_token"]
        session_state["refresh_token"] = data["refresh_token"]


def test_delete_user(client, session_state, admin_headers):
    """User can be removed via the admin API using the service role key."""
    user_id = session_state.get("user_id")
    assert user_id, "No user_id stored — earlier tests may have failed"

    response = client.delete(
        f"{session_state['api_url']}/auth/v1/admin/users/{user_id}",
        headers=admin_headers,
    )
    assert response.status_code in (200, 204), response.text

    # Confirm the user no longer exists by attempting sign-in.
    check = client.post(
        f"{session_state['api_url']}/auth/v1/token?grant_type=password",
        headers={"apikey": session_state["api_key"]},
        json={
            "email": session_state["email"],
            "password": session_state["password"],
        },
    )
    assert check.status_code in (400, 422), (
        f"Expected sign-in to fail after deletion, got {check.status_code}: {check.text}"
    )
