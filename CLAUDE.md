# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Suplex is a Python library providing state management for user authentication and database queries in [Reflex](https://reflex.dev/) web applications backed by Supabase.

## Commands

```bash
# Set up environment
uv venv && source .venv/bin/activate
uv sync

# Build the package
uv build

# Run a specific file
uv run python src/suplex/suplex.py

# Publish to PyPI
uv publish
```

There is no test suite currently. Linting is not configured.

## Architecture

The entire library lives in a single file: `src/suplex/suplex.py`. The `__init__.py` just re-exports `Suplex`.

### `Query` class

Builds and executes Supabase REST API requests using method chaining. Supports:
- CRUD: `select`, `insert`, `upsert`, `update`, `delete`
- Filters: `eq`, `neq`, `gt`, `lt`, `gte`, `lte`, `like`, `ilike`, `is_`, `in_`, `contains`, etc.
- Modifiers: `order`, `limit`, `range`, `rpc`
- Both sync (`execute()`) and async (`async_execute()`) execution
- `.admin()` to use the service role key (bypasses Row-Level Security)

### `Suplex` class (extends `rx.State`)

Manages Supabase auth within a Reflex app. Stores `access_token` and `refresh_token` as cookies. Exposes decoded JWT claims as computed `@rx.var` properties (`user_id`, `user_email`, `user_is_authenticated`, `user_token_expired`, etc.).

Auth methods mirror Supabase's auth API: `sign_up`, `sign_in_with_password`, `sign_in_with_oauth`, `exchange_code_for_session`, `refresh_session`, `log_out`, `get_user`, `update_user`, `reset_password_email`.

### API key support

Two Supabase API key schemes are supported:
- **Legacy** (pre-Oct 2025): `jwt_secret` + `service_role` keys
- **New** (Oct 2025+): JWKS-based verification using `sb_publishable_*` and `sb_secret_*` keys

### Configuration

Suplex reads config from `rxconfig.py` at app startup via `rx.Config`:

```python
config = rx.Config(
    suplex={
        "api_url": "...",
        "api_key": "...",
        "jwt_secret": "...",       # Legacy only
        "service_role": "...",     # Legacy only
        "secret_api_key": "...",   # New API only
        "let_jwt_expire": False,   # Auto-refresh tokens on expiry
        "cookie_max_age": 3600,
        "debug": False,
    }
)
```

Environment variables are loaded from `.env` using `dotenv`. See `.env.example` for required keys.
