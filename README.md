

```markdown
# Using Suplex and Suplex.auth with Supabase

`Suplex` provides a Pythonic interface to interact with your Supabase database's REST API, inspired by the official Supabase Python library but tailored for use, potentially within frameworks like Reflex. It simplifies performing CRUD (Create, Read, Update, Delete) operations and handling user authentication.

This guide will walk you through setting up `Suplex`, authenticating users using `Suplex.auth`, and performing common database operations.

## Prerequisites

Before you start, you need a Supabase project. You'll need the following details from your project settings:

1.  **API URL**: Found in *Project Settings* > *API* > *Project URL*.
2.  **API Key (anon key)**: Found in *Project Settings* > *API* > *Project API Keys* (use the `anon` public key for client-side operations).
3.  **JWT Secret**: Found in *Project Settings* > *API* > *JWT Settings* > *JWT Secret*. This is crucial for the `Auth` class to verify tokens locally if needed (though direct decoding isn't the primary use case shown in the provided `auth.py`'s `get_session` which relies on a secret, you still need it for the `Auth` class setup).
4.  **Service Role Key (Optional)**: Found in *Project Settings* > *API* > *Project API Keys* (use the `service_role` key *only* for backend operations where you need to bypass Row Level Security (RLS) policies). **Never expose this key in frontend code.**

## Setup and Instantiation

First, ensure you have the `auth.py` and `suplex.py` files in your project directory. You can then import and instantiate the `Suplex` class:

```python
# main_app.py (or wherever you initialize your client)
import os
from suplex import Suplex

# Load credentials securely (e.g., from environment variables)
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET")
# Only load SERVICE_ROLE if needed for admin/backend tasks
SUPABASE_SERVICE_ROLE = os.environ.get("SUPABASE_SERVICE_ROLE")

if not all([SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_JWT_SECRET]):
    raise ValueError("Missing Supabase credentials in environment variables")

# Instantiate for standard user operations (respects RLS)
supabase = Suplex(
    api_url=SUPABASE_URL,
    api_key=SUPABASE_ANON_KEY,
    jwt_secret=SUPABASE_JWT_SECRET,
)

# Instantiate for admin operations (bypasses RLS - use with caution)
# supabase_admin = Suplex(
#     api_url=SUPABASE_URL,
#     api_key=SUPABASE_ANON_KEY, # Still needed
#     jwt_secret=SUPABASE_JWT_SECRET, # Still needed
#     service_role=SUPABASE_SERVICE_ROLE # Provides admin privileges
# )
```

**Key Points:**

* The `Suplex` instance holds your connection details and the `Auth` instance under `supabase.auth`.
* If you provide `service_role`, requests made *before* a user logs in will use this key, bypassing RLS.
* Once a user logs in via `supabase.auth`, subsequent requests will automatically use the user's `access_token`, enforcing RLS policies, even if `service_role` was provided during instantiation.

## Authentication (`supabase.auth`)

The `supabase.auth` object handles all user authentication tasks.

### Signing Up a New User

```python
try:
    # Sign up with email and password
    supabase.auth.sign_up(
        email="test@example.com",
        password="your-secure-password"
    )
    print("Sign up successful! Check your email for verification.")

    # Sign up with phone and password (if enabled in Supabase)
    # supabase.auth.sign_up(
    #     phone="+1234567890",
    #     password="your-secure-password"
    # )
    # print("Sign up successful! Check your phone for verification.")

except Exception as e:
    print(f"Sign up failed: {e}")
```

### Signing In a User (Password)

This method logs the user in and stores the `access_token` and `refresh_token` as `rx.Cookie` objects within the `supabase.auth` instance. These cookies will be managed by the Reflex state or browser.

```python
try:
    user_session = supabase.auth.sign_in_with_password(
        email="test@example.com",
        password="your-secure-password"
    )
    print("Sign in successful!")
    # user_session contains user info, access_token, refresh_token etc.
    # print(user_session)
    # Tokens are now stored in supabase.auth.access_token (as rx.Cookie)
    # and supabase.auth.refresh_token (as rx.Cookie)

except Exception as e:
    print(f"Sign in failed: {e}")
```

### Signing In with OAuth (e.g., Google, GitHub)

OAuth requires redirecting the user to the provider's login page.

```python
import reflex as rx # Assuming usage within a Reflex app

try:
    # Get the OAuth provider's authorization URL
    auth_url = supabase.auth.sign_in_with_oauth(
        provider="google",
        options={
            "redirect_to": "http://localhost:3000/callback" # Your app's callback URL
        }
    )
    if auth_url:
        # In a Reflex event handler, redirect the user
        return rx.redirect(auth_url)

except Exception as e:
    print(f"OAuth initiation failed: {e}")
```

**Note:** After the user authenticates with the provider, they are redirected back to your `redirect_to` URL. Supabase appends `#access_token=...&refresh_token=...` etc., to this URL fragment. Your frontend application needs to handle this callback, parse the tokens from the URL fragment, and potentially store them (though `Suplex`/`Auth` seems designed to handle this via cookies after a password login, the OAuth flow might require manual token setting or rely on Supabase's client-side library if used alongside).

### Getting User Information

```python
try:
    # Ensure user is logged in first (e.g., after sign_in_with_password)
    if supabase.auth.access_token: # Check if token exists
        user_info = supabase.auth.get_user()
        if user_info:
            print(f"Current User ID: {user_info.get('id')}")
            print(f"Current User Email: {user_info.get('email')}")
        else:
            print("Could not retrieve user info (maybe token expired or invalid?).")
    else:
        print("User is not logged in.")
except Exception as e:
    print(f"Failed to get user: {e}")
```

### Getting Session Information (from JWT)

This decodes the *currently stored* JWT access token. Useful for checking expiration or roles stored within the token itself. Requires the `jwt_secret` provided during instantiation.

```python
try:
    if supabase.auth.access_token:
        session_info = supabase.auth.get_session()
        print("Decoded JWT Session Info:")
        # print(session_info)
        # Example: Check expiration
        # import time
        # expires_at = session_info.get('exp', 0)
        # if time.time() < expires_at:
        #     print("Token is valid.")
        # else:
        #     print("Token has expired.")
    else:
        print("No access token available to get session.")
except Exception as e:
    print(f"Failed to decode session token: {e}") # Might be due to bad secret or invalid token
```

### Updating User Data

```python
try:
    if supabase.auth.access_token:
        updated_user = supabase.auth.update_user(
            user_metadata={"preferred_theme": "dark"}
        )
        print("User metadata updated successfully.")
        # print(updated_user)
    else:
        print("User must be logged in to update details.")
except Exception as e:
    print(f"Failed to update user: {e}")
```

### Logging Out

This invalidates the refresh token on the server and clears local tokens.

```python
try:
    if supabase.auth.access_token:
        supabase.auth.logout()
        print("User logged out successfully.")
        # supabase.auth.access_token and supabase.auth.refresh_token are now cleared
    else:
        print("User is not logged in.")
except Exception as e:
    print(f"Logout failed: {e}")
```

## Database Operations

`Suplex` uses a chained-method (builder) pattern to construct database queries. You always end the chain with `.execute()` (synchronous) or `.async_execute()` (asynchronous).

### Selecting Data

```python
try:
    # Select specific columns from the 'profiles' table
    response = supabase.table("profiles").select("id, username, website").execute()
    profiles = response.json()
    print("Fetched Profiles:")
    # print(profiles) # Output: [{'id': ..., 'username': ..., 'website': ...}, ...]

    # Select all columns
    response = supabase.table("countries").select("*").execute()
    countries = response.json()
    print("Fetched Countries:")
    # print(countries)

except Exception as e:
    print(f"Data selection failed: {e}")
```

### Inserting Data

```python
try:
    # Insert a single row
    response = supabase.table("countries").insert({
        "name": "Japan",
        "iso2": "JP"
    }).execute()
    new_country = response.json()
    print("Inserted Country:")
    # print(new_country) # Output: [{'id': ..., 'name': 'Japan', 'iso2': 'JP', ...}]

    # Insert multiple rows
    response = supabase.table("countries").insert([
        {"name": "France", "iso2": "FR"},
        {"name": "Germany", "iso2": "DE"}
    ]).execute()
    new_countries = response.json()
    print("Inserted Countries:")
    # print(new_countries)

except Exception as e:
    print(f"Data insertion failed: {e}")
```

### Updating Data

**Important:** Always use filters (`.eq()`, `.in_()`, etc.) when updating to avoid modifying unintended rows.

```python
try:
    # Update the website for a specific user
    response = supabase.table("profiles").update({
        "website": "https://new-website.example.com"
    }).eq("username", "testuser").execute() # Filter by username
    updated_profile = response.json()
    print("Updated Profile:")
    # print(updated_profile) # Output: [{'id': ..., 'username': 'testuser', 'website': '...', ...}]

except Exception as e:
    print(f"Data update failed: {e}")
```

### Upserting Data

Upsert inserts a row if it doesn't exist (based on primary key) or updates it if it does.

```python
try:
    # Upsert profile data (assuming 'id' is the primary key)
    response = supabase.table("profiles").upsert({
        "id": "some-user-uuid", # Must include primary key
        "username": "new_or_updated_user",
        "status": "ACTIVE"
    }).execute()
    upserted_profile = response.json()
    print("Upserted Profile:")
    # print(upserted_profile)

except Exception as e:
    print(f"Data upsert failed: {e}")
```

### Deleting Data

**Important:** Always use filters (`.eq()`, `.in_()`, etc.) when deleting to avoid removing unintended rows. Deleting without filters will attempt to delete **all** rows in the table (if RLS allows).

```python
try:
    # Delete a specific country by its iso2 code
    response = supabase.table("countries").delete().eq("iso2", "JP").execute()
    # response.json() is typically empty for delete, check status code
    if response.status_code == 204: # No Content on successful delete
         print("Successfully deleted country JP.")
    else:
         print(f"Delete might have failed: Status {response.status_code}, Response: {response.text}")


    # Example of deleting multiple rows (use with extreme caution)
    # response = supabase.table("logs").delete().lt("created_at", "2023-01-01").execute()
    # print(f"Deleted old logs. Status: {response.status_code}")

except Exception as e:
    print(f"Data deletion failed: {e}")
```

## Filtering Data

Filters are chained *before* the action method (`select`, `update`, `delete`).

```python
try:
    # Find profiles where username is exactly 'admin'
    response = supabase.table("profiles").select("*").eq("username", "admin").execute()
    admin_profiles = response.json()
    # print(admin_profiles)

    # Find countries whose name starts with 'United' (case-insensitive)
    response = supabase.table("countries").select("name").ilike("name", "United%").execute()
    united_countries = response.json()
    # print(united_countries)

    # Find posts created after a certain date
    response = supabase.table("posts").select("title").gt("created_at", "2024-01-01T00:00:00Z").execute()
    recent_posts = response.json()
    # print(recent_posts)

    # Find users whose IDs are in a list
    user_ids = ["uuid-1", "uuid-2"]
    response = supabase.table("profiles").select("username").in_("id", user_ids).execute()
    selected_users = response.json()
    # print(selected_users)

except Exception as e:
    print(f"Filtering failed: {e}")
```

## Using Modifiers

Modifiers like `order` and `limit` refine your query results. They are typically chained after filters but before `execute()`.

```python
try:
    # Get the 5 newest profiles, ordered by creation date descending
    response = supabase.table("profiles") \
        .select("username, created_at") \
        .order("created_at", ascending=False) \
        .limit(5) \
        .execute() # Note: .limit() is shown here conceptually based on docs, but is 'pass' in the provided code.
                   # Only .order() is implemented. Adjust chain if using actual code.

    # For the provided code, only .order() is implemented:
    response = supabase.table("profiles") \
        .select("username, created_at") \
        .order("created_at", ascending=False) \
        .execute()
    newest_profiles = response.json()
    print("Newest profiles (ordered):")
    # print(newest_profiles)

except Exception as e:
    print(f"Query with modifiers failed: {e}")
```

Other modifiers mentioned in the docstrings (`limit`, `range`, `single`, `maybe_single`, `csv`, `explain`) have `pass` statements in the provided `suplex.py` code and are not functional as implemented there.

## Admin vs. User Mode & RLS

* If you initialize `Suplex` **without** `service_role`, all requests respect Supabase Row Level Security (RLS) policies. An anonymous user (before login) can only access data allowed by RLS rules for the `anon` role. A logged-in user can only access data allowed by RLS rules for the `authenticated` role (or custom roles defined in your policies).
* If you initialize `Suplex` **with** `service_role`, requests made *before* a user logs in (i.e., when `supabase.auth.access_token` is not set) will use the service role key, bypassing all RLS policies. This is useful for admin tasks.
* **Crucially**, once a user logs in using `supabase.auth.sign_in_...`, `Suplex` automatically switches to using the user's `access_token` for subsequent requests. RLS policies **will** be enforced for that user, even if `service_role` was initially provided.

## Error Handling

`Suplex` methods will raise exceptions on failure:

* `httpx.HTTPStatusError`: For API errors (e.g., 4xx client errors like Not Found or Unauthorized, 5xx server errors). Check `error.response.status_code` and `error.response.text`.
* `ValueError`: For configuration issues (e.g., missing table name, missing data for insert/update, missing token when required).
* Other exceptions from `httpx` or `jwt` might occur.

Wrap your `Suplex` calls in `try...except` blocks to handle potential issues gracefully.

## Troubleshooting Tips (from Docstring)

* If no rows are returned in user mode (after login) and your query seems correct, double-check the **Row Level Security (RLS)** policies on the Supabase table. The logged-in user might not have permission.
* When using reserved PostgreSQL keywords (like `order`, `user`, `select`) as column names, you **must** enclose them in double quotes within the filter or select string: `supabase.table("...").select('"order", name').eq('"user"', user_id).execute()`
  * Reserved words list: <https://www.postgresql.org/docs/current/sql-keywords-appendix.html>

This guide covers the primary functionalities of the provided `Suplex` and `Auth` classes. Refer to the inline docstrings for details on specific method parameters and options. Remember to handle credentials securely and be mindful of RLS policies.
```
