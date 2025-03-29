# Suplex

Suplex is a Python library that provides a clean interface for interacting with Supabase REST API in Reflex applications. It simplifies user authentication, session management, and database operations.

## Installation

```bash
pip install suplex
```

## Features

- User authentication (sign-in, sign-up, OAuth providers)
- Session management with JWT tokens
- Database operations (select, insert, update, delete)
- Query filters and modifiers
- Synchronous and asynchronous execution

## Quick Start

### Initialize Suplex

```python
from suplex import Suplex

# Initialize Suplex with your Supabase credentials
supabase = Suplex(
    api_url="your-supabase-url",
    api_key="your-api-key",
    jwt_secret="your-jwt-secret",
    service_role="your-service-role"  # Optional: only for admin operations
)
```

### User Authentication

#### Sign Up

```python
# Sign up a new user with email and password
supabase.auth.sign_up(
    email="user@example.com",
    password="secure-password"
)

# Sign up with additional metadata
supabase.auth.sign_up(
    email="user@example.com",
    password="secure-password",
    options={
        "data": {
            "first_name": "John",
            "last_name": "Doe"
        }
    }
)
```

#### Sign In with Password

```python
# Sign in with email and password
user = supabase.auth.sign_in_with_password(
    email="user@example.com",
    password="secure-password"
)
```

#### Sign In with OAuth

```python
import reflex as rx

class BaseState(rx.State):
    def login_with_google(self):
        redirect_url = supabase.auth.sign_in_with_oauth(
            provider="google",
            options={
                "redirect_to": "https://your-app.com/auth/callback"
            }
        )
        return rx.redirect(redirect_url)
```

#### Get Current User

```python
# Get the current authenticated user
user = supabase.auth.get_user()

# Get the current session info
session = supabase.auth.get_session()
```

#### Update User

```python
# Update user profile
updated_user = supabase.auth.update_user(
    email="new-email@example.com",
    user_metadata={
        "first_name": "Updated",
        "profile_picture": "https://example.com/picture.jpg"
    }
)
```

#### Logout

```python
# Logout the current user
supabase.auth.logout()
```

### Database Operations

#### Select Data

```python
# Select all columns from a table
response = supabase.table("users").select("*").execute()
users = response.json()

# Select specific columns
response = supabase.table("users").select("id, name, email").execute()
users = response.json()

# Select with filtering
response = supabase.table("users").select("*").eq("id", 123).execute()
user = response.json()
```

#### Insert Data

```python
# Insert a single row
response = supabase.table("users").insert({
    "name": "John Doe",
    "email": "john@example.com"
}).execute()

# Insert multiple rows
response = supabase.table("users").insert([
    {"name": "Jane Doe", "email": "jane@example.com"},
    {"name": "Bob Smith", "email": "bob@example.com"}
]).execute()
```

#### Update Data

```python
# Update data
response = supabase.table("users").update({
    "name": "Updated Name"
}).eq("id", 123).execute()
```

#### Upsert Data

```python
# Insert if not exists, update if exists
response = supabase.table("users").upsert({
    "id": 123,
    "name": "John Doe Updated",
    "email": "john@example.com"
}).execute()
```

#### Delete Data

```python
# Delete data (CAUTION: this will match all rows by default!)
response = supabase.table("users").delete().eq("id", 123).execute()
```

### Using Filters

```python
# Equal
response = supabase.table("users").select("*").eq("name", "John Doe").execute()

# Not equal
response = supabase.table("users").select("*").neq("status", "inactive").execute()

# Greater than
response = supabase.table("users").select("*").gt("age", 21).execute()

# Less than
response = supabase.table("users").select("*").lt("age", 65).execute()

# Like (case-sensitive pattern matching)
response = supabase.table("users").select("*").like("name", "%Doe%").execute()

# Case-insensitive pattern matching
response = supabase.table("users").select("*").ilike("name", "%doe%").execute()

# Check for null values
response = supabase.table("users").select("*").is_("deleted_at", "null").execute()

# Check for values in a list
response = supabase.table("users").select("*").in_("status", ["active", "pending"]).execute()
```

### Using Modifiers

```python
# Order results
response = supabase.table("users").select("*").order("created_at", ascending=False).execute()

# Limit results
response = supabase.table("users").select("*").limit(10).execute()
```

### Async Operations

```python
import asyncio

async def get_users():
    # Async execution
    response = await supabase.table("users").select("*").async_execute()
    return response.json()

# Run the async function
users = asyncio.run(get_users())
```

### Error Handling

Suplex methods will raise exceptions for most errors. Use try/except blocks for production code:

```python
try:
    response = supabase.table("users").select("*").execute()
    users = response.json()
except Exception as e:
    # Handle error appropriately
    print(f"Error fetching users: {e}")
```

### Row Level Security

When working with authenticated users, Supabase Row Level Security (RLS) policies will be applied. If you're not seeing data that should be available, check your RLS policies.

For admin operations that should bypass RLS, instantiate Suplex with the service_role parameter.

### JWT Token Management

Suplex automatically manages JWT tokens, including refreshing them when they're close to expiration. The tokens are stored as cookies.

## Advanced Usage

### Custom HTTP Parameters

You can pass additional parameters to the underlying httpx client:

```python
# Set a timeout for the request
response = supabase.table("users").select("*").execute(timeout=10.0)
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.