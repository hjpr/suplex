# Suplex

Supabase built in Reflex!

The official Supabase library written in Python can't be used within rx.State. Outside of Reflex you can use it like this...

```python
from supabase import Client, create_client

supabase = create_client(API_URL, API_KEY)
```

The user can then use that client to make queries.

```python
response = supabase.table("foo").insert({"bar": "baz"}).execute()
```

## The issue...

The Supabase client normally can either act as admin using a service role, or a user utilizing the auth module.

```python
supabase.auth.sign_in_with_email()
```

This will store the access token which will restrict the logged in user based on the Row-Level Security Policies. User data is stored within the supabase client object.

When attempting to create that supabase class within a State module so that it can be used, you will throw this error.

```
TypeError: can't pickle _thread.RLock objects
```

## Enter handbuilt queries.

Since we can't instantiate multiple classes of the supabase client, it would mean that all users would share one instance of said class. Not so great for authentication and user management.

I've built most of the supabase requests possible in the official Python library in a way that jives with Reflex's frontend to backend communication.
When the initial state is created, by instantiating a Suplex class within your rx.State, each user gets their own copy of the class when they visit the site. By calling the auth class within each Suplex class, a user can login and have their data stored within the Suplex class in one simple line of code.

Basic examples...

```python
# Instantiate a client
# Can pass service role to utilize this class as admin.
suplex = Suplex(API_URL, API_KEY, JWT_KEY)
```

```python
# Sign a user in and retrieve user data.
suplex.auth.sign_in_with_password(email, password)
suplex.auth.get_user()

# Sign in with oauth.
suplex.auth.sign_in_with_oauth(provider)

# Logout
suplex.auth.logout()
```

```python
# Once user is signed in, queries respect RLS policies.
response = suplex.table("foo").eq("id", 1).select("*").execute()

# Table methods too!
response = suplex.table("bar").upsert({"id": "1", "spam": "ham"}).execute()
```

## To start.

1. Clone the repository.

```bash
git clone https://github.com/hjpr/suplex.git
```

2. [Install UV](https://docs.astral.sh/uv/#installation)

3. Create and activate venv.

```bash
cd /suplex
uv venv
source .venv/bin/activate
```

4. Sync dependencies

```
uv sync
```

5. Supabase Account >>> Create New Project

6. Project >>> Project Settings >>> Data API

7. Create a .env file in suplex folder containing these keys found in Data API.

```md
api_url = "your-api-url"
api_key = "your-api-key"
jwt_secret = "your-jwt-secret"
service_role = "your-service-role"
```

8. Under Table Editor, create a new table called "test" with columns "id":int8, "created_at":timestamptz, "text":text, "json":jsonb, "bool":bool, and "null":text

9. Run test.py -d (Working on auth tests now.)

```python
cd folder/to/suplex
python test.py -d
```

You should see a full table of garbage!

I'm actively working on building and verifying this package as I'm using it in my own production. Check back later for the mostly full implementation!
