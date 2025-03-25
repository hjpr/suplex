# Suplex

Building a syntactically similar REST API query builder to the Supabase Python library.



The Supabase library written in Python can be used within a Reflex website, but only as an admin. The way the standard Python operates is by instantiating a client and using that client to make queries.

```python
from supabase import Client, create_client

supabase = create_client(API_URL, API_KEY)
```

The user can then use that client to make queries.

```python
response = supabase.table("foo").insert({"bar": "baz"}).execute()
```



## The issue...

The Supabase client will require either the service role to act as an admin bearer token, or an access_token retrieved from logging in a user with the auth module.

```python
supabase.auth.sign_in_with_email()
```

This will store the access token which will restrict the logged in user based on the Row-Level Security Policies.

This also means that every user (and every State) will need it's own version of that instantiated class. When attempting to create that supabase class within a State module so that it can be used, you will throw this error.

```
TypeError: can't pickle _thread.RLock objects
```



## Enter handbuilt queries.

Since we can't instantiate multiple classes of the supabase client, it would mean that all users would share one instance of said class. Not so great for authentication and user management.

I've simply wrapped all REST queries using httpx, so that when instantiating the Suplex class, it can be serialized correctly and all users can have their own instance thus allowing a clean store of auth data and user data using basically the same syntax as the official Python library so that it can be used for reference (save for a few little params here and there).



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


