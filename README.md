# Suplex

Simple state module to manage user auth and create database queries with the Reflex web framework.

---

## Install

Add Suplex to your project.

```bash
# Install uv with curl
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install uv with wget
wget -qO- https://astral.sh/uv/install.sh | sh

# Activate your venv in your base folder
cd /path/to/project
uv venv # or uv venv my-project-venv
source .venv/bin/activate # or source /my-project-venv/bin/activate

# Add suplex as dependency
uv add suplex
```

---

## Configure

In your project top-level directory, where rxconfig.py is located create a .env file as follows...

```bash
api_url="your-api-url"
api_key="your-api-key"
jwt_secret="your-jwt-secret"
service_role="your-service-role"
```

These values can be retrieved from Supabase. Log In >> Choose Project >> Project Settings >> Data API

Then in rxconfig.py add...

```python
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("api_key")
api_url = os.getenv("api_url")
jwt_secret = os.getenv("jwt_secret")
# service_role = os.getenv("service_role") Only for admin use.

config = rx.Config(
    # You may have a few entries here...
    suplex={
        "api_url": api_url,
        "api_key": api_key,
        "jwt_secret": jwt_secret
        "let_jwt_expire": False # (Optional: Default is False) Specify if tokens auto refresh. Can set to True for tighter/manual control of token refresh
        "cookie_max_age": 3600 # (Optional: Default = None) Seconds until cookie expires, otherwise is a session cookie.
    } 
) 
```

---

## Build into existing State Class

Import Suplex, and subclass the module at the lowest layer. A BaseState class that is already built, or fresh will work. For a BaseState that is already built, make sure that you check the suplex functions and vars to ensure there aren't any collisions.

```python
from suplex import Suplex

class BaseState(Suplex):
    # Your class below...
```

---

## Other Subclassing

For any other classes within your Reflex project, subclass your BaseState to give them access to the auth information and query methods. There shouldn't be any classes in your state requiring auth that don't inherit from the BaseState.

```python
class OtherState(BaseState):
    # Your class below...
```

---

## Auth

Suplex comes with built-in vars and functions to manage users, user objects, JWT claims and more. Because front-end handling is different from project to project, you'll need to create functions for how you'd like to update your UI, redirect on success/failure, and handle exceptions.

### Auth Functions

- sign_up(email: str, phone: str, password: str, options: Dict[str, Any])
  
  - Sign a user up using email or phone, and password. May pass in options - email_redirect_to, data, captcha_token, and channel.

- sign_in_with_password(email: str, phone: str, password: str, options: Dict[str, Any])
  
  - Sign a user in with email or phone, and password. May pass in options - captcha_token.
  
  - Returns user object dict and other info.

- sign_in_with_oauth(provider: str, options: Dict[str, Any])
  
  - Returns a url to use with rx.redirect to send user to OAuth endpoint. May pass in options redirect_to, scopes, query_params, code_challenge, and code_challenge_method. Will need to manually parse the url that OAuth redirects to for storing the tokens. Use set_tokens() to set access_token and refresh_token.

- exchange_code_for_session(params: Dict[str, Any])
  
  - Provide params auth_code, code_verifier for an access_token and refresh_token when using PKCE flow. Sets tokens automatically. Returns the user object and other information.

- set_tokens(access_token: str, refresh_token: str)
  
  - Sets both tokens as well as setting the bearer token of the query object using the access_token. Use this if manually parsing a URL to set tokens.

- reset_password_email(email: str)
  
  - Send password reset email to specified email address.

- get_user()
  
  - Returns the user object of the current authenticated user from Supabase.

- update_user(email: str, phone: str, password: str, user_metadata: Dict[str, Any])
  
  - Updates the current users email, phone, password, or custom data stored in user_metadata.
  
  - Returns the updated user object.

- refresh_session()
  
  - Manually refreshes the authentication session using the stored refresh token.

- get_settings()
  
  - Returns the authentication settings for the Supabase project.

- log_out()
  
  - Clears local tokens and attempts to nullify the refresh_token to Supabase.

- session_manager(event: Callable, on_failure: List[Callable] | Callable | None)
  
  - Pass an event. If users token has expired, will attempt to refresh the token. If the token is unable to be refreshed, will trigger the on_failure event. Used typically to redirect to login page on failure.

Check docstrings for params, returns and exceptions.

```python
from suplex import Suplex


class BaseState(Suplex):
    # Login example.
    def log_in(self, email, password):
        try:
            self.sign_in_with_password(email, password)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
            yield rx.toast.error("Invalid email or password.")
        except Exception:
            yield rx.toast.error("Login failed.")

    # Update user example.
    def update_user_info(self, email, phone, password, user_metadata):
        try:
            self.update_user(email, phone, password, user_metadata)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
            # Refresh token here and try again.
        except Exception:
            yield rx.toast.error("Updating user info failed.")

    def log_out(self):
        try:
            self.logout()
        except httpx.HTTPStatusError:
            yield rx.toast.error("Unable to logout remotely, local session cleared.")
        except Exception:
            yield rx.toast.error("Something went wrong during logout.")
```

### Auth Vars

There is a full set of vars that pull values from the signed JWT that gets provided from Supabase in the form of an access_token. These vars pull those claims. If you don't want to use local information and instead only want to rely on a user object pulled directly from Supabase then you will want to use the get_user() function and parse the user object directly.

- user_id
  
  - str - user's id as uuid.

- user_email
  
  - str - user's email.

- user_phone
  
  - str = user's phone.

- user_audience
  
  - str - audience that user is a part of. Currently only supports audience "authenticated" as the JWT checks for this audience for validation.

- user_role
  
  - str - role assigned to user.

- claims_issuer
  
  - str - url that issued claim.

- claims_expire_at
  
  - int - unix timestamp for when token expires.

- claims_issued_at
  
  - int - unix timestamp for when token was issued.

- claims_session_id
  
  - str - unique session id from Supabase.

- user_metadata
  
  - Dict[str, Any] - custom data within user object.

- app_metadata
  
  - Dict[str, Any] - extra info stored by Supabase.

- user_aal
  
  - Literal["aal1" | "aal2"] - specifies 1 or 2 factor auth was used.

- user_is_authenticated
  
  - bool - if user audience is "authenticated" will be True.

- user_is_anonymous
  
  - bool - if user is anonymous will be True.

- user_token_expired
  
  - bool - checks expiry for claims.

```python
# Frontend
def auth_component() -> rx.Component:
    # Show only if user is logged in.
    return rx.cond(
        BaseState.user_is_authenticated,
        shown_if_authenticated(),
        shown_if_not_authenticated()
)

def user_info_panel() -> rx.Component:
    # Show currently logged in user info.
    return rx.flex(
        rx.text(BaseState.user_id),
        rx.text(BaseState.user_email),
        rx.text(BaseState.user_phone),
        class_name="flex-col items-center w-full"
)

# Setup a page to use auth_flow. Redirects user who isn't logged in.
@rx.page("/recipes", on_load=BaseState.auth_flow)
def recipes() -> rx.Component:
    return rx.flex(
        rx.button("Get Recipes")
        on_click=BaseState.get_recipes()
)

class BaseState(Suplex):

    def auth_flow(self) -> Callable:
        if not self.user_is_authenticated:
            return rx.redirect("/login")
```

### Session Manager

For making database queries where a user's inactivity might cause a token to go stale and raise a 401 status when user clicks a submit or other database action.

Pass the event to a session manager. This manager will attempt to refresh a stale session, and if that fails, you can specify an event to trigger like sending user to re-login.

If let_jwt_expire is passed as True, then the session manager will not refresh the session and will simply trigger the event on_failure if a token is expired.

```python
# Frontend
def database_component() -> rx.Component:
    return rx.button(
        on_click=BaseState.session_manager(
            BaseState.retrieve_database_info,
            on_failure=rx.redirect("/login")
        )
)
```

---

## Query

Once a user is signed in, building the query class inside of your BaseClass is how you build a query using the logged in user's credentials. The style of query is similar to the official Supabase python client located at - [Python API Reference | Supabase Docs](https://supabase.com/docs/reference/python/select).

By creating a new instance of the query for each request, this avoids concurrency issues with Reflex's asyncronous events system.

```python
from suplex import Suplex


class BaseState(Suplex):
    def get_all_ingredients(self) -> list:
        # Get all unique ingredients from a collection of recipes.
        try:
            ingredients = []
            query = self.query.table("recipes").select("ingredients")
            results = query.execute()
            for result in results:
                ingredients.extend(result["ingredients"])
            return list(set(ingredients))
        except Exception:
            rx.toast.error("Unable to retrieve ingredients.")


    def get_recipes_with_parmesan_cheese(self) -> list:
        # Get recipes with parmesan cheese as an ingredient.
        try:
            query = self.query.table("recipes").select("*").in_("ingredients", ["parmesan"])
            results = query.execute()
            return results
        except Exception:
            rx.toast.error("Unable to retrieve recipes.")
```

### Query Methods

[Python API Reference | Supabase Docs](https://supabase.com/docs/reference/python/select)

- select(column: str)
  
  - Specify column(s) to return or '*' to return all.

- insert(data: dict[str, Any] | list, return_: Literal["representation", "minimal"])
  
  - Add new data to specified .table(). Can specify if the inserted row is returned by setting return_ to "representation".

- upsert(data: dict, return_: Literal["representation","minimal"])
  
  - Add item to specified .table() if it doesn't exist, otherwise update item. One column must be primary key.

- update(data: Dict[str, Any], return_: Literal["representation","minimal"])
  
  - Update rows with specified data - will match all rows by default. Use filters to update specific rows like eq(), lt(), or is().

- delete()
  
  - Deletes rows - will match all rows by default. Use filters to specify how to select the rows to delete.

### Query Filters (Incomplete)

[Python API Reference | Supabase Docs](https://supabase.com/docs/reference/python/using-filters)

- eq(column: str, value: Any)
  
  - Match only rows where column is equal to value.

- neq(column: str, value: Any)
  
  - Match only rows where column is not equal to value.

- gt(column: str, value: Any)
  
  - Match only rows where column is greater than value.

- lt(column: str, value: Any)
  
  - Match only rows where column is less than value.

- gte(column: str, value: Any)
  
  - Match only rows where column is greater than or equal to value.

- lte(column: str, value: Any)
  
  - Match only rows where column is less than or equal to value.

- like(column: str, pattern: str)
  
  - Match only rows where column matches pattern case-sensitively.

- ilike(column: str, pattern: str)
  
  - Match only rows where column matches pattern case-insensitively.

- is_(column: str, value: Literal["null"] | bool | None)
  
  - Match only rows where column is null or bool. Use instead of eq() for null values.

- is_not(column: str, value: Literal["null"] | bool | None)
  
  - Match only rows where column is NOT null/bool. Use instead of neq() for null values.

- in_(column: str, values: List[Any])
  
  - Match only rows where columsn is in the list of values.

- contains(array_column, value: List[Any] | Dict[str, Any] | str)
  
  - Only relevant for jsonb, array, and range columns. Match only rows where column contains every element appearing in values.

- contained_by(array_column: str, value: List[Any] | Dict[str, Any] | str)
  
  - Only relevant for jsonb, array, and range columns. Match only rows where every element appearing in column is contained by value.

### Query Modifiers (Incomplete)

[Python API Reference | Supabase Docs](https://supabase.com/docs/reference/python/using-modifiers)

- order(column: str, ascending: bool = True, nulls_first: Optional[bool] = None)
  - Order the query result by column. Defaults to ascending (lowest -> highest). Use nulls_first to place nulls at top or bottom of order.
- limit(count: int)
  - Limit the number of rows returned by count.
- range(start: int, end: int)
  - Limit the result starting at start offset and ending at end offset.
- csv()
  - Return data as a string in CSV format.
- single()
  - Not implemented yet.
- maybe_single()
  - Not implemented yet.

## Other Functions

- rpc(function: str, params: Dict[Any, Any])
  
  - Calls a postgres function deployed in Supabase.

---

## Notes

Generally this module is attempting to do the dirty work of setting up a request and turning the response into a python object. I'm leaving error handling, logging, and flows up to the devs so that you can more easily integrate this into your own flows.

If there is a feature you'd like added that keeps the spirit of flexibility but adds functionality then please let me know and I'll be happy to extend this module.

Documentation and structure of this project is **very early** so expect changes as I integrate this project and test all the features thoroughly.
