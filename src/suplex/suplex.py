import httpx
import json
import jwt
from jwt.jwks_client import PyJWKClient
import reflex as rx
import time

from rich.console import Console
from typing import Any, Dict, List, Literal, Optional, Self

console = Console()

class BearerTokenExpired(Exception):
    """
    Raised when bearer token has expired, and user is requesting an action that would cause the bearer token
    to return a 401 - Unauthorized if used.
    """

class Query(rx.Base):
    """
    Query class for building and executing queries against Supabase.
    This class provides methods for constructing SQL-like queries.
    To build a query, use self.query(self.access_token) from your State class.
    """

    _bearer_token: Optional[str]
    _api_url: Optional[str]
    _api_key: Optional[str]
    _service_role: Optional[str]
    _debug: Optional[str]
    _headers: Dict[str, str]
    _table: Optional[str]
    _params: Dict[str, Any]
    _method: Optional[str]
    _data: Optional[Dict[str, Any] | List]
    _accept_csv: bool

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set configs from rxconfig.py
        config = rx.config.get_config()
        required_keys = {"api_url", "api_key"}
        missing_keys = required_keys - config.suplex.keys() # type: ignore
        if missing_keys:
            raise ValueError(f"Missing required Suplex configuration keys: {', '.join(missing_keys)}")

        self._bearer_token = kwargs.get("bearer_token")
        self._api_url = config.suplex["api_url"] # type: ignore
        self._api_key = config.suplex["api_key"] # type: ignore
        self._service_role = config.suplex.get("service_role", None)
        self._debug = config.suplex.get("debug", False)
        self._headers = {}
        self._table = None
        self._params = {}
        self._method = "get"
        self._data = None
        self._accept_csv = False

    def _add_param(self, key: str, value: Any) -> None:
        self._params[key] = value

    def admin(self) -> Self:
        """
        Chain this function inline after .query() to bypass Postgres Row Level Security.
        """
        if not self._service_role:
            console.print(
                "Unable to perform service level query. A valid service role key needs to be added to config.",
                style="bold red"
            )
            raise Exception("Missing valid service role key.")
        else:
            self._bearer_token = self._service_role
            return self

    def table(self, table: str) -> Self:
        """Targeted table to read from."""
        self._table = f"{table}"
        return self

    def eq(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is equal to value.
        Use .is_ for null or bool.
        https://supabase.com/docs/reference/python/eq
        """
        self._add_param(column, f"eq.{value}")
        return self

    def neq(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is not equal to value.
        Use .is_not for null or bool.
        https://supabase.com/docs/reference/python/neq
        """
        self._add_param(column, f"neq.{value}")
        return self

    def gt(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is greater than value.
        https://supabase.com/docs/reference/python/gt
        """
        self._add_param(column, f"gt.{value}")
        return self

    def lt(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is less than value.
        https://supabase.com/docs/reference/python/lt
        """
        self._add_param(column, f"lt.{value}")
        return self

    def gte(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is greater than or equal to value.
        https://supabase.com/docs/reference/python/gte
        """
        self._add_param(column, f"gte.{value}")
        return self

    def lte(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is less than or equal to value.
        https://supabase.com/docs/reference/python/lte
        """
        self._add_param(column, f"lte.{value}")
        return self

    def like(self, column: str, pattern: str) -> Self:
        """
        Match only rows where column matches pattern case-sensitively.
        https://supabase.com/docs/reference/python/like
        """
        self._add_param(column, f"like.{pattern}")
        return self

    def ilike(self, column: str, pattern: str) -> Self:
        """
        Match only rows where column matches pattern case-insensitively.
        https://supabase.com/docs/reference/python/ilike
        """
        self._add_param(column, f"ilike.{pattern}")
        return self

    def is_(self, column: str, value: Literal["null"] | bool | None) -> Self:
        """
        Match only rows where column is null/bool. May use None, and True/False
        rather than the string value equivalents.
        Use this instead of eq() for null values.
        https://supabase.com/docs/reference/python/is
        """
        param = ""
        if value is None or value == "null":
            param = "null"
        elif isinstance(value, bool):
            param = str(value).lower()
        else:
            raise ValueError(f"Unsupported value {value} for 'is' filter. Use None, True, False, or 'null'.")
        self._add_param(column, f"is.{param}")
        return self

    def is_not(self, column: str, value: Literal["null"] | bool | None) -> Self:
        """
        Match only rows where column is NOT null/bool. May use None, and True/False
        rather than the string value equivalents.
        Use this instead of neq() for null values.
        https://supabase.com/docs/reference/python/is
        """
        param = ""
        if value is None or value == "null":
            param = "null"
        elif isinstance(value, bool):
            param = str(value).lower()
        else:
            raise ValueError(f"Unsupported value {value} for 'is_not' filter. Use None, True, False, or 'null'.")
        self._add_param(column, f"is.not.{param}")
        return self        

    def in_(self, column: str, values: List[Any]) -> Self:
        """
        Match only rows where column is in the list of values.
        https://supabase.com/docs/reference/python/in
        """
        formatted_values = []
        for v in values:
            if isinstance(v, str):
                escaped_v = v.replace('"', '""')
                formatted_values.append(f'"{escaped_v}"')
            elif isinstance(v, (int, float, bool)):
                if isinstance(v, bool):
                    formatted_values.append(str(v).lower())
                else:
                    formatted_values.append(str(v))
            elif v is None:
                formatted_values.append("NULL")
            else:
                raise ValueError(f"Unsupported value {values} for filter 'in'. Needs to be str, int, float, bool, or None")
        value_string = ",".join(formatted_values)
        param = f"in.({value_string})"
        self._add_param(column, param)
        return self

    def contains(self, array_column: str, value: List[Any] | Dict[str, Any] | str) -> Self:
        """
        Only relevant for jsonb, array, and range columns.
        Match only rows where column contains every element appearing in values.
        https://supabase.com/docs/reference/python/contains
        """
        param: str
        if isinstance(value, list):
            formatted_list = self._format_array_literal(value)
            param = f"cs.{formatted_list}"
        elif isinstance(value, dict):
            json_string = json.dumps(value)
            param = f"cs.{json_string}"
        elif isinstance(value, (str, int, float)):
            param = f"cs.{value}"
        else:
            raise TypeError(f"Unsupported type '{type(value)}' for 'contains' value. Expected list, dict, str, int, or float.")
        self._add_param(array_column, param)
        return self

    def contained_by(self, array_column: str, value: List[Any] | Dict[str, Any] | str) -> Self:
        """
        Only relevant for jsonb, array, and range columns.
        Match only rows where every element appearing in column is contained by value.
        https://supabase.com/docs/reference/python/containedby
        """
        param: str
        if isinstance(value, list):
            formatted_list = self._format_array_literal(value)
            param = f"cd.{formatted_list}"
        elif isinstance(value, dict):
            json_string = json.dumps(value)
            param = f"cd.{json_string}"
        elif isinstance(value, (str, int, float)):
            param = f"cd.{value}"
        else:
            raise TypeError(f"Unsupported type '{type(value)}' for 'contains' value. Expected list, dict, str, int, or float.")
        self._add_param(array_column, param)
        return self

    def select(self, column: str) -> Self:
        """
        Specify columns to return, or '*' to return all.
        https://supabase.com/docs/reference/python/select
        """
        self._add_param("select", column)
        return self

    def insert(self, data: dict[str, Any] | list, return_: Literal["representation", "minimal"] = "representation") -> Self:
        """
        Add new item to table as {'column': 'value', 'other_column': 'other_value'}
        or new items as [{'column': 'value'}, {'other_column': 'other_value'}]
        https://supabase.com/docs/reference/python/insert
        """
        self._data = data
        self._method = "post"
        self._headers["Prefer"] = f"return={return_}"
        return self

    def upsert(self, data: dict, return_: Literal["representation","minimal"]="representation") -> Self:
        """
        Add item to table as {'column': 'value', 'other_column': 'other_value'}
        if it doesn't exist, otherwise update item. One column must be a primary key.
        https://supabase.com/docs/reference/python/upsert
        """
        self._data = data
        self._method = "post"
        self._headers["Prefer"] = f"return={return_},resolution=merge-duplicates"
        return self

    def update(self, data: Dict[str, Any], return_: Literal["representation","minimal"]="representation") -> Self:
        """
        Update lets you update rows. update will match all rows by default.
        You can update specific rows using horizontal filters, e.g. eq, lt, and is.
        https://supabase.com/docs/reference/python/update
        """
        self._data = data
        self._method = "patch"
        self._headers["Prefer"] = f"return={return_}"
        return self

    def delete(self) -> Self:
        """
        Delete matching rows from the table. Matches all rows by default! Use filters to specify.
        https://supabase.com/docs/reference/python/delete
        """
        self._method = "delete"
        return self

    def order(self, column: str, ascending: bool = True, nulls_first: Optional[bool] = None) -> Self:
        """
        Order the query result by column. Defaults to ascending order (lowest to highest).
        Use nulls_first to place nulls at top or bottom of order.
        https://supabase.com/docs/reference/python/order
        """
        direction = 'asc' if ascending else 'desc'
        criterion = f"{column}.{direction}"

        # Don't append if nulls_first is None
        if nulls_first is True:
            criterion += ".nullsfirst"
        elif nulls_first is False:
            criterion += ".nullslast"

        current_order_value = self._params.get("order", "")
        if current_order_value:
            updated_order_value = f"{current_order_value},{criterion}"
        else:
            updated_order_value = criterion

        self._add_param("order", updated_order_value)
        return self
    
    def rpc(self, function: str, params: Optional[Dict[Any, Any]] = None) -> Self:
        """
        Call a remote procedure (Postgres function) deployed in Supabase.
        https://supabase.com/docs/reference/python/rpc
        """
        self._table = f"rpc/{function}"
        self._data = params or {}
        self._method = "post"
        return self

    def limit(self, count: int) -> Self:
        """
        Limit the number of rows returned.
        https://supabase.com/docs/reference/python/limit
        """
        if count <= 0:
            raise ValueError("Limit must be a positive integer.")
        self._headers["Range"] = f"0-{count - 1}" # Range header is inclusive.
        return self

    def range(self, start: int, end: int) -> Self:
        """
        Limit the query result by starting at an offset (start) and ending at the offset (end). 
        https://supabase.com/docs/reference/python/range
        """
        if start < 0 or end < 0:
            raise ValueError("Range start and end must be non-negative.")
        if start > end:
            raise ValueError("Range start cannot be greater than end.")
        self._headers["Range"] = f"{start}-{end}"
        return self

    def single(self) -> Self:
        """
        Return data as a single object instead of an array of objects.
        Expects a single row to be returned. If exactly one row is not returned, an error is raised.
        https://supabase.com/docs/reference/python/single
        """
        pass
        return self

    def maybe_single(self) -> Self:
        """
        Return data as a single object instead of an array of objects.
        Expects a single row to be returned. If no rows are returned, no error is raised.
        https://supabase.com/docs/reference/python/maybesingle
        """
        pass
        return self

    def csv(self) -> Self:
        """
        Return data as a string in CSV format.
        https://supabase.com/docs/reference/python/csv
        """
        self._headers["Accept"] = "text/csv"
        self._accept_csv = True
        return self

    def explain(self) -> Self:
        """
        For debugging slow queries, you can get the Postgres EXPLAIN execution plan
        of a query using the explain() method.
        https://supabase.com/docs/reference/python/explain
        """
        pass
        return self

    def execute(self, **kwargs) -> List[Dict[str, Any]] | str | None:
        """
        Execute sync request to Supabase. Use async_execute() for async requests.
        Requests use httpx.Client(). See list of available parameters to pass with
        request at https://www.python-httpx.org/api/#client
        """
        # Raise exceptions
        if not self._bearer_token:
            raise ValueError("Request requires a bearer token. User needs to be signed in first, or service_role provided for admin use.")
        if not self._table:
            raise ValueError("No table name was provided for request.")

        # Set base URL and parameters
        url = f"{self._api_url}/rest/v1/{self._table}"

        # Set headers
        headers = {
            **self._headers,
            "apikey": self._api_key,
            "Authorization": f"Bearer {self._bearer_token}",
        }

        if self._method == "get":
            if not self._params.get("select"):
                raise ValueError("Must select columns to return or '*' to return all.")
            response = httpx.get(url, headers=headers, params=self._params, **kwargs)
        elif self._method == "post":
            if not self._data and "rpc" not in self._table:
                raise ValueError("Missing data for request.")
            response = httpx.post(url, headers=headers, params=self._params, json=self._data, **kwargs)
        elif self._method == "put":
            if not self._data:
                raise ValueError("Missing data for request.")
            response = httpx.put(url, headers=headers, params=self._params, json=self._data, **kwargs)
        elif self._method == "patch":
            if not self._data:
                raise ValueError("Missing data for request.")
            response = httpx.patch(url, headers=headers, params=self._params, json=self._data, **kwargs)
        elif self._method == "delete":
            response = httpx.delete(url, headers=headers, params=self._params, **kwargs)
        else:
            raise ValueError("Unrecognized method. Must be one of: get, post, put, patch, delete.")
        
        if self._debug:
            console.log(response)
        # Raise any HTTP errors
        response.raise_for_status()

        if self._accept_csv:
            return response.text # Raw CSV string
        elif not response.content or response.status_code == 204:
            return None

        # Return the response
        try:
            return response.json()
        except json.JSONDecodeError:
            return response.text

    async def async_execute(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute async request to Supabase. Use execute() for sync requests.
        Requests use httpx.AsyncClient(). See list of available parameters to pass with
        request at https://www.python-httpx.org/api/#asyncclient.
        """
        # Raise exceptions
        if not self._bearer_token:
            raise ValueError("Request requires a bearer token.")
        if not self._table:
            raise ValueError("No table name was provided for request.")

        # Set base URL and parameters
        url = f"{self._api_url}/rest/v1/{self._table}"

        # Set headers
        headers = {
            **self._headers,
            "apikey": self._api_key,
            "Authorization": f"Bearer {self._bearer_token}",
        }
        async with httpx.AsyncClient() as client:
            if self._method == "get":
                if not self._params.get("select"):
                    raise ValueError("Must select columns to return or '*' to return all.")
                response = await client.get(url, headers=headers, params=self._params, **kwargs)
            elif self._method == "post":
                if not self._data and "rpc" not in self._table:
                    raise ValueError("Missing data for request.")
                response = await client.post(url, headers=headers, params=self._params, json=self._data, **kwargs)
            elif self._method == "put":
                if not self._data:
                    raise ValueError("Missing data for request.")
                response = await client.put(url, headers=headers, params=self._params, json=self._data, **kwargs)
            elif self._method == "patch":
                if not self._data:
                    raise ValueError("Missing data for request.")
                response = await client.patch(url, headers=headers, params=self._params, json=self._data, **kwargs)
            elif self._method == "delete":
                response = await client.delete(url, headers=headers, params=self._params, **kwargs)
            else:
                raise ValueError("Unrecognized method. Must be one of: get, post, put, patch, delete.")
    
        if self._debug:
            console.log(response)
        # Raise any HTTP errors
        response.raise_for_status()

        if self._accept_csv:
            return response.text # Raw CSV string
        elif not response.content or response.status_code == 204:
            return None

        # Return the response
        try:
            return response.json()
        except json.JSONDecodeError:
            return response.text
        

    def _format_array_literal(self, values: List[Any]) -> str:
        if not values:
            return "{}"

        formatted_elements = []
        for v in values:
            if v is None:
                formatted_elements.append("NULL")
            elif isinstance(v, str):
                if not v or any(c in v for c in ',{} \\"') or v.strip() != v:
                    # Escape backslashes and double quotes
                    escaped_v = v.replace('\\', '\\\\').replace('"', '\\"')
                    formatted_elements.append(f'"{escaped_v}"') # Formatted for safety
                else:
                    formatted_elements.append(v) # Elements are safe.
            elif isinstance(v, bool):
                formatted_elements.append(str(v).lower()) # e.g. True -> 'true'
            elif isinstance(v, (int, float)):
                formatted_elements.append(str(v))
            else:
                raise ValueError(f"Unsupported value in {values} to format an array literal string. List must contain str, bool, int, or float.")

        return "{" + ",".join(formatted_elements) + "}"


class Suplex(rx.State):
    """
    State class for managing authentication with Supabase.

    Attributes:
        - access_token - Cookie for storing the JWT access token.
        - refresh_token - Cookie for storing the refresh token.

    Vars:
        - claims: Decoded JWT claims from the access token.
        - user_id: ID of the authenticated user.
        - user_email: Email of the authenticated user.
        - user_phone: Phone number of the authenticated user.
        - user_audience: Audience of the authenticated user.
        - user_role: Role of the authenticated user.
        - claims_issuer: Issuer of the JWT claims.
        - claims_expire_at: Expiration time of the JWT claims.
        - claims_issued_at: Issued time of the JWT claims.
        - claims_session_id: Session ID from the JWT claims.
        - user_metadata: User metadata from the JWT claims.
        - app_metadata: App metadata from the JWT claims.
        - user_aal: Authentication assurance level (1 or 2).
        - user_is_authenticated: Boolean indicating if the user is authenticated.
        - user_is_anonymous: Boolean indicating if the user is anonymous.
        - user_token_expired: Boolean indicating if the token is expired.

    Auth Functions:
        - sign_up: Register a new user with email or phone and password.
        - sign_in_with_password: Authenticate a user with email/phone and password.
        - sign_in_with_oauth: Authenticate a user with third-party OAuth providers.
        - get_user: Retrieve the current authenticated user's data.
        - update_user: Update the current user's profile information.
        - refresh_session: Refresh the authentication session using the refresh token.
        - get_settings: Retrieve authentication settings for the Supabase project.
        - logout: Log out the current user and invalidate the session.

    """
    access_token: rx.Cookie | str = rx.Cookie(
        name="access_token",
        path="/",
        secure=True,
        same_site="lax",
        domain=None,
        max_age=rx.config.get_config().suplex.get("cookie_max_age", None) # type: ignore
    )
    refresh_token: rx.Cookie | str = rx.Cookie(
        name="refresh_token",
        path="/",
        secure=True,
        same_site="lax",
        domain=None,
        max_age=rx.config.get_config().suplex.get("cookie_max_age", None) # type: ignore
    )
    
    # Load from config in rxconfig.py
    _api_url: str = rx.config.get_config().suplex["api_url"]
    _api_key: str = rx.config.get_config().suplex["api_key"]
    _jwt_secret: str = rx.config.get_config().suplex["jwt_secret"]
    _service_role: str | None = rx.config.get_config().suplex.get("service_role", None)
    let_jwt_expire: bool = rx.config.get_config().suplex.get("let_jwt_expire", False)
    debug: bool = rx.config.get_config().suplex.get("debug", False)

    console.print(
        "Loaded Suplex configuration:",
        style="bold cyan"
    )
    console.print(
        f"    API URL: {'\u2713' if _api_url else '\u2717'}",
        style="bold green" if _api_url else "bold red"
        )
    console.print(
        f"    API Key: {'\u2713' if _api_key else '\u2717'}",
        style="bold green" if _api_key else "bold red"
        )
    console.print(f"    JWT Secret: {'\u2713' if _jwt_secret else '\u2717'}",
        style="bold green" if _jwt_secret else "bold red"
    )
    console.print(
        f"    Cookie Max Age: {rx.config.get_config().suplex.get('cookie_max_age')}",
        style="bold cyan"
    )
    console.print(f"    Let JWT Expire: {let_jwt_expire}", style="bold cyan")
    console.print(f"    Debug Mode: {let_jwt_expire}", style="bold cyan")
    console.print(
        f"    Service Role: {"Service role enabled. Chain like .query().admin() to bypass Postgres RLS." if _service_role else "Not Enabled"}",
        style="bold red" if _service_role else "bold cyan"
        )

    # Set for events requiring front-end tracking of loading state.
    is_loading = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Load our config
        config = rx.config.get_config()
        required_keys = {"api_url", "api_key", "jwt_secret"}
        missing_keys = required_keys - config.suplex.keys() # type: ignore
        if missing_keys:
            raise ValueError(f"Missing required Suplex configuration keys: {', '.join(missing_keys)}")

    def _get_jwks_client(self, api_url: str) -> Optional[PyJWKClient]:
        _jwks_clients: dict[str, PyJWKClient] = {}
        jwks_url = api_url.rstrip('/') + '/auth/v1/.well-known/jwks.json'
        client = _jwks_clients.get(jwks_url)
        if client is None:
            try:
                client = PyJWKClient(jwks_url)
                _jwks_clients[jwks_url] = client
            except Exception as e: 
                return None
        return client
    
    @rx.var
    def claims(self) -> Dict[str, Any] | None:
        if not self.access_token:
            return None
        
        # Legacy API
        if self._jwt_secret:
            try:
                claims = jwt.decode(
                    self.access_token,
                    self._jwt_secret, # type: ignore
                    algorithms=["HS256"],
                    audience="authenticated",
                )
                return claims
            except Exception:
                return None

        # New API
        if self._api_url:
            jwks_client = self._get_jwks_client(self._api_url)
            if jwks_client:
                try:
                    signing_key = jwks_client.get_signing_key_from_jwt(self.access_token)
                    claims = jwt.decode(
                        self.access_token,
                        signing_key.key,
                        algorithms=["ES256"],
                        audience="authenticated",
                    )
                    return claims  
                except Exception as e: 
                    print(f"Error decoding JWT: {e}")
                    return None
            
    @rx.var
    def user_id(self) -> str | None:
        if self.claims:
            return self.claims["sub"]
        return None
    
    @rx.var
    def user_email(self) -> str | None:
        if self.claims:
            return self.claims["email"]
        return None
    
    @rx.var
    def user_phone(self) -> str | None:
        if self.claims:
            return self.claims["phone"]
        return None
    
    @rx.var
    def user_audience(self) -> str | None:
        if self.claims:
            return self.claims["aud"]
        return None
    
    @rx.var
    def user_role(self) -> str | None:
        if self.claims:
            return self.claims["role"]
        return None
    
    @rx.var
    def claims_issuer(self) -> str | None:
        if self.claims:
            return self.claims["iss"]
        return None
    
    @rx.var
    def claims_expire_at(self) -> int | None:
        """Unix timestamp of when the token expires."""
        if self.claims:
            return self.claims["exp"]
        return None
    
    @rx.var
    def claims_issued_at(self) -> int | None:
        """Unix timestamp of when the token was issued."""
        if self.claims:
            return self.claims["iat"]
        return None
    
    @rx.var
    def claims_session_id(self) -> str | None:
        """Unique identifier for the session."""
        if self.claims:
            return self.claims["session_id"]
        return None
    
    @rx.var
    def user_metadata(self) -> Dict[str, Any] | None:
        if self.claims:
            return self.claims["user_metadata"]
        return None
    
    @rx.var
    def app_metadata(self) -> Dict[str, Any] | None:
        if self.claims:
            return self.claims["app_metadata"]
        return None
    
    @rx.var
    def user_aal(self) -> Literal["aal1", "aal2"] | None:
        """aal1 is 1-factor auth, aal2 is 2-factor auth."""
        if self.claims:
            return self.claims["aal"]
        return None
            
    @rx.var
    def user_is_authenticated(self) -> bool:
        if self.claims:
            return True if self.claims["aud"] == "authenticated" else False
        return False
    
    @rx.var
    def user_is_anonymous(self) -> bool:
        if self.claims:
            return self.claims["is_anonymous"]
        return False
    
    @rx.var
    def user_token_expired(self) -> bool:
        """
        Manual check that user can user prior to request.
        Give 10 seconds of leeway for token expiration for a slow request.
        """
        if self.claims:
            return True if self.claims_expire_at - 10 < int(time.time()) else False
        return True
    
    def query(self) -> Query:
        """
        Helper function to create a query builder.
        Used as part of a query chain ex. self.query().chained().functions().here().execute().

        If let_jwt_expire is True, will throw BearerTokenExpired to handle on frontend.
        If let_jwt_expire is False, will attempt to refresh session prior to executing query.
        """
        if self.access_token:
            if not self.user_token_expired:
                return Query(bearer_token=self.access_token)
            elif self.user_token_expired and not self.let_jwt_expire:
                self.refresh_session()
                return Query(bearer_token=self.access_token)
            else:
                raise BearerTokenExpired
        else:
            raise ValueError(
                "Query class may not be instantiated without tokens from login. Ensure user is logged in prior to calling .query()"
            )

        
    def sign_up(
        self,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: str = "",
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register a new user with email or phone and password.
        
        Args:
            email: The email address of the user. Either email or phone must be provided.
            phone: The phone number of the user. Either email or phone must be provided.
            password: The password for the user (required).
            options: Additional options for the signup process:
                - email_redirect_to: URL to redirect after email confirmation
                - data: Custom user metadata to store
                - captcha_token: Token from a captcha provider
                - channel: Channel for sending messages (phone signups only)
                
        Returns:
            Dict containing the user data and authentication tokens.
            
        Raises:
            ValueError: If neither email nor phone is provided, or if password is missing.
            httpx.HTTPStatusError: If the API request fails.
        """
        data = {}
        url = f"{self._api_url}/auth/v1/signup"
        headers = {
            "apikey": self._api_key,
        }
        if not email and not phone:
            raise ValueError("Either email or phone must be provided.")
        if not password:
            raise ValueError("Password must be provided.")

        data["password"] = password
        if email:
            data["email"] = email
        if phone:
            data["phone"] = phone
        if options:
            if "data" in options:
                data["data"] = options.pop("data")
            if "email_redirect_to" in options:
                data["email_redirect_to"] = options.pop("email_redirect_to")
            if "captcha_token" in options:
                data["captcha_token"] = options.pop("captcha_token")
            if "channel" in options:
                data["channel"] = options.pop("channel")

        response = httpx.post(url, headers=headers, json=data)
        if self.debug:
            console.log(response)
        response.raise_for_status()
        
        return response.json()

    def sign_in_with_password(
        self,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: str = "",
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Authenticate a user with email/phone and password.
        
        Args:
            email: The email address of the user. Either email or phone must be provided.
            phone: The phone number of the user. Either email or phone must be provided.
            password: The password for authentication (required).
            options: Additional options for the signin process:
                - captcha_token: Token from a captcha provider
                
        Returns:
            Dict containing user data, access_token, refresh_token, and other session info.
            
        Raises:
            ValueError: If neither email nor phone is provided, or if password is missing.
            httpx.HTTPStatusError: If the API request fails (e.g., invalid credentials).
        """
        data = {}
        url = f"{self._api_url}/auth/v1/token?grant_type=password"
        headers = {
            "apikey": self._api_key,
        }

        data["password"] = password
        if email:
            data["email"] = email
        if phone:
            data["phone"] = phone
        if options:
            if "captcha_token" in options:
                data["captcha_token"] = options.pop("captcha_token")

        response = httpx.post(url, headers=headers, json=data)
        if self.debug:
            console.log(response)
        response.raise_for_status()

        data = response.json()

        self.set_tokens(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"]
        )
        return data

    def sign_in_with_oauth(
        self,
        provider: Literal[
            "google",
            "facebook",
            "apple",
            "azure",
            "twitter",
            "github",
            "gitlab",
            "bitbucket",
            "discord",
            "figma",
            "kakao",
            "keycloak",
            "linkedin_oidc",
            "notion",
            "slack_oidc",
            "spotify",
            "twitch",
            "workos",
            "zoom",
        ],
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate a URL for OAuth authentication with a third-party provider.
        
        Args:
            provider: The OAuth provider to use (must be one of the supported providers).
            options: Additional options for the OAuth flow:
                - redirect_to: URL to redirect after authentication
                - scopes: List of permission scopes to request
                - query_params: Additional parameters to include in the OAuth request
                - code_challenge: A random string used for PKCE to mitigate authorization code interception attacks.
                - code_challenge_method: The method used to generate the code challenge. Must be either 'plain' or 's256'.
                
        Returns:
            A URL string to redirect the user to for OAuth authentication. When the user 
            successfully authenticates, they will be redirected back to the redirect_to URL.
            Parse the URL for the tokens and use set_tokens() to store them.
            
        Raises:
            ValueError: If the provider is not supported.
            httpx.HTTPStatusError: If the API request fails.
            
        Note:
            The returned URL should be used with rx.redirect() to redirect
            the user to the OAuth provider's login page.
        """
        data = {}
        headers = {
            "apikey": self._api_key,
        }
        url = f"{self._api_url}/auth/v1/authorize"
        data["provider"] = provider
        if options:
            if "redirect_to" in options:
                data["redirect_to"] = options.pop("redirect_to")
            if "scopes" in options:
                data["scopes"] = options.pop("scopes")
            if "query_params" in options:
                data["query_params"] = options.pop("query_params")
            if "code_challenge" in options:
                data["code_challenge"] = options.pop("code_challenge")
            if "code_challenge_method" in options:
                data["code_challenge_method"] = options.pop("code_challenge_method")

        response = httpx.get(url, headers=headers, params=data)
        if self.debug:
            console.log(response)
        if response.status_code == 302:
            return response.headers["location"]
        
        # If not a redirect response, check for other errors
        response.raise_for_status()
        raise ValueError("Expected a redirect response from OAuth provider, but none was received.")
    
    def set_tokens(self, access_token: str, refresh_token:str) -> None:
        """
        Ensures that query is also updated whenever tokens are set.

        Args:
            access_token: The JWT access token for authentication.
            refresh_token: The refresh token for session management.
        """
        self.access_token = access_token
        self.refresh_token = refresh_token
    
    def reset_password_email(
        self,
        email: str,
        # options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Send a password reset email to the specified email address.
        
        This method initiates the password reset flow by sending an email
        with a reset link to the user's email address.
        
        Args:
            email: The email address of the user requesting a password reset (required)
            options: Additional options for the password reset process:
                - redirect_to: URL to redirect after password reset (See Note)
                - captcha_token: Token from a captcha provider (See Note)
                
        Returns:
            Dict containing the API response data
            
        Raises:
            ValueError: If email is not provided
            httpx.HTTPStatusError: If the API request fails
            
        Note:
            The user will receive an email with a link to reset their password.

            IMPORTANT: For some reason, the REST API does not take a redirect-to parameter. 
            The email link will redirect to the default redirect URL (called Site-URL) in your 
            Supabase project.  My workaround was to intercept the access token and 
            manually redirect to the appropriate url when self.router.page.params["type"] 
            is "recovery".
        """
        if not email:
            raise ValueError("Email must be provided.")
        data = {"email": email}
        url = f"{self._api_url}/auth/v1/recover"
        headers = {
            "apikey": self._api_key,
        }

        # In case supabase ever matches the REST API with the Client SDKs
        # if options:
        #     if "redirect_to" in options:
        #         data["redirect_to"] = options.pop("redirect_to")
        #     if "captcha_token" in options:
        #         data["captcha_token"] = options.pop("captcha_token")

        response = httpx.post(url, headers=headers, json=data)
        if self.debug:
            console.log(response)
        response.raise_for_status()
        
        return response.json()

    def get_user(self) -> Optional[Dict[str, Any]]:
        """
        Retrieve the current authenticated user's data from the database.
        
        This method gets the current user information from the Supabase API.
        It first verifies that the session is valid, and if not, returns None.
        
        Args:
            None
            
        Returns:
            A dictionary containing the user data if authenticated, or None if:
            - No valid session exists
            - The access token is expired and refresh fails
            - Any error occurs during API request
            
        Note:
            This method will clear auth tokens if an error occurs.
            Use get_session() to retrieve the JWT token claims instead of the full user profile.
        """
        if self.user_token_expired and not self.let_jwt_expire:
            self.refresh_session()

        response = httpx.get(
            f"{self._api_url}/auth/v1/user",
            headers={
                "apikey": self._api_key,
                "Authorization": f"Bearer {self.access_token}",
            },
        )
        if self.debug:
            console.log(response)
        response.raise_for_status()
        return response.json()

    def update_user(
        self,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: Optional[str] = None,
        user_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update the current user's profile information.
        
        This method updates one or more user attributes including email,
        phone number, password, or custom metadata.
        
        Args:
            email: New email address for the user
            phone: New phone number for the user
            password: New password for the user
            user_metadata: Dictionary of custom metadata to store with the user profile
            
        Returns:
            Dictionary containing the updated user data
            
        Raises:
            ValueError: If no access token exists (user not authenticated)
            httpx.HTTPStatusError: If the API request fails
        """
        if self.user_token_expired and not self.let_jwt_expire:
            self.refresh_session()
        if not self.access_token:
            raise ValueError("Expected access token to update user information.")

        data = {}
        url = f"{self._api_url}/auth/v1/user"
        headers = {
            "apikey": self._api_key,
            "Authorization": f"Bearer {self.access_token}",
        }

        if email:
            data["email"] = email
        if phone:
            data["phone"] = phone
        if password:
            data["password"] = password
        if user_metadata:
            data["data"] = user_metadata
            
        if not data:
            raise ValueError("At least one attribute (email, phone, password, or user_metadata) must be provided to update.")

        response = httpx.put(url, headers=headers, json=data)
        if self.debug:
            console.log(response)
        response.raise_for_status()

        return response.json()

    def refresh_session(self) -> Dict[str, Any] | None:
        """
        Manually refresh the authentication session using the refresh token.
        
        This method uses the stored refresh token to obtain a new access token
        when the current one expires. It automatically updates the token storage
        if successful.
        
        Returns:
            - Dictionary containing the user data if refresh successful.
            - None if:
                - No refresh token exists
                - Refresh token is expired or invalid
                - API request fails for any reason

        Raises:
            httpx.HTTPStatusError: If the API request fails
            KeyError: If the expected keys are not present in the response
        """
        url = f"{self._api_url}/auth/v1/token?grant_type=refresh_token"
        headers = {
            "apikey": self._api_key,
            "Authorization": f"Bearer {self.access_token}",
        }
        response = httpx.post(
            url, 
            headers=headers, 
            json={"refresh_token": self.refresh_token}
        )
        if self.debug:
            console.log("Token expired, using refresh token to reissue access token.")
            console.log(response)
        response.raise_for_status()

        data = response.json()

        self.set_tokens(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
        )
        return data["user"]

    def get_settings(self) -> Dict[str, Any]:
        """
        Retrieve the authentication settings for the Supabase project.
        
        This method fetches the authentication configuration settings from
        the Supabase API, including enabled providers and security settings.
            
        Returns:
            Dictionary containing the authentication settings
            
        Raises:
            httpx.HTTPStatusError: If the API request fails
        """
        url = f"{self._api_url}/auth/v1/settings"
        headers = {
            "apikey": self._api_key,
        }
        response = httpx.get(url, headers=headers)
        if self.debug:
            console.log(response)
        response.raise_for_status()
        return response.json()

    def log_out(
        self, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log out the current user and invalidate the refresh token on Supabase.
        Clears cookies and the bearer token from the query object.
        
        Args:
            options: Additional options for logout:
                - scope: How the user should be logged out:
                    - "global": Log out from all active sessions across all devices
                    - "local": Log out from the current session only (default)
                    - "others": Log out from all other sessions except the current one
        
        Raises:
            httpx.HTTPStatusError: If the API request fails.
            
        Note:
           - Without a scope specified, the logout API uses the global scope.
           - When scope is "others", local tokens are preserved. For "global" and "local"
            (or when scope is not specified), local tokens are cleared.
        """
        # Only attempt server-side logout if we have an access token
        if self.access_token:
            # Build URL with optional scope parameter
            url = f"{self._api_url}/auth/v1/logout"
            
            # Extract scope from options if provided
            query_params = {}
            if options and "scope" in options:
                scope = options["scope"]
                if scope in ["global", "local", "others"]:
                    query_params["scope"] = scope
            
            headers = {
                "apikey": self._api_key,
                "Authorization": f"Bearer {self.access_token}",
            }
            
            response = httpx.post(url, headers=headers, params=query_params)
            if self.debug:
                console.log(response)
            response.raise_for_status()
            
            # Only reset local tokens if we're not using "others" scope
            if not (options and options.get("scope") == "others"):
                self.reset()
        else:
            # Reset state if no token exists
            self.reset()

    def exchange_code_for_session(
        self,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Exchange an authorization code for an access token and refresh token using PKCE flow.
        
        This method is used as part of the PKCE (Proof Key for Code Exchange) OAuth flow,
        typically after redirecting back from an OAuth provider with an authorization code.
        
        Args:
            params: Dictionary containing:
                - auth_code: The authorization code received from the OAuth provider
                - code_verifier: The code verifier that was created and stored during the OAuth request
            
        Returns:
            Dict containing user data, access_token, refresh_token, and other session info
            
        Raises:
            ValueError: If auth_code or code_verifier is missing from params
            httpx.HTTPStatusError: If the API request fails
        """
        if "auth_code" not in params:
            raise ValueError("Authorization code is required")
        if "code_verifier" not in params:
            raise ValueError("Code verifier is required")
            
        data = {
            "auth_code": params["auth_code"],
            "code_verifier": params["code_verifier"]
        }
            
        url = f"{self._api_url}/auth/v1/token?grant_type=pkce"
        headers = {
            "apikey": self._api_key,
        }
        
        response = httpx.post(url, headers=headers, json=data)
        if self.debug:
            console.log(response)
        response.raise_for_status()
        
        response_data = response.json()
        self.set_tokens(
            access_token=response_data["access_token"], 
            refresh_token=response_data["refresh_token"],
        )
        
        return response_data