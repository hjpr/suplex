import httpx
import reflex as rx
import rich
import time

from auth import Auth
from rich.console import Console
from typing import Any, Literal, Self
from urllib.parse import quote

console = Console()
        
class Suplex(rx.Base):
    """
    Uses httpx clients to interact with Supabase REST API. To use or test in a locally hosted supabase instance, follow the guide at:
        https://supabase.com/docs/guides/self-hosting/docker

    Otherwise you can find your api_url, api_key, service_role and jwt_secret in your project at:
        https://supabase.com/dashboard/projects:
            Project Settings > Data API > Project URL (api_url)
            Project Settings > Data API > Project API keys (api_key, service_role)
            Project Settings > Data API > JWT Settings (jwt_secret)

    Instatiating this class without specifying api_url, or api_key, will use the
    environment variables api_url and api_key.

    **Example:**
    ```python
        from suplex import Suplex
        
        # Instantiate class, use service role for admin, otherwise omit.
        supabase = Suplex(
            api_url="your-api-url",
            api_key="your-api-key",
            jwt_secret="your-jwt-secret",
            service_role="your-service-role" # Only pass if using client as admin.
        )

        # If service role is provided, this request bypasses RLS policies.
        response = supabase.table("your-table").select("*").execute()
        data = response.json()

        # Sign in user
        supabase.auth.sign_in_with_password(
            email="email",
            password="password"
        )

        # Even if a service role is provided, after user sign in,
        # all requests will use the access token and RLS policies will be enforced.
        response = supabase.table("your-table").select("*").execute()
        data = response.json()
    ```

    **Table Methods** - https://supabase.com/docs/reference/python/select:
        .select()
        .insert()
        .upsert()
        .update()
        .delete()

    **Filter Methods** - https://supabase.com/docs/reference/python/using-filters:
        .eq()
        .neq()
        .gt()
        .lt()
        .gte()
        .lte()
        .like()
        .ilike()
        .is_()
        .in_()
        .contains()
        .contained_by()
        
    **Modifiers**- https://supabase.com/docs/reference/python/using-modifiers:
        .order()
        .limit()
        .range()
        .single()
        .maybe_single()
        .csv()
        .explain()

    **Troubleshooting:**
        While in user mode, if no rows are returned and everything else is
        correct, check the Row Level Security (RLS) policies on the table.

        When using reserved words for column names you need to add double quotes e.g. .gt('"order"', 2)
        Reserved words are listed here:
            https://www.postgresql.org/docs/current/sql-keywords-appendix.html
    """
    def __init__(
            self,
            api_url: str,
            api_key: str,
            jwt_secret: str,
            service_role: str | None = None,            
        ):
        super().__init__()
        self.api_url = api_url
        self.api_key = api_key
        self.service_role = service_role
        self.auth = Auth(
            api_url,
            api_key,
            jwt_secret,
        )
        self.headers = {}
        self._table: str | None = None
        self._filters: str | None = None
        self._select: str | None = None
        self._order: str | None = None
        self._method: str | None = None
        self._data: dict[str, Any] | list | None = None

    def table(self, table: str) -> Self:
        """Targeted table to read from."""
        self._table = f"{table}"
        return self

    def eq(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is equal to value.
        https://supabase.com/docs/reference/python/eq
        """
        self._filters = f"{column}=eq.{value}"
        return self
    
    def neq(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is not equal to value.
        https://supabase.com/docs/reference/python/neq
        """
        self._filters = f"{column}=neq.{value}"
        return self
    
    def gt(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is greater than value.
        https://supabase.com/docs/reference/python/gt
        """
        self._filters = f"{column}=gt.{value}"
        return self
    
    def lt(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is less than value.
        https://supabase.com/docs/reference/python/lt
        """
        self._filters = f"{column}=lt.{value}"
        return self
    
    def gte(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is greater than or equal to value.
        https://supabase.com/docs/reference/python/gte
        """
        self._filters = f"{column}=gte.{value}"
        return self
    
    def lte(self, column: str, value: Any) -> Self:
        """
        Match only rows where column is less than or equal to value.
        https://supabase.com/docs/reference/python/lte
        """
        self._filters = f"{column}=lte.{value}"
        return self
    
    def like(self, column: str, pattern: str) -> Self:
        """
        Match only rows where column matches pattern case-sensitively.
        https://supabase.com/docs/reference/python/like
        """
        self._filters = f"{column}=like.{pattern}"
        return self
    
    def ilike(self, column: str, pattern: str) -> Self:
        """
        Match only rows where column matches pattern case-insensitively.
        https://supabase.com/docs/reference/python/ilike
        """
        self._filters = f"{column}=ilike.{pattern}"
        return self
    
    def is_(self, column: str, value: Literal["null"] | bool) -> Self:
        """
        Match only rows where column is null or bool.
        Use this instead of eq() for null values.
        https://supabase.com/docs/reference/python/is
        """
        self._filters = f"{column}=is.{value}"
        return self
    
    def in_(self, column: str, values: list) -> Self:
        """
        Match only rows where column is in the list of values.
        https://supabase.com/docs/reference/python/in
        """
        formatted = ",".join(quote(f'"{v}"') for v in values)
        self._filters = f"{column}=in.({formatted})"
        return self
    
    def contains(self, array_column: str, values: list) -> Self:
        """
        Only relevant for jsonb, array, and range columns.
        Match only rows where column contains every element appearing in values.
        https://supabase.com/docs/reference/python/contains
        """
        formatted = ",".join(quote(f'"{v}"') for v in values)
        self._filters = f"{array_column}=cs.{{{formatted}}}"
        return self
    
    def contained_by(self, array_column: str, values: list) -> Self:
        """
        Only relevant for jsonb, array, and range columns.
        Match only rows where every element appearing in column is contained by value.
        https://supabase.com/docs/reference/python/containedby
        """
        formatted = ",".join(quote(f'"{v}"') for v in values)
        self._filters = f"{array_column}=cd.{{{formatted}}}"
        return self
    
    def select(self, select: str) -> Self:
        """
        Specify columns to return, or '*' to return all.
        https://supabase.com/docs/reference/python/select
        """
        self._select = f"select={select}"
        self._method = "get"
        return self
    
    def insert(self, data: dict[str, Any] | list) -> Self:
        """
        Add new item to table as {'column': 'value', 'other_column': 'other_value'}
        or new items as [{'column': 'value'}, {'other_column': 'other_value'}]
        https://supabase.com/docs/reference/python/insert
        """
        self._data = data
        self._method = "post"
        return self
    
    def upsert(self, data: dict, return_: Literal["representation","minimal"]="representation") -> Self:
        """
        Add item to table as {'column': 'value', 'other_column': 'other_value'}
        if it doesn't exist, otherwise update item. One column must be a primary key.
        https://supabase.com/docs/reference/python/upsert
        """
        self._data = data
        self._method = "post"
        self.headers["Prefer"] = f"return={return_},resolution=merge-duplicates"
        return self
    
    def update(self, data: dict) -> Self:
        """
        Update lets you update rows. update will match all rows by default.
        You can update specific rows using horizontal filters, e.g. eq, lt, and is.
        https://supabase.com/docs/reference/python/update
        """
        self.headers["Prefer"] = "return=representation"
        self._method = "patch"
        self._data = data
        return self
    
    def delete(self) -> Self:
        """
        Delete matching rows from the table. Matches all rows by default! Use filters to specify.
        https://supabase.com/docs/reference/python/delete
        """
        self._method = "delete"
        return self
    
    def order(self, column: str, ascending: bool = True) -> Self:
        """
        Order the query result by column. Defaults to ascending order (lowest to highest).
        https://supabase.com/docs/reference/python/order
        """
        self._order = f"order={column}.{('asc' if ascending else 'desc')}"
        return self
    
    def limit(self, limit: int) -> Self:
        """
        Limit the number of rows returned.
        https://supabase.com/docs/reference/python/limit
        """
        pass
        return self

    def range(self, start: int, end: int) -> Self:
        """
        Limit the query result by starting at an offset (start) and ending at the offset (end). 
        https://supabase.com/docs/reference/python/range
        """
        pass
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
        pass
        return self

    def explain(self) -> Self:
        """
        For debugging slow queries, you can get the Postgres EXPLAIN execution plan
        of a query using the explain() method.
        https://supabase.com/docs/reference/python/explain
        """
        pass
        return self

    def execute(self, **kwargs) -> httpx.Response:
        """
        Execute sync request to Supabase. Use async_execute() for async requests.
        Requests use httpx.Client(). See list of available parameters to pass with
        request at https://www.python-httpx.org/api/#client
        """
        # Set base URL and parameters
        base_url = f"{self.api_url}/rest/v1/{self._table}"
        params = []
        if self._filters:
            params.append(self._filters)
        if self._select:
            params.append(self._select)
        if self._order:
            params.append(self._order)
        url = f"{base_url}?{'&'.join(params)}"

        # Check for token expiration and refresh if within 5 seconds of expiration.
        if self.auth.access_token:
            claims = self.auth.get_session()
            if claims and (claims["exp"] - time.time() <= 5):
                self.auth.refresh_session()

        # Set headers
        headers = {
            **self.headers,
            "apiKey": self.api_key,
            "Authorization": f"Bearer {self.auth.access_token if self.auth.access_token else self.service_role}"
        }

        # Raise general exceptions
        if not self._table:
            raise ValueError("No table name was provided for request.")
        if not self.auth.access_token and not self.service_role:
            raise ValueError("No user access_token or service_role available to use as bearer.")

        # Finally make the built request.
        if self._method == "get":
            if not self._select:
                raise ValueError("Must select columns to return or '*' to return all.")
            response = httpx.get(url, headers=headers, **kwargs)
        elif self._method == "post":
            if not self._data:
                raise ValueError("Missing data for request.")
            response = httpx.post(url, headers=headers, json=self._data, **kwargs)
        elif self._method == "put":
            if not self._data:
                raise ValueError("Missing data for request.")
            response = httpx.put(url, headers=headers, json=self._data, **kwargs)
        elif self._method == "patch":
            if not self._data:
                raise ValueError("Missing data for request.")
            response = httpx.patch(url, headers=headers, json=self._data, **kwargs)
        elif self._method == "delete":
            response = httpx.delete(url, headers=headers, **kwargs)
        else:
            raise ValueError("Unrecognized method. Must be one of: get, post, put, patch, delete.")
        
        # Raise any HTTP errors
        response.raise_for_status()

        # Clean up headers and attributes
        self.headers.pop("Prefer", None)
        self._table = ""
        self._filters = ""
        self._select = ""
        self._order = ""
        self._method = ""
        self._data = {}

        # Return the response
        return response
    
    async def async_execute(self, **kwargs) -> httpx.Response:
        """
        Execute async request to Supabase. Use execute() for sync requests.
        Requests use httpx.AsyncClient(). See list of available parameters to pass with
        request at https://www.python-httpx.org/api/#asyncclient.
        """
        # Set base URL and parameters
        base_url = f"{self.api_url}/rest/v1/{self._table}"
        params = []
        if self._filters:
            params.append(self._filters)
        if self._select:
            params.append(self._select)
        if self._order:
            params.append(self._order)
        url = f"{base_url}?{'&'.join(params)}"

        # Raise general exceptions
        if not self._table:
            raise ValueError("No table name was provided for request.")
        if not self.auth.access_token and not self.service_role:
            raise ValueError("No user access_token or service_role available to use as bearer.")
        
        # Check for token expiration and refresh if within 5 seconds of expiration.
        if self.auth.access_token:
            claims = self.auth.get_session()
            if claims and (claims["exp"] - time.time() <= 5):
                self.auth.refresh_session()

        # Check and set headers
        headers = {
            **self.headers,
            "apiKey": self.api_key,
            "Authorization": f"Bearer {self.auth.access_token if self.auth.access_token else self.service_role}",
        }

        async with httpx.AsyncClient() as client:
            if self._method == "get":
                if not self._table:
                    raise ValueError("No table name was provided for request.")
                if not self._select:
                    raise ValueError("Must select columns to return or '*' to return all.")
                response = await client.get(url, headers=headers, **kwargs)
            elif self._method == "post":
                if not self._data:
                    raise ValueError("Missing data for request.")
                response = await client.post(url, headers=headers, json=self._data, **kwargs)
            elif self._method == "put":
                if not self._data:
                    raise ValueError("Missing data for request.")
                response = await client.put(url, headers=headers, json=self._data, **kwargs)
            elif self._method == "patch":
                if not self._data:
                    raise ValueError("Missing data for request.")
                response = await client.patch(url, headers=headers, json=self._data, **kwargs)
            elif self._method == "delete":
                response = await client.delete(url, headers=headers, **kwargs)
            else:
                raise ValueError("Unrecognized method. Must be one of: get, post, put, patch, delete.")
            
            # Raise any HTTP errors
            response.raise_for_status()

            # Clean up any headers and attributes
            self.headers.pop("Prefer", None)
            self._table = ""
            self._filters = ""
            self._select = ""
            self._order = ""
            self._method = ""
            self._data = {}

            # Return the response
            return response
