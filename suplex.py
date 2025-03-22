import httpx
import json
import logging
import reflex as rx

from typing import Any, Coroutine, Literal, Self
from urllib.parse import quote

log = logging.getLogger("rich")

class Suplex():
    """
    Uses httpx clients to interact with Supabase REST API. To use or test in a locally hosted supabase instance, follow the guide at:
        https://supabase.com/docs/guides/self-hosting/docker

    Otherwise you can find your api_url, api_key, service_role and jwt_secret in your project at
        https://supabase.com/dashboard/projects:
            Project Settings > Data API > Project URL (api_url)
            Project Settings > Data API > Project API keys (api_key, service_role)
            Project Settings > Data API > JWT Settings (jwt_secret)

    Pass service role only for debugging, testing, or admin use.
    Use auth module to retrieve the access token to use this class
    as a user.

    Table Methods:
        .select()
        .insert()
        .upsert()
        .update()
        .delete()

    Filter Methods:
        .eq()
        .neq()
        .gt()
        .lt()
        .gte()
        .lte()
        .like()
        .ilike()
        .is_()
        .contains()
        .contained_by()

    Example Usages:
        Admin - UNSAFE. Can read/write to/from any table.:
            supabase = Suplex("api-url-from-env", "api-key-from-env",service_role="service-role-from-env")
            sync_response = supabase.table("foo").select("*").execute()
            async_response = await supabase.table("foo").select("*").async_execute()
    
        User - SAFE. Limited to scope of the 'role' in the JWT token.:
            supabase = Suplex()"api-url-from-env", "api-key-from-env")
            supabase.auth.sign_in_with_password()
            sync_response = supabase.table("foo").select("*").execute()
            async_response = await supabase.table("foo").select("*").async_execute()

    Troubleshooting:
        While in user mode, if no rows are returned and everything else is
        correct, check the Row Level Security (RLS) policies on the table.

        When using reserved words for column names you need to add double quotes e.g. .gt('"order"', 2)
        Reserved words are listed here:
            https://www.postgresql.org/docs/current/sql-keywords-appendix.html
    """
    api_url: str
    api_key: str
    access_token: str 
    refresh_token: str
    headers: dict

    _table: str = ""
    _filters: str = ""
    _select: str = ""
    _order: str = ""
    _method: str = ""
    _data: dict = {}

    def __init__(
            self,
            api_url: str,
            api_key: str,
            refresh_token: str = "",
            service_role: str = "",
        ):
        self.api_url = api_url
        self.api_key = api_key
        self.refresh_token = refresh_token
        self.headers = {
            "apikey": api_key,
            "Authorization": f"Bearer {service_role}",
        }

    def table(self, table: str) -> Self:
        """Targeted table to read from."""
        self._table = f"{table}"
        return self

    def eq(self, column: str, value: Any) -> Self:
        """Match only rows where column is equal to value."""
        self._filters = f"{column}=eq.{value}"
        return self
    
    def neq(self, column: str, value: Any) -> Self:
        """Match only rows where column is not equal to value."""
        self._filters = f"{column}=neq.{value}"
        return self
    
    def gt(self, column: str, value: Any) -> Self:
        """Match only rows where column is greater than value."""
        self._filters = f"{column}=gt.{value}"
        return self
    
    def lt(self, column: str, value: Any) -> Self:
        """Match only rows where column is less than value."""
        self._filters = f"{column}=lt.{value}"
        return self
    
    def gte(self, column: str, value: Any) -> Self:
        """Match only rows where column is greater than or equal to value."""
        self._filters = f"{column}=gte.{value}"
        return self
    
    def lte(self, column: str, value: Any) -> Self:
        """Match only rows where column is less than or equal to value."""
        self._filters = f"{column}=lte.{value}"
        return self
    
    def like(self, column: str, pattern: str) -> Self:
        """Match only rows where column matches pattern case-sensitively."""
        self._filters = f"{column}=like.{pattern}"
        return self
    
    def ilike(self, column: str, pattern: str) -> Self:
        """Match only rows where column matches pattern case-insensitively."""
        self._filters = f"{column}=ilike.{pattern}"
        return self
    
    def is_(self, column: str, value: Literal["null"] | bool) -> Self:
        """
        Match only rows where column is null or bool.
        Use this instead of eq() for null values.
        """
        self._filters = f"{column}=is.{value}"
        return self
    
    def in_(self, column: str, values: list) -> Self:
        """
        Match only rows where column is in the list of values.
        e.g. the row's column must be one of the given list.
        """
        formatted = ",".join(quote(f'"{v}"') for v in values)
        self._filters = f"{column}=in.({formatted})"
        return self
    
    def contains(self, array_column: str, values: list) -> Self:
        """
        Only relevant for jsonb, array, and range columns.
        Match only rows where column contains every element appearing in values.
        e.g. the row's array must contain all elements in the given list.
        """
        formatted = ",".join(quote(f'"{v}"') for v in values)
        self._filters = f"{array_column}=cs.{{{formatted}}}"
        return self
    
    def contained_by(self, array_column: str, values: list) -> Self:
        """
        Only relevant for jsonb, array, and range columns.
        Match only rows where every element appearing in column is contained by value.
        e.g. the row's array must be a subset of the given list. 
        """
        formatted = ",".join(quote(f'"{v}"') for v in values)
        self._filters = f"{array_column}=cd.{{{formatted}}}"
        return self
    
    def select(self, select: str) -> Self:
        """Specify columns to return, or '*' to return all."""
        self._select = f"select={select}"
        self._method = "get"
        return self
    
    def insert(self, data: dict | list) -> Self:
        """
        Add new item to table as {'column': 'value', 'other_column': 'other_value'}
        or new items as [{'column': 'value'}, {'other_column': 'other_value'}]
        """
        self._data = json.dumps(data)
        self._method = "post"
        return self
    
    def upsert(self, data: dict, return_: Literal["representation","minimal"]="representation") -> Self:
        """
        Add item to table as {'column': 'value', 'other_column': 'other_value'}
        if it doesn't exist, otherwise update item. One column must be a primary key.
        Returns updated values unless return_ is set to 'minimal'.
        """
        self._data = json.dumps(data)
        self._method = "post"
        self.headers["Prefer"] = f"return={return_},resolution=merge-duplicates"
        return self
    
    def update(self, data: dict) -> Self:
        """
        Update lets you update rows. update will match all rows by default.
        You can update specific rows using horizontal filters, e.g. eq, lt, and is.
        Update will also return the replaced values.
        """
        self.headers["Prefer"] = "return=representation"
        self._method = "patch"
        self._data = json.dumps(data)
        return self
    
    def delete(self) -> Self:
        """Delete matching rows from the table. Matches all rows by default! Use filters to specify."""
        self._method = "delete"
        return self
    
    def order(self, column: str, ascending: bool = True) -> Self:
        """Order the query result by column. Defaults to ascending order (lowest to highest)."""
        self._order = f"order={column}.{('asc' if ascending else 'desc')}"
        return self

    def execute(self, **kwargs) -> httpx.Response:
        """
        Execute sync request to Supabase. Use async_execute() for async requests.
        Requests use httpx.Client(). See list of available parameters to pass with
        request at https://www.python-httpx.org/api/#client
        """
        # Build the request URL
        base_url = f"{self.api_url}/rest/v1/{self._table}"
        params = []
        if self._filters:
            params.append(self._filters)
        if self._select:
            params.append(self._select)
        if self._order:
            params.append(self._order)
        url = f"{base_url}?{'&'.join(params)}"
        log.info("Executing a sync request to...")
        log.info(f"URL: {url}")

        if self._method == "get":
            if not self._table:
                raise ValueError("No table name was provided for request.")
            if not self._select:
                raise ValueError("Must select columns to return or '*' to return all.")
            response = httpx.get(url, headers=self.headers, **kwargs)
        elif self._method == "post":
            if not self._data:
                raise ValueError("No data was provided for insert request.")
            response = httpx.post(url, headers=self.headers, data=self._data, **kwargs)
        elif self._method == "put":
            if not self._data:
                raise ValueError("Data must be provided for PUT requests.")
            response = httpx.put(url, headers=self.headers, data=self._data, **kwargs)
        elif self._method == "patch":
            response = httpx.patch(url, headers=self.headers, data=self._data, **kwargs)
        elif self._method == "delete":
            response = httpx.delete(url, headers=self.headers, **kwargs)
        
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
        log.info("Sync request completed successfully.")
        return response
    
    async def async_execute(self, **kwargs) -> Coroutine:
        """
        Execute async request to Supabase. Use execute() for sync requests.
        Requests use httpx.AsyncClient(). See list of available parameters to pass with
        request at https://www.python-httpx.org/api/#asyncclient
        """
        # Build the request URL
        base_url = f"{self.api_url}/rest/v1/{self._table}"
        params = []
        if self._filters:
            params.append(self._filters)
        if self._select:
            params.append(self._select)
        if self._order:
            params.append(self._order)
        url = f"{base_url}?{'&'.join(params)}"
        log.info("Executing an async request to...")
        log.info(f"URL: {url}")

        async with httpx.AsyncClient() as client:
            if self._method == "get":
                if not self._table:
                    raise ValueError("No table name was provided for request.")
                if not self._select:
                    raise ValueError("Must select columns to return or '*' to return all.")
                response = await client.get(url, headers=self.headers, **kwargs)
            elif self._method == "post":
                if not self._data:
                    raise ValueError("No data was provided for insert request.")
                response = await client.post(url, headers=self.headers, data=self._data, **kwargs)
            elif self._method == "put":
                if not self._data:
                    raise ValueError("Data must be provided for PUT requests.")
                response = await client.put(url, headers=self.headers, data=self._data **kwargs)
            elif self._method == "patch":
                response = await client.patch(url, headers=self.headers, data=self._data, **kwargs)
            elif self._method == "delete":
                response = await client.delete(url, headers=self.headers, **kwargs)
            
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
            log.info("Async request completed successfully.")
            return response
