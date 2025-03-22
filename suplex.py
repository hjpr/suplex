import httpx
import json
import logging

from typing import Coroutine, Self

log = logging.getLogger("rich")

class Suplex:
    """
    Uses httpx clients to interact with Supabase REST API.
    
    Pass service role only for debugging, testing, or admin use.
    Use auth module to retrieve the access token to use this class
    as a user.

    Basic UNSAFE admin format is :
    supabase = Suplex(
        api_url="api-url-from-env",
        api_key="api-key-from-env",
        service_role="service-role-from-env"
    )

    Basic SAFE user format is:
    supabase = Suplex(
        api_url="api-url-from-env",
        api_key="api-key-from-env",
        access_token="access-token-from-user"
    )
    """
    api_url: str
    api_key: str
    access_token: str 
    refresh_token: str
    headers: dict

    _table: str = ""
    _filters: str = ""
    _select: str = ""
    _method: str = ""
    _data: dict = {}

    def __init__(
            self,
            api_url: str,
            api_key: str,
            access_token: str = "",
            refresh_token: str = "",
            service_role: str = "",
        ):
        self.api_url = api_url
        self.api_key = api_key
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.headers = {
            "apikey": api_key,
            "Authorization": f"Bearer {access_token if access_token else service_role}",
        }

    def table(self, table: str) -> Self:
        """Targeted table to read from."""
        self._table = table
        return self

    def eq(self, column: str, value: str) -> Self:
        """Specify filters to apply to the request as column, value"""
        self._filters = f"{column}=eq.{value}"
        return self
    
    def select(self, select: str) -> Self:
        """Specify columns to return or '*' to return all."""
        self._select = f"&select={select}"
        self._method = "get"
        return self
    
    def insert(self, data: dict) -> Self:
        """Specify items to insert as {'column': 'value'}"""
        self._data = json.dumps(data)
        self._method = "post"
        return self

    def execute(self, **kwargs) -> httpx.Response:
        """
        Execute sync request to Supabase. Use async_execute() for async requests.
        Requests use httpx.Client(). See list of available parameters to pass with
        request at https://www.python-httpx.org/api/#client
        """
        url = f"{self.api_url}/rest/v1/{self._table}?{self._filters}{self._select}"
        log.info("Executing a sync request to...")
        log.info(f"URL: {url}")

        if self._method == "get":
            response = httpx.get(url, headers=self.headers, **kwargs)
        elif self._method == "post":
            if not self._data:
                raise ValueError("Data must be provided for POST requests.")
            response = httpx.post(url, headers=self.headers, data=self._data, **kwargs)
        elif self._method == "put":
            if not self._data:
                raise ValueError("Data must be provided for PUT requests.")
            response = httpx.put(url, headers=self.headers, data=self._data, **kwargs)
        elif self._method == "patch":
            response = httpx.patch(url, headers=self.headers, **kwargs)
        elif self._method == "delete":
            response = httpx.delete(url, headers=self.headers, **kwargs)
        else:
            exception = httpx.RequestError("Unsupported HTTP method.")
            exception.add_note("Valid methods are: get, post, put, patch, or delete.")
            raise exception
        
        log.info("Sync request completed successfully.")
        return response
    
    async def async_execute(self, **kwargs) -> Coroutine:
        """
        Execute async request to Supabase. Use execute() for sync requests.
        Requests use httpx.AsyncClient(). See list of available parameters to pass with
        request at https://www.python-httpx.org/api/#asyncclient
        """
        url = f"{self.api_url}/rest/v1/{self._table}?{self._filters}{self._select}"
        log.info("Executing an async request to...")
        log.info(f"URL: {url}")

        async with httpx.AsyncClient() as client:
            if self._method == "get":
                response = await client.get(url, headers=self.headers, **kwargs)
            elif self._method == "post":
                if not self._data:
                    raise ValueError("Data must be provided for POST requests.")
                response = await client.post(url, headers=self.headers,data=self._data, **kwargs)
            elif self._method == "put":
                if not self._data:
                    raise ValueError("Data must be provided for PUT requests.")
                response = await client.put(url, headers=self.headers, data=self._data **kwargs)
            elif self._method == "patch":
                response = await client.patch(url, headers=self.headers, **kwargs)
            elif self._method == "delete":
                response = await client.delete(url, headers=self.headers, **kwargs)
            else:
                exception = httpx.RequestError("Unsupported HTTP method.")
                exception.add_note("Valid methods are: get, post, put, patch, or delete.")
                raise exception
            
            log.info("Async request completed successfully.")
            return response
