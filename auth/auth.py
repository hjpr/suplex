import httpx
import jwt
import reflex as rx

from typing import Any, Dict, Literal, Mapping, Optional


class Auth(rx.Base):
    """
    Authentication handler for Supabase.
    
    This class provides methods to handle authentication flows with Supabase,
    including user registration, login, session management, and token handling.
    
    Args:
        api_url: The URL of the Supabase API endpoint.
        api_key: The Supabase API key for authentication.
        jwt_secret: The secret key for decoding and verifying JWT tokens.
        domain: Optional domain for cookies. Defaults to the current domain if not provided.
        
    References:
        https://supabase.com/docs/reference/python/auth-api
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        jwt_secret: str,
        domain: Optional[str] = None,
    ):
        super().__init__()
        self.api_url = api_url
        self.api_key = api_key
        self._jwt_secret = jwt_secret
        self.headers: Mapping[str, str] = {"apikey": self.api_key}
        self.access_token = rx.Cookie(
            name="access_token",
            path="/",
            secure=True,
            same_site="lax",
            domain=domain,
        )
        self.refresh_token = rx.Cookie(
            name="refresh_token",
            path="/",
            secure=True,
            same_site="lax",
            domain=domain,
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
        url = f"{self.api_url}/auth/v1/signup"
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

        response = httpx.post(url, headers=self.headers, json=data)
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
        url = f"{self.api_url}/auth/v1/token?grant_type=password"
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
            if "captcha_token" in options:
                data["captcha_token"] = options.pop("captcha_token")

        response = httpx.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        
        response_data = response.json()
        self.access_token = response_data["access_token"]
        self.refresh_token = response_data["refresh_token"]
        return response_data

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
                
        Returns:
            A URL string to redirect the user to for OAuth authentication.
            
        Raises:
            ValueError: If the provider is not supported.
            httpx.HTTPStatusError: If the API request fails.
            
        Note:
            The returned URL should be used with rx.redirect() to redirect
            the user to the OAuth provider's login page.
        """
        data = {}
        url = f"{self.api_url}/auth/v1/authorize"
        data["provider"] = provider
        if options:
            if "redirect_to" in options:
                data["redirect_to"] = options.pop("redirect_to")
            if "scopes" in options:
                data["scopes"] = options.pop("scopes")
            if "query_params" in options:
                data["query_params"] = options.pop("query_params")

        response = httpx.get(url, headers=self.headers, params=data)

        if response.status_code == 302:
            return response.headers["location"]
        
        # If not a redirect response, check for other errors
        response.raise_for_status()
        raise ValueError("Expected a redirect response from OAuth provider, but none was received.")

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
        try:
            session = self.get_session()
            if not session:
                return None
                
            response = httpx.get(
                f"{self.api_url}/auth/v1/user",
                headers={
                    **self.headers,
                    "Authorization": f"Bearer {self.access_token}",
                },
            )
            response.raise_for_status()
            return response.json()
            
        except Exception:
            # Clear tokens on any error
            self.access_token = ""
            self.refresh_token = ""
            return None

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
            
        Note:
            At least one parameter must be provided to update the user.
            Changes to email may require verification depending on Supabase settings.
        """
        if not self.access_token:
            raise ValueError("Expected access token to update user information.")

        data = {}
        url = f"{self.api_url}/auth/v1/user"
        headers = {
            **self.headers,
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
        response.raise_for_status()

        return response.json()

    def get_session(self) -> Optional[Dict[str, Any]]:
        """
        Get the current session data from the JWT access token.
        
        This method decodes the JWT access token to extract the session claims.
        If the token is expired, it will automatically attempt to refresh the session.
        
        Args:
            None
            
        Returns:
            Dictionary containing the JWT claims (session data) if valid, or None if:
            - No access token exists
            - Token is invalid or malformed
            - Token is expired and refresh attempt fails
            
        Note:
            This method is used internally to verify authentication status
            before making authenticated API calls.
        """
        try:
            return self._get_claims()
        except jwt.ExpiredSignatureError:
            # If token is expired, try to refresh
            user = self.refresh_session()
            if user and self.access_token:
                try:
                    return self._get_claims()
                except Exception:
                    return None
            return None
        except Exception:
            # Handle any other JWT errors (invalid token, etc.)
            return None
        
    def _get_claims(self) -> Dict[str, Any]:
        """
        Decode and verify the JWT access token.
        
        Args:
            None
            
        Returns:
            Dictionary containing the decoded JWT claims
            
        Raises:
            jwt.PyJWTError: If token decoding fails for any reason
            
        Note:
            This is an internal method used by get_session().
        """
        if not self.access_token:
            raise ValueError("No access token available to decode")
            
        decoded_jwt = jwt.decode(
            self.access_token,
            self._jwt_secret,
            algorithms=["HS256"],
            audience="authenticated",
        )
        return decoded_jwt

    def refresh_session(self) -> Optional[Dict[str, Any]]:
        """
        Refresh the authentication session using the refresh token.
        
        This method uses the stored refresh token to obtain a new access token
        when the current one expires. It automatically updates the token storage
        if successful.
        
        Args:
            None
            
        Returns:
            Dictionary containing the user data if refresh was successful, or None if:
            - No refresh token exists
            - Refresh token is expired or invalid
            - API request fails for any reason
            
        Note:
            This method is called automatically by get_session() when the
            access token has expired. It will clear both tokens on failure.
        """
        if not self.refresh_token:
            return None
            
        url = f"{self.api_url}/auth/v1/token?grant_type=refresh_token"
        
        try:
            response = httpx.post(
                url, 
                headers=self.headers, 
                json={"refresh_token": self.refresh_token}
            )
            response.raise_for_status()

            data = response.json()
            if data and all(key in data for key in ["user", "access_token", "refresh_token"]):
                # Update tokens
                self.access_token = data["access_token"]
                self.refresh_token = data["refresh_token"]
                return data["user"]
            else:
                # Clear tokens if response is incomplete
                self.access_token = ""
                self.refresh_token = ""
                return None
                
        except Exception:
            # Clear tokens on any error
            self.access_token = ""
            self.refresh_token = ""
            return None

    def get_settings(self) -> Dict[str, Any]:
        """
        Retrieve the authentication settings for the Supabase project.
        
        This method fetches the authentication configuration settings from
        the Supabase API, including enabled providers and security settings.
        
        Args:
            None
            
        Returns:
            Dictionary containing the authentication settings
            
        Raises:
            httpx.HTTPStatusError: If the API request fails
            
        Note:
            This method does not require authentication - it uses the API key only.
        """
        response = httpx.get(
            f"{self.api_url}/auth/v1/settings", 
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()

    def logout(self) -> None:
        """
        Log out the current user and invalidate the session.
        
        This method revokes the refresh token on the server and
        clears both tokens from local storage. After calling this method,
        the user will need to authenticate again to access protected resources.
        
        Args:
            None
            
        Returns:
            None
            
        Raises:
            httpx.HTTPStatusError: If the API request fails
            
        Note:
            This method clears tokens even if the API request fails,
            ensuring the user is always logged out locally.
        """
        # Only attempt server-side logout if we have an access token
        if self.access_token:
            url = f"{self.api_url}/auth/v1/logout"
            headers = {
                **self.headers,
                "Authorization": f"Bearer {self.access_token}",
            }

            try:
                response = httpx.post(url, headers=headers)
                response.raise_for_status()
            except Exception:
                # Continue with local logout even if server request fails
                pass

        # Always clear tokens
        self.access_token = ""
        self.refresh_token = ""
