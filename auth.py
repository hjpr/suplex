import httpx
import jwt
import reflex as rx

from typing import Any, Literal, Mapping, Optional


class Auth(rx.Base):
    """
    https://supabase.com/docs/reference/python/auth-api

    Stores user authentication information. Handles user requests in a way to allow for enforcing login flows,
    user sessions, and rate-limiting.
    - **api_url**: *str* - The URL of the API endpoint.
    - **api_key**: *str* - The API key for authentication.
    - **jwt_secret**: *str* - The secret key for signing JWT tokens.
    - **access_token**: *str* - (Optional) The access token for the user session. Can initialize here if token already exists, otherwise token is stored when logging user in.
    - **refresh_token**: *str* - (Optional) The refresh token for the user session. Can initialize here if token already exists, otherwise token is stored when logging user in.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        jwt_secret: str,
        access_token: Optional[str] | None = None,
        refresh_token: Optional[str] | None = None,
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
            domain=None,
        )
        self.refresh_token = rx.Cookie(
            name="access_token",
            path="/",
            secure=True,
            same_site="lax",
            domain=None,
        )

    def sign_up(
        self,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: str = "",
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Sign up a user with email or phone, and password.
        - **email**: *str* - The email address of the user.
        - **phone**: *str* - The phone number of the user.
        - **password**: *str* - The password for the user.
        - **options**: *dict* - (Optional) Extra options for the signup process.
            - **email_redirect_to**: *str* - Only for email signups. The redirect URL embedded in the email link. Must be a configured redirect URL for your Supabase instance.
            - **data**: *dict* - A custom data object to store additional user metadata.
            - **captcha_token**: *str* - A token from a captcha provider.
            - **channel**: *str* - The channel to use for sending messages. Only for phone signups.
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

    def sign_in_with_password(
        self,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: str = "",
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Sign user in with email or phone, and password.
        - **email**: *str* - The email address of the user.
        - **phone**: *str* - The phone number of the user.
        - **password**: *str* - The password for the user.
        - **options**: *dict* - (Optional) Extra options for the signup process.
            - **captcha_token**: *str* - A token from a captcha provider.

        Returns user object of user successfully logged in.
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

        self.access_token = response.json()["access_token"]
        self.refresh_token = response.json()["refresh_token"]
        return response.json()

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
        options: Optional[dict[str, Any]] = None,
    ) -> str | None:
        """
        Sign user in with OAuth provider.
        - **provider**: *str* - Supported OAuth provider by Supabase.
        - **options**: *dict* - (Optional) Extra options for the signup process.
            - **redirect_to**: *str* - The redirect URL after authentication.
            - **scopes**: *list[str]* - A list of scopes to request from the provider.
            - **query_params**: *dict* - A dictionary of query parameters to include in the OAuth request.

        Returns the url redirect location for user to sign in to OAuth provider. Handle with rx.redirect(url)
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
        else:
            response.raise_for_status()

    def get_user(self) -> dict[str, Any] | None:
        """
        Retrieves user object from database. To return current session stored as JWT use get_session().

        Returns the user object.
        """
        if not self.access_token:
            return None

        response = httpx.get(
            f"{self.api_url}/auth/v1/user",
            headers={
                **self.headers,
                "Authorization": f"Bearer {self.access_token}",
            },
        )
        response.raise_for_status()
        user = response.json()

        return dict(user)

    def update_user(
        self,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: Optional[str] = None,
        user_metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Updates user object with new email, phone, password, or user metadata.
        - **email**: *str* - The new email address of the user.
        - **phone**: *str* - The new phone number of the user.
        - **password**: *str* - The new password for the user.
        - **user_metadata**: *dict* - A dictionary of custom user metadata to update.

        Returns the updated user object.
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

        response = httpx.put(url, headers=headers, json=data)
        response.raise_for_status()

        return response.json()

    def get_session(self) -> dict[str, Any] | None:
        """
        Gets current session from the signed JWT token. Will attempt to refresh if token expired.

        Returns claims from JWT token.
        """
        if not self.access_token:
            raise ValueError("Expected access token to retrieve session data.")

        decoded_jwt = jwt.decode(
            self.access_token,
            self._jwt_secret,
            algorithms=["HS256"],
            audience="authenticated",
        )
        return decoded_jwt

    def refresh_session(self) -> dict[str, Any] | None:
        """
        Refreshes current session using the refresh token.

        Sets new access and refresh token to self, and returns current user object.
        """
        if not self.access_token or not self.refresh_token:
            raise ValueError(
                "Expected access and refresh tokens to request new session"
            )

        params = {"grant_type": "refresh_token"}
        json = {"refresh_token": self.refresh_token}
        url = f"{self.api_url}/auth/v1/token?grant_type=refresh_token"

        response = httpx.post(url, headers=self.headers, params=params, json=json)
        response.raise_for_status()

        self.access_token = response.json()["access_token"]
        self.refresh_token = response.json()["refresh_token"]
        return response.json()["user"]

    def get_settings(self) -> dict[str, Any]:
        """
        Retrieves authentication settings for the project.
        """
        response = httpx.get(f"{self.api_url}/auth/v1/settings", headers=self.headers)
        response.raise_for_status()

        settings = response.json()
        return dict(settings)

    def logout(self) -> None:
        """
        Revokes refresh token from endpoint. Clears access token, refresh token, and user data locally.
        """
        url = f"{self.api_url}/auth/v1/logout"
        headers = {
            **self.headers,
            "Authorization": f"Bearer {self.access_token}",
        }

        response = httpx.post(url, headers=headers)
        response.raise_for_status()

        self.access_token = ""
        self.refresh_token = ""
