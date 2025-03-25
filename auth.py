import httpx
import jwt
import reflex as rx
import rich

from typing import Any, Literal, Mapping, Optional

class Auth(rx.Base):
    """
    Stores user authentication information.

    Handles user requests in a way to allow for enforcing login flows,
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
            access_token,
            name="access_token",
            path="/",
            secure=True,
            same_site="lax",
            domain=None
            )
        self.refresh_token = rx.Cookie(
            refresh_token,
            name="access_token",
            path="/",
            secure=True,
            same_site="lax",
            domain=None
            )
        self._user_data = None

    def sign_up_with_email(
            self,
            email: Optional[str] = None,
            phone: Optional[str] = None,
            password: str = "",
            options: Optional[dict[str, Any]] = None,
        ) -> httpx.Response:
        """
        Sign up a user with email or phone, and password.
        - **email**: *str* - The email address of the user.
        - **phone**: *str* - The phone number of the user.
        - **password**: *str* - The password for the user.
        - **options**: *dict* - (Optional) Extra options for the signup process.
            - **email_redirect_to**: *str* - Only for email signups. The redirect URL embedded in the email link. Must be a configured redirect URL for your Supabase instance.
            - **data**: *dict* - A custom data object to store additional user metadata.
            - **captcha_token**: *str* - A token from a captcha provider.
            - **channel**: *str* - The channel to use for verification. Can be "email" or "sms".
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

        return response
        
    def sign_in_with_password(
            self,
            email: Optional[str] = None,
            phone: Optional[str] = None,
            password: str = "",
            options: Optional[dict[str, Any]] = None,
        ) -> None:
        """
        Sign user in with email or phone, and password.

        https://supabase.com/docs/reference/python/auth-signinwithpassword
        - **email**: *str* - The email address of the user.
        - **phone**: *str* - The phone number of the user.
        - **password**: *str* - The password for the user.
        - **options**: *dict* - (Optional) Extra options for the signup process.
            - **captcha_token**: *str* - A token from a captcha provider.
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
        self._user_data = response.json()["user"]

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
        ) -> None:
        """
        Sign user in with OAuth provider.

        https://supabase.com/docs/reference/python/auth-signinwithoauth

        https://supabase.com/docs/guides/auth/social-login
        - **provider**: *str* - Supported OAuth provider by Supabase.
        - **options**: *dict* - (Optional) Extra options for the signup process.
            - **redirect_to**: *str* - The redirect URL after authentication.
            - **scopes**: *list[str]* - A list of scopes to request from the provider.
            - **query_params**: *dict* - A dictionary of query parameters to include in the OAuth request.
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
        response.raise_for_status()

    def get_user(self, jwt_: Optional[str] = "") -> dict[str, Any]:
        """
        Takes in an optional access token JWT. If no JWT is provided, the JWT from the current session is used.

        https://supabase.com/docs/reference/python/auth-getuser
        - **jwt_**: *str* - (Optional) The JWT token to decode.
        """
        if jwt_:
            decoded_jwt = jwt.decode(
                jwt_,
                self._jwt_secret,
                algorithms=["HS256"],
                audience="authenticated",
                )
            return dict(decoded_jwt)
        else:
            if not self.access_token:
                raise ValueError("User has no stored access token.")
            response = httpx.get(
                f"{self.api_url}/auth/v1/user",
                headers={
                    **self.headers,
                    "Authorization": f"Bearer {self.access_token}",
                },
            )
            response.raise_for_status()
            user = response.json()["user"]

            return dict(user)




    def logout(self) -> None:
        """
        Revokes refresh token from endpoint.
        Clears access token, refresh token, and user data locally.

        https://supabase.com/docs/reference/python/auth-signout
        """
        url = f"{self.api_url}/auth/v1/logout"
        headers = {
            **self.headers,
            "Authorization": f"Bearer {self.access_token}",
        }

        response = httpx.post(url, headers=headers)
        response.raise_for_status()

        self.access_token = None
        self.refresh_token = None
        self._user_data = None
