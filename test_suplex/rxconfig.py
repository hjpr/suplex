import os
from dotenv import load_dotenv

load_dotenv()

import reflex as rx

config = rx.Config(
    app_name="test_suplex",
    plugins=[
        rx.plugins.sitemap.SitemapPlugin(),
        rx.plugins.TailwindV4Plugin(),
    ],
    suplex={
        "api_url": os.environ.get("api_url", ""),
        "api_key": os.environ.get("api_key", ""),
        "jwt_secret": os.environ.get("jwt_secret") or None,
        "service_role": os.environ.get("service_role") or None,
        "secret_api_key": os.environ.get("secret_api_key") or None,
        "let_jwt_expire": True,
        "debug": False,
    },
)
