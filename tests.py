
import asyncio
import logging
import os
import rich
import uuid

from dotenv import load_dotenv
from rich.logging import RichHandler
from suplex import Suplex

# Set up logging. Select INFO, DEBUG, WARNING, ERROR, CRITICAL
logging.basicConfig(
    level="DEBUG",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
log = logging.getLogger("rich")

# Load environment variables from .env file
load_dotenv()
api_url = os.getenv("api_url")
api_key = os.getenv("api_key")
service_role = os.getenv("service_role")

# Set up logging. Select INFO, DEBUG, WARNING, ERROR, CRITICAL
log = logging.getLogger("rich")

supabase = Suplex(
    api_url=api_url,
    api_key=api_key,
    service_role=service_role
    )

async def main():
    try:
        user_id = str(uuid.uuid4())
        async_user_id = str(uuid.uuid4())

        # Check sync insertion
        response = supabase.table("pantry").insert({"user_id": user_id, "meat_seafood": [{"name": "beef"}, {"name": "fish"}]}).execute()
        response = supabase.table("pantry").eq("user_id", user_id).select("*").execute()
        assert response.json()[0]["meat_seafood"][1]["name"] == "fish", f"Expected 'fish', got {response.json()[0]['meat_seafood'][1]['name']}"

        # Check async insertion
        response = await supabase.table("pantry").insert({"user_id": async_user_id, "meat_seafood": [{"name": "beef"}, {"name": "fish"}]}).async_execute()
        response = supabase.table("pantry").eq("user_id", async_user_id).select("*").execute()
        assert response.json()[0]["meat_seafood"][1]["name"] == "fish", f"Expected 'fish', got {response.json()[0]['meat_seafood'][1]['name']}"

    except AssertionError as e:
        log.error(f"Assertion failed: {e}", exc_info=True)
    except Exception as e:
        log.error(f"An error occurred: {e}", exc_info=True)
    else:
        log.info("🎉 🎉 🎉 All tests passed successfully! 🎉 🎉 🎉")


if __name__ == "__main__":
    asyncio.run(main())