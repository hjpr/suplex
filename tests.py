
import asyncio
import logging
import os
import rich
import uuid

from dotenv import load_dotenv
from rich.logging import RichHandler
from suplex import Suplex

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
    service_role=service_role,
    headers={
        "apikey": api_key,
        "Authorization": f"Bearer {service_role}",
        "Content-Type": "application/json"
        }
    )

async def main():
    try:
        user_id = str(uuid.uuid4())
        async_user_id = str(uuid.uuid4())
        # Insert data into the pantry table
        response = supabase.table("pantry").insert({"user_id": user_id, "meat_seafood": [{"name": "beef"}, {"name": "fish"}]}).execute()
        # Retrieve that data from the pantry table where user_id matches and check the response.
        response = supabase.table("pantry").eq("user_id", user_id).select("*").execute()
        assert response.json()[0]["meat_seafood"][1]["name"] == "fish", f"Expected 'fish', got {response.json()[0]['meat_seafood'][1]['name']}"




        # response = await supabase.table("pantry").insert({"user_id": async_user_id, "meat_seafood": [{"name": "beef"}, {"name": "fish"}]}).async_execute()
        # response = supabase.table("pantry").select("*").execute()
        # response = await supabase.table("pantry").select("*").async_execute()
    except AssertionError as e:
        log.error(f"Assertion failed: {e}", exc_info=True)
    except Exception as e:
        log.error(f"An error occurred: {e}", exc_info=True)
    else:
        log.info("🎉 🎉 🎉 All tests passed successfully! 🎉 🎉 🎉")



if __name__ == "__main__":
    asyncio.run(main())