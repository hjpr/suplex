
import argparse
import asyncio
import logging
import os
import rich

from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskID
from suplex import Suplex

console = Console()

# Load environment variables from .env file
load_dotenv()
api_url = str(os.getenv("api_url"))
api_key = str(os.getenv("api_key"))
jwt_secret = str(os.getenv("jwt_secret"))
service_role = str(os.getenv("service_role"))
env_email = str(os.getenv("user"))
env_password = str(os.getenv("password"))


supabase = Suplex(
    api_url, 
    api_key,
    jwt_secret,
    service_role=service_role,
    )

def run_user_tests():
    try:
        test_funcs = [
            ("Signup...", signup_test, 1),
            ("Login...", login_test, 1),
        ]
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            transient=True,
        ) as progress:

            main_task = progress.add_task("[green]Running all tests...", total=len(test_funcs))
            for label, func, steps in test_funcs:
                sub_task = progress.add_task(f"[yellow]{label}", total=steps)
                func(progress, sub_task)

                progress.update(main_task, advance=1)

    except AssertionError:
        progress.console.print("\n[bold red] The cake is a lie. [/bold red]") # type: ignore
        console.print_exception()
    except Exception:
        progress.console.print("\n[bold red] That was a joke. HA HA. FAT CHANCE [/bold red]") # type: ignore
        console.print_exception()
    else:
        progress.console.print("\n[bold green] 🎂 This was a triumph. I'm making a note here: HUGE SUCCESS. 🎂 [/bold green]")

def signup_test(progress: Progress, task_id:TaskID) -> None:
    response = supabase.auth.sign_up_with_email(
        email=env_email,
        password=env_password,
        options={
            "email_redirect_to": "localhost:3000/redirect_link",
            "data": {
                "test_data": "test_value",
            },
        },
    )
    
    rich.inspect(response)
    rich.print(response.json())

    progress.update(task_id, advance=1)

def login_test(progress: Progress, task_id: TaskID) -> None:
    supabase.auth.sign_in_with_password(email, password) # type: ignore
    assert supabase.auth.access_token != "None", "Expected access token after login"
    assert supabase.auth.refresh_token != "None", "Expected refresh token after login"

    progress.update(task_id, advance=1)


def run_database_tests():
    try:
        test_funcs = [
            ("Building test table...", build_test_table, 10),  # 10 steps
            ("Insert...", test_insert, 2),
            ("Delete...", test_delete, 1),
            ("Upsert...", test_upsert, 5),
            ("Update...", test_update, 2),
            ("Order...", test_order, 1),
            ("Not Equal...", test_neq, 1),
            ("Greater Than...", test_gt, 1),
            ("Less Than...", test_lt, 1),
            ("Greater Than or Equal...", test_gte, 1),
            ("Less Than or Equal...", test_lte, 1),
            ("Like...", test_like, 1),
            ("ILike...", test_ilike, 1),
        ]
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            transient=True,
        ) as progress:

            main_task = progress.add_task("[green]Running all tests...", total=len(test_funcs))
            for label, func, steps in test_funcs:
                sub_task = progress.add_task(f"[yellow]{label}", total=steps)
                func(progress, sub_task)

                progress.update(main_task, advance=1)

    except AssertionError:
        progress.console.print("\n[bold red] The cake is a lie. [/bold red]") # type: ignore
        console.print_exception()
    except Exception:
        progress.console.print("\n[bold red] That was a joke. HA HA. FAT CHANCE [/bold red]") # type: ignore
        console.print_exception()
    else:
        progress.console.print("\n[bold green] 🎂 This was a triumph. I'm making a note here: HUGE SUCCESS. 🎂 [/bold green]")


def build_test_table(progress:Progress, task_id:TaskID) -> None:
    id = [id for id in range(1, 11)]
    for id in id:
        response = supabase.table("test").upsert(
            {
                "id": id,
                "text": f"test-{id}",
                "json": {
                    f"key-{id}": f"value-{id}",
                },
                "bool": True if id < 5 else False,
                "null": None if id == 3 else "(ツ)"
            }
        ).execute()

        response = supabase.table('test').select('text').eq("text", f"test-{id}").execute()
        assert response.json()[0]['text'] == f"test-{id}", f"Expected 'test-{id}', got {response.json()[0]['text']}"
        
        progress.update(task_id, advance=1)

def test_insert(progress:Progress, task_id:TaskID) -> None:
    supabase.table("test").insert({"id": 11, "text": "insert-test", "json": {"insert": "success"}}).execute()
    response = supabase.table('test').select('*').eq("text", "insert-test").execute()
    assert response.json()[0]['json']["insert"] == "success", f"Expected 'success', got {response.json()[0]['json']['insert']}"
    
    progress.update(task_id, advance=1)

    try:
        supabase.table("test").insert({"id": 11, "text": "insert-test", "json": {"insert": "success"}}).execute()
    except Exception:
        pass
    else:
        raise AssertionError("Expected an error when inserting a duplicate record.")
    
    progress.update(task_id, advance=1)

def test_delete(progress:Progress, task_id:TaskID) -> None:
    supabase.table("test").delete().eq("id", 11).execute()

    response = supabase.table("test").select("*").eq("id", 11).execute()
    assert len(response.json()) == 0, f"Expected no records, but found {len(response.json())}"
    
    progress.update(task_id, advance=1)

def test_upsert(progress:Progress, task_id:TaskID) -> None:
    supabase.table("test").upsert({"id": 1, "text": "upsert-1"}).execute()

    response = supabase.table('test').select('*').eq("id", 1).execute()
    assert response.json()[0]["text"] == "upsert-1", f"Expected 'upsert-1', got {response.json()[0]['text']}"
    
    progress.update(task_id, advance=1)

    response = supabase.table("test").upsert({"id":11, "text": "upsert-11"}).execute()
    assert response.json()[0]["text"] == "upsert-11", f"Expected 'upsert-11', got {response.json()[0]['text']}"

    progress.update(task_id, advance=1)

    response = supabase.table("test").upsert({"id":11, "text": "upsert-12"}, return_="minimal").execute()
    assert response.text == "", f"Expected empty response, got: {response.text}"

    progress.update(task_id, advance=1)

    response = supabase.table('test').select('*').eq("id", 11).execute()
    assert response.json()[0]["text"] == "upsert-12", f"Expected 'upsert-12', got {response.json()[0]['text']}"
    
    progress.update(task_id, advance=1)

    supabase.table("test").delete().eq("id", 11).execute()

    progress.update(task_id, advance=1)

def test_update(progress:Progress, task_id:TaskID) -> None:
    response = supabase.table("test").update({"text": "updated-test"}).eq("id", 1).execute()
    assert response.json()[0]["text"] == "updated-test", f"Expected 'updated-test', got {response.json()['text']}"
    
    progress.update(task_id, advance=1)

    response = supabase.table('test').select('*').eq("id", 1).execute()
    assert response.json()[0]["text"] == "updated-test", f"Expected 'updated-test', got {response.json()[0]['text']}"
    
    progress.update(task_id, advance=1)

def test_order(progress:Progress, task_id:TaskID) -> None:
    response = supabase.table('test').select('*').order('id').execute()
    assert response.json()[0]["id"] == 1, f"Expected id 1, got {response.json()[0]['id']}"
    assert len(response.json()) == 10, f"Expected 10 records, got {len(response.json())}"
    
    progress.update(task_id, advance=1)

def test_neq(progress:Progress, task_id:TaskID) -> None:
    response = supabase.table('test').select('*').neq("id", 1).execute()
    assert len(response.json()) == 9, f"Expected 9 records, got {len(response.json())}"
    
    progress.update(task_id, advance=1)

def test_gt(progress:Progress, task_id:TaskID) -> None:
    response = supabase.table('test').select('*').gt("id", 5).execute()
    assert len(response.json()) == 5, f"Expected 5 records, got {len(response.json())}"
    
    progress.update(task_id, advance=1)

def test_lt(progress:Progress, task_id:TaskID) -> None:
    response = supabase.table('test').select('*').lt("id", 5).execute()
    assert len(response.json()) == 4, f"Expected 4 records, got {len(response.json())}"

    progress.update(task_id, advance=1)

def test_gte(progress:Progress, task_id:TaskID) -> None:
    response = supabase.table('test').select('*').gte("id", 5).execute()
    assert len(response.json()) == 6, f"Expected 6 records, got {len(response.json())}"

    progress.update(task_id, advance=1)

def test_lte(progress:Progress, task_id:TaskID) -> None:
    response = supabase.table('test').select('*').lte("id", 5).execute()
    assert len(response.json()) == 5, f"Expected 5 records, got {len(response.json())}"

    progress.update(task_id, advance=1)

def test_like(progress:Progress, task_id:TaskID) -> None:
    supabase.table("test").update({"text":"Test-3"}).eq("id", 3).execute()
    response = supabase.table('test').select('*').like("text", "Test-3").execute()
    assert len(response.json()) == 1, f"Expected 1 record, got {len(response.json())}"

    progress.update(task_id, advance=1)

def test_ilike(progress:Progress, task_id:TaskID) -> None:
    response = supabase.table('test').select('*').ilike("text", "test-3").execute()
    assert len(response.json()) == 1, f"Expected 1 record, got {len(response.json())}"

    progress.update(task_id, advance=1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Suplex test suite.")
    parser.add_argument("-u", "--user", action="store_true", help="Run user authentication tests")
    parser.add_argument("-d", "--database", action="store_true", help="Run database tests")

    args = parser.parse_args()

    if args.user:
        run_user_tests()
    if args.database:
        run_database_tests()

    # If no arguments are passed, run both
    if not args.user and not args.database:
        run_user_tests()
        run_database_tests()