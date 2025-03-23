
import asyncio
import logging
import os
import rich

from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from suplex import Suplex

console = Console()

# Load environment variables from .env file
load_dotenv()
api_url = os.getenv("api_url")
api_key = os.getenv("api_key")
service_role = os.getenv("service_role")


supabase = Suplex(
    api_url=api_url,
    api_key=api_key,
    service_role=service_role
    )

def run_tests():
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
                if steps:
                    sub_task = progress.add_task(f"[yellow]{label}", total=steps)
                    func(progress, sub_task)
                else:
                    func(progress, None)

                progress.update(main_task, advance=1)

    except AssertionError:
        progress.console.print("\n[bold red] The cake is a lie. [/bold red]")
        console.print_exception()
    except Exception:
        progress.console.print("\n[bold red] That was a joke. HA HA. FAT CHANCE [/bold red]")
        console.print_exception()
    else:
        progress.console.print("\n[bold green] 🎂 This was a triumph. I'm making a note here: HUGE SUCCESS. 🎂 [/bold green]")


def build_test_table(progress:Progress=None, task_id=None) -> None:
    # Build test table
    id = [id for id in range(1, 11)]
    for id in id:
        supabase.table("test").upsert(
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
        # Check that record inserted
        response = supabase.table('test').select('text').eq("text", f"test-{id}").execute()
        assert response.json()[0]['text'] == f"test-{id}", f"Expected 'test-{id}', got {response.json()[0]['text']}"
        if progress and task_id:
            progress.update(task_id, advance=1)

def test_insert(progress:Progress=None, task_id=None) -> None:
    # Test insert and check that record inserted
    supabase.table("test").insert({"id": 11, "text": "insert-test", "json": {"insert": "success"}}).execute()
    response = supabase.table('test').select('*').eq("text", "insert-test").execute()
    assert response.json()[0]['json']["insert"] == "success", f"Expected 'success', got {response.json()[0]['json']['insert']}"
    if progress and task_id:
        progress.update(task_id, advance=1)

    # Ensure duplicate insert fails
    try:
        supabase.table("test").insert({"id": 11, "text": "insert-test", "json": {"insert": "success"}}).execute()
    except Exception:
        pass
    else:
        raise AssertionError("Expected an error when inserting a duplicate record.")
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_delete(progress:Progress=None, task_id=None) -> None:
    # Test delete and check that record deleted
    supabase.table("test").delete().eq("id", 11).execute()
    response = supabase.table("test").select("*").eq("id", 11).execute()
    assert len(response.json()) == 0, f"Expected no records, but found {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_upsert(progress:Progress=None, task_id=None) -> None:
    # Check that upsert updates when existing record found.
    supabase.table("test").upsert({"id": 1, "text": "upsert-1"}).execute()
    response = supabase.table('test').select('*').eq("id", 1).execute()
    assert response.json()[0]["text"] == "upsert-1", f"Expected 'upsert-1', got {response.json()[0]['text']}"
    if progress and task_id:
        progress.update(task_id, advance=1)

    # Check that upsert inserts when no record found and that it returns updated row.
    response = supabase.table("test").upsert({"id":11, "text": "upsert-11"}).execute()
    assert response.json()[0]["text"] == "upsert-11", f"Expected 'upsert-11', got {response.json()[0]['text']}"
    if progress and task_id:
        progress.update(task_id, advance=1)

    # Check that upsert returns no data when return_="minimal"
    response = supabase.table("test").upsert({"id":11, "text": "upsert-12"}, return_="minimal").execute()
    assert response.text == "", f"Expected empty response, got: {response.text}"
    if progress and task_id:
        progress.update(task_id, advance=1)

    # Ensure that upsert wrote to the database
    response = supabase.table('test').select('*').eq("id", 11).execute()
    assert response.json()[0]["text"] == "upsert-12", f"Expected 'upsert-12', got {response.json()[0]['text']}"
    if progress and task_id:
        progress.update(task_id, advance=1)

    # Clean entry up to avoid duplicate errors
    supabase.table("test").delete().eq("id", 11).execute()
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_update(progress:Progress=None, task_id=None) -> None:
    # Test update - returns the updated record
    response = supabase.table("test").update({"text": "updated-test"}).eq("id", 1).execute()
    assert response.json()[0]["text"] == "updated-test", f"Expected 'updated-test', got {response.json()['text']}"
    if progress and task_id:
        progress.update(task_id, advance=1)

    # Test that update wrote to the database
    response = supabase.table('test').select('*').eq("id", 1).execute()
    assert response.json()[0]["text"] == "updated-test", f"Expected 'updated-test', got {response.json()[0]['text']}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_order(progress:Progress=None, task_id=None) -> None:
    # Test order by
    response = supabase.table('test').select('*').order('id').execute()
    assert response.json()[0]["id"] == 1, f"Expected id 1, got {response.json()[0]['id']}"
    assert len(response.json()) == 10, f"Expected 10 records, got {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_neq(progress:Progress=None, task_id=None) -> None:
    # Test not equal
    response = supabase.table('test').select('*').neq("id", 1).execute()
    assert len(response.json()) == 9, f"Expected 9 records, got {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_gt(progress:Progress=None, task_id=None) -> None:
    # Test greater than or equal to
    response = supabase.table('test').select('*').gt("id", 5).execute()
    assert len(response.json()) == 5, f"Expected 5 records, got {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_lt(progress:Progress=None, task_id=None) -> None:
    # Test less than
    response = supabase.table('test').select('*').lt("id", 5).execute()
    assert len(response.json()) == 4, f"Expected 4 records, got {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_gte(progress:Progress=None, task_id=None) -> None:
    # Test greater than or equal to
    response = supabase.table('test').select('*').gte("id", 5).execute()
    assert len(response.json()) == 6, f"Expected 6 records, got {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_lte(progress:Progress=None, task_id=None) -> None:
    # Test less than or equal to
    response = supabase.table('test').select('*').lte("id", 5).execute()
    assert len(response.json()) == 5, f"Expected 5 records, got {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_like(progress:Progress=None, task_id=None) -> None:
    # Test like - case sensitive
    supabase.table("test").update({"text":"Test-3"}).eq("id", 3).execute()
    response = supabase.table('test').select('*').like("text", "Test-3").execute()
    assert len(response.json()) == 1, f"Expected 1 record, got {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

def test_ilike(progress:Progress=None, task_id=None) -> None:
    # Test ilike - case insensitive
    response = supabase.table('test').select('*').ilike("text", "test-3").execute()
    assert len(response.json()) == 1, f"Expected 1 record, got {len(response.json())}"
    if progress and task_id:
        progress.update(task_id, advance=1)

if __name__ == "__main__":
    run_tests()