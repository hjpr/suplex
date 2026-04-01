import json
import os
import time
import uuid
import httpx
import reflex as rx
from dataclasses import dataclass
from rich.console import Console
from suplex import Suplex

console = Console()

TEST_PASSWORD = "SupleXTest123!"

TEST_NAMES = [
    "sign_up",
    "sign_in_with_password",
    "get_user",
    "update_user — set metadata",
    "update_user — modify metadata",
    "update_user — clear metadata",
    "admin_delete_user",
    "verify_sign_in_rejected",
]

REQUIRES_AUTH = [False, False, True, True, True, True, True, True]
NUM_TESTS = len(TEST_NAMES)

@dataclass
class TestResult:
    name: str = ""
    status: str = "pending"
    duration_str: str = "—"
    detail: str = ""


def _blank_results() -> list[TestResult]:
    return [TestResult(name=n) for n in TEST_NAMES]


class TestState(Suplex):
    results: list[TestResult] = _blank_results()
    next_step: int = 0
    is_running: bool = False
    failed_early: bool = False
    test_email: str = ""
    test_user_id: str = ""
    has_started: bool = False
    last_user_data: dict = {}

    @rx.var
    def button_label(self) -> str:
        if self.is_running:
            return "Running…"
        if self.next_step >= NUM_TESTS:
            return "Finished"
        return "Run Test Step"

    @rx.var
    def button_disabled(self) -> bool:
        return self.is_running or (self.has_started and self.next_step >= NUM_TESTS)

    @rx.var
    def claims_display(self) -> list[dict]:
        def fmt(v) -> str:
            if v is None:
                return "—"
            if isinstance(v, dict):
                return json.dumps(v)
            return str(v)

        return [
            {"section": "Auth Status", "label": "", "value": ""},
            {"section": "", "label": "Authenticated", "value": str(self.user_is_authenticated)},
            {"section": "", "label": "Token Expired", "value": str(self.user_token_expired)},
            {"section": "", "label": "AAL", "value": fmt(self.user_aal)},
            {"section": "Identity", "label": "", "value": ""},
            {"section": "", "label": "User ID", "value": fmt(self.user_id)},
            {"section": "", "label": "Email", "value": fmt(self.user_email)},
            {"section": "", "label": "Phone", "value": fmt(self.user_phone)},
            {"section": "", "label": "Role", "value": fmt(self.user_role)},
            {"section": "", "label": "Audience", "value": fmt(self.user_audience)},
            {"section": "", "label": "Anonymous", "value": str(self.user_is_anonymous)},
            {"section": "Session", "label": "", "value": ""},
            {"section": "", "label": "Session ID", "value": fmt(self.claims_session_id)},
            {"section": "", "label": "Issued At", "value": fmt(self.claims_issued_at)},
            {"section": "", "label": "Expires At", "value": fmt(self.claims_expire_at)},
            {"section": "", "label": "Issuer", "value": fmt(self.claims_issuer)},
            {"section": "Metadata", "label": "", "value": ""},
            {"section": "", "label": "User Metadata", "value": fmt(self.last_user_data.get("user_metadata", self.user_metadata))},
            {"section": "", "label": "App Metadata", "value": fmt(self.app_metadata)},
            {"section": "", "label": "Updated At", "value": fmt(self.last_user_data.get("updated_at"))},
        ]

    # Helpers

    def _set_result(self, i: int, status: str, elapsed: float = 0.0, detail: str = "") -> None:
        updated = list(self.results)
        updated[i] = TestResult(
            name=TEST_NAMES[i],
            status=status,
            duration_str=f"{elapsed:.1f} ms" if elapsed > 0 else "—",
            detail=detail,
        )
        self.results = updated

    # Test runners

    def _run_sign_up(self) -> str:
        console.print("[dim]\\[sign_up][/dim] calling sign_up()")
        data = self.sign_up(email=self.test_email, password=TEST_PASSWORD)
        console.print(f"[dim]\\[sign_up][/dim] response keys: [cyan]{list(data.keys())}[/cyan]")
        user = data.get("user") or data
        user_id = user.get("id")
        if not user_id:
            raise AssertionError("No user id in sign-up response")
        self.test_user_id = user_id
        if data.get("access_token"):
            self.set_tokens(data["access_token"], data["refresh_token"])
        return f"user_id={user_id[:8]}…"

    def _run_sign_in(self) -> str:
        console.print("[dim]\\[sign_in][/dim] calling sign_in_with_password()")
        data = self.sign_in_with_password(email=self.test_email, password=TEST_PASSWORD)
        console.print(f"[dim]\\[sign_in][/dim] response keys: [cyan]{list(data.keys())}[/cyan]")
        if "access_token" not in data or "refresh_token" not in data:
            raise AssertionError("Missing tokens in sign-in response")
        self.test_user_id = data["user"]["id"]
        return f"user_id={self.test_user_id[:8]}…"

    def _run_get_user(self) -> str:
        console.print("[dim]\\[get_user][/dim] calling get_user()")
        data = self.get_user()
        console.print(f"[dim]\\[get_user][/dim] response keys: [cyan]{list(data.keys()) if data else None}[/cyan]")
        if not data:
            raise AssertionError("No user data returned")
        if data.get("email") != self.test_email:
            raise AssertionError(f"Email mismatch: got {data.get('email')!r}")
        self.last_user_data = data
        return f"email={data['email']}"

    def _run_update_set(self) -> str:
        console.print("[dim]\\[update_set][/dim] setting metadata")
        data = self.update_user(user_metadata={"display_name": "Suplex Tester", "theme": "dark"})
        meta = data.get("user_metadata") or {}
        if meta.get("display_name") != "Suplex Tester":
            raise AssertionError(f"display_name not set: {meta!r}")
        self.last_user_data = data
        return "display_name='Suplex Tester', theme='dark'"

    def _run_update_modify(self) -> str:
        console.print("[dim]\\[update_modify][/dim] modifying metadata")
        data = self.update_user(user_metadata={"display_name": "Suplex Tester Modified", "theme": "light"})
        meta = data.get("user_metadata") or {}
        if meta.get("display_name") != "Suplex Tester Modified":
            raise AssertionError(f"display_name not modified: {meta!r}")
        self.last_user_data = data
        return "display_name='Suplex Tester Modified', theme='light'"

    def _run_update_clear(self) -> str:
        console.print("[dim]\\[update_clear][/dim] clearing metadata")
        data = self.update_user(user_metadata={"display_name": None, "theme": None})
        meta = data.get("user_metadata") or {}
        if meta.get("display_name") is not None:
            raise AssertionError(f"display_name not cleared: {meta!r}")
        self.last_user_data = data
        return "metadata cleared"

    def _run_admin_delete(self) -> str:
        console.print("[dim]\\[admin_delete][/dim] deleting user via service role")
        service_role = os.environ.get("service_role")
        if not service_role:
            raise Exception("service_role not set in .env")
        if not self.test_user_id:
            raise Exception("No test_user_id stored — earlier tests failed")

        response = httpx.delete(
            f"{self._api_url}/auth/v1/admin/users/{self.test_user_id}",
            headers={
                "apikey": self._api_key,
                "Authorization": f"Bearer {service_role}",
            },
        )
        console.print(f"[dim]\\[admin_delete][/dim] delete status: [cyan]{response.status_code}[/cyan]")
        response.raise_for_status()
        return f"deleted user_id={self.test_user_id[:8]}…"

    def _run_verify_sign_in_rejected(self) -> str:
        console.print("[dim]\\[verify_sign_in_rejected][/dim] attempting sign-in for deleted user")
        check = httpx.post(
            f"{self._api_url}/auth/v1/token?grant_type=password",
            headers={"apikey": self._api_key},
            json={"email": self.test_email, "password": TEST_PASSWORD},
        )
        console.print(f"[dim]\\[verify_sign_in_rejected][/dim] status: [cyan]{check.status_code}[/cyan]")
        if check.status_code not in (400, 422):
            raise AssertionError(f"Expected sign-in to fail after deletion (got {check.status_code})")
        return "sign-in correctly rejected ✓"

    # Event handlers

    def _init_run(self) -> None:
        self._reset_state()
        self.test_email = f"suplex_test_{uuid.uuid4().hex[:8]}@example.com"
        self.has_started = True
        console.rule("[bold blue]Suplex Test Suite[/bold blue]")
        console.print(f"[dim]email:[/dim] [cyan]{self.test_email}[/cyan]\n")

    def _test_fns(self) -> list:
        return [
            self._run_sign_up,
            self._run_sign_in,
            self._run_get_user,
            self._run_update_set,
            self._run_update_modify,
            self._run_update_clear,
            self._run_admin_delete,
            self._run_verify_sign_in_rejected,
        ]

    def _run_step(self, i: int) -> None:
        start = time.monotonic()
        try:
            detail = self._test_fns()[i]()
            elapsed = (time.monotonic() - start) * 1000
            console.print(f"[bold green]  ✓ PASS[/bold green] [white]{TEST_NAMES[i]}[/white] [dim]({elapsed:.1f}ms) — {detail}[/dim]")
            self._set_result(i, "pass", elapsed, detail)
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            console.print(f"[bold red]  ✗ FAIL[/bold red] [white]{TEST_NAMES[i]}[/white] [dim]({elapsed:.1f}ms)[/dim]\n         [red]{exc}[/red]")
            self._set_result(i, "fail", elapsed, str(exc))
            self.failed_early = True

    def _reset_state(self) -> None:
        self.next_step = 0
        self.test_email = ""
        self.test_user_id = ""
        self.results = _blank_results()
        self.access_token = ""
        self.refresh_token = ""
        self.failed_early = False
        self.last_user_data = {}
        self.has_started = False

    @rx.event
    def reset_tests(self):
        self._reset_state()

    @rx.event
    async def run_all_tests(self):
        if self.is_running:
            return
        self._init_run()
        yield
        for i in range(NUM_TESTS):
            if self.failed_early and REQUIRES_AUTH[i]:
                self._set_result(i, "skip", detail="Skipped — earlier test failed")
                self.next_step += 1
                yield
                continue
            self.is_running = True
            self._set_result(i, "running")
            yield
            self._run_step(i)
            self.next_step += 1
            self.is_running = False
            yield

    @rx.event
    async def run_next_test(self):
        if self.is_running:
            return

        i = self.next_step

        if i >= NUM_TESTS:
            return

        if i == 0:
            self._init_run()

        if self.failed_early and REQUIRES_AUTH[i]:
            self._set_result(i, "skip", detail="Skipped — earlier test failed")
            self.next_step += 1
            return

        self.is_running = True
        self._set_result(i, "running")
        yield

        self._run_step(i)
        self.next_step += 1
        self.is_running = False


# UI

def status_badge(status: rx.Var) -> rx.Component:
    color = rx.match(
        status,
        ("pending", "gray"),
        ("running", "blue"),
        ("pass", "green"),
        ("fail", "red"),
        ("skip", "orange"),
        "gray",
    )
    label = rx.match(
        status,
        ("pending", "Pending"),
        ("running", "Running…"),
        ("pass", "Pass"),
        ("fail", "Fail"),
        ("skip", "Skip"),
        "?",
    )
    return rx.badge(label, color_scheme=color, variant="solid", size="1")


def result_row(result: TestResult) -> rx.Component:
    return rx.table.row(
        rx.table.cell(rx.text(result.name, size="2", weight="medium"), class_name="w-48"),
        rx.table.cell(status_badge(result.status), class_name="w-20"),
        rx.table.cell(rx.text(result.duration_str, size="2", color="gray"), class_name="w-24"),
        rx.table.cell(
            rx.text(result.detail, size="1", color="gray", class_name="font-mono")
        ),
    )


def claim_row(item: dict) -> rx.Component:
    return rx.cond(
        item["section"] != "",
        rx.table.row(
            rx.table.cell(
                rx.text(
                    item["section"],
                    size="1",
                    weight="bold",
                    color="indigo",
                    class_name="uppercase tracking-wider",
                ),
                col_span=2,
                class_name="pt-3 pb-1.5 border-b border-indigo-200",
            ),
        ),
        rx.table.row(
            rx.table.cell(
                rx.text(item["label"], size="2", color="gray", weight="medium"),
                class_name="w-36 py-0.5 align-middle",
            ),
            rx.table.cell(
                rx.text(item["value"], size="2", class_name="font-mono break-all"),
                class_name="py-0.5 align-middle",
            ),
        ),
    )


def tests_panel() -> rx.Component:
    return rx.card(
        rx.vstack(
            rx.hstack(
                rx.heading("Tests", size="5"),
                rx.hstack(
                    rx.button(
                        TestState.button_label,
                        on_click=TestState.run_next_test,
                        disabled=TestState.button_disabled,
                        size="2",
                    ),
                    rx.button(
                        "Run All",
                        on_click=TestState.run_all_tests,
                        disabled=TestState.is_running,
                        size="2",
                        variant="soft",
                    ),
                    class_name="flex flex-row gap-2 items-center",
                ),
                class_name="flex flex-row justify-between items-center w-full",
            ),
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Test", class_name="w-48"),
                        rx.table.column_header_cell("Status", class_name="w-20"),
                        rx.table.column_header_cell("Duration", class_name="w-24"),
                        rx.table.column_header_cell("Detail"),
                    )
                ),
                rx.table.body(rx.foreach(TestState.results, result_row)),
                variant="surface",
                class_name="w-full",
            ),
            rx.hstack(
                rx.cond(
                    TestState.has_started,
                    rx.text(
                        "User: " + TestState.test_email,
                        size="1",
                        color="gray",
                        class_name="font-mono",
                    ),
                    rx.fragment(),
                ),
                rx.button(
                    rx.icon("rotate-ccw", size=14),
                    "Reset",
                    on_click=TestState.reset_tests,
                    disabled=TestState.is_running,
                    size="2",
                    variant="ghost",
                    color_scheme="gray",
                    class_name="ml-auto",
                ),
                class_name="flex flex-row items-center w-full",
            ),
            class_name="flex flex-col gap-3 w-full items-start",
        ),
        class_name="w-full p-4",
    )


def claims_panel() -> rx.Component:
    return rx.card(
        rx.vstack(
            rx.heading("JWT Claims", size="5"),
            rx.table.root(
                rx.table.body(rx.foreach(TestState.claims_display, claim_row)),
                variant="ghost",
                class_name="w-full",
            ),
            class_name="flex flex-col gap-3 w-full items-start",
        ),
        class_name="w-full p-4",
    )


def index() -> rx.Component:
    return rx.box(
        rx.vstack(
            rx.vstack(
                rx.heading("Suplex Auth Test Suite", size="7"),
                rx.text(
                    "Supabase authentication integration tests for Reflex",
                    size="3",
                    color="gray",
                ),
                class_name="flex flex-col gap-1 items-start w-full",
            ),
            rx.vstack(
                tests_panel(),
                claims_panel(),
                class_name="flex flex-col gap-5 w-full",
            ),
            class_name="flex flex-col gap-6 w-full max-w-[1200px] px-8 pt-12 pb-8",
        ),
        class_name="min-h-screen flex justify-center bg-[var(--gray-1)]",
    )


app = rx.App()
app.add_page(index)
