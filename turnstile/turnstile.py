
import reflex as rx

from reflex.vars import Var
from rich.console import Console
from typing import Callable, Literal, Sequence

console = Console()


class TurnstileState(rx.State):
    def on_load(self, widget_id: str):
        """
        Called when the Turnstile widget is loaded.
        """
        console.log(f"Turnstile loaded with widget ID: {widget_id}")

class Turnstile(rx.Component):
    """
    Turnstile component (Cloudflare CAPTCHA).
    This component is a wrapper around the Turnstile widget from Cloudflare:
        https://www.npmjs.com/package/react-turnstile
        https://developers.cloudflare.com/turnstile/get-started/#new-sites
    """

    library = "react-turnstile"
    tag = "Turnstile"
    is_default = True

    sitekey: rx.Var[str] # Required
    theme: rx.Var[str] = rx.Var.create("auto")
    size: rx.Var[Literal["normal","compact"]] = rx.Var.create("normal")
    fixed_size: rx.Var[bool] = rx.Var.create(False)
    class_name: rx.Var[str] = rx.Var.create(False)

    def get_event_triggers(self) -> dict[str, Callable[[], Sequence[Var]] | Callable[[Var], Sequence[Var]] | Callable[[Var, Var], Sequence[Var]] | Callable[[Var, Var, Var], Sequence[Var]] | Callable[[Var, Var, Var, Var], Sequence[Var]] | Callable[[Var, Var, Var, Var, Var], Sequence[Var]] | Callable[[Var, Var, Var, Var, Var, Var], Sequence[Var]] | Callable[[Var, Var, Var, Var, Var, Var, Var], Sequence[Var]] | Sequence[Callable[[], Sequence[Var]] | Callable[[Var], Sequence[Var]] | Callable[[Var, Var], Sequence[Var]] | Callable[[Var, Var, Var], Sequence[Var]] | Callable[[Var, Var, Var, Var], Sequence[Var]] | Callable[[Var, Var, Var, Var, Var], Sequence[Var]] | Callable[[Var, Var, Var, Var, Var, Var], Sequence[Var]] | Callable[[Var, Var, Var, Var, Var, Var, Var], Sequence[Var]]]]:
        return {
            **super().get_event_triggers(),
            "on_verify": lambda token: [token],
            "on_success": lambda token, preclearance_obtained: [token, preclearance_obtained],
            "on_load": lambda widget_id: [widget_id],
            "on_error": lambda error: [error],
            "on_timeout": lambda token: [token],
        }

turnstile = Turnstile.create