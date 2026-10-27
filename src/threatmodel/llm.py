"""LLM access: a tiny pluggable interface plus a validate-and-retry JSON loop."""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Protocol

DEFAULT_MODEL = "claude-sonnet-5-5"


class LLM(Protocol):
    def complete(self, system: str, messages: list[dict]) -> str: ...


class LLMError(RuntimeError):
    """The model never produced output that passed validation."""


class AnthropicLLM:
    """Real client. Imported lazily so the rules engine works without the SDK."""

    def __init__(self, model: str | None = None, max_tokens: int = 4000):
        try:
            import anthropic
        except ImportError as err:
            raise LLMError("The LLM stage needs the SDK: pip install anthropic "
                           "(or run with --no-llm for rules only).") from err
        try:
            self._client = anthropic.Anthropic()
        except Exception as err:  # missing key surfaces here
            raise LLMError(f"Could not create the Anthropic client: {err}. "
                           "Set ANTHROPIC_API_KEY or run with --no-llm.") from err
        self.model = model or os.environ.get("TM_MODEL", DEFAULT_MODEL)
        self.max_tokens = max_tokens

    def complete(self, system: str, messages: list[dict]) -> str:
        resp = self._client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system, messages=messages)
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


def extract_json(text: str) -> Any:
    """Pull the outermost JSON object out of a reply, tolerating prose and code fences."""
    try:
        return json.loads(text[text.index("{"): text.rindex("}") + 1])
    except ValueError as err:  # includes JSONDecodeError and missing braces
        raise ValueError(f"reply was not valid JSON ({err})") from err


def ask_json(llm: LLM, system: str, prompt: str,
             validate: Callable[[Any], Any], retries: int = 2) -> Any:
    """Ask, parse, validate in code. On failure, show the model its error and retry.

    `validate` returns the cleaned value or raises ValueError / KeyError / TypeError.
    """
    messages = [{"role": "user", "content": prompt}]
    last_error = "no attempt made"
    for _ in range(retries + 1):
        reply = llm.complete(system, messages)
        try:
            return validate(extract_json(reply))
        except (ValueError, KeyError, TypeError) as err:
            last_error = f"{type(err).__name__}: {err}"
            messages += [
                {"role": "assistant", "content": reply},
                {"role": "user", "content": f"That was rejected: {last_error}. "
                                            "Fix it and return JSON only."},
            ]
    raise LLMError(f"Model output failed validation {retries + 1} times. Last error: {last_error}")
