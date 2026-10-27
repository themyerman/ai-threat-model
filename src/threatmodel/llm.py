"""LLM access: a tiny pluggable interface, three backends, and a validate-and-retry JSON loop.

Backends:
  mock       canned, deterministic replies (see mock.py); no key, no network
  anthropic  the Anthropic API (needs ANTHROPIC_API_KEY and the SDK)
  local      any OpenAI-compatible server: Ollama, LM Studio, vLLM, llama.cpp
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Protocol

DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_BASE_URL = "http://localhost:11434/v1"  # Ollama
BACKENDS = ("mock", "anthropic", "local")


class LLM(Protocol):
    label: str

    def complete(self, system: str, messages: list[dict]) -> str: ...


class LLMError(RuntimeError):
    """The model could not be reached, or never produced output that passed validation."""


class AnthropicLLM:
    """Real client. Imported lazily so the rules engine works without the SDK."""

    def __init__(self, model: str | None = None, max_tokens: int = 4000):
        try:
            import anthropic
        except ImportError as err:
            raise LLMError("The anthropic backend needs the SDK: pip install anthropic "
                           "(or use --llm mock, or --no-llm for rules only).") from err
        # The SDK only checks for a key when the first request is sent, so check here.
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            raise LLMError("ANTHROPIC_API_KEY is not set. Set it, or use --llm mock "
                           "(no key needed), or --no-llm for rules only.")
        self._anthropic = anthropic
        self._client = anthropic.Anthropic()
        self.model = model or os.environ.get("TM_MODEL", DEFAULT_MODEL)
        self.max_tokens = max_tokens
        self.label = f"anthropic ({self.model})"

    def complete(self, system: str, messages: list[dict]) -> str:
        try:
            resp = self._client.messages.create(
                model=self.model, max_tokens=self.max_tokens, system=system, messages=messages)
        except self._anthropic.AnthropicError as err:
            raise LLMError(f"Anthropic API call failed: {err}") from err
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


class LocalLLM:
    """Any server that speaks the OpenAI chat-completions API. Standard library only."""

    def __init__(self, model: str | None = None, base_url: str | None = None,
                 timeout: float = 300, max_tokens: int = 4000):
        self.model = model or os.environ.get("TM_MODEL")
        if not self.model:
            raise LLMError("The local backend needs a model name: --model llama3.1:8b "
                           "(or set TM_MODEL). Run 'ollama list' to see what you have.")
        self.base_url = (base_url or os.environ.get("TM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = os.environ.get("TM_API_KEY", "")  # only hosted servers need one
        self.timeout = timeout
        # Without a cap, a small model that loses the thread can generate until the context fills.
        self.max_tokens = max_tokens
        self.label = f"local ({self.model} at {self.base_url})"

    def complete(self, system: str, messages: list[dict]) -> str:
        url = f"{self.base_url}/chat/completions"
        body = {"model": self.model, "temperature": 0, "max_tokens": self.max_tokens,
                "messages": [{"role": "system", "content": system}] + messages}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.load(resp)
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")[:300]
            raise LLMError(f"{url} returned HTTP {err.code}: {detail}") from err
        except (urllib.error.URLError, OSError) as err:
            reason = getattr(err, "reason", err)
            if isinstance(err, TimeoutError) or isinstance(reason, TimeoutError):
                raise LLMError(f"{url} did not answer within {self.timeout:.0f}s. The model may be too "
                               "large for this machine, or still loading; try a smaller one.") from err
            raise LLMError(f"Could not reach {url} ({reason}). Is the server running? "
                           "For Ollama: ollama serve") from err
        except json.JSONDecodeError as err:
            raise LLMError(f"{url} did not return JSON: {err}") from err
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as err:
            raise LLMError(f"Unexpected response shape from {url}: {str(data)[:300]}") from err
        # Reasoning models think out loud first; that text can contain stray braces.
        return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)


def make_llm(backend: str, model: str | None = None, base_url: str | None = None) -> LLM:
    if backend == "mock":
        from .mock import MockLLM
        return MockLLM()
    if backend == "anthropic":
        return AnthropicLLM(model=model)
    if backend == "local":
        return LocalLLM(model=model, base_url=base_url)
    raise LLMError(f"unknown backend {backend!r}; choose one of {BACKENDS}")


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
