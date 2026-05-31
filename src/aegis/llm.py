"""LLM client interface for Phase 3 (capability generation and verification).

Design: LLMClient is a Protocol so any backend satisfies it without subclassing.
OllamaLLMClient is the reference local-inference implementation (stdlib only,
no new runtime deps). MockLLMClient is used in all tests.

External APIs (e.g. Anthropic) can be wired in by implementing the Protocol;
they require explicit allowlisting and appear in the audit log per PLAN.md §5.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Callable, Protocol, runtime_checkable

DEFAULT_TIMEOUT_S: float = 60.0


class LLMError(RuntimeError):
    """Raised when an LLM call fails or returns an unusable response."""


@runtime_checkable
class LLMClient(Protocol):
    """Minimal interface every LLM backend must satisfy."""

    def complete(self, *, system: str, user: str, temperature: float = 0.0) -> str:
        """Return the model's text completion for the given prompts."""
        ...


class OllamaLLMClient:
    """Local-inference client backed by Ollama (default: http://localhost:11434).

    Serves llama.cpp, Mistral, Qwen, Phi, and other open-weight models. Uses
    only stdlib so the zero-runtime-dep constraint is maintained.
    """

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://localhost:11434",
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._model = model
        self._chat_url = f"{base_url.rstrip('/')}/api/chat"
        self._timeout_s = timeout_s

    def complete(self, *, system: str, user: str, temperature: float = 0.0) -> str:
        payload = json.dumps(
            {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {"temperature": temperature},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            self._chat_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:
                body: dict[str, object] = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise LLMError(f"Ollama unreachable at {self._chat_url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise LLMError(f"Ollama returned invalid JSON: {exc}") from exc

        try:
            return str(body["message"]["content"])  # type: ignore[index]
        except KeyError as exc:
            raise LLMError(f"Unexpected Ollama response shape: {body!r}") from exc


class MockLLMClient:
    """Deterministic mock for testing — no network calls, no API keys.

    Pass a fixed string for uniform responses, or a callable
    ``(system, user) -> str`` to inspect prompts and return context-specific
    JSON payloads.
    """

    def __init__(self, response: str | Callable[[str, str], str]) -> None:
        self._response = response

    def complete(self, *, system: str, user: str, temperature: float = 0.0) -> str:
        if callable(self._response):
            return self._response(system, user)
        return self._response
