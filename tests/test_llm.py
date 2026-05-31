"""Tests for LLM client implementations (Phase 3)."""

from __future__ import annotations

import pytest

from aegis import LLMClient, LLMError, MockLLMClient, OllamaLLMClient


def test_mock_fixed_string() -> None:
    client = MockLLMClient('{"hello": "world"}')
    result = client.complete(system="sys", user="usr")
    assert result == '{"hello": "world"}'


def test_mock_callable() -> None:
    def responder(system: str, user: str) -> str:
        return f"system_len={len(system)}"

    client = MockLLMClient(responder)
    result = client.complete(system="short", user="anything")
    assert result == "system_len=5"


def test_mock_satisfies_protocol() -> None:
    client = MockLLMClient("response")
    assert isinstance(client, LLMClient)


def test_ollama_satisfies_protocol() -> None:
    client = OllamaLLMClient("llama3")
    assert isinstance(client, LLMClient)


def test_ollama_raises_llm_error_on_connection_failure() -> None:
    client = OllamaLLMClient("llama3", base_url="http://127.0.0.1:1", timeout_s=0.1)
    with pytest.raises(LLMError):
        client.complete(system="s", user="u")
