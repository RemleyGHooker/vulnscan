"""Anthropic API client with retries and graceful error handling."""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import anthropic

DEFAULT_MODEL = "claude-sonnet-4-20250514"
MAX_RETRIES = 5
BASE_DELAY_SEC = 2.0


class LLMClientError(Exception):
    """Raised when the API fails after retries or returns unusable output."""


def _extract_json_text(text: str) -> str:
    text = text.strip()
    # Strip accidental markdown fences
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def parse_json_response(text: str) -> dict[str, Any]:
    """Parse model output that should be a single JSON object."""
    return json.loads(_extract_json_text(text))


def analyze_chunk(
    client: anthropic.Anthropic,
    system: str,
    user_messages: list[dict[str, Any]],
    model: str = DEFAULT_MODEL,
    max_tokens: int = 4096,
) -> dict[str, Any]:
    last_error: Exception | None = None
    raw = ""
    for attempt in range(MAX_RETRIES):
        try:
            message = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=user_messages,
            )
            if not message.content:
                raise LLMClientError("Empty response content from API")

            block = message.content[0]
            if block.type != "text":
                raise LLMClientError(f"Unexpected block type: {block.type}")

            raw = block.text
            json_text = _extract_json_text(raw)
            return json.loads(json_text)

        except anthropic.RateLimitError as e:
            last_error = e
            delay = BASE_DELAY_SEC * (2**attempt)
            time.sleep(min(delay, 60.0))
        except anthropic.APIStatusError as e:
            last_error = e
            status = getattr(e, "status_code", None) or 0
            if status in (429, 500, 502, 503, 529):
                delay = BASE_DELAY_SEC * (2**attempt)
                time.sleep(min(delay, 60.0))
            else:
                raise LLMClientError(f"API error: {e}") from e
        except anthropic.APIConnectionError as e:
            last_error = e
            delay = BASE_DELAY_SEC * (2**attempt)
            time.sleep(min(delay, 60.0))
        except json.JSONDecodeError as e:
            snippet = (raw[:500] + "…") if len(raw) > 500 else raw
            raise LLMClientError(f"Model returned invalid JSON: {e}\nRaw: {snippet}") from e

    raise LLMClientError(f"Failed after {MAX_RETRIES} retries: {last_error}")


def completion_text(
    client: anthropic.Anthropic,
    system: str,
    messages: list[dict[str, Any]],
    *,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 4096,
) -> str:
    """Multi-turn safe: returns raw assistant text (no JSON parse)."""
    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            message = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=messages,
            )
            if not message.content:
                raise LLMClientError("Empty response content from API")
            block = message.content[0]
            if block.type != "text":
                raise LLMClientError(f"Unexpected block type: {block.type}")
            return block.text
        except anthropic.RateLimitError as e:
            last_error = e
            time.sleep(min(BASE_DELAY_SEC * (2**attempt), 60.0))
        except anthropic.APIStatusError as e:
            last_error = e
            status = getattr(e, "status_code", None) or 0
            if status in (429, 500, 502, 503, 529):
                time.sleep(min(BASE_DELAY_SEC * (2**attempt), 60.0))
            else:
                raise LLMClientError(f"API error: {e}") from e
        except anthropic.APIConnectionError as e:
            last_error = e
            time.sleep(min(BASE_DELAY_SEC * (2**attempt), 60.0))

    raise LLMClientError(f"Failed after {MAX_RETRIES} retries: {last_error}")


def get_client() -> anthropic.Anthropic:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise LLMClientError(
            "ANTHROPIC_API_KEY is not set. Export it before running vulnscan."
        )
    return anthropic.Anthropic(api_key=api_key)
