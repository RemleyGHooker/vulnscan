"""Groq (OpenAI-compatible chat) API for JSON vulnerability findings."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from groq import Groq

from llm_client import LLMClientError

DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
MAX_RETRIES = 5
BASE_DELAY_SEC = 2.0


def _extract_json_text(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def get_groq_client() -> Groq:
    import os

    key = os.environ.get("GROQ_API_KEY")
    if not key:
        raise LLMClientError("GROQ_API_KEY is not set. Export it to use --compare.")
    return Groq(api_key=key)


def analyze_chunk_groq(
    client: Groq,
    system: str,
    user_content: str,
    model: str = DEFAULT_GROQ_MODEL,
    max_tokens: int = 4096,
) -> dict[str, Any]:
    """Run the same vulnerability prompt as Anthropic; expect JSON with findings list."""
    last_error: Exception | None = None
    raw = ""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]
    for attempt in range(MAX_RETRIES):
        try:
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": 0.1,
            }
            try:
                completion = client.chat.completions.create(
                    **kwargs,
                    response_format={"type": "json_object"},
                )
            except Exception:
                completion = client.chat.completions.create(**kwargs)

            choice = completion.choices[0]
            raw = choice.message.content or ""
            json_text = _extract_json_text(raw)
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            snippet = (raw[:500] + "…") if len(raw) > 500 else raw
            raise LLMClientError(f"Groq returned invalid JSON: {e}\nRaw: {snippet}") from e
        except Exception as e:
            last_error = e
            err = str(e).lower()
            if "429" in err or "rate" in err or "503" in err or "502" in err:
                delay = BASE_DELAY_SEC * (2**attempt)
                time.sleep(min(delay, 60.0))
            else:
                delay = BASE_DELAY_SEC * (2**attempt)
                time.sleep(min(delay, 30.0))

    raise LLMClientError(f"Groq failed after {MAX_RETRIES} retries: {last_error}")
