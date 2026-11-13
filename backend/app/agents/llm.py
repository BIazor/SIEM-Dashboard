"""LLM provider abstraction: Ollama, OpenAI-compatible, or deterministic fallback."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from ..config import Settings, get_settings

logger = logging.getLogger(__name__)


@dataclass
class LLMResult:
    ok: bool
    text: str = ""
    provider: str = "none"
    model: str = ""
    error: str | None = None


class LLMClient:
    """Small, explicit client.

    ``generate_json`` never raises: callers fall back to the deterministic engine when
    ``ok`` is False, and the reason is stored on the investigation record.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._probed: tuple[bool, str, str] | None = None

    # ------------------------------------------------------------------ probing
    def probe(self) -> tuple[bool, str, str]:
        """Return (available, provider, reason). Result is cached per process."""
        if self._probed is not None:
            return self._probed

        configured = self.settings.llm_provider
        if configured == "none":
            self._probed = (False, "heuristic", "LLM_PROVIDER=none: deterministic analysis only")
            return self._probed

        if configured in ("auto", "ollama"):
            base = self.settings.ollama_base_url.rstrip("/")
            try:
                response = httpx.get(f"{base}/api/tags", timeout=2.0)
                if response.status_code == 200:
                    self._probed = (True, "ollama", self.settings.ollama_model)
                    return self._probed
                reason = f"Ollama responded with HTTP {response.status_code}"
            except Exception as exc:  # noqa: BLE001 - connectivity probing
                reason = f"Ollama unreachable at {base}: {type(exc).__name__}"
            if configured == "ollama":
                self._probed = (False, "ollama", reason)
                return self._probed

        if configured in ("auto", "openai"):
            if self.settings.openai_api_key:
                self._probed = (True, "openai", self.settings.openai_model)
                return self._probed
            self._probed = (
                False,
                "heuristic",
                "No LLM available: OLLAMA not running and OPENAI_API_KEY unset. "
                "Deterministic analysis used.",
            )
            return self._probed

        self._probed = (False, "heuristic", "No LLM provider configured")
        return self._probed

    @property
    def available(self) -> bool:
        return self.probe()[0]

    @property
    def provider_label(self) -> str:
        available, provider, _ = self.probe()
        return provider if available else "heuristic"

    def describe(self) -> dict[str, object]:
        available, provider, reason = self.probe()
        return {"available": available, "provider": provider, "detail": reason}

    # ------------------------------------------------------------------ calls
    def generate_json(self, system_prompt: str, user_prompt: str) -> LLMResult:
        available, provider, reason = self.probe()
        if not available:
            return LLMResult(ok=False, provider=provider, error=reason)
        try:
            if provider == "ollama":
                return self._call_ollama(system_prompt, user_prompt)
            if provider == "openai":
                return self._call_openai(system_prompt, user_prompt)
        except Exception as exc:  # noqa: BLE001 - a failed model call must not break the API
            logger.warning("LLM call failed: %s", type(exc).__name__)
            return LLMResult(ok=False, provider=provider, error=f"LLM request failed: {type(exc).__name__}")
        return LLMResult(ok=False, provider=provider, error="No usable provider")

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> LLMResult:
        base = self.settings.ollama_base_url.rstrip("/")
        model = self.settings.ollama_model
        payload = {
            "model": model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_predict": 900},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        with httpx.Client(timeout=self.settings.llm_timeout_seconds) as client:
            response = client.post(f"{base}/api/chat", json=payload)
            response.raise_for_status()
            body = response.json()
        content = (body.get("message") or {}).get("content", "")
        if not content:
            return LLMResult(ok=False, provider="ollama", model=model, error="Empty completion")
        return LLMResult(ok=True, text=content, provider="ollama", model=model)

    def _call_openai(self, system_prompt: str, user_prompt: str) -> LLMResult:
        base = self.settings.openai_base_url.rstrip("/")
        model = self.settings.openai_model
        headers = {"Authorization": f"Bearer {self.settings.openai_api_key}"}
        payload = {
            "model": model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        with httpx.Client(timeout=self.settings.llm_timeout_seconds) as client:
            response = client.post(f"{base}/chat/completions", headers=headers, json=payload)
            if response.status_code == 400:
                # Some OpenAI-compatible servers reject response_format; retry plainly.
                payload.pop("response_format", None)
                response = client.post(f"{base}/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return LLMResult(ok=False, provider="openai", model=model, error="Malformed completion")
        return LLMResult(ok=bool(content), text=content or "", provider="openai", model=model)


_client: LLMClient | None = None


def get_llm_client() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
