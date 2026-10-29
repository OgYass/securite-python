from abc import ABC, abstractmethod
import os
import requests

from tp2.utils.config import logger


class LLMClient(ABC):
    """
    interface client LLM
    """

    @abstractmethod
    def generate(self, summary: str, system: str) -> str:
        raise NotImplementedError


class OpenRouterClient(LLMClient):
    def __init__(self) -> None:
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.model = "recursive/flint-v1.0:free"

    def generate(self, summary: str, system: str) -> str:
        api_key = self.api_key
        logger.info("calling openrouter backend")

        if not api_key:
            raise RuntimeError("Pas de API_KEY OPENROUTER")

        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": summary},
                ],
            },
            timeout=60,
        )

        if not r.ok:
            raise RuntimeError(f"Openrouter HTTP {r.status_code}: {r.text}")

        return r.json()["choices"][0]["message"]["content"]


class OllamaClient(LLMClient):
    def __init__(self) -> None:
        self.model = "qwen2.5:3b"

    def generate(self, summary: str, system: str) -> str:
        logger.info("calling ollama backend")

        r = requests.post(
            "http://localhost:11434/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": summary},
                ],
            },
            timeout=120,
        )
        r.raise_for_status()
        return r.json()["message"]["content"]
