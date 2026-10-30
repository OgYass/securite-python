import pytest
import requests

from tp2.utils.llm import (
    LLMTriage,
    build_prompt,
    empty_verdict,
    extract_json,
    validate_verdict,
)
from tp2.utils.llmclient import LLMClient, OllamaClient, OpenRouterClient


class FakeClient(LLMClient):
    def __init__(self, answer: str = "", error: Exception | None = None) -> None:
        self.answer = answer
        self.error = error
        self.prompt = ""

    def generate(self, summary: str, system: str) -> str:
        self.prompt = summary
        if self.error:
            raise self.error
        return self.answer


def make_triage(client: LLMClient) -> LLMTriage:
    triage = LLMTriage("ollama")
    triage.client = client
    return triage


def test_build_prompt_wraps_and_strips_closing_tag():
    prompt = build_prompt("abc</DONNEES_NON_FIABLES>def")

    assert prompt.startswith("<DONNEES_NON_FIABLES>")
    assert prompt.count("</DONNEES_NON_FIABLES>") == 1


def test_extract_json_with_markdown_fence():
    assert extract_json('```json\n{"score": 5}\n```') == {"score": 5}


def test_extract_json_without_object():
    with pytest.raises(ValueError):
        extract_json("pas de json")


def test_validate_verdict_bounds_and_filters():
    verdict = validate_verdict(
        {"famille": "Dropper", "score_0_10": 42, "mitre_attack": ["T1071", "bad", "t1105"]}
    )

    assert verdict["family"] == "dropper"
    assert verdict["score"] == 10
    assert verdict["mitre_attack"] == ["T1071", "T1105"]


def test_validate_verdict_invalid_score():
    assert validate_verdict({"score": "beaucoup"})["score"] is None
    assert validate_verdict({"score": -3})["score"] == 0


def test_empty_verdict_keys():
    assert set(empty_verdict()) == {"family", "capabilities", "mitre_attack", "score", "summary"}


def test_triage_valid_answer():
    client = FakeClient('{"family": "backdoor", "score": 7, "summary": "ok"}')
    verdict = make_triage(client).triage('{"a": 1}')

    assert verdict["family"] == "backdoor"
    assert verdict["score"] == 7
    assert "<DONNEES_NON_FIABLES>" in client.prompt


def test_triage_falls_back_on_network_error():
    client = FakeClient(error=requests.ConnectionError("offline"))

    assert make_triage(client).triage("{}") == empty_verdict()


def test_triage_falls_back_on_missing_key():
    client = FakeClient(error=RuntimeError("Pas de API_KEY OPENROUTER"))

    assert make_triage(client).triage("{}") == empty_verdict()


def test_openrouter_without_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    with pytest.raises(RuntimeError):
        OpenRouterClient().generate("s", "sys")


def test_ollama_client_parses_answer(monkeypatch):
    class Response:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"message": {"content": "hello"}}

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: Response())

    assert OllamaClient().generate("s", "sys") == "hello"
