from unittest.mock import MagicMock

import requests

from tp3.utils.fuzzer import Fuzzer


def test_load_words_contains_hidden_path():
    fuzzer = Fuzzer("http://x:8080")
    words = fuzzer._load_words()
    assert "internal-panel" in words
    assert all(w and not w.startswith("#") for w in words)


def test_probe_returns_status_when_not_404():
    fuzzer = Fuzzer("http://x:8080")
    fuzzer.session = MagicMock()
    fuzzer.session.get.return_value = MagicMock(status_code=200)
    assert fuzzer._probe("internal-panel") == 200


def test_probe_returns_none_on_404():
    fuzzer = Fuzzer("http://x:8080")
    fuzzer.session = MagicMock()
    fuzzer.session.get.return_value = MagicMock(status_code=404)
    assert fuzzer._probe("nope") is None


def test_probe_returns_none_on_error():
    fuzzer = Fuzzer("http://x:8080")
    fuzzer.session = MagicMock()
    fuzzer.session.get.side_effect = requests.RequestException("boom")
    assert fuzzer._probe("nope") is None


def test_fuzz_keeps_found_endpoints():
    fuzzer = Fuzzer("http://x:8080")
    fuzzer._load_words = MagicMock(return_value=["a", "b"])
    fuzzer._probe = MagicMock(side_effect=lambda w: 200 if w == "a" else None)

    found = fuzzer.fuzz()

    assert found == {"a": 200}


def test_best_endpoint_prefers_200():
    fuzzer = Fuzzer("http://x:8080")
    fuzzer.found = {"old": 302, "panel": 200}
    assert fuzzer.best_endpoint() == "panel"


def test_best_endpoint_none_when_empty():
    fuzzer = Fuzzer("http://x:8080")
    assert fuzzer.best_endpoint() is None
