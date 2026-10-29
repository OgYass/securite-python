from unittest.mock import patch

import pytest

from tp3.main import breach_network, breach_web


@patch("tp3.main.Session")
@patch("tp3.main.Fuzzer")
def test_breach_web_returns_service(mock_fuzzer_cls, mock_session_cls):
    fuzzer = mock_fuzzer_cls.return_value
    fuzzer.best_endpoint.return_value = "internal-panel"

    session = mock_session_cls.return_value
    session.solve.return_value = True
    session.host = "10.0.0.1"
    session.port = 9090
    session.key = b"\xde\xad\xbe\xef"

    host, port, key = breach_web("http://x:8080")

    assert (host, port, key) == ("10.0.0.1", 9090, b"\xde\xad\xbe\xef")


@patch("tp3.main.Fuzzer")
def test_breach_web_exits_when_no_endpoint(mock_fuzzer_cls):
    fuzzer = mock_fuzzer_cls.return_value
    fuzzer.best_endpoint.return_value = None

    with pytest.raises(SystemExit):
        breach_web("http://x:8080")


@patch("tp3.main.Decoder")
def test_breach_network_returns_flag(mock_decoder_cls):
    decoder = mock_decoder_cls.return_value
    decoder.run.return_value = True
    decoder.get_flag.return_value = "ESGI{chain_ok}"

    assert breach_network("10.0.0.1", 9090, b"\xde\xad\xbe\xef") == "ESGI{chain_ok}"


@patch("tp3.main.Decoder")
def test_breach_network_exits_on_failure(mock_decoder_cls):
    decoder = mock_decoder_cls.return_value
    decoder.run.return_value = False

    with pytest.raises(SystemExit):
        breach_network("10.0.0.1", 9090, b"\xde\xad\xbe\xef")
