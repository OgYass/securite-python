from unittest.mock import MagicMock, patch

from tp3.utils.session import Session


def test_session_init():
    s = Session("http://x:8080/internal-panel")
    assert s.url == "http://x:8080/internal-panel"
    assert s.captcha_url == "http://x:8080/captcha.png"
    assert s.valid_flag == ""
    assert s.host == ""
    assert s.port == 0
    assert s.key == b""


def test_process_response_parses_json():
    s = Session("http://x:8080/internal-panel")
    s._response = MagicMock()
    s._response.json.return_value = {
        "flag1": "ESGI{web_ok}",
        "host": "10.0.0.1",
        "port": 9090,
        "key": "deadbeef",
    }

    assert s.process_response() is True
    assert s.valid_flag == "ESGI{web_ok}"
    assert s.host == "10.0.0.1"
    assert s.port == 9090
    assert s.key == b"\xde\xad\xbe\xef"


def test_process_response_rejects_non_json():
    s = Session("http://x:8080/internal-panel")
    s._response = MagicMock()
    s._response.json.side_effect = ValueError
    assert s.process_response() is False


def test_process_response_rejects_incomplete():
    s = Session("http://x:8080/internal-panel")
    s._response = MagicMock()
    s._response.json.return_value = {"error": "captcha invalide"}
    assert s.process_response() is False


@patch("tp3.utils.session.Captcha")
def test_prepare_request_sets_value(mock_captcha):
    mock_captcha.return_value.get_value.return_value = "AB12C"
    s = Session("http://x:8080/internal-panel")
    s.session = MagicMock()

    s.prepare_request()

    assert s.captcha_value == "AB12C"


def test_submit_request_stores_response():
    s = Session("http://x:8080/internal-panel")
    s.session = MagicMock()
    s.session.post.return_value = MagicMock(text="ok")

    s.submit_request()

    assert s._response is not None


def test_solve_returns_true_on_first_success():
    s = Session("http://x:8080/internal-panel")
    s.prepare_request = MagicMock()
    s.submit_request = MagicMock()
    s.process_response = MagicMock(return_value=True)

    assert s.solve() is True
    s.prepare_request.assert_called_once()


def test_get_flag():
    s = Session("http://x:8080/internal-panel")
    s.valid_flag = "ESGI{web_ok}"
    assert s.get_flag() == "ESGI{web_ok}"
