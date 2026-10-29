from unittest.mock import MagicMock, patch

from tp3.utils.session import Session


def test_session_init():
    s = Session("http://x/secret")
    assert s.url == "http://x/secret"
    assert s.captcha_value == ""
    assert s.valid_flag == ""
    assert s.host == ""
    assert s.port == 0
    assert s.key == b""


def test_process_response_parses_page():
    s = Session("http://x/secret")
    s._response = MagicMock(text="flag ESGI{web_ok} service 10.0.0.1:9090 key: deadbeef")
    assert s.process_response() is True
    assert s.valid_flag == "ESGI{web_ok}"
    assert s.host == "10.0.0.1"
    assert s.port == 9090
    assert s.key == b"\xde\xad\xbe\xef"


def test_process_response_rejects_incomplete():
    s = Session("http://x/secret")
    s._response = MagicMock(text="wrong captcha")
    assert s.process_response() is False


@patch("tp3.utils.session.Captcha")
def test_prepare_request_sets_value(mock_captcha):
    mock_captcha.return_value.get_value.return_value = "AB12"
    s = Session("http://x/secret")
    s.prepare_request()
    assert s.captcha_value == "AB12"


@patch("requests.Session.post")
def test_submit_request_stores_response(mock_post):
    mock_post.return_value = MagicMock(text="ok")
    s = Session("http://x/secret")
    s.submit_request()
    assert s._response is not None


def test_get_flag():
    s = Session("http://x/secret")
    s.valid_flag = "ESGI{web_ok}"
    assert s.get_flag() == "ESGI{web_ok}"