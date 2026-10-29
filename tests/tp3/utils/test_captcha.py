import io
from unittest.mock import MagicMock, patch

from PIL import Image

from tp3.utils.captcha import Captcha


def _png_bytes() -> bytes:
    """Petit PNG blanc valide pour que Image.open ne plante pas."""
    buf = io.BytesIO()
    Image.new("RGB", (60, 24), "white").save(buf, "PNG")
    return buf.getvalue()


def test_captcha_init():
    captcha = Captcha("http://example.com/captcha.png")
    assert captcha.url == "http://example.com/captcha.png"
    assert captcha.image == b""
    assert captcha.value == ""


def test_capture_stores_content():
    captcha = Captcha("http://example.com/captcha.png")
    captcha.session = MagicMock()
    captcha.session.get.return_value = MagicMock(content=b"PNGDATA")

    captcha.capture()

    assert captcha.image == b"PNGDATA"


@patch("tp3.utils.captcha.pytesseract.image_to_string", return_value="AB 12C\n")
def test_solve_keeps_only_alnum(_mock_ocr):
    captcha = Captcha("http://example.com/captcha.png")
    captcha.image = _png_bytes()

    captcha.solve()

    assert captcha.value == "AB12C"


def test_solve_without_image_keeps_empty():
    captcha = Captcha("http://example.com/captcha.png")
    captcha.solve()
    assert captcha.value == ""


def test_get_value():
    captcha = Captcha("http://example.com/captcha.png")
    captcha.value = "TEST12"
    assert captcha.get_value() == "TEST12"
