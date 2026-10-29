import io
from unittest.mock import MagicMock, patch

import pytesseract
from PIL import Image

from tp3.utils.captcha import Captcha, configure_tesseract


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


@patch("tp3.utils.captcha.shutil.which", return_value="/usr/bin/tesseract")
def test_configure_tesseract_keeps_path_env(_mock_which):
    # tesseract dans le PATH : on ne force rien.
    before = pytesseract.pytesseract.tesseract_cmd
    assert configure_tesseract() == before


@patch("tp3.utils.captcha.os.path.exists", return_value=True)
@patch("tp3.utils.captcha.shutil.which", return_value=None)
def test_configure_tesseract_sets_known_path(_mock_which, _mock_exists):
    saved = pytesseract.pytesseract.tesseract_cmd
    try:
        result = configure_tesseract()
        assert result in (
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        )
        assert pytesseract.pytesseract.tesseract_cmd == result
    finally:
        pytesseract.pytesseract.tesseract_cmd = saved


@patch("tp3.utils.captcha.os.path.exists", return_value=False)
@patch("tp3.utils.captcha.shutil.which", return_value=None)
def test_configure_tesseract_returns_none_when_absent(_mock_which, _mock_exists):
    assert configure_tesseract() is None
