import io

import pytesseract
import requests
from PIL import Image

from tp3.utils.config import logger


class Captcha:
    _WHITELIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    _CONFIG = f"--psm 7 -c tessedit_char_whitelist={_WHITELIST}"

    def __init__(self, url: str, session: requests.Session | None = None, timeout: int = 5) -> None:
        self.url: str = url
        self.session: requests.Session = session or requests.Session()
        self.image: bytes = b""
        self.value: str = ""
        self._timeout: int = timeout

    def solve(self) -> None:
        """
        Fonction permettant la résolution du captcha.
        """
        if not self.image:
            logger.warn("solve called with no captured image")
            return

        image = Image.open(io.BytesIO(self.image))
        gray = image.convert("L")
        bw = gray.point(lambda px: 0 if px < 140 else 255)
        clean = bw.resize((bw.width * 3, bw.height * 3))

        raw = pytesseract.image_to_string(clean, config=Captcha._CONFIG)
        self.value = "".join(c for c in raw if c.isalnum())

        logger.debug(f"captcha solved as '{self.value}'")

    def capture(self) -> None:
        """
        Fonction permettant la capture du captcha.
        """
        try:
            resp = self.session.get(self.url, timeout=self._timeout)
        except requests.RequestException as exc:
            logger.debug(f"captcha download error {exc}")
            return

        self.image = resp.content

        logger.debug(f"captcha image captured ({len(self.image)} bytes)")

    def get_value(self) -> str:
        """
        Fonction retournant la valeur du captcha
        """
        return self.value