import re

import requests

from tp3.utils.captcha import Captcha
from tp3.utils.config import logger

FLAG_RE = re.compile(r"ESGI\{[^}]+\}")
HOSTPORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[\w.-]+):(\d{2,5})")
KEY_RE = re.compile(r"key\s*[:=]\s*([0-9a-fA-F]+)")


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.
    """

    _MAX_RETRIES = 5

    def __init__(self, url: str, session: requests.Session | None = None) -> None:
        self.url: str = url
        """Url of the hidden page serving the captcha and the form
        """

        self.session: requests.Session = session or requests.Session()
        """Shared session so the captcha matches the server-side cookie
        """

        self.captcha_value: str = ""
        self.flag_value: str = ""
        self.valid_flag: str = ""

        self.host: str = ""
        """Host of the TCP service revealed by the page
        """

        self.port: int = 0
        """Port of the TCP service revealed by the page
        """

        self.key: bytes = b""
        """Encoding key revealed by the page
        """

        self._response: requests.Response | None = None

    def prepare_request(self) -> None:
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url, session=self.session)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()

        logger.debug(f"prepared captcha '{self.captcha_value}'")

    def submit_request(self) -> None:
        """
        Sends the flag and captcha.
        """
        try:
            self._response = self.session.post(self.url, data={"captcha": self.captcha_value}, timeout=5)
        except requests.RequestException as exc:
            logger.debug(f"submit error {exc}")
            self._response = None

    def process_response(self) -> bool:
        """
        Processes the response.
        """
        if self._response is None:
            return False

        body = self._response.text

        flags = FLAG_RE.findall(body)
        hostport = HOSTPORT_RE.search(body)
        key = KEY_RE.search(body)

        if not (flags and hostport and key):
            logger.debug("captcha rejected or page incomplete")
            return False

        self.valid_flag = flags[0]
        self.host = hostport.group(1)
        self.port = int(hostport.group(2))
        self.key = bytes.fromhex(key.group(1))

        logger.info(f"[+] FLAG1: {self.valid_flag}")
        logger.info(f"service revealed : {self.host}:{self.port}")

        return True

    def solve(self) -> bool:
        """
        Retries the captcha until the page accepts it.
        """
        for attempt in range(1, Session._MAX_RETRIES + 1):
            logger.debug(f"captcha attempt {attempt}/{Session._MAX_RETRIES}")
            self.prepare_request()
            self.submit_request()
            if self.process_response():
                return True

        logger.warn("captcha not solved after retries")
        return False

    def get_flag(self) -> str:
        """
        Returns the valid flag.
        """
        return self.valid_flag