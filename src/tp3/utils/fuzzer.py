from pathlib import Path

import requests

from tp3.utils.config import logger


class Fuzzer:
    _WORDLIST = Path(__file__).parent / "wordlist.txt"

    def __init__(self, target: str, wordlist: Path | None = None, timeout: int = 5) -> None:
        self.target: str = target.rstrip("/")
        """Base url of the target, without trailing slash
        """

        self.wordlist: Path = wordlist or Fuzzer._WORDLIST
        """Path of the wordlist embedded with the code
        """

        self.session: requests.Session = requests.Session()
        """Shared session so cookies persist for the captcha step
        """

        self.found: dict[str, int] = {}
        """Endpoints that answered something else than 404 (endpoint -> status)
        """

        self._timeout: int = timeout

    def _load_words(self) -> list[str]:
        """Read the wordlist, skip blank lines and comments

        Returns:
            list[str]: Cleaned list of endpoints to test
        """
        lines = self.wordlist.read_text(encoding="utf-8").splitlines()
        return [w.strip() for w in lines if w.strip() and not w.startswith("#")]

    def _probe(self, word: str) -> int | None:
        """Send a GET on one endpoint

        Args:
            word (str): Endpoint to test, appended to the target url

        Returns:
            int | None: Status code if different from 404, None otherwise
        """
        url = f"{self.target}/{word}"

        try:
            resp = self.session.get(url, timeout=self._timeout, allow_redirects=False)
        except requests.RequestException as exc:
            logger.debug(f"{url} -> error {exc}")
            return None

        logger.debug(f"{url} -> {resp.status_code}")

        if resp.status_code == 404:
            return None

        return resp.status_code

    def fuzz(self) -> dict[str, int]:
        """Test every word of the wordlist and keep the valid endpoints

        Returns:
            dict[str, int]: Found endpoints with their status code
        """
        for word in self._load_words():
            code = self._probe(word)
            if code is not None:
                self.found[word] = code
                logger.info(f"Endpoint found : /{word} ({code})")

        logger.debug(f"{len(self.found)} endpoint(s) found")

        return self.found

    def best_endpoint(self) -> str | None:
        """Return the most likely hidden page (200 first)

        Returns:
            str | None: Best endpoint, None if nothing was found
        """
        if not self.found:
            return None

        return min(self.found, key=lambda w: (self.found[w] != 200, w))