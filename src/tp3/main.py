"""TP3 - Breach the target (squelette).

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080
"""

from tp3.utils.config import logger
from tp3.utils.args import Args


def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz les endpoints, casse le CAPTCHA, retourne (host, port, key).

    Affiche aussi Flag 1. Indices : requests, PIL, pytesseract.
    """
    raise NotImplementedError


def breach_network(host: str, port: int, key: bytes) -> str:
    """pwntools/socket : décode le flux base64+XOR en boucle sous 30 s.

    Retourne le flag final. Indices : pwn.remote, base64.
    """
    raise NotImplementedError


def main() -> None:
    
    logger.info(f"Starting TP3 against {Args.target}")

    host, port, key = breach_web(Args.target)
    flag = breach_network(host, port, key)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
