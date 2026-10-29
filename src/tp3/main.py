"""TP3 - Breach the target (squelette).

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080
"""

from tp3.utils.config import logger
from tp3.utils.args import Args
from tp3.utils.fuzzer import Fuzzer
from tp3.utils.session import Session


def breach_web(target: str) -> tuple[str, int, bytes]:
    fuzzer = Fuzzer(target)
    fuzzer.fuzz()
    endpoint = fuzzer.best_endpoint()
    if endpoint is None:
        logger.error("Aucun endpoint trouvé")
        raise SystemExit(1)

    session = Session(f"{target}/{endpoint}", session=fuzzer.session)
    if not session.solve():
        logger.error("Captcha non résolu")
        raise SystemExit(1)

    return session.host, session.port, session.key


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
