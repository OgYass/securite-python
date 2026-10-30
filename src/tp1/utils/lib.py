import re
from collections.abc import Iterable
from re import Pattern

from scapy.config import conf

from tp1.utils.args import Args

_FLAG_PATTERN = re.compile(r"ESGI\{tp1_[^}\s]+\}")

_SQL_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"'\s*or\s+'?\d+'?\s*=\s*'?\d+",  # ' OR 1=1 / ' or '1'='1
        r"'\s*or\s+'[^']*'\s*=\s*'",  # ' or 'a'='a
        r"\bunion\b(\s+all)?\s+select\b",  # UNION SELECT
        r"'\s*;\s*(drop|delete|insert|update)\b",  # '; DROP TABLE
        r"'\s*(--|#|/\*)",  # ' -- commentaire
        r"\b(sleep|benchmark)\s*\(",  # injection temporelle
        r"information_schema",
    ]
]


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interface = Args.iface or conf.iface.name or ""

    return interface


def find_flags(data: str | bytes | Iterable[str | bytes]) -> list[str]:
    """Recherche des flags dans les donnees."""
    return _find_pattern(data, _FLAG_PATTERN)


def contains_sql_injection(data: str | bytes | Iterable[str | bytes]) -> bool:
    """Recherche des motifs d'injection SQL."""
    return len(_find_pattern(data, _SQL_PATTERNS)) > 0


def _find_pattern(
    data: str | bytes | Iterable[str | bytes], pattern: Pattern[str] | Iterable[Pattern[str]]
) -> list[str]:
    """Applique une liste de regex sur les donnees."""
    result: list[str] = []

    if isinstance(data, (str, bytes)):
        data = [data]

    if isinstance(pattern, Pattern):
        pattern = [pattern]

    for text in data:
        if isinstance(text, bytes):
            text = text.decode(errors="ignore")

        for p in pattern:
            result.extend(p.findall(text))

    return result


def hello_world():
    """Renvoie hello world."""
    return "hello world"
