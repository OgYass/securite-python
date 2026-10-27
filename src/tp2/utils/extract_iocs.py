import re

from tp2.utils.config import logger
from tp2.utils.get_data import get_file

DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL = re.compile(r"https?://[^\s\"']+")
MUTEX_PATTERN = re.compile(
    r"\b(?:Global\\|Local\\)?"
    r"[A-Za-z0-9_.-]*"
    r"(?:mutex|malware|ransom|lock)"
    r"[A-Za-z0-9_.-]*\b",
    re.IGNORECASE,
)

REGISTRY_PATTERN = re.compile(
    r"\b(?:HKCU|HKLM|HKCR|HKU|HKCC)"
    r"\\[^\s\"']+",
    re.IGNORECASE,
)

data = get_file("./test.txt")

def extract_iocs():


    return {

        }

def extract_text(data:bytes) -> list[bytes]:
    """
        extraction de chaines ascii
    """
    TEXT = re.findall(rb"[\x20-\x7e]{4,}", data)
    return [match.decode("ascii") for match in TEXT]

def extract_ipv4(data:bytes) -> any|list[bytes]:
    """
        TODO: remove typing "any" later
    """
    return 0