import ipaddress
import re

def extract_iocs(data:bytes) -> dict:
    """
        Extraction des iocs en utilisant des patterns regex
    """
    text = "\n".join(extract_text(data))

    domain = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
    domains_list = set(domain.findall(text))

    url = re.compile(r"https?://[^\s\"']+")
    urls_list = set(url.findall(text))

    mutex = re.compile(
        r"\b(?:Global\\|Local\\)?"
        r"[A-Za-z0-9_.-]*"
        r"(?:mutex|malware|ransom|lock)"
        r"[A-Za-z0-9_.-]*\b",
        re.IGNORECASE,
    )
    mutex_list = set(mutex.findall(text))

    registry = re.compile(
        r"\b(?:HKCU|HKLM|HKCR|HKU|HKCC)"
        r"\\[^\s\"']+",
        re.IGNORECASE,
    )
    registry_list = set(registry.findall(text))

    path_windows = re.compile(
        r"""(?<![A-Za-z0-9_])(?:[A-Za-z]:\\|\\\\)[^\s"'<>|:*?]+(?:\\[^\s"'<>|:*?]+)*"""
    )

    path_linux = re.compile(
        r"""(?<![A-Za-z0-9_])/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+"""
    )
    paths_list = (set(path_windows.findall(text)))
    paths_list.update(path_linux.findall(text))

    ipv4_list = set(extract_ipv4(data))

    return {
        "domains": domains_list,
        "ips": ipv4_list,
        "urls":urls_list,
        "mutex":mutex_list,
        "registry": registry_list,
        "paths": paths_list,
        }

def extract_text(data:bytes) -> list[str]:
    """
        extraction de chaines ascii
    """
    text = re.findall(rb"[\x20-\x7e]{4,}", data)
    return [match.decode("ascii") for match in text]

def extract_ipv4(data:bytes) -> list[str]:
    """
        extraction d'adresse IPv4
    """
    text = "\n".join(extract_text(data))
    ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    ipv4_list = set()

    for match in ipv4.findall(text):
        try:
            ipaddress.IPv4Address(match)
            ipv4_list.add(match)
        except ipaddress.AddressValueError:
            continue

    return sorted(ipv4_list)