import ipaddress
import re

FILE_EXTENSIONS = {
    "dll",
    "exe",
    "sys",
    "so",
    "php",
    "bat",
    "txt",
    "dat",
    "bin",
    "debug",
    "hash",
    "got",
    "plt",
    "dyn",
    "version",
    "property",
    "build",
    "tag",
}
BENIGN_DOMAINS = {"gnu.org", "translationproject.org", "microsoft.com"}


def extract_iocs(data: bytes) -> dict:
    """
    Extraction des iocs en utilisant des patterns regex
    """
    text = "\n".join(extract_text(data))

    domain = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
    domains_list = {d for d in domain.findall(text) if is_valid_domain(d)}
    if len(domains_list) == 0:
        domains_list = []

    url = re.compile(r"https?://[^\s\"'<>]+")
    urls_list = set()
    for u in url.findall(text):
        host = u.split("://")[1].split("/")[0].split(":")[0]
        if not is_benign(host):
            urls_list.add(u)
    if len(urls_list) == 0:
        urls_list = []

    mutex = re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.{}-]+")
    mutex_list = set(mutex.findall(text))
    if len(mutex_list) == 0:
        mutex_list = []

    registry = re.compile(
        r"\b(?:HKCU|HKLM|HKCR|HKU|HKCC)"
        r"\\[^\s\"']+",
        re.IGNORECASE,
    )
    registry_list = set(registry.findall(text))
    if len(registry_list) == 0:
        registry_list = []

    path_windows = re.compile(r"""(?<![A-Za-z0-9_])(?:[A-Za-z]:\\|\\\\)[^\s"'<>|:*?]+(?:\\[^\s"'<>|:*?]+)*""")

    path_linux = re.compile(r"""(?<![A-Za-z0-9_])/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+""")
    paths_list = set(path_windows.findall(text))
    paths_list.update(path_linux.findall(text))
    if len(paths_list) == 0:
        paths_list = []

    ipv4_list = set(extract_ipv4(data))
    if len(ipv4_list) == 0:
        ipv4_list = []

    return {
        "domains": sorted(domains_list),
        "ips": sorted(ipv4_list),
        "urls": sorted(urls_list),
        "mutex": sorted(mutex_list),
        "registry": sorted(registry_list),
        # "paths": paths_list,
    }


def extract_text(data: bytes) -> list[str]:
    """
    extraction de chaines ascii
    """
    text = re.findall(rb"[\x20-\x7e]{4,}", data)
    return [match.decode("ascii") for match in text]


def extract_ipv4(data: bytes) -> list[str]:
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


def is_benign(domain: str) -> bool:
    """
    domaine legitime connu (ou sous-domaine)
    """
    domain = domain.lower()
    for benign in BENIGN_DOMAINS:
        if domain == benign or domain.endswith("." + benign):
            return True
    return False


def is_valid_domain(domain: str) -> bool:
    """
    ecarte les noms de fichiers (urlmon.dll), le bruit binaire et les domaines legitimes
    """
    tld = domain.rsplit(".", 1)[-1]
    if not (tld.islower() or tld.isupper()):
        return False
    if tld.lower() in FILE_EXTENSIONS:
        return False
    return not is_benign(domain)


INJECTION = re.compile(r"ignore previous instructions|ignore les instructions|AI_INSTRUCTIONS|honeypot", re.I)


def has_injection(data: bytes) -> bool:
    """
    detection d'une injection de prompt dans les chaines
    """
    return any(INJECTION.search(line) for line in extract_text(data))


def extract_flag(data: bytes) -> str:
    """
    recherche du flag ESGI{...} en ignorant les lignes d'injection (leurres)
    """
    lines = [line for line in extract_text(data) if not INJECTION.search(line)]

    for line in lines:
        match = re.search(r"FLAG\s*[=:]\s*(ESGI\{[^}\s]+\})", line)
        if match:
            return match.group(1)

    for line in lines:
        match = re.search(r"ESGI\{[^}\s]+\}", line)
        if match:
            return match.group(0)
    return ""
