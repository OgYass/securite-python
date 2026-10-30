import ipaddress
import re

# Extensions de fichiers que la regex de domaine confond avec un TLD (urlmon.dll, cmd.exe...)
FILE_EXTENSIONS = {
    "dll",
    "exe",
    "sys",
    "so",
    "php",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "js",
    "txt",
    "log",
    "dat",
    "bin",
    "ini",
    "cfg",
    "tmp",
    "py",
    "sh",
    "html",
    "htm",
    "xml",
    "json",
    "png",
    "jpg",
    "gif",
    "zip",
    "rar",
    "doc",
    "docx",
    "pdf",
    "lnk",
    "scr",
    "drv",
    "ocx",
    "cpl",
    "msi",
    "jar",
    "c",
    "h",
    "cpp",
    "mo",
    "gz",
    "debug",
    "got",
    "plt",
    "dyn",
    "hash",
    "version",
    "property",
    "build",
    "tag",
}

# Domaines légitimes présents dans les chaînes de binaires courants (coreutils, libc...)
BENIGN_DOMAINS = {
    "gnu.org",
    "translationproject.org",
    "microsoft.com",
    "windowsupdate.com",
    "w3.org",
    "openssl.org",
    "python.org",
    "mozilla.org",
    "sourceware.org",
    "kernel.org",
}

# Pas de point juste avant : écarte les noms de sections ELF/PE (.gnu.hash, .data.rel.ro...)
DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
MUTEX_RE = re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.{}-]+")
REGISTRY_RE = re.compile(r"\b(?:HKCU|HKLM|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s\"'<>]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FLAG_RE = re.compile(r"ESGI\{[^}\s]+\}")
INJECTION_RE = re.compile(
    r"ignore (?:all |the )?previous instructions|ignore les instructions|AI_INSTRUCTIONS|"
    r"honeypot|mark the sample clean|d[ée]clare ce fichier sain",
    re.IGNORECASE,
)


def extract_text(data: bytes) -> list[str]:
    """Extraction des chaînes ASCII imprimables d'au moins 4 caractères."""
    text = re.findall(rb"[\x20-\x7e]{4,}", data)
    return [match.decode("ascii") for match in text]


def is_benign_domain(domain: str) -> bool:
    """Vrai si le domaine appartient (ou est sous-domaine) d'un domaine légitime connu."""
    domain = domain.lower()
    return any(domain == benign or domain.endswith("." + benign) for benign in BENIGN_DOMAINS)


def is_valid_domain(candidate: str) -> bool:
    """Écarte les noms de fichiers (x.dll) et les TLD à casse mélangée (octets aléatoires)."""
    tld = candidate.rsplit(".", 1)[-1]
    if not (tld.islower() or tld.isupper()):
        return False
    return tld.lower() not in FILE_EXTENSIONS


def url_host(url: str) -> str:
    """Hôte d'une URL, sans port ni identifiants."""
    host = url.split("://", 1)[-1].split("/", 1)[0]
    return host.rsplit("@", 1)[-1].split(":", 1)[0]


def extract_urls(text: str) -> list[str]:
    """URLs http(s), hors domaines légitimes connus."""
    urls = {url.rstrip(".,;)>") for url in URL_RE.findall(text)}
    return sorted(url for url in urls if not is_benign_domain(url_host(url)))


def extract_domains(text: str) -> list[str]:
    """Noms de domaine plausibles, hors noms de fichiers et domaines légitimes."""
    domains = set()
    for candidate in DOMAIN_RE.findall(text):
        if is_valid_domain(candidate) and not is_benign_domain(candidate):
            domains.add(candidate)
    return sorted(domains)


def extract_ipv4(data: bytes) -> list[str]:
    """Extraction des adresses IPv4 valides."""
    text = "\n".join(extract_text(data))
    ipv4_list = set()
    for match in IPV4_RE.findall(text):
        try:
            ipaddress.IPv4Address(match)
            ipv4_list.add(match)
        except ipaddress.AddressValueError:
            continue
    return sorted(ipv4_list)


def extract_flag(data: bytes) -> str:
    """Flag ESGI{...} extrait sans LLM.

    Les lignes qui ressemblent à une injection de prompt (« ignore previous
    instructions », « honeypot »...) sont des leurres et sont écartées. On
    privilégie un flag annoncé explicitement par « FLAG= ».
    """
    trusted = [line for line in extract_text(data) if not INJECTION_RE.search(line)]
    for line in trusted:
        match = re.search(r"FLAG\s*[=:]\s*(ESGI\{[^}\s]+\})", line, re.IGNORECASE)
        if match:
            return match.group(1)
    for line in trusted:
        match = FLAG_RE.search(line)
        if match:
            return match.group(0)
    return ""


def has_prompt_injection(data: bytes) -> bool:
    """Détecte un texte destiné à manipuler un LLM."""
    return any(INJECTION_RE.search(line) for line in extract_text(data))


def extract_iocs(data: bytes) -> dict:
    """Extraction des IOC (domaines, IP, URLs, mutex, clés de registre) par regex."""
    text = "\n".join(extract_text(data))
    return {
        "domains": extract_domains(text),
        "ips": extract_ipv4(data),
        "urls": extract_urls(text),
        "mutex": sorted(set(MUTEX_RE.findall(text))),
        "registry": sorted({key.rstrip(".,;") for key in REGISTRY_RE.findall(text)}),
    }
