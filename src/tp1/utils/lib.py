import re
from collections.abc import Iterable
from scapy.config import conf

from src.tp1.utils.args import Args

_FLAG_PATTERN = re.compile(r"ESGI\{tp1_[^}\s]+\}")

def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interface = Args.iface or conf.iface.name or ""
    
    return interface

def find_flags(data: str | bytes | Iterable[str | bytes]) -> list[str]:
    flags: list[str] = []
    
    if isinstance(data, (str, bytes)):
        data = [data]
        
    for text in data:
        if isinstance(text, bytes):
            text = text.decode(errors="ignore")
        for flag in _FLAG_PATTERN.findall(text):
            if flag not in flags:
                flags.append(flag)
                
    return flags