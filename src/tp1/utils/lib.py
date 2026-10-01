from scapy.config import conf

from src.tp1.utils.args import Args


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interface = Args.iface or conf.iface.name or ""
    
    return interface
