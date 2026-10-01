from scapy.all import sniff
from scapy.packet import Packet
from scapy.plist import PacketList

from src.tp1.utils.args import Args
from src.tp1.utils.config import logger
from src.tp1.utils.lib import choose_interface


class Attack:
    
    def __init__(self, type: str, attacker: str):
        self.type = type 
        self.attacker = attacker 
        
    def to_dict(self) -> dict[str, str]:
        return {
            "type" : self.type,
            "attacker" : self.attacker
        }
        
Protocols = dict[str, int]

class Summary:
    def __init__(self, protocols: Protocols = {}, attacks: list[Attack] = [], flag: str = "") -> None:
        self.protocols = protocols
        self.attacks = attacks
        self.flag = flag
        
    def to_dict(self) -> dict[str, Protocols | str | list[Attack]]:
        return {
            "protocols": self.protocols,
            "attacks": self.attacks,
            "flag": self.flag
        }
                                


class Capture:
    def __init__(self, timeout: int = 5, pcap_file: str | None = None) -> None:
        self.interface:str = choose_interface()
        """Interface to sniff if no pcap"""
        
        self.pcap_file: str | None = pcap_file or Args.pcap_file or None
        self.is_offline:bool = self.pcap_file != None
        
        self.summary:Summary | None = None
        self.attacks:list[Attack] = []
        self.flag: str | None = None
        
        self.captured_packets: PacketList | None = None
        
        self._protocols: Protocols = {}
        self._timeout:int = timeout
        
    def _handle_packet(self, pkt: Packet) -> None:
        logger.debug("{}".format(pkt.summary()))
        for proto in pkt.layers():
            name = proto.__name__
            self._protocols[name] = self._protocols.get(name, 0) + 1
          

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        
        packets: PacketList | None = None
        
        if self.is_offline:
          logger.info(f"Capture offline of {Args.pcap_file}")
          packets = sniff(prn=self._handle_packet, offline=self.pcap_file, timeout=self._timeout)
        else:
          interface = self.interface
          logger.info(f"Capture traffic from interface {interface} for {self._timeout} seconds (Press Ctrl + C to interrupt)")

          packets = sniff(prn=self._handle_packet, iface = self.interface, timeout=self._timeout)
        
        self.interface = ""
        self.captured_packets = packets
        
        logger.info(f"{len(self.captured_packets or [])} packets captured")
        

    def sort_network_protocols(self) -> list[str]:
        """
        Sort and return all captured network protocols
        """
        return [k for k, _ in sorted(self._protocols.items(), key=lambda i: i[1], reverse=True)]

    def get_all_protocols(self) -> Protocols:
        """
        Return all protocols captured with total packets number
        """
        return self._protocols.copy()

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un trafic est illégitime (exemple : Injection SQL, ARP
        Spoofing, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")
        
        # TODO Check ARP Spoofing
        
        # TODO Check Port Scan
        
        # TODO Check SQL Injection
        
        
        if len(self.attacks) > 0:
            logger.info(f"{len(self.attacks)} attacks detected out of {len(self.captured_packets or [])}")

        self.summary = self._gen_summary()

    def get_summary(self) -> Summary | None: 
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> Summary: 
        """
        Generate summary
        """
        summary = Summary(self._protocols, self.attacks, self.flag or "")

        return summary
