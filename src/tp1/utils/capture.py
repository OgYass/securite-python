from scapy.all import sniff

from scapy.packet import Packet 

from src.tp1.utils.lib import choose_interface
from src.tp1.utils.args import Args
from src.tp1.utils.config import logger




class Capture:
    def __init__(self, timeout: int = 5) -> None:
        self.interface:str = choose_interface()
        """Interface to sniff if no pcap"""
        
        self.pcap_file: str | None = Args.pcap_file
        self.summary:str = ""
        
        self._protocols: dict[str, int] = {}
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
        
        if Args.is_offline:
          logger.info(f"Capture offline of {Args.pcap_file}")
          sniff(prn=self._handle_packet, offline=self.pcap_file, timeout=self._timeout)
        else:
          interface = self.interface
          logger.info(f"Capture traffic from interface {interface}")

          sniff(prn=self._handle_packet, iface = self.interface, timeout=self._timeout)
        
        self.interface = ""
        

    def sort_network_protocols(self) -> list[str]:
        """
        Sort and return all captured network protocols
        """
        return [k for k, _ in sorted(self._protocols.items(), key=lambda i: i[1], reverse=True)]

    def get_all_protocols(self) -> dict[str, int]:
        """
        Return all protocols captured with total packets number
        """
        return self._protocols.copy()

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
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

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""

        for k, v in self._protocols.items():
          summary += "{} {}\n".format(k, v)

        return summary
