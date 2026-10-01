from scapy.all import sniff
from scapy.packet import Packet
from scapy.plist import PacketList
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP


from src.tp1.utils.args import Args
from src.tp1.utils.config import logger
from src.tp1.utils.lib import choose_interface, contains_sql_injection, find_flags

import inspect


class Attack:

    def __init__(self, type: str, attacker: str):
        self.type = type
        self.attacker = attacker

    def to_dict(self) -> dict[str, str]:
        return {
            "type": self.type,
            "attacker": self.attacker
        }
        
    def __str__(self) -> str:
        return f"({self.type}, {self.attacker})"
    
    __repr__ = __str__


Protocols = dict[str, int]


class Summary:
    def __init__(self, protocols: Protocols | None = None, attacks: list[Attack] | None = None, flag: str = "") -> None:
        self.protocols = protocols or {}
        self.attacks = attacks or []
        self.flag = flag

    def to_dict(self) -> dict[str, Protocols | str | list[Attack]]:
        return {
            "protocols": self.protocols,
            "attacks": self.attacks,
            "flag": self.flag
        }
        
    def __str__(self) -> str:
        return f"Protocols : {self.protocols}\nattacks : {self.attacks}\nFlag : {self.flag}"


class Capture:
    def __init__(self, timeout: int = 5, pcap_file: str | None = None) -> None:
        self.interface: str = choose_interface()
        """Interface to sniff if no pcap"""

        self.pcap_file: str | None = pcap_file or Args.pcap_file or None
        self.is_offline: bool = self.pcap_file is not None

        self.summary: Summary | None = None
        self.attacks: list[Attack] = []
        self.flag: str | None = None

        self.captured_packets: PacketList | None = None

        self._protocols: Protocols = {}
        self._timeout: int = timeout
        
        self._is_capture_done: bool = False 
        self._is_analyse_done: bool = False 
                        

    def _handle_packet(self, pkt: Packet) -> None:
        # logger.debug(f"{pkt.summary()}")
        for proto in pkt.layers():
            name = proto.__name__
            self._protocols[name] = self._protocols.get(name, 0) + 1

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        self._is_analyse_done = False 
        self._is_capture_done = False 
                        
        packets: PacketList | None = None

        if self.is_offline:
            logger.info(f"Capture offline of {Args.pcap_file}")
            packets = sniff(prn=self._handle_packet,
                            offline=self.pcap_file, timeout=self._timeout)
        else:
            interface = self.interface
            logger.info(f"Capture traffic from interface {interface} for {
                        self._timeout} seconds (Press Ctrl + C to interrupt)")

            packets = sniff(prn=self._handle_packet,
                            iface=self.interface, timeout=self._timeout)

        self.captured_packets = packets
        
        self._is_capture_done = True

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

    def _filter_packets(self, protocols: list[str] | None = None) -> list[Packet]:
        filtered: list[Packet] = []

        if self.captured_packets is None:
            return filtered

        if protocols:
            for p in self.captured_packets:
                for layer in p.layers():
                    if layer.name in protocols:
                        filtered.append(p)
                        break

        else:
            filtered = self.captured_packets.res or []

        return filtered

    def _find_arp_spoofing(self) -> list[Attack]:
        attacks: list[Attack] = []
        
        if self.captured_packets is None : return attacks
        
        _detected = 0
        _arp_count = 0
        
        arp_table: dict[str, str] = {}
                        

        for pck in self.captured_packets:
            if pck.haslayer(ARP):
                _arp_count += 1
                _arp_l = pck.getlayer(ARP)
                if isinstance(_arp_l, ARP):
                    arp_l: ARP = _arp_l
                    mac, src = arp_l.hwsrc, arp_l.psrc
                    
                    if arp_table.get(src, mac) == mac:
                        arp_table[src] = mac 
                    
                    else: 
                        _detected += 1
                        
                        logger.debug(f"ARP Spoofing detected from {mac}")
                                                                        
                        attacks.append(Attack("arp", mac))
              
        logger.debug(f"{_detected} out of {_arp_count} ARP Spoofing detected !")

        return attacks

    def _find_port_scan(self, threshold: int = 20) -> list[Attack]:
        attacks: list[Attack] = []
        
        if self.captured_packets is None: return attacks
        
        # (ip src, ip dst) -> ports 
        scanned_ports: dict[tuple[str, str], set[int]] = {}
        
        for pck in self.captured_packets:
            if pck.haslayer(IP) and pck.haslayer(TCP):
                ip_l, tcp_l = pck[IP], pck[TCP]
                
                if tcp_l.flags == "S":
                    key = (ip_l.src, ip_l.dst)
                    scanned_ports.setdefault(key, set()).add(tcp_l.dport)
                    
        for (src, dst), ports in scanned_ports.items():
            if len(ports) >= threshold:
                logger.debug(f"Port scan detected from {src} on {dst} ({len(ports)} ports)")
                attacks.append(Attack("port_scan", src))

        logger.debug(f"{len(attacks)} port scan detected !")
        
        return attacks
    
    def _find_sql_injection(self) -> list[Attack]:
        attacks: list[Attack] = []
        
        if self.captured_packets is None: return attacks

        _detected = 0
        
        for pck in self.captured_packets:
            if not (pck.haslayer(IP) and pck.haslayer(TCP)):
                continue
            
            payload = pck[TCP].payload.load if pck[TCP].payload else "" 
            
            if len(payload) == 0:
                continue
            
            if contains_sql_injection(payload):
                flags = find_flags(payload)
                
                # TODO Test before remove and rely on _find_flag
                if len(flags) == 1:
                    self.flag = flags[0]
                elif len(flags) > 1:
                    logger.warn(f"More than one flag has been found in payload \"{payload}\"")
                
                _detected += 1
                src = pck[IP].src
                
                logger.debug(f"SQL injection ({src}:{pck[TCP].sport} -> {pck[IP].dst}:{pck[TCP].dport})")
                
                attacks.append(Attack("sql_injection", src))
                
        logger.debug(f"{_detected} SQL injection detected !")
        
        return attacks

    def _find_flag(self) -> str | None:
        raise NotImplemented()
    
        logger.debug("Starting search of SQL injection")
        
        if self.captured_packets is None: return 
        
        flags: list[str] = []
        
        for pck in self.captured_packets:
            if not (pck.haslayer(IP) and pck.haslayer(TCP)):
                continue
            
            payload = pck[TCP].payload.load if pck[TCP].payload else "" 
                        
            if len(payload) == 0:
                continue
            
            flags += find_flags(payload)
        
        if len(flags) != 1: return 
        
        return flags[0]

    def analyse(self, protocols: list[str] | str) -> None:
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
        
        if not self._is_capture_done:
            logger.warn("Analyse started without the capture done")
        
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        # TODO Check ARP Spoofing
        protocols_set: list[str] = [protocols] if isinstance(protocols, str) else protocols
        self.attacks += self._find_arp_spoofing()

        # TODO Check Port Scan
        self.attacks += self._find_port_scan()

        # TODO Check SQL Injection
        self.attacks += self._find_sql_injection()

        if len(self.attacks) > 0:
            logger.info(f"{len(self.attacks)} attacks detected out of {
                        len(self.captured_packets or [])}")
            
            
        self._is_analyse_done = True

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

        if not self._is_analyse_done:
            logger.warn("Summary generation started without the analyse done")
            
        summary = Summary(self._protocols, self.attacks, self.flag or "")
        
        _caller = inspect.stack()[1].function
        
        logger.debug(f"summary generated : \n==== Summary ====\n{summary}\n====\n (from func {_caller})")

        return summary
