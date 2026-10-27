from unittest.mock import patch

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.plist import PacketList
from scapy.utils import wrpcap

from tp1.utils.capture import Attack, Capture, Summary

ETHERNET = Capture._LAYER_ALIASES["Ether"]


def _arp_reply(ip: str, mac: str) -> Ether:
    return Ether(src=mac) / ARP(op=2, psrc=ip, hwsrc=mac, pdst="10.0.0.20")


def _syn(src: str, dst: str, dport: int) -> Ether:
    return Ether() / IP(src=src, dst=dst) / TCP(dport=dport, flags="S")


def _http_request(src: str, payload: bytes) -> Ether:
    return Ether() / IP(src=src, dst="10.0.0.1") / TCP(dport=80, flags="PA") / Raw(load=payload)


def test_attack_to_dict():
    # Given
    attack = Attack("port_scan", "10.0.0.5")

    # When
    result = attack.to_dict()

    # Then
    assert result == {"type": "port_scan", "attacker": "10.0.0.5"}


def test_attack_str():
    # Given
    attack = Attack("arp_spoofing", "aa:bb:cc:dd:ee:ff")

    # When
    result = str(attack)

    # Then
    assert result == "(arp_spoofing, aa:bb:cc:dd:ee:ff)"
    assert repr(attack) == result


def test_summary_init():
    # When
    summary = Summary()

    # Then
    assert summary.protocols == {}
    assert summary.attacks == []
    assert summary.flag == ""


def test_summary_to_dict():
    # Given
    summary = Summary({"TCP": 3}, [Attack("sql_injection", "10.0.0.9")], "ESGI{tp1_test}")

    # When
    result = summary.to_dict()

    # Then
    assert result == {
        "protocols": {"TCP": 3},
        "attacks": [{"type": "sql_injection", "attacker": "10.0.0.9"}],
        "flag": "ESGI{tp1_test}",
    }


def test_summary_str():
    # Given
    summary = Summary({"ARP": 1}, [], "ESGI{tp1_test}")

    # When
    result = str(summary)

    # Then
    assert "{'ARP': 1}" in result
    assert "ESGI{tp1_test}" in result


def test_capture_init():
    # When
    capture = Capture(20)
    capture2 = Capture()

    # Then
    assert isinstance(capture.interface, str)
    assert capture.summary == None
    assert capture.attacks == []
    assert capture.flag == None

    assert capture.captured_packets == None
    assert capture._protocols == {}
    assert capture._timeout == 20

    assert capture2._timeout == 5


def test_capture_init_with_pcap():
    # When
    capture = Capture(pcap_file="test.pcap", interface="eth0")

    # Then
    assert capture.pcap_file == "test.pcap"
    assert capture.interface == "eth0"
    assert capture.is_offline


def test_handle_packet():
    # Given
    capture = Capture()

    # When
    capture._handle_packet(_syn("10.0.0.5", "10.0.0.1", 80))
    capture._handle_packet(_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:ff"))

    # Then
    assert capture._protocols == {ETHERNET: 2, "IP": 1, "TCP": 1, "ARP": 1}


def test_capture_pcap(tmp_path):
    # Given
    pcap_file = tmp_path / "test.pcap"
    wrpcap(str(pcap_file), [_syn("10.0.0.5", "10.0.0.1", 22), _arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:ff")])
    capture = Capture(pcap_file=str(pcap_file))

    # When
    capture.capture_traffic()

    # Then
    assert capture.is_offline
    assert len(capture.captured_packets) == 2
    assert capture._protocols[ETHERNET] == 2
    assert capture._protocols["ARP"] == 1
    assert capture._is_capture_done


def test_capture_interface():
    # Given
    capture = Capture(interface="eth0", timeout=1)
    capture.pcap_file = None
    capture.is_offline = False
    packets = PacketList([_syn("10.0.0.5", "10.0.0.1", 22)])

    # When
    with patch("tp1.utils.capture.sniff", return_value=packets) as mock_sniff:
        capture.capture_traffic()

    # Then
    mock_sniff.assert_called_once_with(prn=capture._handle_packet, iface="eth0", timeout=1)
    assert capture.captured_packets == packets
    assert capture._is_capture_done


def test_sort_network_protocols():
    # Given
    capture = Capture()
    capture._protocols = {"TCP": 5, "ARP": 2, "IP": 7}

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == ["IP", "TCP", "ARP"]


def test_get_all_protocols():
    # Given
    capture = Capture()
    capture._protocols = {"TCP": 5}

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {"TCP": 5}
    assert result is not capture._protocols


def test_find_arp_spoofing():
    # Given
    capture = Capture()
    capture.captured_packets = PacketList(
        [_arp_reply("10.0.0.1", "aa:aa:aa:aa:aa:aa")] + [_arp_reply("10.0.0.1", "bb:bb:bb:bb:bb:bb")] * 3
    )

    # When
    result = capture._find_arp_spoofing()

    # Then
    assert [a.to_dict() for a in result] == [{"type": "arp_spoofing", "attacker": "bb:bb:bb:bb:bb:bb"}]


def test_find_arp_spoofing_without_attack():
    # Given
    capture = Capture()
    capture.captured_packets = PacketList([_arp_reply("10.0.0.1", "aa:aa:aa:aa:aa:aa")] * 3)

    # When
    result = capture._find_arp_spoofing()

    # Then
    assert result == []


def test_find_arp_spoofing_without_capture():
    # Given
    capture = Capture()

    # When
    result = capture._find_arp_spoofing()

    # Then
    assert result == []


def test_find_port_scan():
    # Given
    capture = Capture()
    capture.captured_packets = PacketList([_syn("10.0.0.5", "10.0.0.1", port) for port in range(1, 21)])

    # When
    result = capture._find_port_scan()

    # Then
    assert [a.to_dict() for a in result] == [{"type": "port_scan", "attacker": "10.0.0.5"}]


def test_find_port_scan_under_threshold():
    # Given
    capture = Capture()
    capture.captured_packets = PacketList([_syn("10.0.0.5", "10.0.0.1", port) for port in range(1, 6)])

    # When
    result = capture._find_port_scan(threshold=10)

    # Then
    assert result == []


def test_find_port_scan_without_capture():
    # Given
    capture = Capture()

    # When
    result = capture._find_port_scan()

    # Then
    assert result == []


def test_find_sql_injection():
    # Given
    capture = Capture()
    capture.captured_packets = PacketList(
        [
            _http_request("10.0.0.2", b"GET /index.html HTTP/1.1\r\n\r\n"),
            _http_request("10.0.0.9", b"GET /login?user=admin' OR 1=1 -- ESGI{tp1_test} HTTP/1.1\r\n\r\n"),
            _syn("10.0.0.5", "10.0.0.1", 80),
        ]
    )

    # When
    result = capture._find_sql_injection()

    # Then
    assert [a.to_dict() for a in result] == [{"type": "sql_injection", "attacker": "10.0.0.9"}]
    assert capture.flag == "ESGI{tp1_test}"


def test_find_sql_injection_without_capture():
    # Given
    capture = Capture()

    # When
    result = capture._find_sql_injection()

    # Then
    assert result == []
    assert capture.flag == None


def test_find_flag():
    # Given
    capture = Capture()

    # When/Then
    with pytest.raises(NotImplementedError):
        capture._find_flag()


def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_analyse_detects_attacks():
    # Given
    capture = Capture()
    capture._is_capture_done = True
    capture.captured_packets = PacketList([_syn("10.0.0.5", "10.0.0.1", port) for port in range(1, 21)])

    # When
    capture.analyse("tcp")

    # Then
    assert capture._is_analyse_done
    assert capture.summary.to_dict()["attacks"] == [{"type": "port_scan", "attacker": "10.0.0.5"}]


def test_get_summary():
    # Given
    capture = Capture()
    summary = Summary({"TCP": 1})
    capture.summary = summary

    # When
    result = capture.get_summary()

    # Then
    assert result is summary


def test_gen_summary():
    # Given
    capture = Capture()
    capture._protocols = {"TCP": 2}
    capture.attacks = [Attack("port_scan", "10.0.0.5")]
    capture.flag = "ESGI{tp1_test}"

    # When
    result = capture._gen_summary()

    # Then
    assert result.to_dict() == {
        "protocols": {"TCP": 2},
        "attacks": [{"type": "port_scan", "attacker": "10.0.0.5"}],
        "flag": "ESGI{tp1_test}",
    }
