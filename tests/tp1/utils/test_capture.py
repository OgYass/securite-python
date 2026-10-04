from unittest.mock import patch

from src.tp1.utils.capture import Capture, Summary, Attack
from src.tp1.utils.lib import choose_interface


def test_capture_init():
    # When
    capture = Capture(20)
    capture2 = Capture(interface="test-ifc")
    capture3 = Capture(pcap_file="test-pcap")

    # Then
    assert capture.interface == choose_interface()
    assert capture.summary == None
    assert capture.attacks == []
    assert capture.flag == None

    assert capture.captured_packets == None
    assert capture._protocols == {}
    assert capture._timeout == 20

    assert capture2.pcap_file is None
    assert not capture2.is_offline
    assert capture2.interface == "test-ifc"

    assert capture3.pcap_file == "test-pcap"
    assert capture3.is_offline

    assert capture2._timeout == 5


def test_capture_pcap():
    # Given
    capture = Capture(pcap_file="sample.pcap")

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == choose_interface()
    assert capture.is_offline
    assert capture.captured_packets

    assert capture._is_capture_done
    assert not capture._is_analyse_done

    assert len(capture.captured_packets) == 143
    assert capture._protocols == {
        "ETHERNET": 143,
        "ICMP": 16,
        "IP": 123,
        "Raw": 13,
        "TCP": 95,
        "ARP": 20,
        "UDP": 12,
        "DNS": 12,
    }


def test_capture_interface():
    pass  # TODO


def test_sort_network_protocols():
    # Given
    capture = Capture(pcap_file="sample.pcap")

    capture.capture_traffic()

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == [
        "ETHERNET",
        "IP",
        "TCP",
        "ARP",
        "ICMP",
        "Raw",
        "DNS",
        "UDP",
    ]  # Method currently returns None


def test_get_all_protocols():
    # Given
    capture = Capture(pcap_file="sample.pcap")

    capture.capture_traffic()

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {
        "ETHERNET": 143,
        "IP": 123,
        "ICMP": 16,
        "Raw": 13,
        "TCP": 95,
        "ARP": 20,
        "UDP": 12,
        "DNS": 12,
    }  # Method currently returns None


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


def test_get_summary():
    # Given
    capture = Capture(pcap_file="sample.pcap")

    capture.capture_traffic()
    capture.analyse()

    excepted_result = Summary(
        {"ETHERNET": 143, "ICMP": 16, "IP": 123, "Raw": 13, "TCP": 95, "ARP": 20, "UDP": 12, "DNS": 12},
        [
            Attack("arp_spoofing", "02:b8:04:ba:3d:35"),
            Attack("arp_spoofing", "02:b8:04:ba:3d:35"),
            Attack("arp_spoofing", "02:b8:04:ba:3d:35"),
            Attack("arp_spoofing", "02:b8:04:ba:3d:35"),
            Attack("port_scan", "192.168.241.66"),
            Attack("sql_injection", "192.168.241.77"),
        ],
        "ESGI{tp1_24b8a7d7be23}",
    )

    # When
    result = capture.get_summary()

    # Then
    assert result == excepted_result


def test_gen_summary():
    # Given
    capture = Capture()

    excepted_result = Summary()

    # When
    result = capture._gen_summary()

    # Then
    assert result == excepted_result  # Method currently returns empty string
