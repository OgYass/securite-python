from unittest.mock import MagicMock, patch
import pytest

from src.tp1.utils.capture import Attack, Capture, Summary


@pytest.fixture
def mock_choose_interface():
    with patch("src.tp1.utils.capture.choose_interface", return_value="eth0") as mock:
        yield mock


def test_capture_init(mock_choose_interface):
    capture = Capture(timeout=20)
    assert capture.interface == "eth0"
    assert capture.summary is None
    assert capture.attacks == []
    assert capture.flag is None
    assert capture.captured_packets is None
    assert capture._protocols == {}
    assert capture._timeout == 20

    capture_ifc = Capture(interface="test-ifc")
    assert capture_ifc.pcap_file is None
    assert not capture_ifc.is_offline
    assert capture_ifc.interface == "test-ifc"
    assert capture_ifc._timeout == 5

    capture_pcap = Capture(pcap_file="test.pcap")
    assert capture_pcap.pcap_file == "test.pcap"
    assert capture_pcap.is_offline


@patch("src.tp1.utils.capture.sniff")
def test_capture_pcap(mock_sniff, mock_choose_interface):
    mock_packets = [MagicMock()] * 143
    mock_sniff.return_value = mock_packets

    capture = Capture(pcap_file="sample.pcap")
    capture.capture_traffic()

    assert capture.is_offline
    assert capture.captured_packets == mock_packets
    assert capture._is_capture_done is True
    assert capture._is_analyse_done is False
    mock_sniff.assert_called_once_with(prn=capture._handle_packet, offline="sample.pcap", timeout=5)


@patch("src.tp1.utils.capture.sniff")
def test_capture_interface(mock_sniff):
    capture = Capture(interface="eth0", timeout=10)
    capture.capture_traffic()

    assert not capture.is_offline
    mock_sniff.assert_called_once_with(prn=capture._handle_packet, iface="eth0", timeout=10)


def test_sort_network_protocols():
    capture = Capture(pcap_file="dummy.pcap")
    capture._protocols = {"IP": 123, "ETHERNET": 143, "TCP": 95, "UDP": 12}

    result = capture.sort_network_protocols()

    assert result == ["ETHERNET", "IP", "TCP", "UDP"]


def test_get_all_protocols():
    capture = Capture(pcap_file="dummy.pcap")
    expected_protocols = {"ETHERNET": 143, "IP": 123, "TCP": 95}
    capture._protocols = expected_protocols.copy()

    result = capture.get_all_protocols()

    assert result == expected_protocols
    result["NEW"] = 1
    assert capture._protocols != result


def test_analyse():
    capture = Capture()
    capture._is_capture_done = True

    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_find_arp_spoofing", return_value=[]),
        patch.object(capture, "_find_port_scan", return_value=[]),
        patch.object(capture, "_find_sql_injection", return_value=[]),
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        expected_summary = Summary(protocols={}, attacks=[], flag="")
        mock_gen_summary.return_value = expected_summary

        capture.analyse()

        mock_get_protocols.assert_called_once()
        mock_sort.assert_called_once()
        mock_gen_summary.assert_called_once()
        assert capture.summary == expected_summary
        assert capture._is_analyse_done is True


def test_gen_summary():
    capture = Capture()
    capture._protocols = {"ETHERNET": 10}
    capture.attacks = [Attack("arp_spoofing", "00:11:22:33:44:55")]
    capture.flag = "FLAG{test}"

    result = capture._gen_summary()

    assert result.protocols == {"ETHERNET": 10}
    assert result.attacks == [Attack("arp_spoofing", "00:11:22:33:44:55")]
    assert result.flag == "FLAG{test}"
