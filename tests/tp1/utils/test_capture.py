from unittest.mock import patch
from src.tp1.utils.capture import Capture


def test_capture_init():
    # When
    capture = Capture(20)
    capture2 = Capture()

    # Then
    assert capture.interface is str
    assert capture.summary == None
    assert capture.attacks == []
    assert capture.flag == None 
    
    assert capture.captured_packets == None 
    assert capture._protocols == {}
    assert capture._timeout == 20
    
    assert capture._timeout == 5


def test_capture_pcap():
    # Given
    capture = Capture(pcap_file='sample.pcap')

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == ""
    assert capture.is_offline == True
    assert capture.captured_packets != None # TODO Finir
    
def test_capture_interface():
  pass # TODO


def test_sort_network_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == ""  # Method currently returns None


def test_get_all_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == ""  # Method currently returns None


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
    capture = Capture()
    # capture.summary = "Test summary" 
    # TODO Corriger

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == ""  # Method currently returns empty string
