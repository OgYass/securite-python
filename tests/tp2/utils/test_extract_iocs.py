from src.tp2.utils.extract_iocs import extract_iocs, extract_text, extract_ipv4


class TestExtractText:
    def test_extract_ascii_strings(self):
        data = b"Hello World\x00https://evil.com\x01"
        assert extract_text(data) == [
            "Hello World",
            "https://evil.com",
        ]

    def test_ignores_strings_shorter_than_four_characters(self):
        data = b"abc\x00xy\x00test"
        assert extract_text(data) == ["test"]

    def test_empty_data(self):
        assert extract_text(b"") == []

    def test_non_ascii_bytes_split_strings(self):
        data = b"hello\xffworld"
        assert extract_text(data) == ["hello", "world"]


class TestExtractIPv4:
    def test_extract_valid_ipv4(self):
        data = b"Server: 192.168.1.10 and 8.8.8.8"
        assert extract_ipv4(data) == sorted(
            [
                "8.8.8.8",
                "192.168.1.10",
            ]
        )

    def test_rejects_invalid_ipv4(self):
        data = b"999.999.999.999 256.1.1.1 192.168.1.1"
        assert extract_ipv4(data) == ["192.168.1.1"]

    def test_removes_duplicate_ipv4(self):
        data = b"8.8.8.8 8.8.8.8 1.1.1.1"
        assert extract_ipv4(data) == ["1.1.1.1", "8.8.8.8"]

    def test_empty_data(self):
        assert extract_ipv4(b"") == []


class TestExtractIOCs:
    def test_extracts_all_ioc_types(self):
        data = (
            b"evil.example.com "
            b"https://evil.example.com/payload "
            b"192.168.1.10 "
            b"Global\\MalwareMutex "
            b"HKCU\\Software\\BadApp"
        )

        result = extract_iocs(data)

        assert result["domains"] == ["evil.example.com"]
        assert result["ips"] == ["192.168.1.10"]
        assert result["urls"] == ["https://evil.example.com/payload"]
        assert result["mutex"] == ["Global\\MalwareMutex"]
        assert result["registry"] == ["HKCU\\Software\\BadApp"]

    def test_extracts_multiple_domains(self):
        data = b"evil.com malware.example.org api.test.net"
        result = extract_iocs(data)

        assert result["domains"] == [
            "api.test.net",
            "evil.com",
            "malware.example.org",
        ]

    def test_domain_matching_is_case_insensitive(self):
        data = b"EVIL.COM Example.ORG"
        result = extract_iocs(data)

        assert result["domains"] == ["EVIL.COM", "Example.ORG"]

    def test_removes_duplicate_iocs(self):
        data = b"evil.com evil.com https://evil.com https://evil.com 8.8.8.8 8.8.8.8"
        result = extract_iocs(data)

        assert result["domains"] == ["evil.com"]
        assert result["urls"] == ["https://evil.com"]
        assert result["ips"] == ["8.8.8.8"]

    def test_extracts_urls_with_query_parameters(self):
        data = b"https://evil.com/download?id=123&file=abc"
        result = extract_iocs(data)

        assert result["urls"] == ["https://evil.com/download?id=123&file=abc"]

    def test_extracts_local_and_global_mutexes(self):
        data = b"Global\\MalwareMutex Local\\RansomLock BadMutex MalwareService"
        result = extract_iocs(data)

        assert result["mutex"] == [
            "BadMutex",
            "Global\\MalwareMutex",
            "Local\\RansomLock",
            "MalwareService",
        ]

    def test_extracts_registry_keys(self):
        data = (
            b"HKCU\\Software\\BadApp HKLM\\Software\\Microsoft HKCR\\CLSID\\1234 HKU\\User\\Run HKCC\\System"
        )
        result = extract_iocs(data)

        assert result["registry"] == [
            "HKCC\\System",
            "HKCR\\CLSID\\1234",
            "HKCU\\Software\\BadApp",
            "HKLM\\Software\\Microsoft",
            "HKU\\User\\Run",
        ]

    def test_registry_matching_is_case_insensitive(self):
        data = b"hkcu\\Software\\BadApp"
        result = extract_iocs(data)

        assert result["registry"] == ["hkcu\\Software\\BadApp"]

    def test_empty_data_returns_empty_lists(self):
        result = extract_iocs(b"")

        assert result == {
            "domains": [],
            "ips": [],
            "urls": [],
            "mutex": [],
            "registry": [],
        }

    def test_binary_data_does_not_crash(self):
        data = bytes(range(256))
        result = extract_iocs(data)

        assert set(result.keys()) == {
            "domains",
            "ips",
            "urls",
            "mutex",
            "registry",
        }

    def test_paths_are_not_returned(self):
        data = b"C:\\Windows\\System32\\cmd.exe /etc/passwd"
        result = extract_iocs(data)

        assert "paths" not in result
