from pathlib import Path

from tp2.utils.scanner import YaraScanner

RULE = """
rule Test_Rule
{
    meta:
        description = "regle de test"
        mitre_attack = "T1000"
    strings:
        $a = "EVILSTRING"
    condition:
        $a
}
"""


def write_rules(folder: Path) -> Path:
    folder.mkdir()
    (folder / "test.yar").write_text(RULE)
    (folder / "broken.yar").write_text("rule {")
    return folder


def test_scan_returns_rule_names(tmp_path: Path):
    scanner = YaraScanner(str(write_rules(tmp_path / "rules")))

    assert scanner.scan(b"xx EVILSTRING xx") == ["Test_Rule"]
    assert scanner.scan(b"clean") == []


def test_scan_details_contains_meta(tmp_path: Path):
    scanner = YaraScanner(str(write_rules(tmp_path / "rules")))

    details = scanner.scan_details(b"EVILSTRING")

    assert details[0]["name"] == "Test_Rule"
    assert details[0]["mitre_attack"] == "T1000"


def test_rule_files_accepts_single_file(tmp_path: Path):
    path = tmp_path / "one.yar"
    path.write_text(RULE)

    assert YaraScanner(str(path)).rule_files() == {"one": str(path)}


def test_missing_rules_folder(tmp_path: Path):
    scanner = YaraScanner(str(tmp_path / "absent"))

    assert scanner.rules is None
    assert scanner.compile_rules() is None
    assert scanner.scan(b"EVILSTRING") == []


def test_course_rules_match():
    rules = Path(__file__).resolve().parents[3] / "rules"
    scanner = YaraScanner(str(rules))

    assert "Reverse_Shell" in scanner.scan(b"WSASocketA cmd.exe")
    assert "Keylogger" in scanner.scan(b"SetWindowsHookExA")
    assert "Has_Mutex" in scanner.scan(b"Global\\abc12345")
