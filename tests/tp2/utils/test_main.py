import json
import sys
from pathlib import Path

from tp2 import main as tp2_main

RULES = Path(__file__).resolve().parents[3] / "rules"


def test_main_writes_one_json_per_sample(tmp_path: Path, monkeypatch):
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "a.bin").write_bytes(b"SetWindowsHookExA\x00FLAG=ESGI{key}\x00")
    out = tmp_path / "out"
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(
        sys, "argv", ["tp2", "--samples", str(samples), "--rules", str(RULES), "--out", str(out)]
    )

    tp2_main.main()

    files = list(out.glob("*.triage.json"))
    assert len(files) == 1
    result = json.loads(files[0].read_text())
    assert result["flag"] == "ESGI{key}"
    assert "Keylogger" in result["yara_matches"]


def test_main_empty_folder(tmp_path: Path, monkeypatch):
    samples = tmp_path / "samples"
    samples.mkdir()
    monkeypatch.setattr(
        sys, "argv", ["tp2", "--samples", str(samples), "--rules", str(RULES), "--out", str(tmp_path / "o")]
    )

    tp2_main.main()

    assert list((tmp_path / "o").iterdir()) == []
