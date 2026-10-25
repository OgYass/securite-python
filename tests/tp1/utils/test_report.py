import json
from unittest.mock import MagicMock

import matplotlib.pyplot as pylab
import pytest

from tp1.utils.capture import Attack, Summary
from tp1.utils.report import Report


@pytest.fixture
def summary() -> Summary:
    return Summary({"TCP": 3, "ARP": 1}, [Attack("port_scan", "10.0.0.5")], "ESGI{tp1_test}")


def test_report_init(summary):
    # Given
    capture = MagicMock()
    filename = "test.pdf"

    # When
    report = Report(capture, filename, summary)

    # Then
    assert report.capture == capture
    assert report.filename == filename
    assert report.title == "TITRE DU RAPPORT"
    assert report.summary == summary
    assert report.array == []
    assert report.graph == pylab
    assert report.json == {}


def test_concat_report(tmp_path, summary):
    # Given
    filename = tmp_path / "test.pdf"
    report = Report(MagicMock(), str(filename), summary)

    # When
    result = report.concat_report()

    # Then
    assert isinstance(result, str)
    assert filename.read_bytes().startswith(b"%PDF")


def test_save(tmp_path, summary):
    # Given
    filename = tmp_path / "test.pdf"
    report = Report(MagicMock(), str(filename), summary)

    # When
    report.save(str(filename))

    # Then
    assert filename.exists()


@pytest.mark.skip(reason="graph generation is not implemented yet (TODO FIX graph in main.py)")
def test_generate_graph(summary):
    # Given
    report = Report(MagicMock(), "test.pdf", summary)

    # When
    report.generate("graph")

    # Then
    assert report.graph != pylab


def test_generate_array(summary):
    # Given
    report = Report(MagicMock(), "test.pdf", summary)

    # When
    report.generate("array")

    # Then
    assert report.array[0] == ["protocol", "count"]
    assert len(report.array) == 1 + len(summary.protocols)


def test_generate_invalid_param(summary):
    # Given
    report = Report(MagicMock(), "test.pdf", summary)

    # When
    report.generate("invalid")

    # Then
    assert report.graph == pylab
    assert report.array == []


def test_generate_json(summary):
    # Given
    report = Report(MagicMock(), "test.pdf", summary)

    # When
    report.generate_json()

    # Then
    assert json.loads(report.json) == summary.to_dict()
