import json

from pathlib import Path


from fpdf import FPDF
from tp2.utils.report import Report


def test_report_initializes_with_result():
    """
    Verifie que le resultat est correctement stocke
    """
    result = {"sha256": "abc123", "size": 1024}

    report = Report(result)

    assert report.result == result


def test_generate_json_creates_file(tmp_path: Path):
    """
    Verifie que le fichier JSON est genere
    """
    result = {"sha256": "abc123", "size": 1024}
    file_path = tmp_path / "report.json"

    report = Report(result)
    report.generate_json(str(file_path))

    assert file_path.exists()
    assert file_path.is_file()


def test_generate_json_contains_expected_data(tmp_path: Path):
    """
    Verifie que le fichier JSON contient les donnees attendues
    """
    result = {
        "sha256": "abc123",
        "md5": "def456",
        "size": 1024,
    }
    file_path = tmp_path / "report.json"

    report = Report(result)
    report.generate_json(str(file_path))

    with file_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    assert data == result


def test_generate_json_preserves_unicode(tmp_path: Path):
    """
    Verifie que les caracteres Unicode sont conserves dans le JSON
    """
    result = {"description": "Fichier malveillant détecté"}
    file_path = tmp_path / "report.json"

    report = Report(result)
    report.generate_json(str(file_path))

    content = file_path.read_text(encoding="utf-8")

    assert "détecté" in content
    assert "\\u00e9" not in content


def test_generate_json_creates_parent_directories(tmp_path: Path):
    """
    Verifie que les repertoires parents sont crees automatiquement
    """
    result = {"sha256": "abc123"}
    file_path = tmp_path / "nested" / "reports" / "report.json"

    report = Report(result)
    report.generate_json(str(file_path))

    assert file_path.exists()
    assert json.loads(file_path.read_text(encoding="utf-8")) == result


def test_generate_json_empty_result(tmp_path: Path):
    """
    Verifie qu'un resultat vide est correctement exporte
    """
    file_path = tmp_path / "empty.json"

    report = Report({})
    report.generate_json(str(file_path))

    assert json.loads(file_path.read_text(encoding="utf-8")) == {}


def test_generate_json_nested_data(tmp_path: Path):
    """
    Verifie que les dictionnaires et listes imbriques sont conserves
    """
    result = {
        "meta": {"sha256": "abc123", "size": 512},
        "iocs": {
            "domains": ["evil.com", "malware.test"],
            "ips": ["192.168.1.10"],
        },
    }
    file_path = tmp_path / "nested.json"

    report = Report(result)
    report.generate_json(str(file_path))

    data = json.loads(file_path.read_text(encoding="utf-8"))

    assert data == result
    assert data["iocs"]["domains"] == ["evil.com", "malware.test"]


def test_generate_json_converts_non_serializable_values(tmp_path: Path):
    """
    Verifie que les objets non serialisables sont convertis en chaines
    """
    result = {"path": Path("samples") / "sample.exe"}
    file_path = tmp_path / "report.json"

    report = Report(result)
    report.generate_json(str(file_path))

    data = json.loads(file_path.read_text(encoding="utf-8"))

    assert data["path"] == str(result["path"])


def test_generate_pdf_creates_file(tmp_path: Path):
    """
    Verifie que le fichier PDF est genere
    """
    file_path = tmp_path / "report.pdf"
    report = Report({"sha256": "abc123"})

    report.generate_pdf(str(file_path))

    assert file_path.exists()
    assert file_path.is_file()
    assert file_path.stat().st_size > 0


def test_generate_pdf_creates_parent_directories(tmp_path: Path):
    """
    Verifie que les repertoires parents sont crees automatiquement
    """
    file_path = tmp_path / "nested" / "reports" / "report.pdf"
    report = Report({"sha256": "abc123"})

    report.generate_pdf(str(file_path))

    assert file_path.exists()
    assert file_path.stat().st_size > 0


def test_generate_pdf_contains_report_title(tmp_path: Path):
    """
    Verifie que le PDF contient le titre du rapport
    """
    import pymupdf

    file_path = tmp_path / "report.pdf"
    report = Report({"sha256": "abc123"})

    report.generate_pdf(str(file_path))

    pdf = FPDF()
    pdf.set_compression(False)

    # Le fichier genere est verifie avec PyMuPDF.

    document = pymupdf.open(str(file_path))
    text = "\n".join(page.get_text() for page in document)

    assert "Malware Triage Report" in text


def test_generate_pdf_contains_result_keys_and_values(tmp_path: Path):
    """
    Verifie que les cles et valeurs du resultat apparaissent dans le PDF
    """
    file_path = tmp_path / "report.pdf"
    result = {"sha256": "abc123", "size": 1024}
    report = Report(result)

    report.generate_pdf(str(file_path))

    import pymupdf

    document = pymupdf.open(str(file_path))
    text = "\n".join(page.get_text() for page in document)

    assert "Analysis results" in text
    assert "sha256" in text
    assert "abc123" in text
    assert "size" in text
    assert "1024" in text


def test_generate_pdf_empty_result(tmp_path: Path):
    """
    Verifie que le PDF est genere avec un resultat vide
    """
    file_path = tmp_path / "empty.pdf"
    report = Report({})

    report.generate_pdf(str(file_path))

    assert file_path.exists()
    assert file_path.stat().st_size > 0


def test_generate_pdf_nested_data(tmp_path: Path):
    """
    Verifie que les donnees imbriquees sont presentes dans le PDF
    """
    file_path = tmp_path / "nested.pdf"
    result = {
        "meta": {"sha256": "abc123"},
        "iocs": {
            "domains": ["evil.com"],
            "ips": ["192.168.1.10"],
        },
    }
    report = Report(result)

    report.generate_pdf(str(file_path))

    import pymupdf

    document = pymupdf.open(str(file_path))
    text = "\n".join(page.get_text() for page in document)

    assert "meta" in text
    assert "sha256" in text
    assert "abc123" in text
    assert "iocs" in text
    assert "evil.com" in text
    assert "192.168.1.10" in text


def test_write_pdf_empty_list(tmp_path: Path):
    """
    Verifie qu'une liste vide est representee par none dans le PDF
    """
    file_path = tmp_path / "empty_list.pdf"
    report = Report({"domains": []})

    report.generate_pdf(str(file_path))

    import pymupdf

    document = pymupdf.open(str(file_path))
    text = "\n".join(page.get_text() for page in document)

    assert "domains" in text
    assert "(none)" in text


def test_write_pdf_nested_list(tmp_path: Path):
    """
    Verifie que les elements d'une liste sont ecrits individuellement
    """
    file_path = tmp_path / "list.pdf"
    report = Report({"domains": ["evil.com", "malware.test"]})

    report.generate_pdf(str(file_path))

    import pymupdf

    document = pymupdf.open(str(file_path))
    text = "\n".join(page.get_text() for page in document)

    assert "evil.com" in text
    assert "malware.test" in text


def test_write_pdf_mixed_data_types(tmp_path: Path):
    """
    Verifie que les differentes valeurs sont converties en texte
    """
    file_path = tmp_path / "mixed.pdf"
    result = {
        "enabled": True,
        "count": 42,
        "value": None,
        "items": [1, "test", False],
    }
    report = Report(result)

    report.generate_pdf(str(file_path))

    import pymupdf

    document = pymupdf.open(str(file_path))
    text = "\n".join(page.get_text() for page in document)

    assert "True" in text
    assert "42" in text
    assert "None" in text
    assert "test" in text
    assert "False" in text
