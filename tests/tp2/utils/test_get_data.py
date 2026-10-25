
import hashlib

from pathlib import Path

import pytest

from tp2.utils.get_data import (
    get_data,
    get_file,
    get_metadata,
    entropy_calc,
)


# --- Tests de get_file ---

def test_get_file_reads_binary_file(tmp_path: Path):
    """
        Verifie que le fichier est lu correctement
    """
    file_path = tmp_path / "sample.bin"
    expected_data = b"\x00\x01Hello\xff"
    file_path.write_bytes(expected_data)

    result = get_file(str(file_path))

    assert result == expected_data
    assert isinstance(result, bytes)


def test_get_file_missing_file():
    """
        Verifie qu'une erreur est envoyée si le fichier n'existe pas
    """
    with pytest.raises(FileNotFoundError):
        get_file("fichier_inexistant.bin")


# --- Tests de get_data ---

def test_get_data_returns_metadata(tmp_path: Path):
    """
        Verifie que get_data lit le fichier et retourne ses metadata
    """
    file_path = tmp_path / "sample.txt"
    data = b"Bonjour"
    file_path.write_bytes(data)

    result = get_data(str(file_path))

    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["md5"] == hashlib.md5(data).hexdigest()
    assert result["size"] == len(data)
    assert "ftype" in result
    assert result["entropy"] == pytest.approx(entropy_calc(data))


def test_get_data_missing_file():
    """
        Verifie que get_data envoie une erreur si le fichier est absent
    """
    with pytest.raises(FileNotFoundError):
        get_data("fichier_inexistant.bin")


# --- Tests de get_metadata ---

def test_get_metadata_hashes_and_size():
    """
        Verifie les hashes et la taille du fichier
    """
    data = b"Bonjour"

    result = get_metadata(data)

    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["md5"] == hashlib.md5(data).hexdigest()
    assert result["size"] == len(data)


def test_get_metadata_has_expected_keys():
    """
        Verifie la structure de la réponse
    """
    result = get_metadata(b"Bonjour")

    assert set(result.keys()) == {
        "sha256",
        "md5",
        "ftype",
        "size",
        "entropy",
    }


def test_get_metadata_file_type():
    """
        Verifie que le type de fichier est renseigné
    """
    result = get_metadata(b"Bonjour")

    assert isinstance(result["ftype"], str)
    assert len(result["ftype"]) > 0


def test_get_metadata_entropy():
    """
        Verifie que l'entropie correspond au resultat attendu
    """
    data = b"AB"

    result = get_metadata(data)

    assert result["entropy"] == pytest.approx(1.0)


# --- Tests de entropy_calc ---

def test_entropy_empty_data():
    """
        Un fichier vide possède une entropie de 0
    """
    assert entropy_calc(b"") == 0.0


def test_entropy_repeated_bytes():
    """
        Des octets identiques donnent une entropie de 0
    """
    assert entropy_calc(b"AAAAAA") == 0.0


def test_entropy_two_equally_common_bytes():
    """
        Deux octets equiprobables donnent une entropie de 1
    """
    assert entropy_calc(b"AB") == pytest.approx(1.0)


def test_entropy_four_equally_common_bytes():
    """
        Quatre octets equiprobables donnent une entropie de 2
    """
    assert entropy_calc(b"ABCD") == pytest.approx(2.0)


def test_entropy_uniform_byte_distribution():
    """
        Les 256 valeurs d'octets equiprobables donnent une entropie de 8
    """
    data = bytes(range(256))

    assert entropy_calc(data) == pytest.approx(8.0)
