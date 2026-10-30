import lief

from tp2.utils import parse_binary as pb


def test_parse_binary_non_executable():
    result = pb.parse_binary(b"just text")

    assert result["format"] is None
    assert result["imports"] == []


def test_parse_data_invalid():
    assert pb.parse_data(b"") is None


def test_parse_elf_from_python_interpreter():
    import sys

    with open(sys.executable, "rb") as file:
        data = file.read()
    result = pb.parse_binary(data)
    binary = lief.parse(data)

    assert result["format"] == "ELF"
    assert pb.parse_format(binary) == "ELF"
    assert pb.parse_architecture(binary, "ELF") is not None
    assert isinstance(pb.parse_entrypoint(binary), int)
    assert isinstance(pb.parse_imports(binary, "ELF"), list)
    assert len(pb.parse_sections(binary)) > 0
