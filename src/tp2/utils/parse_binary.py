import lief
from lief import Binary


def parse_binary(data: bytes) -> dict:
    result = {
        "format": None,
        "architecture": None,
        "entrypoint": None,
        "imports": [],
        "sections": [],
    }
    try:
        binary = parse_data(data)
    except (RuntimeError, ValueError):
        binary = None
    if binary is None:
        return result
    # logger.info(binary)

    result["format"] = parse_format(binary)
    result["architecture"] = parse_architecture(binary)
    result["entrypoint"] = parse_entrypoint(binary)
    result["imports"] = parse_imports(binary)
    result["sections"] = parse_sections(binary)

    return result


def parse_data(data: bytes) -> Binary | None:
    try:
        binary = lief.parse(data)
    except (RuntimeError, ValueError):
        return None

    if binary is None:
        return None

    return binary


def parse_entrypoint(binary: Binary) -> int | None:
    try:
        entrypoint = binary.entrypoint
        return entrypoint
    except (RuntimeError, ValueError):
        return None


def parse_format(binary: Binary) -> str | None:
    try:
        return binary.format.name
    except (RuntimeError, ValueError):
        return None


def parse_architecture(binary: Binary) -> str | None:
    try:
        return binary.header.machine.name
    except (RuntimeError, ValueError):
        return None


def parse_imports(binary: Binary) -> list[str] | None:
    try:
        imports = []
        for imp in binary.imports:
            imports.append(imp.name)
        return imports
    except (RuntimeError, ValueError):
        return None


def parse_sections(binary: Binary) -> list[str] | None:
    try:
        sections = []
        for sec in binary.sections:
            sections.append(sec.name)
        return sections
    except (RuntimeError, ValueError):
        return None
