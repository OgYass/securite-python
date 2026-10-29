import lief
from lief import Binary

from tp2.utils.config import logger


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
    result["architecture"] = parse_architecture(binary, result["format"])
    result["entrypoint"] = parse_entrypoint(binary)
    result["imports"] = parse_imports(binary, result["format"])
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


def parse_architecture(binary: Binary, format: str) -> str | None:
    try:
        if format == "PE":
            return binary.header.machine.name
        if format == "ELF":
            return binary.header.machine_type.name
    except (RuntimeError, ValueError):
        return None


def parse_imports(binary: Binary, format: str) -> list[str] | None:
    try:
        if format == "PE":
            imports = []
            for imp in binary.imports:
                imports.append(imp.name)
            return sorted(imports)
        if format == "ELF":
            imports = set()
            for symbol in binary.dynamic_symbols:
                if symbol.name and symbol.value == 0:
                    imports.add(symbol.name)

            for relocation in binary.relocations:
                try:
                    symbol = relocation.symbol
                    if symbol is not None and symbol.name:
                        imports.add(symbol.name)
                except (AttributeError, RuntimeError):
                    continue

            return sorted(imports)
    except (RuntimeError, AttributeError, ValueError) as error:
        logger.warning(f"Failed to parse imports... -> {error}")


def parse_sections(binary: Binary) -> list[str] | None:
    try:
        sections = []
        for sec in binary.sections:
            sections.append(sec.name)
        return sections
    except (RuntimeError, ValueError):
        return None
