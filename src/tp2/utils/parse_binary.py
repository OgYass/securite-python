import lief

def parse_binary(data: bytes) -> dict:
    result = {
        "format": None,
        "architecture": None,
        "entrypoint": None,
        "imports": [],
        "sections": [],
    }

    binary = lief.parse(data)

    if binary is None:
        return result

    result["format"] = binary.format
    result["architecture"] = binary.architecture

    return result