from platform import architecture

import lief
from lief import Binary

from tp2.utils.config import logger


def parse_binary(data: bytes) -> dict:
    binary = parse_data(data)
    logger.info(binary)

    format = parse_format(binary)
    architecture = get_architecture(binary)
    entrypoint = binary.entrypoint

    result = {
        "format": format,
        "architecture": architecture,
        "entrypoint": entrypoint,
        "imports": [],
        "sections": [],
    }
    return result

def parse_data(data: bytes)-> Binary | {}:
    try:
        binary = lief.parse(data)
    except (RuntimeError, ValueError):
        return {}

    if binary is None:
        return {}

    return binary

def parse_format(binary: Binary) -> Binary | {}:
    try:
        format = binary.format.name
    except (RuntimeError, ValueError):
        return {}

def get_architecture(binary: Binary) :
    try:

        return  binary.header
    except (RuntimeError, ValueError):
        return  None
