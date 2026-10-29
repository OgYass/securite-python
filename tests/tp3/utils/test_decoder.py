import base64
from unittest.mock import patch

from tp3.utils.decoder import Decoder


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def test_decode_is_inverse_of_encode():
    key = b"\xde\xad\xbe\xef"
    token = b"0123456789abcdef"
    encoded = base64.b64encode(_xor(token, key))

    decoder = Decoder("x", 9090, key)

    assert decoder.decode(encoded) == token


@patch("tp3.utils.decoder.remote")
def test_run_returns_flag_after_rounds(mock_remote):
    key = b"\x01\x02\x03\x04"
    token = b"0123456789abcdef"
    challenge = base64.b64encode(_xor(token, key)) + b"\n"

    io = mock_remote.return_value
    io.recvline.side_effect = [b"consigne\n", challenge, b"OK ESGI{chain_ok}\n"]

    decoder = Decoder("x", 9090, key)

    assert decoder.run() is True
    assert decoder.get_flag() == "ESGI{chain_ok}"
    io.sendline.assert_called_once_with(token)


@patch("tp3.utils.decoder.remote")
def test_run_returns_false_on_wrong(mock_remote):
    io = mock_remote.return_value
    io.recvline.side_effect = [b"consigne\n", b"WRONG\n"]

    decoder = Decoder("x", 9090, b"\x01\x02\x03\x04")

    assert decoder.run() is False
    assert decoder.get_flag() == ""


def test_get_flag():
    decoder = Decoder("x", 9090, b"\x01")
    decoder.flag = "ESGI{chain_ok}"
    assert decoder.get_flag() == "ESGI{chain_ok}"
