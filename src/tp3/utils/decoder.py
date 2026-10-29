import base64

from pwn import remote

from tp3.utils.config import logger


class Decoder:
    """
    Class decoding the timed base64+XOR stream served by the TCP service.
    """

    _ROUND_TIMEOUT = 5

    def __init__(self, host: str, port: int, key: bytes) -> None:
        self.host: str = host
        """Host of the TCP service revealed by the web page
        """

        self.port: int = port
        """Port of the TCP service revealed by the web page
        """

        self.key: bytes = key
        """Encoding key used to XOR every token
        """

        self.flag: str = ""
        """Final flag returned once every round succeeded
        """

    def decode(self, chunk: bytes) -> bytes:
        """
        Decode one token : base64 then XOR with the key.
        """
        raw = base64.b64decode(chunk)
        return bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(raw))

    def run(self) -> bool:
        """
        Connect, answer every round in time and store the final flag.
        """
        io = remote(self.host, self.port)
        io.recvline()  # ligne de consigne

        while True:
            line = io.recvline(timeout=Decoder._ROUND_TIMEOUT).strip()
            if line.startswith(b"OK "):
                self.flag = line[3:].decode()
                break
            if not line or line in (b"WRONG", b"TIMEOUT"):
                logger.warn(f"round rejected : {line!r}")
                break

            io.sendline(self.decode(line))

        io.close()

        return bool(self.flag)

    def get_flag(self) -> str:
        """
        Returns the final flag.
        """
        return self.flag
