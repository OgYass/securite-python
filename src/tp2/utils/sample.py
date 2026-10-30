import hashlib
import math
from collections import Counter

import magic

from tp2.utils.parse_binary import parse_binary
from tp2.utils.extract_iocs import extract_iocs


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        sha256 = hashlib.sha256(self.data).hexdigest()
        md5 = hashlib.md5(self.data).hexdigest()
        file_type = str(magic.from_buffer(self.data))
        size = len(self.data)
        entropy = self.shannon_entropy()
        return {"sha256": sha256, "md5": md5, "size": size, "entropy": entropy, "file_type": file_type}

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        return extract_iocs(self.data)

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        return parse_binary(self.data)
