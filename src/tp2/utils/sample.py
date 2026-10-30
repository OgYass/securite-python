import hashlib
import math
from collections import Counter

import magic

from tp2.utils.extract_iocs import extract_flag, extract_iocs, has_prompt_injection
from tp2.utils.parse_binary import parse_binary

WINDOW_SIZE = 4096
PACKED_FILE_ENTROPY = 7.0
PACKED_WINDOW_ENTROPY = 7.5


def shannon_entropy(data: bytes) -> float:
    """Entropie de Shannon en bits par octet (0 à 8)."""
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class Sample:
    """Fichier suspect chargé en mémoire, jamais exécuté."""

    def __init__(self, path: str) -> None:
        """Lecture du fichier en binaire."""
        self.path = path
        with open(path, "rb") as file:
            self.data = file.read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        try:
            file_type = str(magic.from_buffer(self.data))
        except Exception:  # noqa: BLE001 - libmagic peut échouer sur une entrée exotique
            file_type = "data"
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "entropy": round(self.shannon_entropy(), 4),
            "file_type": file_type,
        }

    def shannon_entropy(self) -> float:
        """Entropie de Shannon du fichier complet."""
        return shannon_entropy(self.data)

    def max_window_entropy(self, window: int = WINDOW_SIZE) -> float:
        """Entropie maximale sur une fenêtre glissante : repère une zone compressée/chiffrée."""
        if len(self.data) <= window:
            return self.shannon_entropy()
        step = window // 4
        return max(
            shannon_entropy(self.data[i : i + window]) for i in range(0, len(self.data) - window + 1, step)
        )

    def is_packed(self) -> bool:
        """Heuristique de packing/chiffrement basée sur l'entropie."""
        return (
            self.shannon_entropy() > PACKED_FILE_ENTROPY or self.max_window_entropy() > PACKED_WINDOW_ENTROPY
        )

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        return extract_iocs(self.data)

    def extract_flag(self) -> str:
        """Flag ESGI{...} hors leurres d'injection."""
        return extract_flag(self.data)

    def has_prompt_injection(self) -> bool:
        """Vrai si le fichier contient une tentative d'injection de prompt."""
        return has_prompt_injection(self.data)

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        return parse_binary(self.data)
