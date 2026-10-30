from pathlib import Path
import yara

from tp2.utils.config import logger


class YaraScanner:
    def __init__(self, rules_path: str = "rules") -> None:
        self.rules_path = Path(rules_path)
        self.rules = self.load_rules()

    def load_rules(self) -> yara.Rules | None:
        if self.rules_path.is_file():
            files = [self.rules_path]
        else:
            files = sorted(self.rules_path.glob("*.yar")) + sorted(self.rules_path.glob("*.yara"))
        filepaths = {}
        for i, path in enumerate(files):
            try:
                yara.compile(filepath=str(path))
                filepaths[f"rules_{i}"] = str(path)
            except yara.Error as error:
                logger.warning(f"regle yara invalide: {path} -> {error}")

            if len(path) == 0:
                logger.warning(f"rule {self.rules_path} is empty")
                return None
        return yara.compile(filepaths=filepaths)

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        if self.rules is None:
            return []
        matches = self.rules.match(data=data)

        return sorted(match.rule.name for match in matches)

    def spoofscan(self) -> list[str]:
        spoofs = []
        spoofs.append(
            {
                "name": "spoofed",
                "family": "family",
                "mitre_attack": "nono",
                "description": "blabla",
            }
        )
        return spoofs
