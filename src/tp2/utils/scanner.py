from pathlib import Path

import yara

from tp2.utils.config import logger

RULE_EXTENSIONS = {".yar", ".yara"}


class YaraScanner:
    """Compile toutes les règles YARA d'un dossier (ou d'un fichier) et scanne des données."""

    def __init__(self, rules_path: str = "rules") -> None:
        """Compilation des regles du dossier."""
        self.rules_path = Path(rules_path)
        self.rules = self.compile_rules()

    def rule_files(self) -> dict[str, str]:
        """Associe un namespace à chaque fichier de règles trouvé."""
        if self.rules_path.is_file():
            return {self.rules_path.stem: str(self.rules_path)}
        if not self.rules_path.is_dir():
            logger.warning(f"Dossier de règles introuvable : {self.rules_path}")
            return {}
        files = sorted(p for p in self.rules_path.rglob("*") if p.suffix.lower() in RULE_EXTENSIONS)
        return {f"{p.stem}_{i}": str(p) for i, p in enumerate(files)}

    def compile_rules(self) -> yara.Rules | None:
        """Compile les règles valides ; un fichier invalide est ignoré, pas bloquant."""
        valid = {}
        for namespace, filepath in self.rule_files().items():
            try:
                yara.compile(filepath=filepath)
                valid[namespace] = filepath
            except yara.Error as error:
                logger.warning(f"Règle YARA invalide ignorée {filepath} : {error}")
        if not valid:
            return None
        return yara.compile(filepaths=valid)

    def scan_details(self, data: bytes) -> list[dict]:
        """Matches avec leurs métadonnées (family, mitre_attack, description)."""
        if self.rules is None:
            return []
        try:
            matches = self.rules.match(data=data)
        except yara.Error as error:
            logger.warning(f"Scan YARA échoué : {error}")
            return []
        return [
            {
                "name": match.rule,
                "family": match.meta.get("family"),
                "mitre_attack": match.meta.get("mitre_attack"),
                "description": match.meta.get("description"),
            }
            for match in matches
        ]

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées, triés et dédoublonnés."""
        return sorted({match["name"] for match in self.scan_details(data)})
