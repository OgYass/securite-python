class YaraScanner:
    def __init__(self, rules_path: str = "rules/course_rules.yar") -> None:
        self.rules_path = rules_path

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        yara_matches = []
        return yara_matches
        raise NotImplementedError
