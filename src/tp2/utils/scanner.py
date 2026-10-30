class YaraScanner:
    def __init__(self, rules_path: str = "rules/course_rules.yar") -> None:
        self.rules_path = rules_path

    #   self.rules = open(rules_path, "rb").read()

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""

        matches = self.rules.match(data=data)

        results = []

        for match in matches:
            results.append(
                {
                    "name": match.rule,
                    "family": match.meta.get("family"),
                    "mitre_attack": match.meta.get("mitre_attack"),
                    "description": match.meta.get("description"),
                }
            )

        return results

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
