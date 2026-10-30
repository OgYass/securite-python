import json

from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner

# Règle YARA -> (famille, techniques MITRE ATT&CK, poids dans le score)
RULE_PROFILES: dict[str, tuple[str | None, list[str], int]] = {
    "Suspicious_Downloader": ("dropper", ["T1105", "T1204"], 3),
    "Reverse_Shell": ("backdoor", ["T1059.003", "T1095"], 4),
    "Keylogger": ("keylogger", ["T1056.001"], 3),
    "Has_Mutex": (None, ["T1480"], 1),
    "Registry_Run_Persistence": (None, ["T1547.001"], 2),
    "C2_Gate_URL": (None, ["T1071.001"], 2),
    "Prompt_Injection_Attempt": (None, [], 1),
}
FAMILY_PRIORITY = ["backdoor", "keylogger", "dropper", "packed"]
LLM_WEIGHT = 0.3


class Triage:
    """Pipeline de triage d'un échantillon : métadonnées, IOC, binaire, YARA, puis LLM."""

    def __init__(self, path: str, rules: str, backend: str) -> None:
        """Preparation du scanner YARA et du client LLM."""
        self.path = path
        self.scanner = YaraScanner(rules)
        self.llm = LLMTriage(backend)

    @staticmethod
    def deterministic_verdict(yara_matches: list[str], iocs: dict, packed: bool, injection: bool) -> dict:
        """Famille, MITRE et score calculés sans LLM, à partir de YARA, des IOC et de l'entropie."""
        families = set()
        mitre = set()
        score = 0
        for rule in yara_matches:
            family, techniques, weight = RULE_PROFILES.get(rule, (None, [], 1))
            if family:
                families.add(family)
            mitre.update(techniques)
            score += weight
        if packed:
            families.add("packed")
            mitre.add("T1027")
            score += 2
        if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
            mitre.add("T1071")
            score += 1
        if injection:
            score += 1

        family = next((f for f in FAMILY_PRIORITY if f in families), "unknown")
        return {"family": family, "mitre_attack": sorted(mitre), "score": min(score, 10)}

    @staticmethod
    def combine_score(deterministic: int, llm_score: int | None) -> int:
        """Le LLM ne peut que nuancer le score : YARA et IOC restent majoritaires."""
        if llm_score is None:
            return deterministic
        combined = round((1 - LLM_WEIGHT) * deterministic + LLM_WEIGHT * llm_score)
        return max(0, min(10, max(combined, deterministic - 2)))

    @staticmethod
    def default_summary(verdict: dict, yara_matches: list[str], injection: bool) -> str:
        """Résumé lisible quand le LLM est indisponible."""
        rules = ", ".join(yara_matches) or "aucune"
        text = f"Famille estimée : {verdict['family']}. Règles YARA : {rules}. Score {verdict['score']}/10."
        if injection:
            text += " Tentative d'injection de prompt détectée et ignorée."
        return text

    def run(self) -> dict:
        """Analyse l'échantillon et renvoie le résultat au format attendu par la correction."""
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        yara_matches = self.scanner.scan(sample.data)
        packed = sample.is_packed()
        injection = sample.has_prompt_injection()
        verdict = self.deterministic_verdict(yara_matches, iocs, packed, injection)

        # Résumé structuré envoyé au LLM : jamais le binaire brut, jamais le flag
        summary = json.dumps(
            {
                "file_type": meta["file_type"],
                "size": meta["size"],
                "entropy": meta["entropy"],
                "packed": packed,
                "iocs": iocs,
                "imports": (bininfo.get("imports") or [])[:100],
                "sections": (bininfo.get("sections") or [])[:50],
                "yara_matches": yara_matches,
                "prompt_injection_detected": injection,
            }
        )
        llm = self.llm.triage(summary)

        family = verdict["family"]
        if family == "unknown" and llm["family"]:
            family = llm["family"]

        result = {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "entropy": meta["entropy"],
            "file_type": meta["file_type"],
            "iocs": iocs,
            "imports": bininfo.get("imports") or [],
            "yara_matches": yara_matches,
            "family_guess": family,
            "mitre_attack": sorted(set(verdict["mitre_attack"]) | set(llm["mitre_attack"])),
            "llm_summary": llm["summary"] or self.default_summary(verdict, yara_matches, injection),
            "score": self.combine_score(verdict["score"], llm["score"]),
            "flag": sample.extract_flag(),
        }
        logger.info(f"Verdict {self.path} : {family}, score {result['score']}")
        return result
