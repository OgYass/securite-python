import json
from tp2.utils.config import logger
from tp2.utils.extract_iocs import extract_flag
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner

RULES_FAMILY = {"Suspicious_Downloader": "dropper", "Reverse_Shell": "backdoor", "Keylogger": "keylogger"}
RULES_MITRE = {
    "Suspicious_Downloader": ["T1105"],
    "Reverse_Shell": ["T1059.003"],
    "Keylogger": ["T1056.001"],
    "Has_Mutex": ["T1480"],
    "Registry_Run_Persistence": ["T1547.001"],
}


class Triage:
    def __init__(self, path: str, rules: str, backend: str) -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner(rules)
        self.llm = LLMTriage(backend)

    def run(self):
        """
        Acquisition des samples, extraction des iocs, parsing des binaires -> construction du summary
        """
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        # logger.info(meta)
        iocs = sample.extract_iocs()
        # logger.info(iocs)
        bininfo = sample.parse_binary()
        # logger.info(bininfo)
        # unfinished, placeholder spoof
        matches = self.scanner.scan(sample.data)
        flag = extract_flag(sample.data)
        # logger.info(matches)
        summary = json.dumps(
            {**meta, "iocs": iocs, "imports": bininfo.get("imports") or [], "yara_matches": matches}
        )
        # logger.info(summary)

        verdict = self.llm.triage(summary)

        # famille et score calcules sans le llm (yara + ioc + entropie)
        family = "unknown"
        mitre = set()
        for rule in matches:
            family = RULES_FAMILY.get(rule, family)
            mitre.update(RULES_MITRE.get(rule, []))
        if family == "unknown" and meta["entropy"] > 7.0:
            family = "packed"
            mitre.add("T1027")
        if family == "unknown" and verdict["family"]:
            family = verdict["family"]

        score = min(10, 2 * len(matches) + (1 if iocs["urls"] else 0))
        if verdict["score"] is not None:
            # le llm nuance le score, il ne peut pas declarer le fichier sain
            score = max(score - 2, round(0.7 * score + 0.3 * verdict["score"]))

        final = {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "entropy": meta["entropy"],
            "file_type": meta["file_type"],
            "iocs": iocs,
            "imports": bininfo.get("imports") or [],
            "yara_matches": matches,
            "family_guess": family,
            "mitre_attack": sorted(mitre | set(verdict["mitre_attack"])),
            "llm_summary": verdict["summary"] or f"Famille {family}, regles {', '.join(matches)}",
            "score": score,
            "flag": flag,
        }
        logger.info(final)

        return final
