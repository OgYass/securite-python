import json
from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


class Triage:
    def __init__(self, path: str, rules: str, backend: str) -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner(rules)
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        """
        Acquisition des samples
        """
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        #       logger.info(meta)
        iocs = sample.extract_iocs()
        #       logger.info(iocs)
        bininfo = sample.parse_binary()
        #       logger.info(bininfo)
        matches = self.scanner.scan(sample.data)
        summary = json.dumps({**meta, "iocs": iocs, **bininfo, "yara_matches": matches})
        try:
            verdict = json.loads(self.llm.triage(summary))
        except (json.JSONDecodeError, TypeError):
            logger.warning("Pas de json generé par le LLM")
            verdict = {}

        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "entropy": meta["entropy"],
            "file_type": meta["file_type"],
            "iocs": iocs,
            "imports": bininfo["imports"],
            "yara_matches": matches,
            "family_guess": verdict.get("family_guess", "unknown"),
            "mitre_attack": verdict.get("mitre_attack", []),
            "llm_summary": verdict.get("llm_summary", ""),
            "score": verdict.get("score", 0),
            "flag": verdict.get("flag", ""),
        }
