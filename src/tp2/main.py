import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.report import Report
from tp2.utils.triage import Triage


def main() -> None:
    """Analyse chaque échantillon de --samples et écrit <sha256>.json dans --out."""
    ap = argparse.ArgumentParser(description="Triage automatisé de malware")
    ap.add_argument("--samples", type=Path, required=True)
    ap.add_argument("--rules", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    samples = sorted(path for path in args.samples.iterdir() if path.is_file())
    if len(samples) == 0:
        logger.warning("no samples found")
        return

    for sample in samples:
        try:
            logger.info(f"Triage of sample {sample}")
            triage = Triage(sample, str(args.rules), args.llm)
            report = Report(triage.run())
            # nom attendu par la moulinette : <fichier>.triage.json (comme le template)
            report.generate_json(args.out / f"{sample.name}.triage.json")
            report.generate_json(args.out / f"{report.result['sha256']}.json")
            try:
                report.generate_pdf(args.out / f"{sample.name}.triage.pdf")
            except Exception:  # noqa: BLE001 - un PDF raté ne doit pas bloquer le JSON
                logger.exception(f"PDF non généré pour {sample}")
            logger.info(f"Done with {sample}")
        except Exception:  # noqa: BLE001 - un échantillon ne doit pas bloquer les autres
            logger.exception(f"Exception during triage of sample {sample}")

    logger.info("All Done")


if __name__ == "__main__":
    main()
