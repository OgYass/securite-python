import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.report import Report
from tp2.utils.triage import Triage


def main() -> None:
    ap = argparse.ArgumentParser()
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
            result = triage.run()
            # logger.info(type(result))
            # logger.info(result)

            logger.info("Success! Writing report...")
            report = Report(result)
            # logger.info(report.result)
            # sha256 = report.result["sha256"]
            # report.generate_json(args.out / f"{sample.name}.json")
            report.generate_json(args.out / f"{sample.name}.triage.json")
            report.generate_pdf(args.out / f"{sample.name}.pdf")
            logger.info(f"Done with {sample}")
        except Exception:
            logger.exception(f"Exception during triage of sample {sample}")

    logger.info("All Done")


if __name__ == "__main__":
    main()
