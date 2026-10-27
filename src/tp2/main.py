import argparse

from tp2.utils.report import Report
from tp2.utils.triage import Triage


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", required=True)
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args()

    triage = Triage(args.file, args.llm)
    result = triage.run()

    report = Report(result)
    report.generate_pdf(f"{args.file}.triage.pdf")
    report.generate_json(f"{args.file}.triage.json")

from tp2.utils.check_ioc import check_ioc
from tp2.utils.config import logger
from tp2.utils.get_data import get_data


def main(path:str) :
    logger.info('start')
    data = get_data(path)
    logger.info(data)
    ioc_check = check_ioc(data)
    logger.info(ioc_check)
    logger.info('end')
    return 1

if __name__ == "__main__":
    logger.info(f"Key openai value : {os.getenv('OPENAI_KEY')}")
    main()
