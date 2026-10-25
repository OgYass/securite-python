from tp1.utils.capture import Capture, Summary
from tp1.utils.config import logger
from tp1.utils.args import Args

import json

from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    capture = Capture()
    capture.capture_traffic()
    capture.analyse("tcp")

    _summary: Summary | None = capture.get_summary()

    if _summary is None:
        logger.error("Cannot get summary")
        exit()

    summary: Summary = _summary

    with open(Args.report_path or "report.json", "w") as f:
        json.dump(summary.to_dict(), f)

    logger.debug("summary : {}".format(summary))

    filename = Args.report_path or "report.pdf"
    report = Report(capture, filename, summary)
    # TODO FIX graph
    # report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
