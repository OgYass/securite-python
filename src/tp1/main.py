from tp1.utils.capture import Capture
from tp1.utils.config import logger
# from tp1.utils.args import Args

# import json


def main():
    logger.info("Starting TP1")

    capture = Capture()
    capture.capture_traffic()
    capture.analyse("tcp")

    # summary = capture.get_summary()

    # with open(Args.report_path or 'report.json', 'w') as f:
    #     json.dump(summary.to_dict(), f)

    # logger.debug("summary : {}".format(summary))

    # filename = "report.pdf"
    # report = Report(capture, filename, summary)
    # report.generate("graph")
    # report.generate("array")
    # report.save(filename)


if __name__ == "__main__":
    main()
