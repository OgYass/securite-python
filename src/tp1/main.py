from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    logger.info("Starting TP1")
    
    capture = Capture()
    capture.capture_traffic()
    capture.analyse("tcp")
    
    capture._gen_summary()
    summary = capture.get_summary()
    logger.debug("summary : {}".format(summary))

    filename = "report.pdf"
    # report = Report(capture, filename, summary)
    # report.generate("graph")
    # report.generate("array")
    # report.save(filename)


if __name__ == "__main__":
    main()
