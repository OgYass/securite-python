import logging
from dotenv import load_dotenv

load_dotenv()

level = logging.INFO


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.INFO: "\033[32m",
        logging.WARNING: "\033[31m",
    }
    RESET = "\033[0m"

    def format(self, record):
        message = super().format(record)
        color = self.COLORS.get(record.levelno)
        return f"{color}{message}{self.RESET}" if color else message


logging.basicConfig(
    level=level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log", mode="a"),
        logging.StreamHandler(),
    ],
)

for handler in logging.getLogger().handlers:
    if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
        handler.setFormatter(ColorFormatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
