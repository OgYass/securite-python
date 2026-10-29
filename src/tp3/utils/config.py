from src.config import logging
from tp3.utils.args import Args

logger = logging.getLogger("TP3")

if Args.verbose:
    logger.setLevel(logging.DEBUG)