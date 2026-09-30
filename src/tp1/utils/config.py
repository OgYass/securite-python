from src.config import logging
from src.tp1.utils.args import Args

logger = logging.getLogger("TP1")

if Args.verbose:
  logger.setLevel(logging.DEBUG)
