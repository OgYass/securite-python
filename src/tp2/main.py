import os

from tp2.utils.config import logger
from tp2.utils.get_data import get_data


def main():
    logger.info('start')
    data = get_data("test.txt")
    logger.info(data)
    logger.info('end')
    return 1

if __name__ == "__main__":
    logger.info(f"Key openai value : {os.getenv('OPENAI_KEY')}")
    main()
