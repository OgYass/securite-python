import os

from tp2.utils.config import logger

def main():
    logger.info('start')

if __name__ == "__main__":
    logger.info(f"Key openai value : {os.getenv('OPENAI_KEY')}")
    main()
