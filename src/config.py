import logging
from dotenv import load_dotenv

load_dotenv()

level = logging.INFO

logging.basicConfig(
    level=level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(
        "app.log", mode="a"), logging.StreamHandler()]
)
