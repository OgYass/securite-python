from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from tp2.utils.config import logger

root = Path(__file__).resolve().parent
destination = root.parent / "projet.zip"

excluded_dirs = {".venv", "__pycache__", ".idea", ".vscode", "output", "testsamples"}

with ZipFile(destination, "w", ZIP_DEFLATED) as archive:
    for path in root.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(root)

        if any(part in excluded_dirs for part in relative.parts):
            continue

        if any(part.endswith("_cache") for part in relative.parts):
            continue

        archive.write(path, relative)

logger.info(f"Archive créée : {destination}")
