import json
from pathlib import Path
from fpdf import FPDF

from tp2.utils.config import logger


class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        path = Path(out_pdf)
        path.parent.mkdir(parents=True, exist_ok=True)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Malware Triage Report", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)
        self._write_pdf(pdf, "Analysis results", self.result)

        pdf.output(str(path))

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        path = Path(out_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(self.result)

        with path.open("w", encoding="utf-8") as file:
            json.dump(
                self.result,
                file,
                indent=4,
                ensure_ascii=False,
                default=str,
            )

    def _write_pdf(self, pdf: FPDF, key: str, value, level: int = 0) -> None:
        indent = min(level * 5, 30)

        if isinstance(value, dict):
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_x(10 + indent)
            pdf.multi_cell(0, 7, str(key))

            for child_key, child_value in value.items():
                self._write_pdf(pdf, str(child_key), child_value, level + 1)

        elif isinstance(value, list):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_x(10 + indent)
            pdf.multi_cell(0, 6, f"{key}:")

            if not value:
                pdf.set_font("Helvetica", size=10)
                pdf.set_x(10 + indent + 5)
                pdf.multi_cell(0, 6, "(none)")
            else:
                for item in value:
                    self._write_pdf(pdf, "-", item, level + 1)

        else:
            pdf.set_font("Helvetica", size=10)
            pdf.set_x(10 + indent)
            pdf.multi_cell(0, 6, f"{key}: {value}")
