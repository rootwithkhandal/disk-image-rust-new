# utils/reporter.py
import json
from datetime import datetime
from pathlib import Path

import pandas as pd
from loguru import logger


class ReportGenerator:
    """
    Collects named sections of scan results and exports them to JSON and/or CSV.

    Usage:
        report = ReportGenerator(output_dir="reports")
        report.add_section("hashes", [{"file": "...", "sha256": "..."}])
        report.add_section("vt_results", [...])
        report.save_all("scan_2025-06-05")
    """

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sections: dict[str, list[dict]] = {}
        self._created_at = datetime.utcnow().isoformat()

    def add_section(self, name: str, data: list[dict]) -> None:
        """Add or replace a named section of results."""
        self._sections[name] = data
        logger.debug(f"Report section '{name}' added with {len(data)} records.")

    def save_json(self, filename: str) -> Path:
        """
        Save all sections to a single JSON file.

        Returns the path of the written file.
        """
        if not filename.endswith(".json"):
            filename += ".json"

        output = {
            "generated_at": self._created_at,
            "sections": self._sections,
        }

        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

        logger.info(f"JSON report saved to {out_path}")
        return out_path

    def save_csv(self, filename: str) -> list[Path]:
        """
        Save each section to its own CSV file.

        Files are named <filename>_<section_name>.csv.
        Returns a list of written file paths.
        """
        base = filename.removesuffix(".csv")
        written: list[Path] = []

        for section_name, data in self._sections.items():
            if not data:
                logger.warning(f"Section '{section_name}' is empty — skipping CSV export.")
                continue

            out_path = self.output_dir / f"{base}_{section_name}.csv"
            try:
                df = pd.json_normalize(data)
                df.to_csv(out_path, index=False)
                logger.info(f"CSV report section '{section_name}' saved to {out_path}")
                written.append(out_path)
            except Exception as e:
                logger.error(f"Failed to write CSV for section '{section_name}': {e}")

        return written

    def save_all(self, base_filename: str) -> None:
        """Save both JSON and CSV reports using base_filename as the stem."""
        self.save_json(base_filename)
        self.save_csv(base_filename)
