# utils/json_to_table.py
from pathlib import Path

import pandas as pd
from loguru import logger


def json_to_csv(json_data: list[dict] | dict, output_csv_path: str | Path) -> bool:
    """
    Flatten a JSON object or list of objects and write to CSV.

    Args:
        json_data:       A dict or list of dicts to export.
        output_csv_path: Destination CSV file path.

    Returns:
        True on success, False on failure.
    """
    try:
        df = pd.json_normalize(json_data)
        out = Path(output_csv_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(out, index=False)
        logger.info(f"JSON data exported to CSV at {out}")
        return True
    except Exception as e:
        logger.error(f"Failed to convert JSON to CSV: {e}")
        return False
