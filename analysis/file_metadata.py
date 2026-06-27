# analysis/file_metadata.py
import subprocess
from datetime import datetime
from pathlib import Path

from loguru import logger
from tqdm import tqdm


class FileAnalyzer:
    """Extracts filesystem timestamps and optional exiftool metadata from files."""

    def get_file_metadata(self, filepath: Path) -> dict | None:
        """
        Return metadata for a single file.

        Includes size, MAC timestamps, and extended exiftool metadata when
        available.

        Args:
            filepath: Path to the file.

        Returns:
            Metadata dict, or None on error.
        """
        try:
            stat = filepath.stat()

            result = {
                "file":  str(filepath),
                "size":  stat.st_size,
                "ctime": datetime.utcfromtimestamp(stat.st_ctime).isoformat(),
                "mtime": datetime.utcfromtimestamp(stat.st_mtime).isoformat(),
                "atime": datetime.utcfromtimestamp(stat.st_atime).isoformat(),
                "extended_metadata": {},
            }

            # Attempt exiftool enrichment
            try:
                proc = subprocess.run(
                    ["exiftool", str(filepath)],
                    capture_output=True, text=True,
                )
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        if ":" in line:
                            key, _, val = line.partition(":")
                            result["extended_metadata"][key.strip()] = val.strip()
            except FileNotFoundError:
                logger.warning(
                    "exiftool not found — skipping extended metadata extraction."
                )

            return result

        except Exception as e:
            logger.error(f"Error getting metadata for '{filepath}': {e}")
            return None

    def analyze_directory(self, directory: Path) -> list[dict]:
        """
        Collect metadata for every file under directory recursively.

        Args:
            directory: Root directory to scan.

        Returns:
            List of metadata dicts (one per file).
        """
        logger.info(f"Starting metadata analysis on '{directory}'")

        files = [f for f in directory.rglob("*") if f.is_file()]
        results: list[dict] = []

        for filepath in tqdm(files, desc="Metadata", unit="file", dynamic_ncols=True):
            meta = self.get_file_metadata(filepath)
            if meta:
                results.append(meta)

        logger.info(f"Metadata analysis complete — {len(results)} files processed.")
        return results
