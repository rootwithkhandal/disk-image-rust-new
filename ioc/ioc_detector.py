# ioc/ioc_detector.py
from pathlib import Path

import yara
from loguru import logger
from tqdm import tqdm


class IOCDetector:
    """
    YARA-based IOC scanner.

    Accepts either a single .yar file or a directory of .yar files as the
    rules source.
    """

    def __init__(self, ioc_rules_path: str | Path) -> None:
        """
        Args:
            ioc_rules_path: Path to a .yar file or a directory containing
                            multiple .yar files.
        """
        self.rules_path = Path(ioc_rules_path)
        self.rules: yara.Rules | None = None
        self._load_rules()

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_rules(self) -> None:
        """Compile YARA rules from a file or all .yar files in a directory."""
        try:
            if self.rules_path.is_dir():
                yar_files = list(self.rules_path.glob("*.yar"))
                if not yar_files:
                    logger.error(f"No .yar files found in '{self.rules_path}'")
                    return

                # Build a namespace dict: {namespace: filepath}
                filepaths = {f.stem: str(f) for f in yar_files}
                self.rules = yara.compile(filepaths=filepaths)
                logger.info(
                    f"Loaded {len(yar_files)} YARA rule file(s) from '{self.rules_path}'"
                )

            elif self.rules_path.is_file():
                self.rules = yara.compile(filepath=str(self.rules_path))
                logger.info(f"Loaded YARA rules from '{self.rules_path}'")

            else:
                logger.error(f"Rules path does not exist: '{self.rules_path}'")

        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error in rules: {e}")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_file(self, filepath: Path) -> list | None:
        """
        Scan a single file against the loaded YARA rules.

        Args:
            filepath: File to scan.

        Returns:
            List of YARA match objects if any matched, None otherwise.
        """
        if not self.rules:
            logger.error("No YARA rules loaded — cannot scan.")
            return None

        try:
            matches = self.rules.match(str(filepath))
            if matches:
                logger.warning(
                    f"IOC match in '{filepath}': "
                    + ", ".join(m.rule for m in matches)
                )
                return matches
            return None
        except Exception as e:
            logger.error(f"Error scanning '{filepath}': {e}")
            return None

    def scan_directory(self, directory: Path) -> list[dict]:
        """
        Scan every file under directory recursively.

        Args:
            directory: Root directory to scan.

        Returns:
            List of dicts for files that had matches:
            [{"file": str, "matches": [rule_name, ...]}]
        """
        logger.info(f"Starting IOC scan on '{directory}'")

        files = [f for f in directory.rglob("*") if f.is_file()]
        results: list[dict] = []

        for filepath in tqdm(files, desc="IOC scan", unit="file", dynamic_ncols=True):
            matches = self.scan_file(filepath)
            if matches:
                results.append({
                    "file":    str(filepath),
                    "matches": [m.rule for m in matches],
                })

        logger.info(
            f"IOC scan complete — {len(results)} file(s) with matches "
            f"out of {len(files)} scanned."
        )
        return results
