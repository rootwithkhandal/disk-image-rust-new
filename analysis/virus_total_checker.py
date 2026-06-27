# analysis/virus_total_checker.py
import hashlib
import time
from pathlib import Path

import requests
from loguru import logger
from tqdm import tqdm


class VirusTotalScanner:
    """Hash-based VirusTotal lookups with rate-limit handling."""

    BASE_URL = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key: str, rate_limit_sleep: int = 15) -> None:
        """
        Args:
            api_key:          VirusTotal API key.
            rate_limit_sleep: Seconds to wait between requests (free tier = 15s).
        """
        self.api_key = api_key
        self.rate_limit_sleep = rate_limit_sleep
        self._headers = {"x-apikey": self.api_key}

    # ------------------------------------------------------------------
    # Single-file helpers
    # ------------------------------------------------------------------

    def get_file_hash(self, filepath: str | Path) -> str | None:
        """Return the SHA-256 hex digest of a file, or None on error."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing '{filepath}': {e}")
            return None

    def check_file(self, filepath: str | Path) -> dict | None:
        """
        Look up a single file on VirusTotal by its SHA-256 hash.

        Args:
            filepath: Path to the file to check.

        Returns:
            last_analysis_stats dict on success, None if not found or on error.
        """
        file_hash = self.get_file_hash(filepath)
        if not file_hash:
            return None

        return self._query_hash(file_hash, label=str(filepath))

    # ------------------------------------------------------------------
    # Directory scan
    # ------------------------------------------------------------------

    def check_directory(self, directory: Path) -> list[dict]:
        """
        Scan every file under directory against VirusTotal.

        Respects rate_limit_sleep between requests.

        Args:
            directory: Root directory to scan.

        Returns:
            List of result dicts with keys: file, sha256, stats (or error).
        """
        logger.info(f"Starting VirusTotal scan on '{directory}'")

        files = [f for f in directory.rglob("*") if f.is_file()]
        results: list[dict] = []

        for filepath in tqdm(files, desc="VirusTotal", unit="file", dynamic_ncols=True):
            file_hash = self.get_file_hash(filepath)
            if not file_hash:
                results.append({"file": str(filepath), "sha256": None, "error": "hash_failed"})
                continue

            stats = self._query_hash(file_hash, label=str(filepath))
            results.append({
                "file":   str(filepath),
                "sha256": file_hash,
                "stats":  stats,
            })

            time.sleep(self.rate_limit_sleep)

        logger.info(f"VirusTotal scan complete — {len(results)} files checked.")
        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _query_hash(self, file_hash: str, label: str = "", retries: int = 3) -> dict | None:
        """
        Query VirusTotal for a hash with exponential backoff on 429.

        Args:
            file_hash: SHA-256 hex string.
            label:     Human-readable label for log messages.
            retries:   Maximum number of retry attempts on rate-limit.

        Returns:
            last_analysis_stats dict, or None.
        """
        url = self.BASE_URL + file_hash
        attempt = 0

        while attempt <= retries:
            try:
                response = requests.get(url, headers=self._headers, timeout=30)
            except requests.RequestException as e:
                logger.error(f"Network error querying VT for '{label}': {e}")
                return None

            if response.status_code == 200:
                data = response.json()
                stats = (
                    data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                )
                logger.info(f"VT result for '{label}': {stats}")
                return stats

            elif response.status_code == 404:
                logger.warning(f"No VT report for '{label}' ({file_hash})")
                return None

            elif response.status_code == 429:
                wait = 60 * (2 ** attempt)
                logger.warning(
                    f"VT rate limit hit for '{label}'. "
                    f"Retrying in {wait}s (attempt {attempt + 1}/{retries})..."
                )
                time.sleep(wait)
                attempt += 1

            else:
                logger.error(
                    f"VT API error {response.status_code} for '{label}': {response.text}"
                )
                return None

        logger.error(f"Exhausted retries for '{label}' — giving up.")
        return None
