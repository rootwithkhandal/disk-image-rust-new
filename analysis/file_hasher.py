# analysis/file_hasher.py
import hashlib
from pathlib import Path

from loguru import logger
from tqdm import tqdm


class DirectoryHasher:
    """Computes MD5, SHA-1, and SHA-256 hashes for every file in a directory."""

    ALGORITHMS = ("md5", "sha1", "sha256")

    def hash_file(self, filepath: Path) -> dict | None:
        """
        Hash a single file with all supported algorithms.

        Args:
            filepath: Path to the file.

        Returns:
            Dict with keys 'file', 'md5', 'sha1', 'sha256', or None on error.
        """
        hashers = {algo: hashlib.new(algo) for algo in self.ALGORITHMS}
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    for h in hashers.values():
                        h.update(chunk)

            return {
                "file": str(filepath),
                "md5":    hashers["md5"].hexdigest(),
                "sha1":   hashers["sha1"].hexdigest(),
                "sha256": hashers["sha256"].hexdigest(),
            }
        except Exception as e:
            logger.error(f"Failed to hash '{filepath}': {e}")
            return None

    def analyze(self, directory: Path) -> list[dict]:
        """
        Hash every file under directory recursively.

        Args:
            directory: Root directory to scan.

        Returns:
            List of hash result dicts (one per file).
        """
        logger.info(f"Starting hash analysis on '{directory}'")

        files = [f for f in directory.rglob("*") if f.is_file()]
        results: list[dict] = []

        for filepath in tqdm(files, desc="Hashing files", unit="file", dynamic_ncols=True):
            result = self.hash_file(filepath)
            if result:
                logger.debug(f"{filepath.name}: sha256={result['sha256']}")
                results.append(result)

        logger.info(f"Hashing complete — {len(results)} files processed.")
        return results
