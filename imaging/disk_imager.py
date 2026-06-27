# imaging/disk_imager.py
import hashlib
import os
import subprocess
from pathlib import Path

from loguru import logger
from tqdm import tqdm


class DiskImager:
    """Creates a raw disk image from a block device with SHA-256 integrity hashing."""

    def __init__(self, block_size_mb: int = 4) -> None:
        self.block_size = block_size_mb * 1024 * 1024

    # ------------------------------------------------------------------
    # Interactive helpers (used when running via CLI prompts)
    # ------------------------------------------------------------------

    def select_device(self) -> str | None:
        """List block devices and prompt the user to choose one."""
        logger.info("Listing available block devices...")
        subprocess.run(["lsblk"], check=False)
        device = input("Enter device path to image (e.g. /dev/sdb): ").strip()
        if not os.path.exists(device):
            logger.error(f"Device '{device}' does not exist.")
            return None
        return device

    def get_output_image_path(self) -> Path:
        """Prompt the user for an output image path."""
        path = input("Enter output image path (e.g. /home/user/disk.img): ").strip()
        return Path(path)

    # ------------------------------------------------------------------
    # Core imaging
    # ------------------------------------------------------------------

    def create_image(
        self,
        device: str,
        output_path: Path | str,
        dry_run: bool = False,
    ) -> bool:
        """
        Read a block device and write it to output_path block-by-block.

        Each block is SHA-256 hashed for integrity verification and logged.

        Args:
            device:      Source block device path (e.g. /dev/sdb).
            output_path: Destination .img file path.
            dry_run:     If True, simulate without writing anything.

        Returns:
            True on success, False on failure.
        """
        output_path = Path(output_path)

        if dry_run:
            logger.info(f"[DRY RUN] Would image '{device}' → '{output_path}'")
            return True

        logger.info(f"Starting imaging: '{device}' → '{output_path}'")

        try:
            device_size = self._get_device_size(device)
            total_blocks = (device_size // self.block_size) + 1 if device_size else None

            with (
                open(device, "rb") as src,
                open(output_path, "wb") as dst,
                tqdm(
                    total=total_blocks,
                    unit="block",
                    desc="Imaging",
                    dynamic_ncols=True,
                ) as pbar,
            ):
                block_index = 0
                while True:
                    data = src.read(self.block_size)
                    if not data:
                        break

                    block_hash = self._hash_block(data)
                    logger.debug(f"Block {block_index} SHA-256: {block_hash}")

                    dst.write(data)
                    block_index += 1
                    pbar.update(1)

            logger.info(f"Imaging complete. Image saved at '{output_path}'")
            return True

        except PermissionError:
            logger.error(
                f"Permission denied reading '{device}'. Try running with sudo."
            )
            return False
        except Exception as e:
            logger.error(f"Imaging failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_block(data: bytes) -> str:
        """Return the SHA-256 hex digest of a data block."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _get_device_size(device: str) -> int | None:
        """Return the size of a block device in bytes, or None if unavailable."""
        try:
            result = subprocess.run(
                ["blockdev", "--getsize64", device],
                capture_output=True, text=True, check=True,
            )
            return int(result.stdout.strip())
        except Exception:
            return None
