"""
Hashing Engine
==============
Multi-algorithm hash engine supporting SHA256, SHA1, MD5, and BLAKE3.
Supports file hashing, stream hashing, and chunk-level verification.

Usage:
    from core.hashing.hasher import Hasher, HashAlgorithm

    result = Hasher.hash_file("/path/to/image.dd")
    print(result)

    # Verify against known hash
    ok = Hasher.verify_file("/path/to/image.dd", "sha256", "abc123...")
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO
import os

from loguru import logger

# BLAKE3 is optional — falls back gracefully if not installed
try:
    import blake3 as _blake3

    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False
    logger.warning("blake3 not installed — BLAKE3 hashing unavailable")


class HashAlgorithm(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    BLAKE3 = "blake3"


DEFAULT_BLOCK_SIZE = 65536  # 64 KB


@dataclass
class HashResult:
    """Result of a hashing operation."""

    algorithm: HashAlgorithm
    hex_digest: str
    file_path: str = ""
    size_bytes: int = 0
    duration_seconds: float = 0.0
    chunk_hashes: list[str] = field(default_factory=list)

    @property
    def size_mb(self) -> float:
        return round(self.size_bytes / (1024**2), 2)

    @property
    def throughput_mbps(self) -> float:
        if self.duration_seconds == 0:
            return 0.0
        return round(self.size_mb / self.duration_seconds, 2)

    def __str__(self) -> str:
        return (
            f"{self.algorithm.value.upper()}: {self.hex_digest} | "
            f"{self.size_mb} MB | {self.duration_seconds:.2f}s | "
            f"{self.throughput_mbps} MB/s"
        )


@dataclass
class MultiHashResult:
    """Result of hashing a file with multiple algorithms simultaneously."""

    file_path: str
    size_bytes: int
    duration_seconds: float
    hashes: dict[HashAlgorithm, str] = field(default_factory=dict)

    def get(self, algorithm: HashAlgorithm) -> str | None:
        return self.hashes.get(algorithm)

    def __str__(self) -> str:
        lines = [f"File: {self.file_path} | {self.size_bytes / (1024**2):.2f} MB"]
        for algo, digest in self.hashes.items():
            lines.append(f"  {algo.value.upper()}: {digest}")
        return "\n".join(lines)


class Hasher:
    """
    Multi-algorithm file and stream hasher.
    """

    @staticmethod
    def hash_file(
        file_path: str | Path,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        block_size: int = DEFAULT_BLOCK_SIZE,
        progress_callback: Callable[[int, int], None] | None = None,
        chunk_level: bool = False,
    ) -> HashResult:
        """
        Hash a file using the specified algorithm.

        Args:
            file_path:         Path to the file.
            algorithm:         Hash algorithm to use.
            block_size:        Read block size in bytes.
            progress_callback: Optional callback(bytes_read, total_bytes).
            chunk_level:       If True, store per-chunk hashes.

        Returns:
            HashResult with hex digest and metadata.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        total_bytes = _get_source_size(str(path))

        hasher = _create_hasher(algorithm)
        chunk_hashes: list[str] = []
        bytes_read = 0
        start = time.perf_counter()

        logger.info(
            "Hashing {} with {} ({:.2f} MB)", path.name, algorithm.value, total_bytes / (1024**2)
        )

        fd = _open_fd(str(path))
        f_obj = os.fdopen(fd, "rb") if fd is not None else open(path, "rb")
        try:
            while True:
                chunk = f_obj.read(block_size)
                if not chunk:
                    break
                hasher = _update_hasher(hasher, algorithm, chunk)
                bytes_read += len(chunk)

                if chunk_level:
                    chunk_hasher = _create_hasher(algorithm)
                    chunk_hasher = _update_hasher(chunk_hasher, algorithm, chunk)
                    chunk_hashes.append(_digest(chunk_hasher, algorithm))

                if progress_callback:
                    progress_callback(bytes_read, total_bytes)
        finally:
            f_obj.close()

        duration = time.perf_counter() - start
        digest = _digest(hasher, algorithm)

        result = HashResult(
            algorithm=algorithm,
            hex_digest=digest,
            file_path=str(path),
            size_bytes=bytes_read,
            duration_seconds=round(duration, 4),
            chunk_hashes=chunk_hashes,
        )

        logger.info("Hash complete: {}", result)
        return result

    @staticmethod
    def hash_file_multi(
        file_path: str | Path,
        algorithms: list[HashAlgorithm] | None = None,
        block_size: int = DEFAULT_BLOCK_SIZE,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> MultiHashResult:
        """
        Hash a file with multiple algorithms in a single pass.

        Args:
            file_path:  Path to the file.
            algorithms: List of algorithms. Defaults to [SHA256, MD5].
            block_size: Read block size in bytes.

        Returns:
            MultiHashResult with all digests.
        """
        if algorithms is None:
            algorithms = [HashAlgorithm.SHA256, HashAlgorithm.MD5]

        path = Path(file_path)
        is_raw_device = str(file_path).startswith("\\\\.\\")
        if not is_raw_device and not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # path.stat() doesn't work for raw Windows devices — use seek-to-end fallback
        try:
            total_bytes = path.stat().st_size
        except (OSError, PermissionError):
            total_bytes = 0  # size unknown for raw devices; progress callback will report 0

        hashers = {algo: _create_hasher(algo) for algo in algorithms}
        bytes_read = 0
        start = time.perf_counter()

        logger.info(
            "Multi-hashing {} with {} ({:.2f} MB)",
            path.name,
            [a.value for a in algorithms],
            total_bytes / (1024**2),
        )

        fd = _open_fd(str(file_path))
        f_obj = os.fdopen(fd, "rb") if fd is not None else open(file_path, "rb")
        try:
            while True:
                chunk = f_obj.read(block_size)
                if not chunk:
                    break
                for algo in algorithms:
                    hashers[algo] = _update_hasher(hashers[algo], algo, chunk)
                bytes_read += len(chunk)

                if progress_callback:
                    progress_callback(bytes_read, total_bytes)
        finally:
            f_obj.close()

        duration = time.perf_counter() - start
        hashes = {algo: _digest(hashers[algo], algo) for algo in algorithms}

        result = MultiHashResult(
            file_path=str(path),
            size_bytes=bytes_read,
            duration_seconds=round(duration, 4),
            hashes=hashes,
        )

        logger.info("Multi-hash complete:\n{}", result)
        return result

    @staticmethod
    def hash_stream(
        stream: BinaryIO,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> str:
        """Hash a binary stream and return the hex digest."""
        hasher = _create_hasher(algorithm)
        while chunk := stream.read(block_size):
            hasher = _update_hasher(hasher, algorithm, chunk)
        return _digest(hasher, algorithm)

    @staticmethod
    def verify_file(
        file_path: str | Path,
        algorithm: HashAlgorithm,
        expected_digest: str,
    ) -> bool:
        """
        Verify a file against a known hash.

        Returns:
            True if the file matches the expected digest.
        """
        result = Hasher.hash_file(file_path, algorithm)
        match = result.hex_digest.lower() == expected_digest.lower()

        if match:
            logger.info("Hash verification PASSED: {}", file_path)
        else:
            logger.error(
                "Hash verification FAILED: {} | expected={} | got={}",
                file_path,
                expected_digest,
                result.hex_digest,
            )
        return match

    @staticmethod
    def hash_bytes(data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
        """Hash raw bytes and return hex digest."""
        hasher = _create_hasher(algorithm)
        hasher = _update_hasher(hasher, algorithm, data)
        return _digest(hasher, algorithm)


# ── Internal helpers ──────────────────────────────────────────────────────────


def _create_hasher(algorithm: HashAlgorithm):
    if algorithm == HashAlgorithm.BLAKE3:
        if not BLAKE3_AVAILABLE:
            raise RuntimeError("blake3 is not installed. Run: pip install blake3")
        return _blake3.blake3()
    return hashlib.new(algorithm.value)


def _update_hasher(hasher, algorithm: HashAlgorithm, chunk: bytes):
    if algorithm == HashAlgorithm.BLAKE3:
        hasher.update(chunk)
    else:
        hasher.update(chunk)
    return hasher


def _digest(hasher, algorithm: HashAlgorithm) -> str:
    if algorithm == HashAlgorithm.BLAKE3:
        return hasher.hexdigest()
    return hasher.hexdigest()


def _get_source_size(source: str) -> int:
    path = Path(source)
    if path.is_file():
        return path.stat().st_size
    try:
        with open(source, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            return size if size > 0 else 0
    except Exception:
        return 0


def _open_fd(path: str) -> int | None:
    """Open a file descriptor using native Windows API for raw drives."""
    import platform
    if platform.system() == "Windows" and path.startswith("\\\\.\\"):
        import ctypes
        import msvcrt
        
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        )
        
        if handle == -1: # INVALID_HANDLE_VALUE
            return None
            
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
        return fd
    return None


