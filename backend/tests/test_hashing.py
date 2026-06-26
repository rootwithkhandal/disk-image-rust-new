"""Tests for the hashing engine."""

import tempfile
from pathlib import Path

import pytest

from core.hashing.hasher import HashAlgorithm, Hasher


def _make_temp_file(content: bytes) -> Path:
    tmp = Path(tempfile.mktemp())  # noqa: S306 — deleted by test after use
    tmp.write_bytes(content)
    return tmp


class TestHasher:
    def test_sha256_known_value(self):
        """SHA256 of empty bytes is a known constant."""
        digest = Hasher.hash_bytes(b"", HashAlgorithm.SHA256)
        assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_md5_known_value(self):
        digest = Hasher.hash_bytes(b"", HashAlgorithm.MD5)
        assert digest == "d41d8cd98f00b204e9800998ecf8427e"

    def test_sha1_known_value(self):
        digest = Hasher.hash_bytes(b"hello", HashAlgorithm.SHA1)
        assert digest == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

    def test_hash_file_sha256(self):
        data = b"forgelens test data"
        path = _make_temp_file(data)
        result = Hasher.hash_file(path, HashAlgorithm.SHA256)
        assert result.hex_digest == Hasher.hash_bytes(data, HashAlgorithm.SHA256)
        assert result.size_bytes == len(data)
        path.unlink()

    def test_hash_file_multi(self):
        data = b"multi hash test"
        path = _make_temp_file(data)
        result = Hasher.hash_file_multi(path, [HashAlgorithm.SHA256, HashAlgorithm.MD5])
        assert HashAlgorithm.SHA256 in result.hashes
        assert HashAlgorithm.MD5 in result.hashes
        assert result.hashes[HashAlgorithm.SHA256] == Hasher.hash_bytes(data, HashAlgorithm.SHA256)
        path.unlink()

    def test_verify_file_pass(self):
        data = b"verify me"
        path = _make_temp_file(data)
        expected = Hasher.hash_bytes(data, HashAlgorithm.SHA256)
        assert Hasher.verify_file(path, HashAlgorithm.SHA256, expected) is True
        path.unlink()

    def test_verify_file_fail(self):
        data = b"verify me"
        path = _make_temp_file(data)
        assert Hasher.verify_file(path, HashAlgorithm.SHA256, "deadbeef") is False
        path.unlink()

    def test_chunk_level_hashing(self):
        data = b"x" * (1024 * 10)  # 10 KB
        path = _make_temp_file(data)
        result = Hasher.hash_file(path, HashAlgorithm.SHA256, block_size=1024, chunk_level=True)
        assert len(result.chunk_hashes) == 10
        path.unlink()

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            Hasher.hash_file("/nonexistent/path/file.dd", HashAlgorithm.SHA256)
