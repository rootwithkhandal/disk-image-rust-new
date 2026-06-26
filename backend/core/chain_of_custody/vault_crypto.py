"""
Evidence Vault Cryptography
============================
Provides AES-256-GCM encryption for evidence files and
HMAC-SHA256 signature verification for tamper-evident metadata.

Uses Python's standard `cryptography` library (hazmat layer).

Usage:
    from core.chain_of_custody.vault_crypto import VaultCrypto

    crypto = VaultCrypto()
    key = crypto.generate_key()

    # Encrypt a file
    crypto.encrypt_file("image.dd", "image.dd.enc", key)

    # Decrypt
    crypto.decrypt_file("image.dd.enc", "image.dd.restored", key)

    # Sign metadata
    sig = crypto.sign_metadata(metadata_dict, key)
    ok = crypto.verify_signature(metadata_dict, sig, key)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

from loguru import logger

# Try cryptography library (preferred — AES-GCM)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning(
        "cryptography library not installed — encryption unavailable. Run: pip install cryptography"
    )

CHUNK_SIZE = 64 * 1024  # 64 KB read chunks
NONCE_SIZE = 12  # AES-GCM standard nonce
KEY_SIZE = 32  # AES-256 = 32 bytes
MAGIC = b"FGLENS\x01"  # File magic header


class VaultCrypto:
    """
    AES-256-GCM file encryption and HMAC-SHA256 metadata signing.
    """

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure 256-bit key."""
        return os.urandom(KEY_SIZE)

    @staticmethod
    def key_to_b64(key: bytes) -> str:
        """Encode a key as URL-safe base64 for storage."""
        return base64.urlsafe_b64encode(key).decode()

    @staticmethod
    def key_from_b64(b64_key: str) -> bytes:
        """Decode a base64-encoded key."""
        return base64.urlsafe_b64decode(b64_key.encode())

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
        """
        Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256.
        Returns (key, salt).
        """
        if salt is None:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=600_000,
            dklen=KEY_SIZE,
        )
        return key, salt

    # ── File encryption ───────────────────────────────────────────────────────

    @staticmethod
    def encrypt_file(
        source_path: str | Path,
        output_path: str | Path,
        key: bytes,
    ) -> bool:
        """
        Encrypt a file using AES-256-GCM.

        File format:
            MAGIC (7 bytes) | nonce (12 bytes) | ciphertext+tag

        Args:
            source_path: Plaintext input file.
            output_path: Encrypted output file.
            key:         32-byte AES-256 key.

        Returns:
            True on success.
        """
        if not CRYPTO_AVAILABLE:
            logger.error("cryptography library required for encryption")
            return False

        source = Path(source_path)
        output = Path(output_path)

        if not source.exists():
            logger.error("Source file not found: {}", source)
            return False

        try:
            nonce = os.urandom(NONCE_SIZE)
            aesgcm = AESGCM(key)

            plaintext = source.read_bytes()
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            with open(output, "wb") as f:
                f.write(MAGIC)
                f.write(nonce)
                f.write(ciphertext)

            logger.info(
                "File encrypted | {} -> {} | {:.2f} MB",
                source.name,
                output.name,
                len(plaintext) / (1024**2),
            )
            return True

        except Exception as exc:
            logger.error("Encryption failed: {}", exc)
            return False

    @staticmethod
    def decrypt_file(
        source_path: str | Path,
        output_path: str | Path,
        key: bytes,
    ) -> bool:
        """
        Decrypt an AES-256-GCM encrypted file.

        Returns:
            True on success. Raises ValueError on authentication failure.
        """
        if not CRYPTO_AVAILABLE:
            logger.error("cryptography library required for decryption")
            return False

        source = Path(source_path)
        output = Path(output_path)

        if not source.exists():
            logger.error("Encrypted file not found: {}", source)
            return False

        try:
            with open(source, "rb") as f:
                magic = f.read(len(MAGIC))
                if magic != MAGIC:
                    raise ValueError("Invalid file format — not a ForgeLens encrypted file")
                nonce = f.read(NONCE_SIZE)
                ciphertext = f.read()

            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            output.write_bytes(plaintext)

            logger.info(
                "File decrypted | {} -> {} | {:.2f} MB",
                source.name,
                output.name,
                len(plaintext) / (1024**2),
            )
            return True

        except Exception as exc:
            logger.error("Decryption failed: {}", exc)
            return False

    # ── Metadata signing ──────────────────────────────────────────────────────

    @staticmethod
    def sign_metadata(metadata: dict, key: bytes) -> str:
        """
        Create an HMAC-SHA256 signature of a metadata dict.

        The metadata is serialized to canonical JSON (sorted keys)
        before signing to ensure deterministic output.

        Returns:
            Hex-encoded HMAC signature.
        """
        canonical = json.dumps(metadata, sort_keys=True, default=str).encode("utf-8")
        sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        logger.debug("Metadata signed | evidence_id={}", metadata.get("evidence_id", "?"))
        return sig

    @staticmethod
    def verify_signature(metadata: dict, signature: str, key: bytes) -> bool:
        """
        Verify an HMAC-SHA256 signature against a metadata dict.

        Returns:
            True if the signature is valid (metadata has not been tampered with).
        """
        expected = VaultCrypto.sign_metadata(metadata, key)
        valid = hmac.compare_digest(expected, signature)
        if valid:
            logger.info(
                "Signature VALID | evidence_id={}",
                metadata.get("evidence_id", "?"),
            )
        else:
            logger.error(
                "Signature INVALID — metadata may have been tampered with | evidence_id={}",
                metadata.get("evidence_id", "?"),
            )
        return valid

    # ── Secure metadata storage ───────────────────────────────────────────────

    @staticmethod
    def write_signed_metadata(
        metadata: dict,
        output_path: str | Path,
        key: bytes,
    ) -> Path:
        """
        Write metadata to a JSON file with an embedded HMAC signature.
        The signature covers all metadata fields.
        """
        path = Path(output_path)
        signature = VaultCrypto.sign_metadata(metadata, key)
        signed = {
            "metadata": metadata,
            "signature": signature,
            "signed_at": __import__("datetime")
            .datetime.now(__import__("datetime").timezone.utc)
            .isoformat(),
        }
        path.write_text(
            json.dumps(signed, indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("Signed metadata written: {}", path)
        return path

    @staticmethod
    def read_and_verify_metadata(
        path: str | Path,
        key: bytes,
    ) -> tuple[dict, bool]:
        """
        Read a signed metadata file and verify its signature.

        Returns:
            (metadata_dict, is_valid)
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Signed metadata not found: {path}")

        signed = json.loads(path.read_text(encoding="utf-8"))
        metadata = signed.get("metadata", {})
        signature = signed.get("signature", "")

        is_valid = VaultCrypto.verify_signature(metadata, signature, key)
        return metadata, is_valid
