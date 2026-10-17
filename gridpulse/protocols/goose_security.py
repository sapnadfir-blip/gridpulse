"""
IEC 62351-6 Authentication Extension for GOOSE
===============================================

Implements cryptographic authentication for IEC 61850 GOOSE messages
as specified in IEC 62351-6. Supports HMAC-SHA256 (symmetric) and
RSA-2048 / ECDSA-P256 (asymmetric) signature algorithms.

This module is central to the CIL-DoS research: IEC 62351-6 authentication
adds security but introduces verification latency that can be weaponized
to deny service in time-critical protection systems.

Reference: IEC 62351-6:2020, Section 6 - "Security for GOOSE/SV"
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Tuple


# ============================================================================
# Constants
# ============================================================================

class SecurityAlgorithm(IntEnum):
    """IEC 62351-6 authentication algorithm identifiers."""
    NONE = 0x00
    HMAC_SHA256 = 0x01
    HMAC_SHA256_TRUNCATED_80 = 0x02   # 80-bit truncated HMAC
    RSA_2048_SHA256 = 0x03
    ECDSA_P256_SHA256 = 0x04

    def __str__(self) -> str:
        names = {
            0x00: "None",
            0x01: "HMAC-SHA-256",
            0x02: "HMAC-SHA-256-80",
            0x03: "RSA-2048-SHA-256",
            0x04: "ECDSA-P256-SHA-256",
        }
        return names.get(self.value, f"Unknown(0x{self.value:02X})")


class SecurityErrorCode(IntEnum):
    """Security verification result codes."""
    OK = 0
    INVALID_SIGNATURE = 1
    EXPIRED_KEY = 2
    UNKNOWN_KEY_ID = 3
    REPLAY_DETECTED = 4
    MALFORMED_EXTENSION = 5
    UNSUPPORTED_ALGORITHM = 6


# Security extension tag in BER encoding
SECURITY_EXTENSION_TAG = 0x80   # Context-specific [0]

# Maximum allowed timestamp drift for anti-replay (seconds)
MAX_TIMESTAMP_DRIFT = 5.0

# HMAC-SHA256 full output length
HMAC_SHA256_LEN = 32
HMAC_SHA256_TRUNCATED_LEN = 10   # 80-bit truncated


# ============================================================================
# Security Extension Data Structures
# ============================================================================

@dataclass
class SecurityExtension:
    """
    IEC 62351-6 Security Extension appended to GOOSE APDU.

    Structure:
        ┌──────────────────────────────────────────┐
        │ Security Extension Tag (1 byte)          │
        │ Length (1-3 bytes, BER length encoding)   │
        │ Algorithm ID (1 byte)                     │
        │ Key ID (4 bytes)                          │
        │ Anti-Replay Counter (4 bytes)             │
        │ Timestamp (8 bytes, UTC epoch)            │
        │ Signature/HMAC (variable length)          │
        └──────────────────────────────────────────┘
    """
    algorithm: SecurityAlgorithm
    key_id: int
    anti_replay_counter: int
    timestamp: float    # UTC epoch seconds
    signature: bytes    # HMAC digest or digital signature

    @property
    def signature_hex(self) -> str:
        """Return signature as hex string."""
        return self.signature.hex()

    @property
    def signature_length(self) -> int:
        """Expected signature length for the algorithm."""
        lengths = {
            SecurityAlgorithm.HMAC_SHA256: HMAC_SHA256_LEN,
            SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80: HMAC_SHA256_TRUNCATED_LEN,
            SecurityAlgorithm.RSA_2048_SHA256: 256,     # 2048-bit RSA
            SecurityAlgorithm.ECDSA_P256_SHA256: 72,    # DER-encoded max
        }
        return lengths.get(self.algorithm, 0)

    def build(self) -> bytes:
        """Serialize security extension to bytes."""
        # Pack header fields
        header = struct.pack(
            ">B I I d",
            self.algorithm.value,
            self.key_id,
            self.anti_replay_counter,
            self.timestamp,
        )
        payload = header + self.signature

        # BER TLV encoding
        return _ber_encode_tlv(SECURITY_EXTENSION_TAG, payload)

    @classmethod
    def parse(cls, data: bytes) -> Tuple['SecurityExtension', int]:
        """
        Parse security extension from bytes.

        Returns:
            Tuple of (SecurityExtension, bytes_consumed)

        Raises:
            SecurityParseError: If data is malformed
        """
        if len(data) < 2:
            raise SecurityParseError("Security extension too short")

        tag = data[0]
        if tag != SECURITY_EXTENSION_TAG:
            raise SecurityParseError(
                f"Expected security tag 0x{SECURITY_EXTENSION_TAG:02X}, "
                f"got 0x{tag:02X}"
            )

        # Decode BER length
        length, length_bytes = _ber_decode_length(data[1:])
        offset = 1 + length_bytes

        if len(data) < offset + length:
            raise SecurityParseError(
                f"Security extension truncated: need {offset + length}, "
                f"have {len(data)}"
            )

        payload = data[offset:offset + length]

        # Minimum header: 1 (algo) + 4 (key_id) + 4 (counter) + 8 (timestamp) = 17
        if len(payload) < 17:
            raise SecurityParseError("Security header too short")

        algo_byte = payload[0]
        try:
            algorithm = SecurityAlgorithm(algo_byte)
        except ValueError:
            raise SecurityParseError(f"Unknown algorithm: 0x{algo_byte:02X}")

        key_id, counter = struct.unpack(">II", payload[1:9])
        timestamp = struct.unpack(">d", payload[9:17])[0]
        signature = payload[17:]

        ext = cls(
            algorithm=algorithm,
            key_id=key_id,
            anti_replay_counter=counter,
            timestamp=timestamp,
            signature=signature,
        )

        return ext, offset + length

    def __str__(self) -> str:
        sig_preview = self.signature[:8].hex() + "..." if len(self.signature) > 8 else self.signature.hex()
        return (
            f"SecurityExtension(\n"
            f"  algorithm={self.algorithm},\n"
            f"  key_id=0x{self.key_id:08X},\n"
            f"  counter={self.anti_replay_counter},\n"
            f"  timestamp={self.timestamp:.6f},\n"
            f"  signature={sig_preview} ({len(self.signature)} bytes)\n"
            f")"
        )


# ============================================================================
# Key Management
# ============================================================================

@dataclass
class SymmetricKey:
    """HMAC symmetric key for GOOSE authentication."""
    key_id: int
    key_material: bytes
    algorithm: SecurityAlgorithm = SecurityAlgorithm.HMAC_SHA256
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None

    @classmethod
    def generate(
        cls,
        key_id: int,
        algorithm: SecurityAlgorithm = SecurityAlgorithm.HMAC_SHA256,
        lifetime_seconds: Optional[float] = None,
    ) -> 'SymmetricKey':
        """Generate a new random HMAC key."""
        key_material = os.urandom(32)  # 256-bit key
        now = time.time()
        expires = now + lifetime_seconds if lifetime_seconds else None
        return cls(
            key_id=key_id,
            key_material=key_material,
            algorithm=algorithm,
            created_at=now,
            expires_at=expires,
        )

    @property
    def is_expired(self) -> bool:
        """Check if the key has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def __str__(self) -> str:
        return (
            f"SymmetricKey(id=0x{self.key_id:08X}, "
            f"algo={self.algorithm}, "
            f"expired={self.is_expired})"
        )


@dataclass
class KeyStore:
    """
    In-memory key store for GOOSE authentication.
    Maps key_id -> SymmetricKey for HMAC operations.
    """
    _keys: dict[int, SymmetricKey] = field(default_factory=dict)

    def add_key(self, key: SymmetricKey) -> None:
        """Register a key in the store."""
        self._keys[key.key_id] = key

    def get_key(self, key_id: int) -> Optional[SymmetricKey]:
        """Retrieve a key by ID, returns None if not found or expired."""
        key = self._keys.get(key_id)
        if key is None:
            return None
        if key.is_expired:
            return None
        return key

    def remove_key(self, key_id: int) -> bool:
        """Remove a key. Returns True if it existed."""
        return self._keys.pop(key_id, None) is not None

    def list_keys(self) -> list[SymmetricKey]:
        """List all non-expired keys."""
        return [k for k in self._keys.values() if not k.is_expired]

    def __len__(self) -> int:
        return len(self._keys)


# ============================================================================
# HMAC-SHA256 Authentication Engine
# ============================================================================

class HMACAuthenticator:
    """
    HMAC-SHA256 authentication for GOOSE messages.

    This is the primary symmetric authentication mechanism for IEC 62351-6.
    Used for latency-critical trip signals where sub-millisecond overhead
    is essential.
    """

    def __init__(self, key_store: KeyStore):
        self._key_store = key_store
        self._replay_window: dict[int, int] = {}  # key_id -> last_counter

    def sign(
        self,
        goose_pdu: bytes,
        key_id: int,
        counter: Optional[int] = None,
        truncated: bool = False,
    ) -> SecurityExtension:
        """
        Compute HMAC-SHA256 signature over a GOOSE PDU.

        Args:
            goose_pdu: Raw GOOSE PDU bytes (from 0x61 tag through allData)
            key_id: Key identifier to use for signing
            counter: Anti-replay counter (auto-incremented if None)
            truncated: If True, use 80-bit truncated HMAC

        Returns:
            SecurityExtension with computed HMAC

        Raises:
            SecurityError: If key not found or expired
        """
        key = self._key_store.get_key(key_id)
        if key is None:
            raise SecurityError(f"Key 0x{key_id:08X} not found or expired")

        # Auto-increment counter
        if counter is None:
            counter = self._replay_window.get(key_id, 0) + 1
        self._replay_window[key_id] = counter

        timestamp = time.time()

        # Build authenticated data: PDU + key_id + counter + timestamp
        auth_data = goose_pdu + struct.pack(">IId", key_id, counter, timestamp)

        # Compute HMAC-SHA256
        mac = hmac.new(key.key_material, auth_data, hashlib.sha256).digest()

        if truncated:
            mac = mac[:HMAC_SHA256_TRUNCATED_LEN]
            algo = SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80
        else:
            algo = SecurityAlgorithm.HMAC_SHA256

        return SecurityExtension(
            algorithm=algo,
            key_id=key_id,
            anti_replay_counter=counter,
            timestamp=timestamp,
            signature=mac,
        )

    def verify(
        self,
        goose_pdu: bytes,
        extension: SecurityExtension,
    ) -> SecurityErrorCode:
        """
        Verify HMAC-SHA256 signature on a GOOSE PDU.

        This is the EXPENSIVE operation that CIL-DoS exploits:
        each verification consumes CPU cycles even for invalid frames.

        Args:
            goose_pdu: Raw GOOSE PDU bytes
            extension: Security extension to verify

        Returns:
            SecurityErrorCode indicating verification result
        """
        # Check algorithm support
        if extension.algorithm not in (
            SecurityAlgorithm.HMAC_SHA256,
            SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80,
        ):
            return SecurityErrorCode.UNSUPPORTED_ALGORITHM

        # Look up key
        key = self._key_store.get_key(extension.key_id)
        if key is None:
            return SecurityErrorCode.UNKNOWN_KEY_ID

        # Anti-replay check
        last_counter = self._replay_window.get(extension.key_id, 0)
        if extension.anti_replay_counter <= last_counter:
            return SecurityErrorCode.REPLAY_DETECTED

        # Timestamp freshness check
        now = time.time()
        drift = abs(now - extension.timestamp)
        if drift > MAX_TIMESTAMP_DRIFT:
            return SecurityErrorCode.REPLAY_DETECTED

        # Recompute HMAC
        auth_data = goose_pdu + struct.pack(
            ">IId",
            extension.key_id,
            extension.anti_replay_counter,
            extension.timestamp,
        )
        expected_mac = hmac.new(
            key.key_material, auth_data, hashlib.sha256
        ).digest()

        if extension.algorithm == SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80:
            expected_mac = expected_mac[:HMAC_SHA256_TRUNCATED_LEN]

        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(extension.signature, expected_mac):
            # Update replay window on success
            self._replay_window[extension.key_id] = extension.anti_replay_counter
            return SecurityErrorCode.OK
        else:
            return SecurityErrorCode.INVALID_SIGNATURE


# ============================================================================
# Digital Signature Authentication (RSA-2048 / ECDSA-P256)
# ============================================================================

class AsymmetricAuthenticator:
    """
    RSA-2048 and ECDSA-P256 digital signature authentication for GOOSE.

    These algorithms provide non-repudiation but are significantly slower
    than HMAC, making them the primary target for CIL-DoS attacks.

    Typical verification latencies (measured on commodity hardware):
        - HMAC-SHA256:    ~1-3 µs
        - ECDSA-P256:     ~200-500 µs
        - RSA-2048:       ~50-150 µs (verify), ~2-5 ms (sign)

    The CIL-DoS attack exploits the asymmetry: signing (attacker) is
    cheap for HMAC but verification (defender) is expensive for RSA/ECDSA.
    """

    def __init__(self) -> None:
        self._replay_window: dict[int, int] = {}
        self._rsa_private_key = None
        self._rsa_public_key = None
        self._ecdsa_private_key = None
        self._ecdsa_public_key = None

    def generate_rsa_keypair(self) -> None:
        """Generate RSA-2048 key pair for GOOSE signing."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            self._rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            self._rsa_public_key = self._rsa_private_key.public_key()
        except ImportError:
            raise SecurityError(
                "cryptography library required for RSA. "
                "Install with: pip install cryptography"
            )

    def generate_ecdsa_keypair(self) -> None:
        """Generate ECDSA P-256 key pair for GOOSE signing."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            self._ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
            self._ecdsa_public_key = self._ecdsa_private_key.public_key()
        except ImportError:
            raise SecurityError(
                "cryptography library required for ECDSA. "
                "Install with: pip install cryptography"
            )

    def sign_rsa(
        self,
        goose_pdu: bytes,
        key_id: int,
        counter: Optional[int] = None,
    ) -> SecurityExtension:
        """Sign GOOSE PDU with RSA-2048-SHA256."""
        if self._rsa_private_key is None:
            raise SecurityError("RSA key pair not generated. Call generate_rsa_keypair() first.")

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        if counter is None:
            counter = self._replay_window.get(key_id, 0) + 1
        self._replay_window[key_id] = counter

        timestamp = time.time()
        auth_data = goose_pdu + struct.pack(">IId", key_id, counter, timestamp)

        signature = self._rsa_private_key.sign(
            auth_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return SecurityExtension(
            algorithm=SecurityAlgorithm.RSA_2048_SHA256,
            key_id=key_id,
            anti_replay_counter=counter,
            timestamp=timestamp,
            signature=signature,
        )

    def verify_rsa(
        self,
        goose_pdu: bytes,
        extension: SecurityExtension,
    ) -> SecurityErrorCode:
        """
        Verify RSA-2048-SHA256 signature on GOOSE PDU.

        ⚡ This is the MOST EXPENSIVE verification path and the primary
        target for CIL-DoS: each invalid signature still requires full
        RSA modular exponentiation before rejection.
        """
        if self._rsa_public_key is None:
            return SecurityErrorCode.UNSUPPORTED_ALGORITHM

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.exceptions import InvalidSignature

        # Anti-replay check
        last_counter = self._replay_window.get(extension.key_id, 0)
        if extension.anti_replay_counter <= last_counter:
            return SecurityErrorCode.REPLAY_DETECTED

        auth_data = goose_pdu + struct.pack(
            ">IId",
            extension.key_id,
            extension.anti_replay_counter,
            extension.timestamp,
        )

        try:
            self._rsa_public_key.verify(
                extension.signature,
                auth_data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            self._replay_window[extension.key_id] = extension.anti_replay_counter
            return SecurityErrorCode.OK
        except InvalidSignature:
            return SecurityErrorCode.INVALID_SIGNATURE

    def sign_ecdsa(
        self,
        goose_pdu: bytes,
        key_id: int,
        counter: Optional[int] = None,
    ) -> SecurityExtension:
        """Sign GOOSE PDU with ECDSA-P256-SHA256."""
        if self._ecdsa_private_key is None:
            raise SecurityError("ECDSA key pair not generated. Call generate_ecdsa_keypair() first.")

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        if counter is None:
            counter = self._replay_window.get(key_id, 0) + 1
        self._replay_window[key_id] = counter

        timestamp = time.time()
        auth_data = goose_pdu + struct.pack(">IId", key_id, counter, timestamp)

        signature = self._ecdsa_private_key.sign(
            auth_data,
            ec.ECDSA(hashes.SHA256()),
        )

        return SecurityExtension(
            algorithm=SecurityAlgorithm.ECDSA_P256_SHA256,
            key_id=key_id,
            anti_replay_counter=counter,
            timestamp=timestamp,
            signature=signature,
        )

    def verify_ecdsa(
        self,
        goose_pdu: bytes,
        extension: SecurityExtension,
    ) -> SecurityErrorCode:
        """Verify ECDSA-P256-SHA256 signature on GOOSE PDU."""
        if self._ecdsa_public_key is None:
            return SecurityErrorCode.UNSUPPORTED_ALGORITHM

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature

        last_counter = self._replay_window.get(extension.key_id, 0)
        if extension.anti_replay_counter <= last_counter:
            return SecurityErrorCode.REPLAY_DETECTED

        auth_data = goose_pdu + struct.pack(
            ">IId",
            extension.key_id,
            extension.anti_replay_counter,
            extension.timestamp,
        )

        try:
            self._ecdsa_public_key.verify(
                extension.signature,
                auth_data,
                ec.ECDSA(hashes.SHA256()),
            )
            self._replay_window[extension.key_id] = extension.anti_replay_counter
            return SecurityErrorCode.OK
        except InvalidSignature:
            return SecurityErrorCode.INVALID_SIGNATURE

    def verify(
        self,
        goose_pdu: bytes,
        extension: SecurityExtension,
    ) -> SecurityErrorCode:
        """
        Unified verification dispatcher.

        Routes to the appropriate algorithm based on the extension's
        algorithm field.
        """
        if extension.algorithm == SecurityAlgorithm.RSA_2048_SHA256:
            return self.verify_rsa(goose_pdu, extension)
        elif extension.algorithm == SecurityAlgorithm.ECDSA_P256_SHA256:
            return self.verify_ecdsa(goose_pdu, extension)
        else:
            return SecurityErrorCode.UNSUPPORTED_ALGORITHM


# ============================================================================
# Unified Security Processor
# ============================================================================

class GOOSESecurityProcessor:
    """
    Unified security processor for IEC 62351-6 GOOSE authentication.

    Handles both symmetric (HMAC) and asymmetric (RSA/ECDSA) authentication.
    Tracks verification statistics for benchmarking and CIL-DoS analysis.
    """

    def __init__(self, key_store: Optional[KeyStore] = None):
        self._key_store = key_store or KeyStore()
        self._hmac_auth = HMACAuthenticator(self._key_store)
        self._asym_auth = AsymmetricAuthenticator()

        # Verification statistics (critical for CIL-DoS analysis)
        self.stats = SecurityStats()

    @property
    def key_store(self) -> KeyStore:
        return self._key_store

    @property
    def hmac(self) -> HMACAuthenticator:
        return self._hmac_auth

    @property
    def asymmetric(self) -> AsymmetricAuthenticator:
        return self._asym_auth

    def sign(
        self,
        goose_pdu: bytes,
        key_id: int,
        algorithm: SecurityAlgorithm = SecurityAlgorithm.HMAC_SHA256,
        counter: Optional[int] = None,
    ) -> SecurityExtension:
        """Sign a GOOSE PDU using the specified algorithm."""
        if algorithm in (
            SecurityAlgorithm.HMAC_SHA256,
            SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80,
        ):
            truncated = algorithm == SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80
            return self._hmac_auth.sign(goose_pdu, key_id, counter, truncated)
        elif algorithm == SecurityAlgorithm.RSA_2048_SHA256:
            return self._asym_auth.sign_rsa(goose_pdu, key_id, counter)
        elif algorithm == SecurityAlgorithm.ECDSA_P256_SHA256:
            return self._asym_auth.sign_ecdsa(goose_pdu, key_id, counter)
        else:
            raise SecurityError(f"Unsupported signing algorithm: {algorithm}")

    def verify(
        self,
        goose_pdu: bytes,
        extension: SecurityExtension,
    ) -> SecurityErrorCode:
        """
        Verify a GOOSE PDU's security extension.

        Records timing for CIL-DoS latency analysis.
        """
        start_ns = time.perf_counter_ns()

        if extension.algorithm in (
            SecurityAlgorithm.HMAC_SHA256,
            SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80,
        ):
            result = self._hmac_auth.verify(goose_pdu, extension)
        elif extension.algorithm in (
            SecurityAlgorithm.RSA_2048_SHA256,
            SecurityAlgorithm.ECDSA_P256_SHA256,
        ):
            result = self._asym_auth.verify(goose_pdu, extension)
        else:
            result = SecurityErrorCode.UNSUPPORTED_ALGORITHM

        elapsed_ns = time.perf_counter_ns() - start_ns
        self.stats.record_verification(extension.algorithm, result, elapsed_ns)

        return result

    def append_security(
        self,
        goose_frame_bytes: bytes,
        key_id: int,
        algorithm: SecurityAlgorithm = SecurityAlgorithm.HMAC_SHA256,
    ) -> bytes:
        """
        Append IEC 62351-6 security extension to a complete GOOSE frame.

        Takes raw GOOSE Ethernet frame bytes and appends the security
        extension after the GOOSE PDU.
        """
        # Find the GOOSE PDU within the frame (after Ethernet + GOOSE header)
        # Ethernet header: 14 bytes (or 18 with VLAN)
        # GOOSE header: 8 bytes (APPID + Length + Reserved1 + Reserved2)
        eth_header_len = 14
        if len(goose_frame_bytes) > 16:
            ethertype = struct.unpack(">H", goose_frame_bytes[12:14])[0]
            if ethertype == 0x8100:  # VLAN tagged
                eth_header_len = 18

        goose_header_offset = eth_header_len
        pdu_offset = goose_header_offset + 8  # Skip APPID, Length, Reserved

        if pdu_offset >= len(goose_frame_bytes):
            raise SecurityError("Frame too short for security extension")

        goose_pdu = goose_frame_bytes[pdu_offset:]

        # Sign the PDU
        extension = self.sign(goose_pdu, key_id, algorithm)
        extension_bytes = extension.build()

        # Append extension to frame
        secured_frame = goose_frame_bytes + extension_bytes

        # Update GOOSE header length field
        new_length = len(secured_frame) - goose_header_offset
        length_offset = goose_header_offset + 2  # APPID(2) then Length(2)
        secured_frame = (
            secured_frame[:length_offset]
            + struct.pack(">H", new_length)
            + secured_frame[length_offset + 2:]
        )

        return secured_frame


# ============================================================================
# Verification Statistics (for CIL-DoS analysis)
# ============================================================================

@dataclass
class SecurityStats:
    """
    Tracks verification performance statistics.

    Critical for CIL-DoS research: measures the CPU cost of signature
    verification under flood conditions.
    """
    total_verifications: int = 0
    successful_verifications: int = 0
    failed_verifications: int = 0

    # Per-algorithm timing (nanoseconds)
    _timing: dict[SecurityAlgorithm, list[int]] = field(default_factory=dict)
    _results: dict[SecurityErrorCode, int] = field(default_factory=dict)

    def record_verification(
        self,
        algorithm: SecurityAlgorithm,
        result: SecurityErrorCode,
        elapsed_ns: int,
    ) -> None:
        """Record a verification attempt."""
        self.total_verifications += 1

        if result == SecurityErrorCode.OK:
            self.successful_verifications += 1
        else:
            self.failed_verifications += 1

        # Track timing per algorithm
        if algorithm not in self._timing:
            self._timing[algorithm] = []
        self._timing[algorithm].append(elapsed_ns)

        # Track result distribution
        self._results[result] = self._results.get(result, 0) + 1

    def get_timing_stats(self, algorithm: SecurityAlgorithm) -> dict:
        """Get timing statistics for a specific algorithm."""
        timings = self._timing.get(algorithm, [])
        if not timings:
            return {"count": 0}

        sorted_t = sorted(timings)
        n = len(sorted_t)

        return {
            "count": n,
            "mean_us": sum(sorted_t) / n / 1000,
            "median_us": sorted_t[n // 2] / 1000,
            "p95_us": sorted_t[int(n * 0.95)] / 1000 if n >= 20 else None,
            "p99_us": sorted_t[int(n * 0.99)] / 1000 if n >= 100 else None,
            "min_us": sorted_t[0] / 1000,
            "max_us": sorted_t[-1] / 1000,
        }

    def get_result_distribution(self) -> dict[str, int]:
        """Get distribution of verification results."""
        return {
            SecurityErrorCode(k).name: v
            for k, v in sorted(self._results.items())
        }

    def reset(self) -> None:
        """Reset all statistics."""
        self.total_verifications = 0
        self.successful_verifications = 0
        self.failed_verifications = 0
        self._timing.clear()
        self._results.clear()

    def __str__(self) -> str:
        lines = [
            "╔══════════════════════════════════════════════════╗",
            "║       IEC 62351-6 Verification Statistics        ║",
            "╠══════════════════════════════════════════════════╣",
            f"║  Total Verifications:  {self.total_verifications:>10}                ║",
            f"║  Successful:           {self.successful_verifications:>10}                ║",
            f"║  Failed:               {self.failed_verifications:>10}                ║",
        ]

        for algo in self._timing:
            stats = self.get_timing_stats(algo)
            lines.append(f"║  {algo}:".ljust(51) + "║")
            lines.append(f"║    Mean: {stats['mean_us']:.1f} µs | "
                        f"Median: {stats['median_us']:.1f} µs".ljust(51) + "║")
            if stats.get('p99_us'):
                lines.append(f"║    P99: {stats['p99_us']:.1f} µs | "
                            f"Max: {stats['max_us']:.1f} µs".ljust(51) + "║")

        lines.append("╚══════════════════════════════════════════════════╝")
        return "\n".join(lines)


# ============================================================================
# BER Encoding Utilities
# ============================================================================

def _ber_encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a BER TLV (Tag-Length-Value) triplet."""
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    elif length < 0x10000:
        return bytes([tag, 0x82]) + struct.pack(">H", length) + value
    else:
        raise SecurityError(f"BER length too large: {length}")


def _ber_decode_length(data: bytes) -> Tuple[int, int]:
    """
    Decode BER length field.

    Returns:
        Tuple of (length_value, bytes_consumed_by_length_field)
    """
    if len(data) < 1:
        raise SecurityParseError("BER length field missing")

    first = data[0]
    if first < 0x80:
        return first, 1
    elif first == 0x81:
        if len(data) < 2:
            raise SecurityParseError("BER length truncated")
        return data[1], 2
    elif first == 0x82:
        if len(data) < 3:
            raise SecurityParseError("BER length truncated")
        return struct.unpack(">H", data[1:3])[0], 3
    else:
        raise SecurityParseError(f"Unsupported BER length encoding: 0x{first:02X}")


# ============================================================================
# Exceptions
# ============================================================================

class SecurityError(Exception):
    """General security operation error."""
    pass


class SecurityParseError(SecurityError):
    """Error parsing security extension data."""
    pass
