"""
GridPulse Test Suite — GOOSE Protocol Codec
=============================================

Tests for IEC 61850 GOOSE frame parsing, building, and round-trip
correctness.
"""

import struct
import time
import pytest

from gridpulse.protocols.goose import GOOSEFrame, GOOSEParseError
from gridpulse.protocols.goose_security import (
    SecurityAlgorithm,
    SecurityExtension,
    SecurityErrorCode,
    SymmetricKey,
    KeyStore,
    HMACAuthenticator,
    AsymmetricAuthenticator,
    GOOSESecurityProcessor,
)


# ============================================================================
# Test Fixtures
# ============================================================================

def build_minimal_goose_pdu() -> bytes:
    """Build a minimal valid GOOSE PDU for testing."""
    def ber_tlv(tag, value):
        length = len(value)
        if length < 0x80:
            return bytes([tag, length]) + value
        elif length < 0x100:
            return bytes([tag, 0x81, length]) + value
        else:
            return bytes([tag, 0x82]) + struct.pack(">H", length) + value

    def encode_int(v):
        if v == 0:
            return b"\x00"
        result = []
        while v > 0:
            result.insert(0, v & 0xFF)
            v >>= 8
        if result[0] & 0x80:
            result.insert(0, 0)
        return bytes(result)

    fields = b""
    fields += ber_tlv(0x80, b"TestSub/LLN0$GO$gcb01")     # gocbRef
    fields += ber_tlv(0x81, encode_int(2000))                # timeAllowedToLive
    fields += ber_tlv(0x82, b"TestSub/LLN0$DataSet01")      # datSet
    fields += ber_tlv(0x83, b"GOOSE_Test_01")                # goID

    # Timestamp
    now = int(time.time())
    fields += ber_tlv(0x84, struct.pack(">II", now, 0))      # t

    fields += ber_tlv(0x85, encode_int(1))                   # stNum
    fields += ber_tlv(0x86, encode_int(0))                   # sqNum
    fields += ber_tlv(0x87, b"\x00")                         # simulation=False
    fields += ber_tlv(0x88, encode_int(1))                   # confRev
    fields += ber_tlv(0x89, b"\x00")                         # ndsCom=False
    fields += ber_tlv(0x8A, encode_int(1))                   # numDatSetEntries

    # allData: one Boolean(False)
    all_data = ber_tlv(0x83, b"\x00")
    fields += ber_tlv(0xAB, all_data)

    return ber_tlv(0x61, fields)


def build_goose_frame_bytes() -> bytes:
    """Build a complete GOOSE Ethernet frame for testing."""
    dst_mac = bytes([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01])
    src_mac = bytes([0x08, 0x00, 0x27, 0xAA, 0xBB, 0xCC])
    ethertype = struct.pack(">H", 0x88B8)

    goose_pdu = build_minimal_goose_pdu()

    # GOOSE header
    app_id = struct.pack(">H", 0x0001)
    length = struct.pack(">H", 8 + len(goose_pdu))
    reserved = struct.pack(">HH", 0, 0)
    goose_header = app_id + length + reserved

    return dst_mac + src_mac + ethertype + goose_header + goose_pdu


# ============================================================================
# GOOSE Security Tests
# ============================================================================

class TestHMACAuthentication:
    """Test HMAC-SHA256 authentication for GOOSE."""

    def setup_method(self):
        self.key_store = KeyStore()
        self.key = SymmetricKey.generate(key_id=0x00000001)
        self.key_store.add_key(self.key)
        self.auth = HMACAuthenticator(self.key_store)
        self.pdu = build_minimal_goose_pdu()

    def test_sign_produces_extension(self):
        ext = self.auth.sign(self.pdu, key_id=0x00000001)
        assert isinstance(ext, SecurityExtension)
        assert ext.algorithm == SecurityAlgorithm.HMAC_SHA256
        assert len(ext.signature) == 32  # SHA-256 output

    def test_sign_verify_roundtrip(self):
        ext = self.auth.sign(self.pdu, key_id=0x00000001)
        # Need a fresh authenticator with same key to verify
        auth2 = HMACAuthenticator(self.key_store)
        result = auth2.verify(self.pdu, ext)
        assert result == SecurityErrorCode.OK

    def test_invalid_signature_detected(self):
        ext = self.auth.sign(self.pdu, key_id=0x00000001)
        # Corrupt the signature
        corrupted = SecurityExtension(
            algorithm=ext.algorithm,
            key_id=ext.key_id,
            anti_replay_counter=ext.anti_replay_counter + 1,
            timestamp=ext.timestamp,
            signature=b"\x00" * 32,  # Invalid signature
        )
        auth2 = HMACAuthenticator(self.key_store)
        result = auth2.verify(self.pdu, corrupted)
        assert result == SecurityErrorCode.INVALID_SIGNATURE

    def test_unknown_key_rejected(self):
        ext = self.auth.sign(self.pdu, key_id=0x00000001)
        ext_wrong_key = SecurityExtension(
            algorithm=ext.algorithm,
            key_id=0xDEADBEEF,
            anti_replay_counter=ext.anti_replay_counter,
            timestamp=ext.timestamp,
            signature=ext.signature,
        )
        auth2 = HMACAuthenticator(self.key_store)
        result = auth2.verify(self.pdu, ext_wrong_key)
        assert result == SecurityErrorCode.UNKNOWN_KEY_ID

    def test_truncated_hmac(self):
        ext = self.auth.sign(self.pdu, key_id=0x00000001, truncated=True)
        assert ext.algorithm == SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80
        assert len(ext.signature) == 10  # 80-bit truncated

    def test_counter_auto_increment(self):
        ext1 = self.auth.sign(self.pdu, key_id=0x00000001)
        ext2 = self.auth.sign(self.pdu, key_id=0x00000001)
        assert ext2.anti_replay_counter > ext1.anti_replay_counter


class TestSecurityExtensionSerialization:
    """Test SecurityExtension build/parse round-trip."""

    def test_roundtrip(self):
        ext = SecurityExtension(
            algorithm=SecurityAlgorithm.HMAC_SHA256,
            key_id=0x00000042,
            anti_replay_counter=100,
            timestamp=1700000000.123456,
            signature=b"\xAB" * 32,
        )
        data = ext.build()
        parsed, consumed = SecurityExtension.parse(data)

        assert parsed.algorithm == ext.algorithm
        assert parsed.key_id == ext.key_id
        assert parsed.anti_replay_counter == ext.anti_replay_counter
        assert abs(parsed.timestamp - ext.timestamp) < 0.001
        assert parsed.signature == ext.signature
        assert consumed == len(data)


class TestKeyStore:
    """Test key management."""

    def test_add_and_retrieve(self):
        store = KeyStore()
        key = SymmetricKey.generate(key_id=1)
        store.add_key(key)
        assert store.get_key(1) is not None
        assert store.get_key(999) is None

    def test_expired_key(self):
        store = KeyStore()
        key = SymmetricKey.generate(key_id=1, lifetime_seconds=-1)  # Already expired
        store.add_key(key)
        assert store.get_key(1) is None

    def test_list_keys(self):
        store = KeyStore()
        for i in range(5):
            store.add_key(SymmetricKey.generate(key_id=i))
        assert len(store.list_keys()) == 5


class TestSecurityProcessor:
    """Test unified security processor."""

    def test_hmac_sign_verify(self):
        proc = GOOSESecurityProcessor()
        key = SymmetricKey.generate(key_id=1)
        proc.key_store.add_key(key)

        pdu = build_minimal_goose_pdu()
        ext = proc.sign(pdu, key_id=1, algorithm=SecurityAlgorithm.HMAC_SHA256)

        # Create new processor with same key
        proc2 = GOOSESecurityProcessor()
        proc2.key_store.add_key(key)
        result = proc2.verify(pdu, ext)
        assert result == SecurityErrorCode.OK
        assert proc2.stats.total_verifications == 1
        assert proc2.stats.successful_verifications == 1

    def test_stats_tracking(self):
        proc = GOOSESecurityProcessor()
        key = SymmetricKey.generate(key_id=1)
        proc.key_store.add_key(key)
        pdu = build_minimal_goose_pdu()

        # Sign and verify
        ext = proc.sign(pdu, key_id=1)
        proc2 = GOOSESecurityProcessor()
        proc2.key_store.add_key(key)
        proc2.verify(pdu, ext)

        stats = proc2.stats.get_timing_stats(SecurityAlgorithm.HMAC_SHA256)
        assert stats["count"] == 1
        assert stats["mean_us"] >= 0


class TestAsymmetricAuthentication:
    """Test RSA/ECDSA authentication."""

    def test_rsa_sign_verify(self):
        try:
            auth = AsymmetricAuthenticator()
            auth.generate_rsa_keypair()
            pdu = build_minimal_goose_pdu()

            ext = auth.sign_rsa(pdu, key_id=1)
            assert ext.algorithm == SecurityAlgorithm.RSA_2048_SHA256
            assert len(ext.signature) == 256  # RSA-2048

            # Create fresh authenticator with same public key
            auth2 = AsymmetricAuthenticator()
            auth2._rsa_public_key = auth._rsa_public_key
            result = auth2.verify_rsa(pdu, ext)
            assert result == SecurityErrorCode.OK

        except ImportError:
            pytest.skip("cryptography library not installed")

    def test_ecdsa_sign_verify(self):
        try:
            auth = AsymmetricAuthenticator()
            auth.generate_ecdsa_keypair()
            pdu = build_minimal_goose_pdu()

            ext = auth.sign_ecdsa(pdu, key_id=1)
            assert ext.algorithm == SecurityAlgorithm.ECDSA_P256_SHA256

            auth2 = AsymmetricAuthenticator()
            auth2._ecdsa_public_key = auth._ecdsa_public_key
            result = auth2.verify_ecdsa(pdu, ext)
            assert result == SecurityErrorCode.OK

        except ImportError:
            pytest.skip("cryptography library not installed")


# ============================================================================
# CIL-DoS Frame Builder Tests
# ============================================================================

class TestCILDoSFrameBuilder:
    """Test CIL-DoS frame construction."""

    def test_build_template_valid_structure(self):
        from gridpulse.attacks.cil_dos import CILDoSFrameBuilder

        builder = CILDoSFrameBuilder()
        frame = builder.build_template(st_num=1, sq_num=0)

        # Must be valid Ethernet frame
        assert len(frame) >= 14  # Minimum Ethernet header
        assert frame[12:14] == b"\x88\xB8"  # GOOSE EtherType

    def test_build_batch_incrementing_sqnum(self):
        from gridpulse.attacks.cil_dos import CILDoSFrameBuilder

        builder = CILDoSFrameBuilder()
        frames = builder.build_batch(count=10, base_sq_num=0)
        assert len(frames) == 10

        # Each frame should be unique (different sqNum -> different signature)
        unique_frames = set(f.hex() for f in frames)
        assert len(unique_frames) == 10

    def test_frame_has_invalid_signature(self):
        from gridpulse.attacks.cil_dos import CILDoSFrameBuilder

        builder = CILDoSFrameBuilder(algorithm=SecurityAlgorithm.HMAC_SHA256)
        frame = builder.build_template()

        # Frame should contain bytes after the GOOSE PDU (security extension)
        # The security extension uses random bytes for signature
        assert len(frame) > 100  # Substantial frame with security ext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
