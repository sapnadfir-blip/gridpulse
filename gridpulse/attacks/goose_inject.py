"""
GOOSE Frame Injector — Raw Socket Layer 2 Injection
====================================================

Injects crafted IEC 61850 GOOSE frames directly at Layer 2 using
Linux AF_PACKET raw sockets. Supports single-frame, burst, and
sustained injection modes with rate control.

Platform: Linux only (requires CAP_NET_RAW or root)
Reference: IEC 61850-8-1, IEEE 802.3

⚠️  This tool is for authorized security research on isolated test
    networks only. Unauthorized use against production ICS/SCADA
    systems is illegal and dangerous.
"""

from __future__ import annotations

import os
import platform
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from gridpulse.protocols.goose import GOOSEFrame, GOOSEPDU, EthernetHeader


# ============================================================================
# Constants
# ============================================================================

ETH_P_ALL = 0x0003
ETH_P_GOOSE = 0x88B8
GOOSE_MULTICAST_BASE = bytes([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x00])


# ============================================================================
# Injection Statistics
# ============================================================================

@dataclass
class InjectionStats:
    """Real-time injection statistics."""
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: float = 0.0
    last_send_time: float = 0.0

    @property
    def elapsed(self) -> float:
        """Elapsed time in seconds."""
        if self.start_time == 0:
            return 0.0
        return (self.last_send_time or time.monotonic()) - self.start_time

    @property
    def rate_pps(self) -> float:
        """Current packets per second rate."""
        elapsed = self.elapsed
        return self.packets_sent / elapsed if elapsed > 0 else 0.0

    @property
    def rate_mbps(self) -> float:
        """Current throughput in Mbps."""
        elapsed = self.elapsed
        return (self.bytes_sent * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0.0

    def __str__(self) -> str:
        return (
            f"InjectionStats(pkts={self.packets_sent}, "
            f"bytes={self.bytes_sent}, "
            f"rate={self.rate_pps:.0f} pps, "
            f"throughput={self.rate_mbps:.2f} Mbps, "
            f"errors={self.errors}, "
            f"elapsed={self.elapsed:.2f}s)"
        )


# ============================================================================
# GOOSE Frame Injector
# ============================================================================

class GOOSEInjector:
    """
    Layer 2 GOOSE frame injector using Linux AF_PACKET raw sockets.

    Sends crafted Ethernet frames directly to the network interface
    without any IP/TCP stack involvement. This is essential for GOOSE
    which operates at Layer 2 (EtherType 0x88B8).

    Usage:
        with GOOSEInjector("eth0") as injector:
            frame = GOOSEFrame(...)
            injector.send_frame(frame.build())
    """

    def __init__(
        self,
        interface: str,
        max_rate_pps: Optional[int] = None,
    ):
        """
        Initialize the GOOSE injector.

        Args:
            interface: Network interface name (e.g., "eth0", "enp0s3")
            max_rate_pps: Maximum packets per second (None = unlimited)

        Raises:
            RuntimeError: If not on Linux
            PermissionError: If lacking CAP_NET_RAW capability
        """
        if platform.system() != "Linux":
            raise RuntimeError(
                f"GOOSEInjector requires Linux (current: {platform.system()}). "
                "GOOSE injection uses AF_PACKET raw sockets which are "
                "Linux-specific. Use a Linux VM or container for testing."
            )

        self._interface = interface
        self._max_rate_pps = max_rate_pps
        self._socket: Optional[socket.socket] = None
        self._stats = InjectionStats()

        # Rate limiter state
        self._min_interval = 1.0 / max_rate_pps if max_rate_pps else 0
        self._last_send_ns = 0

        self._open_socket()

    def _open_socket(self) -> None:
        """Open a raw AF_PACKET socket bound to the interface."""
        try:
            self._socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_ALL),
            )
            self._socket.bind((self._interface, 0))
        except PermissionError:
            raise PermissionError(
                "Raw socket requires root or CAP_NET_RAW capability. "
                "Run with: sudo python -m gridpulse inject ..."
            )
        except OSError as e:
            raise OSError(
                f"Failed to bind to interface '{self._interface}': {e}. "
                "Check that the interface exists: ip link show"
            )

    def send_frame(self, frame_bytes: bytes) -> int:
        """
        Send a raw Ethernet frame.

        Args:
            frame_bytes: Complete Ethernet frame including header

        Returns:
            Number of bytes sent

        Raises:
            RuntimeError: If socket is closed
        """
        if self._socket is None:
            raise RuntimeError("Injector socket is closed")

        # Rate limiting
        if self._min_interval > 0:
            now = time.monotonic_ns()
            elapsed_ns = now - self._last_send_ns
            wait_ns = int(self._min_interval * 1e9) - elapsed_ns
            if wait_ns > 0:
                time.sleep(wait_ns / 1e9)
            self._last_send_ns = time.monotonic_ns()

        try:
            sent = self._socket.send(frame_bytes)
            self._stats.packets_sent += 1
            self._stats.bytes_sent += sent
            self._stats.last_send_time = time.monotonic()
            if self._stats.start_time == 0:
                self._stats.start_time = time.monotonic()
            return sent
        except OSError as e:
            self._stats.errors += 1
            raise OSError(f"Send failed: {e}")

    def send_goose(
        self,
        frame: GOOSEFrame,
    ) -> int:
        """
        Build and send a GOOSEFrame object.

        Args:
            frame: GOOSEFrame instance to send

        Returns:
            Number of bytes sent
        """
        return self.send_frame(frame.build())

    def send_burst(
        self,
        frame_bytes: bytes,
        count: int,
        delay_us: float = 0,
    ) -> InjectionStats:
        """
        Send a burst of identical frames.

        Args:
            frame_bytes: Frame to send repeatedly
            count: Number of frames to send
            delay_us: Delay between frames in microseconds

        Returns:
            InjectionStats for this burst
        """
        burst_stats = InjectionStats(start_time=time.monotonic())
        delay_sec = delay_us / 1_000_000 if delay_us > 0 else 0

        for i in range(count):
            try:
                sent = self.send_frame(frame_bytes)
                burst_stats.packets_sent += 1
                burst_stats.bytes_sent += sent
            except OSError:
                burst_stats.errors += 1

            if delay_sec > 0 and i < count - 1:
                time.sleep(delay_sec)

        burst_stats.last_send_time = time.monotonic()
        return burst_stats

    @property
    def stats(self) -> InjectionStats:
        """Get cumulative injection statistics."""
        return self._stats

    def reset_stats(self) -> None:
        """Reset injection statistics."""
        self._stats = InjectionStats()

    def close(self) -> None:
        """Close the raw socket."""
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def __enter__(self) -> 'GOOSEInjector':
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


# ============================================================================
# GOOSE Frame Listener (for capture/monitoring)
# ============================================================================

class GOOSEListener:
    """
    Passive GOOSE frame listener using AF_PACKET.

    Captures GOOSE frames from the network for analysis, replay,
    or IDS monitoring.
    """

    def __init__(self, interface: str):
        if platform.system() != "Linux":
            raise RuntimeError(
                f"GOOSEListener requires Linux (current: {platform.system()})."
            )

        self._interface = interface
        self._socket: Optional[socket.socket] = None
        self._open_socket()

    def _open_socket(self) -> None:
        """Open a raw socket filtered for GOOSE frames."""
        try:
            self._socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_GOOSE),
            )
            self._socket.bind((self._interface, 0))
        except PermissionError:
            raise PermissionError(
                "Raw socket requires root or CAP_NET_RAW. "
                "Run with: sudo python -m gridpulse ..."
            )

    def recv_frame(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Receive a single GOOSE frame.

        Args:
            timeout: Receive timeout in seconds (None = blocking)

        Returns:
            Raw frame bytes or None on timeout
        """
        if self._socket is None:
            raise RuntimeError("Listener socket is closed")

        if timeout is not None:
            self._socket.settimeout(timeout)

        try:
            data, addr = self._socket.recvfrom(65535)
            return data
        except socket.timeout:
            return None

    def recv_parsed(
        self,
        timeout: Optional[float] = None,
    ) -> Optional[GOOSEFrame]:
        """Receive and parse a GOOSE frame."""
        raw = self.recv_frame(timeout)
        if raw is None:
            return None
        try:
            return GOOSEFrame.parse(raw)
        except Exception:
            return None

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def __enter__(self) -> 'GOOSEListener':
        return self

    def __exit__(self, *args) -> None:
        self.close()


if __name__ == "__main__":
    print("GridPulse GOOSE Injector")
    print("=" * 50)
    print(f"Platform: {platform.system()}")
    if platform.system() != "Linux":
        print("⚠️  This module requires Linux with AF_PACKET support.")
        print("   Use a Linux VM or container for testing.")
    else:
        print("✓ Linux detected. Raw socket injection available.")
        print("  Usage: sudo python -m gridpulse inject --interface eth0")
