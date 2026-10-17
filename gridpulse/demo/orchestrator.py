"""
GridPulse Live Demo Orchestrator
==================================

  "When Cryptography Becomes the Attack Surface"

Scripted 6-phase demonstration for Black Hat Briefings.
Runs a complete substation emulation with real GOOSE traffic,
CIL-DoS attack, and eBPF/XDP defense — all in software.

Demo Timeline (~3.5 minutes):
    Phase 0: OVERVIEW        (15s)  System introduction
    Phase 1: BASELINE        (30s)  Normal operation, healthy latency
    Phase 2: RECONNAISSANCE  (15s)  Attacker probing the network
    Phase 3: ATTACK_RAMP     (30s)  Gradual CIL-DoS ramp-up
    Phase 4: FULL_ATTACK     (30s)  Full flood, deadline violations
    Phase 5: DEFENSE         (30s)  XDP defense enabled, recovery
    Phase 6: ESCALATION      (30s)  Attacker increases rate, XDP holds

Usage:
    python -m gridpulse.demo.orchestrator                    # Scripted (default)
    python -m gridpulse.demo.orchestrator --interactive      # Manual control
    python -m gridpulse.demo.orchestrator --headless         # No UI (testing)

⚠️  For authorized security research demonstration only.
"""

from __future__ import annotations

import json
import os
import sys
import struct
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Optional


# ============================================================================
# Demo Phase Definitions
# ============================================================================

class DemoPhase(Enum):
    OVERVIEW = auto()
    BASELINE = auto()
    RECON = auto()
    ATTACK_RAMP = auto()
    FULL_ATTACK = auto()
    DEFENSE = auto()
    ESCALATION = auto()
    COMPLETE = auto()


@dataclass
class PhaseConfig:
    """Configuration for a single demo phase."""
    phase: DemoPhase
    name: str
    duration_seconds: float
    description: str
    attack_rate_pps: float = 0.0
    attack_ramp_to: float = 0.0        # For ramp phase
    defense_enabled: bool = False
    defense_rate_limit: int = 0
    narrative: list[str] = field(default_factory=list)


DEFAULT_TIMELINE: list[PhaseConfig] = [
    PhaseConfig(
        phase=DemoPhase.OVERVIEW,
        name="SYSTEM OVERVIEW",
        duration_seconds=15,
        description="Introducing the substation architecture",
        narrative=[
            "IEC 61850 substation with GOOSE protection messaging",
            "Publisher relay → Subscriber relay over Ethernet LAN",
            "All messages signed with IEC 62351-6 (RSA-2048)",
            "Protection deadline: 3ms from event to relay decision",
        ],
    ),
    PhaseConfig(
        phase=DemoPhase.BASELINE,
        name="BASELINE OPERATION",
        duration_seconds=30,
        description="Normal substation operation — all healthy",
        narrative=[
            "Publisher sending heartbeat GOOSE every 1000ms",
            "Trip commands arrive and verify within ~0.9ms",
            "All protection deadlines met ✅",
            "Verification queue: empty",
        ],
    ),
    PhaseConfig(
        phase=DemoPhase.RECON,
        name="RECONNAISSANCE",
        duration_seconds=15,
        description="Attacker observes traffic, learns publisher state",
        attack_rate_pps=10,
        narrative=[
            "⚠ Attacker connected to substation LAN",
            "Observing GOOSE traffic: gocbRef, stNum, confRev",
            "Learning publisher MAC and frame structure",
            "Preparing CIL-DoS payload...",
        ],
    ),
    PhaseConfig(
        phase=DemoPhase.ATTACK_RAMP,
        name="CIL-DoS RAMP-UP",
        duration_seconds=30,
        description="Gradual flood with invalid cryptographic signatures",
        attack_rate_pps=500,
        attack_ramp_to=15000,
        narrative=[
            "🔴 CIL-DoS attack beginning — 500 pps",
            "Structurally valid GOOSE, INVALID RSA signatures",
            "Each packet forces expensive verification before rejection",
            "Watch the latency climb...",
        ],
    ),
    PhaseConfig(
        phase=DemoPhase.FULL_ATTACK,
        name="FULL ATTACK — PROTECTION FAILURE",
        duration_seconds=30,
        description="Verification queue saturated, deadlines missed",
        attack_rate_pps=25000,
        narrative=[
            "🔴 CRITICAL: Verification queue saturated",
            "Legitimate trip commands delayed beyond 3ms deadline",
            "Protection relay CANNOT respond in time",
            "Physical equipment at risk",
        ],
    ),
    PhaseConfig(
        phase=DemoPhase.DEFENSE,
        name="XDP DEFENSE ACTIVATED",
        duration_seconds=30,
        description="eBPF/XDP filter drops attack traffic at NIC",
        attack_rate_pps=25000,
        defense_enabled=True,
        defense_rate_limit=500,
        narrative=[
            "🟢 XDP defense attached to NIC driver",
            "Filtering BEFORE packets reach verification queue",
            "MAC allowlist + rate limiter at 500/src/sec",
            "Latency returning to baseline...",
        ],
    ),
    PhaseConfig(
        phase=DemoPhase.ESCALATION,
        name="ATTACKER ESCALATION — XDP HOLDS",
        duration_seconds=30,
        description="Attacker increases to 100K pps, XDP still holds",
        attack_rate_pps=100000,
        defense_enabled=True,
        defense_rate_limit=500,
        narrative=[
            "Attacker escalates to 100,000 pps",
            "XDP processing at wire speed — dropping 99.5%",
            "Verification queue remains healthy",
            "All protection deadlines met ✅",
        ],
    ),
]


# ============================================================================
# Demo Event System
# ============================================================================

@dataclass
class DemoEvent:
    """A timestamped event during the demo."""
    timestamp: float          # Monotonic clock
    wall_time: str            # ISO format
    phase: str
    event_type: str           # "phase_start", "metric", "packet", "alert", "narrative"
    data: dict = field(default_factory=dict)


class DemoEventBus:
    """Thread-safe event bus for demo components."""

    def __init__(self):
        self._listeners: list[Callable[[DemoEvent], None]] = []
        self._events: list[DemoEvent] = []
        self._lock = threading.Lock()

    def subscribe(self, callback: Callable[[DemoEvent], None]):
        with self._lock:
            self._listeners.append(callback)

    def emit(self, event: DemoEvent):
        with self._lock:
            self._events.append(event)
            for listener in self._listeners:
                try:
                    listener(event)
                except Exception:
                    pass

    def get_history(self) -> list[DemoEvent]:
        with self._lock:
            return list(self._events)


# ============================================================================
# Simulated Verification Queue (Core CIL-DoS Mechanism)
# ============================================================================

class VerificationQueue:
    """
    Models the cryptographic verification queue in a protection relay.

    Uses the M/M/1 queueing model to compute realistic wait times
    based on the current arrival rate and service rate, rather than
    simulating individual packet processing with time.sleep().

    This correctly models queue buildup: when attack rate approaches
    the service rate (µ), wait times grow dramatically.
    """

    def __init__(self, verify_latency_us: float = 33.5):
        self.verify_latency_us = verify_latency_us
        self.service_rate = 1e6 / verify_latency_us  # µ in ops/sec
        self._current_arrival_rate = 0.0  # λ in pps (set by orchestrator)
        self._queue_depth = 0
        self._lock = threading.Lock()
        self._total_processed = 0
        self._total_legitimate = 0
        self._total_attack = 0

    def set_arrival_rate(self, rate_pps: float):
        """Set the current total arrival rate (attack + legitimate)."""
        with self._lock:
            self._current_arrival_rate = rate_pps

    def compute_latency(self, is_legitimate: bool = False) -> float:
        """
        Compute the expected total processing time for a frame (µs).

        Uses M/M/1: E[T] = 1/(µ-λ) when λ < µ, else ∞ (saturated)
        Returns: verify_latency + queue_wait in microseconds.
        """
        with self._lock:
            self._total_processed += 1
            if is_legitimate:
                self._total_legitimate += 1
            else:
                self._total_attack += 1

            lam = self._current_arrival_rate
            mu = self.service_rate
            rho = lam / mu if mu > 0 else 0

            # Model queue depth as E[N] = ρ/(1-ρ)
            if rho < 1.0:
                self._queue_depth = int(rho / (1 - rho))
                # M/M/1 mean wait: ρ/(µ(1-ρ)) in seconds → convert to µs
                queue_wait_us = (rho / (mu * (1 - rho))) * 1e6
            else:
                # Saturated — queue grows unbounded
                self._queue_depth = int(lam * 0.001)  # visual cue
                queue_wait_us = 50000  # Cap at 50ms for display

            total_us = self.verify_latency_us + queue_wait_us
            return total_us

    def get_depth(self) -> int:
        with self._lock:
            return self._queue_depth

    def get_utilization(self) -> float:
        with self._lock:
            lam = self._current_arrival_rate
            mu = self.service_rate
            return lam / mu if mu > 0 else 0

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "queue_depth": self._queue_depth,
                "total_processed": self._total_processed,
                "total_legitimate": self._total_legitimate,
                "total_attack": self._total_attack,
            }

    def reset(self):
        with self._lock:
            self._queue_depth = 0
            self._current_arrival_rate = 0.0



# ============================================================================
# Simulated XDP Defense
# ============================================================================

class SimulatedXDPDefense:
    """
    Software simulation of eBPF/XDP filtering.

    Models the actual XDP behavior:
    packets_received → inspect → drop/forward → packets_forwarded
    """

    def __init__(self):
        self.enabled = False
        self.rate_limit_pps = 500
        self.allowed_macs: set[str] = set()
        self._stats_lock = threading.Lock()
        self._received = 0
        self._inspected = 0
        self._dropped_mac = 0
        self._dropped_rate = 0
        self._forwarded = 0
        self._rate_counters: dict[str, list[float]] = {}
        self._window_sec = 1.0

    def enable(self, rate_limit: int = 500, allowed_macs: list[str] | None = None):
        self.enabled = True
        self.rate_limit_pps = rate_limit
        if allowed_macs:
            self.allowed_macs = set(allowed_macs)

    def disable(self):
        self.enabled = False

    def process(self, src_mac: str, is_from_attacker: bool) -> bool:
        """
        Process a packet through XDP. Returns True if forwarded, False if dropped.
        """
        if not self.enabled:
            return True

        with self._stats_lock:
            self._received += 1
            self._inspected += 1

            # MAC filter check
            if self.allowed_macs and src_mac not in self.allowed_macs:
                self._dropped_mac += 1
                return False

            # Rate limit check
            now = time.monotonic()
            if src_mac not in self._rate_counters:
                self._rate_counters[src_mac] = []

            timestamps = self._rate_counters[src_mac]
            # Clean old entries
            cutoff = now - self._window_sec
            self._rate_counters[src_mac] = [t for t in timestamps if t > cutoff]
            timestamps = self._rate_counters[src_mac]

            if len(timestamps) >= self.rate_limit_pps:
                self._dropped_rate += 1
                return False

            timestamps.append(now)
            self._forwarded += 1
            return True

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            total_dropped = self._dropped_mac + self._dropped_rate
            return {
                "received": self._received,
                "inspected": self._inspected,
                "dropped_total": total_dropped,
                "dropped_mac": self._dropped_mac,
                "dropped_rate": self._dropped_rate,
                "forwarded": self._forwarded,
                "drop_ratio": total_dropped / max(self._received, 1),
            }

    def reset(self):
        with self._stats_lock:
            self._received = 0
            self._inspected = 0
            self._dropped_mac = 0
            self._dropped_rate = 0
            self._forwarded = 0
            self._rate_counters.clear()


# ============================================================================
# Demo Metrics Collector
# ============================================================================

@dataclass
class DemoSnapshot:
    """A single point-in-time snapshot of demo state."""
    timestamp: float
    phase: str
    elapsed_seconds: float

    # Legitimate traffic metrics
    legit_latency_us: float        # Current legitimate frame latency
    legit_latency_mean_us: float   # Rolling mean
    legit_latency_p99_us: float    # Rolling p99
    deadline_met: bool
    deadline_miss_count: int
    deadline_miss_ratio: float

    # Attack metrics
    attack_rate_pps: float
    attack_frames_total: int

    # Queue metrics
    queue_depth: int
    queue_utilization: float       # ρ = λ/µ

    # Defense metrics
    defense_enabled: bool
    xdp_received: int
    xdp_dropped: int
    xdp_forwarded: int
    xdp_drop_ratio: float

    # Publisher/subscriber state
    publisher_stnum: int
    subscriber_last_stnum: int
    relay_status: str              # "HEALTHY", "DEGRADED", "CRITICAL", "PROTECTED"

    # Last packet details (for protocol field display)
    last_packet: Optional[dict] = None


class MetricsCollector:
    """Collects and stores demo metrics over time."""

    def __init__(self, max_history: int = 10000):
        self._snapshots: list[DemoSnapshot] = []
        self._latencies: list[float] = []
        self._deadline_misses = 0
        self._total_legit = 0
        self._lock = threading.Lock()
        self._max_history = max_history

    def record_latency(self, latency_us: float, deadline_us: float = 3000.0):
        with self._lock:
            self._latencies.append(latency_us)
            self._total_legit += 1
            if latency_us > deadline_us:
                self._deadline_misses += 1
            # Keep bounded
            if len(self._latencies) > self._max_history:
                self._latencies = self._latencies[-self._max_history:]

    def get_latency_stats(self, window: int = 50) -> dict:
        with self._lock:
            recent = self._latencies[-window:] if self._latencies else [0]
            sorted_recent = sorted(recent)
            n = len(sorted_recent)
            return {
                "current": recent[-1] if recent else 0,
                "mean": sum(recent) / n,
                "p95": sorted_recent[int(n * 0.95)] if n >= 20 else sorted_recent[-1],
                "p99": sorted_recent[int(n * 0.99)] if n >= 100 else sorted_recent[-1],
                "min": sorted_recent[0],
                "max": sorted_recent[-1],
                "deadline_misses": self._deadline_misses,
                "total_legit": self._total_legit,
                "miss_ratio": self._deadline_misses / max(self._total_legit, 1),
            }

    def add_snapshot(self, snapshot: DemoSnapshot):
        with self._lock:
            self._snapshots.append(snapshot)

    def get_snapshots(self) -> list[DemoSnapshot]:
        with self._lock:
            return list(self._snapshots)

    def reset(self):
        with self._lock:
            self._snapshots.clear()
            self._latencies.clear()
            self._deadline_misses = 0
            self._total_legit = 0


# ============================================================================
# Demo Orchestrator
# ============================================================================

class DemoOrchestrator:
    """
    Orchestrates the complete Black Hat demo.

    Controls the timeline, manages attack/defense state,
    collects metrics, and drives the dashboard.
    """

    def __init__(
        self,
        timeline: list[PhaseConfig] | None = None,
        relay_profile: str = "mid_range",
        interactive: bool = False,
        headless: bool = False,
    ):
        self.timeline = timeline or DEFAULT_TIMELINE
        self.interactive = interactive
        self.headless = headless

        # Set verify latency from relay profile
        from gridpulse.testbed.ied import RELAY_PROFILES
        profile = RELAY_PROFILES.get(relay_profile, RELAY_PROFILES["mid_range"])
        self._verify_latency = profile.verify_latency_us
        self._parse_latency = profile.parse_latency_us
        self._logic_latency = profile.logic_latency_us
        self._profile = profile

        # Components
        self.event_bus = DemoEventBus()
        self.metrics = MetricsCollector()
        self.verify_queue = VerificationQueue(self._verify_latency)
        self.xdp = SimulatedXDPDefense()

        # State
        self._current_phase: Optional[PhaseConfig] = None
        self._running = False
        self._stop_event = threading.Event()
        self._attack_thread: Optional[threading.Thread] = None
        self._legit_thread: Optional[threading.Thread] = None
        self._attack_rate = 0.0
        self._publisher_stnum = 0
        self._subscriber_stnum = 0
        self._attack_frames_total = 0

        # Dashboard callback
        self._dashboard_callback: Optional[Callable] = None

    def on_dashboard_update(self, callback: Callable[[DemoSnapshot], None]):
        """Register dashboard update callback."""
        self._dashboard_callback = callback

    def run(self):
        """Run the complete scripted demo."""
        self._running = True
        self._stop_event.clear()
        demo_start = time.monotonic()

        try:
            for phase_config in self.timeline:
                if self._stop_event.is_set():
                    break

                self._current_phase = phase_config
                self._run_phase(phase_config, demo_start)

            self._current_phase = PhaseConfig(
                phase=DemoPhase.COMPLETE,
                name="DEMO COMPLETE",
                duration_seconds=5,
                description="",
                narrative=["Demo concluded. All phases complete."],
            )

        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            self._stop_attack()

    def _run_phase(self, config: PhaseConfig, demo_start: float):
        """Run a single demo phase."""
        phase_start = time.monotonic()

        # Emit phase start event
        self.event_bus.emit(DemoEvent(
            timestamp=time.monotonic(),
            wall_time=time.strftime("%H:%M:%S"),
            phase=config.name,
            event_type="phase_start",
            data={"description": config.description, "duration": config.duration_seconds},
        ))

        # Configure attack
        if config.attack_rate_pps > 0:
            if config.attack_ramp_to > 0:
                self._start_ramp_attack(
                    config.attack_rate_pps,
                    config.attack_ramp_to,
                    config.duration_seconds,
                )
            else:
                self._start_attack(config.attack_rate_pps)
        else:
            self._stop_attack()

        # Configure defense
        if config.defense_enabled:
            self.xdp.enable(
                rate_limit=config.defense_rate_limit,
                allowed_macs=["08:00:27:aa:bb:cc"],  # Publisher MAC
            )
        else:
            self.xdp.disable()

        # Start legitimate traffic if not already running
        if self._legit_thread is None or not self._legit_thread.is_alive():
            self._start_legitimate_traffic()

        # Run for phase duration, collecting metrics
        if self.interactive and config.phase not in (DemoPhase.OVERVIEW, DemoPhase.COMPLETE):
            # Wait for user input
            if not self.headless:
                input(f"\n  Press ENTER to proceed from '{config.name}'...")
        else:
            elapsed = 0.0
            while elapsed < config.duration_seconds and not self._stop_event.is_set():
                time.sleep(0.1)
                elapsed = time.monotonic() - phase_start

                # Collect snapshot
                snapshot = self._collect_snapshot(demo_start, config)

                # Drive dashboard
                if self._dashboard_callback:
                    self._dashboard_callback(snapshot)
                self.metrics.add_snapshot(snapshot)

    def _start_legitimate_traffic(self):
        """Simulate legitimate GOOSE publisher sending periodic frames."""
        def _legit_worker():
            while not self._stop_event.is_set():
                self._publisher_stnum += 1

                # Build simulated legitimate frame metadata
                packet_info = {
                    "type": "legitimate",
                    "src_mac": "08:00:27:aa:bb:cc",
                    "dst_mac": "01:0c:cd:01:00:01",
                    "ethertype": "0x88B8",
                    "gocb_ref": "Sub1/LLN0$GO$ProtTrip",
                    "st_num": self._publisher_stnum,
                    "sq_num": 0,
                    "conf_rev": 1,
                    "signature": "RSA-2048 (VALID)",
                    "signature_status": "VALID ✅",
                }

                # Check XDP first
                forwarded = self.xdp.process("08:00:27:aa:bb:cc", is_from_attacker=False)
                if not forwarded:
                    continue  # Dropped (false positive)

                # Compute verification latency using M/M/1 model
                # The queue knows the current attack arrival rate
                total_latency = (
                    self._parse_latency +                        # Parse GOOSE PDU
                    self.verify_queue.compute_latency(True) +    # Signature verify (queued)
                    self._logic_latency                          # Protection logic
                )

                self._subscriber_stnum = self._publisher_stnum
                self.metrics.record_latency(total_latency)

                packet_info["total_latency_us"] = total_latency
                packet_info["queue_depth"] = self.verify_queue.get_depth()
                packet_info["deadline_met"] = total_latency < 3000

                self.event_bus.emit(DemoEvent(
                    timestamp=time.monotonic(),
                    wall_time=time.strftime("%H:%M:%S"),
                    phase=self._current_phase.name if self._current_phase else "",
                    event_type="packet",
                    data=packet_info,
                ))

                # Send legitimate frames every 200ms for demo visibility
                time.sleep(0.2)

        self._legit_thread = threading.Thread(target=_legit_worker, daemon=True)
        self._legit_thread.start()

    def _start_attack(self, rate_pps: float):
        """Start CIL-DoS flood at constant rate."""
        self._stop_attack()
        self._attack_rate = rate_pps
        # Update the queue's arrival rate for M/M/1 model
        self.verify_queue.set_arrival_rate(rate_pps)

        def _attack_worker():
            """Track attack frames and XDP drops at the claimed rate."""
            batch_interval = 0.1  # 100ms batches

            while not self._stop_event.is_set() and self._attack_rate > 0:
                # Calculate batch for this interval
                actual_batch = int(self._attack_rate * batch_interval)

                # Process XDP decisions for a sample of packets
                # (no need to individually process each — just track stats)
                sample_size = min(actual_batch, 100)
                for _ in range(sample_size):
                    src_mac = "de:ad:be:ef:00:01"
                    self.xdp.process(src_mac, is_from_attacker=True)

                self._attack_frames_total += actual_batch

                # Update queue arrival rate (accounts for XDP drops)
                xdp_stats = self.xdp.stats
                if self.xdp.enabled:
                    # Check if attacker MAC is in allowlist
                    attacker_mac = "de:ad:be:ef:00:01"
                    if self.xdp.allowed_macs and attacker_mac not in self.xdp.allowed_macs:
                        # MAC filter blocks all attack traffic → 0 effective rate
                        effective_rate = 0.0
                    elif xdp_stats["received"] > 0:
                        # Rate limiting: some packets pass, calculate ratio
                        # Use attacker-specific ratio (all sampled were attacker)
                        attacker_dropped = xdp_stats["dropped_mac"] + xdp_stats["dropped_rate"]
                        attacker_received = xdp_stats["received"]
                        effective_rate = max(0, self._attack_rate * (1 - attacker_dropped / attacker_received))
                    else:
                        effective_rate = self._attack_rate
                else:
                    effective_rate = self._attack_rate
                self.verify_queue.set_arrival_rate(effective_rate)

                time.sleep(batch_interval)

        self._attack_thread = threading.Thread(target=_attack_worker, daemon=True)
        self._attack_thread.start()

    def _start_ramp_attack(self, start_rate: float, end_rate: float, duration: float):
        """Start CIL-DoS with gradual ramp-up — the key narrative element."""
        self._stop_attack()
        self._attack_rate = start_rate

        def _ramp_worker():
            ramp_start = time.monotonic()
            batch_interval = 0.1

            while not self._stop_event.is_set():
                elapsed = time.monotonic() - ramp_start
                if elapsed >= duration:
                    break

                # Linear ramp: watching latency gradually climb
                progress = elapsed / duration
                self._attack_rate = start_rate + (end_rate - start_rate) * progress

                actual_batch = int(self._attack_rate * batch_interval)
                sample_size = min(actual_batch, 100)
                for _ in range(sample_size):
                    src_mac = "de:ad:be:ef:00:01"
                    self.xdp.process(src_mac, is_from_attacker=True)

                self._attack_frames_total += actual_batch

                # Update queue model with current ramp rate
                self.verify_queue.set_arrival_rate(self._attack_rate)

                time.sleep(batch_interval)

        self._attack_thread = threading.Thread(target=_ramp_worker, daemon=True)
        self._attack_thread.start()

    def _stop_attack(self):
        """Stop attack traffic."""
        self._attack_rate = 0
        self.verify_queue.set_arrival_rate(0)
        if self._attack_thread and self._attack_thread.is_alive():
            # Thread will exit when it checks _attack_rate
            self._attack_thread = None
        self.verify_queue.reset()

    def _collect_snapshot(self, demo_start: float, config: PhaseConfig) -> DemoSnapshot:
        """Collect current state as a snapshot."""
        latency_stats = self.metrics.get_latency_stats()
        xdp_stats = self.xdp.stats
        queue_stats = self.verify_queue.stats

        # Determine relay status
        miss_ratio = latency_stats["miss_ratio"]
        if config.defense_enabled and self.xdp.enabled:
            relay_status = "PROTECTED"
        elif miss_ratio > 0.5:
            relay_status = "CRITICAL"
        elif miss_ratio > 0.1:
            relay_status = "DEGRADED"
        else:
            relay_status = "HEALTHY"

        return DemoSnapshot(
            timestamp=time.monotonic(),
            phase=config.name,
            elapsed_seconds=time.monotonic() - demo_start,
            legit_latency_us=latency_stats["current"],
            legit_latency_mean_us=latency_stats["mean"],
            legit_latency_p99_us=latency_stats["p99"],
            deadline_met=latency_stats["current"] < 3000,
            deadline_miss_count=latency_stats["deadline_misses"],
            deadline_miss_ratio=miss_ratio,
            attack_rate_pps=self._attack_rate,
            attack_frames_total=self._attack_frames_total,
            queue_depth=queue_stats["queue_depth"],
            queue_utilization=self.verify_queue.get_utilization(),
            defense_enabled=self.xdp.enabled,
            xdp_received=xdp_stats["received"],
            xdp_dropped=xdp_stats["dropped_total"],
            xdp_forwarded=xdp_stats["forwarded"],
            xdp_drop_ratio=xdp_stats["drop_ratio"],
            publisher_stnum=self._publisher_stnum,
            subscriber_last_stnum=self._subscriber_stnum,
            relay_status=relay_status,
        )

    def stop(self):
        """Stop the demo."""
        self._stop_event.set()
        self._running = False

    def save_recording(self, path: str | Path):
        """Save demo recording to JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        snapshots = self.metrics.get_snapshots()
        events = self.event_bus.get_history()

        recording = {
            "title": "When Cryptography Becomes the Attack Surface",
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "relay_profile": self._profile.name,
            "verify_latency_us": self._verify_latency,
            "total_snapshots": len(snapshots),
            "total_events": len(events),
            "snapshots": [asdict(s) for s in snapshots],
        }

        with open(path, "w") as f:
            json.dump(recording, f, indent=2)


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="GridPulse Live Demo — 'When Cryptography Becomes the Attack Surface'"
    )
    parser.add_argument("--interactive", action="store_true",
                        help="Interactive mode (manual phase transitions)")
    parser.add_argument("--headless", action="store_true",
                        help="Headless mode (no dashboard, for testing)")
    parser.add_argument("--profile", default="mid_range",
                        choices=["high_performance", "mid_range", "resource_constrained",
                                 "gateway", "desktop_test"],
                        help="Relay profile to simulate")
    parser.add_argument("--save", type=str, default=None,
                        help="Save recording to file")
    args = parser.parse_args()

    orchestrator = DemoOrchestrator(
        interactive=args.interactive,
        headless=args.headless,
        relay_profile=args.profile,
    )

    if not args.headless:
        try:
            from gridpulse.demo.dashboard import DemoDashboard
            dashboard = DemoDashboard(orchestrator)
            dashboard.run()
        except ImportError:
            # Fallback to simple text output
            def simple_dashboard(snapshot: DemoSnapshot):
                status_icon = {
                    "HEALTHY": "🟢", "DEGRADED": "🟡",
                    "CRITICAL": "🔴", "PROTECTED": "🛡️",
                }.get(snapshot.relay_status, "⚪")

                print(
                    f"\r  {status_icon} {snapshot.phase:<30} │ "
                    f"Latency: {snapshot.legit_latency_us:>8.0f}µs │ "
                    f"Attack: {snapshot.attack_rate_pps:>8,.0f} pps │ "
                    f"Queue: {snapshot.queue_depth:>4} │ "
                    f"XDP Drop: {snapshot.xdp_drop_ratio:>5.1%} │ "
                    f"Misses: {snapshot.deadline_miss_count}",
                    end="", flush=True,
                )

            orchestrator.on_dashboard_update(simple_dashboard)
            print("\n  When Cryptography Becomes the Attack Surface")
            print("  " + "═" * 55)
            print()
            orchestrator.run()
    else:
        orchestrator.run()

    if args.save:
        orchestrator.save_recording(args.save)
        print(f"\n  Recording saved to {args.save}")

    print("\n\n  Demo complete.\n")


if __name__ == "__main__":
    main()
