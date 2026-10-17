import threading
import time
import json
from dataclasses import dataclass
from typing import Callable, Optional
from .message_bus import BusPort

@dataclass
class RelayProfile:
    name: str                    # e.g., "High-Performance Relay"
    cpu_class: str               # e.g., "ARM Cortex-A9"
    verify_latency_us: float     # Signature verification time
    parse_latency_us: float      # GOOSE PDU parse time
    logic_latency_us: float      # Protection logic evaluation
    output_latency_us: float     # Relay output actuation

RELAY_PROFILES = {
    "high_performance": RelayProfile("High-Performance Relay", "ARM Cortex-A9 @ 800MHz", 845.0, 5.0, 10.0, 50.0),
    "mid_range": RelayProfile("Mid-Range Relay", "ARM Cortex-R5 @ 600MHz", 2704.0, 15.0, 25.0, 100.0),
    "resource_constrained": RelayProfile("Resource-Constrained Relay", "ARM Cortex-M4 @ 168MHz", 10142.0, 50.0, 80.0, 200.0),
    "gateway": RelayProfile("Substation Gateway", "Intel Atom E3800 @ 1.9GHz", 270.0, 2.0, 5.0, 20.0),
    "desktop_test": RelayProfile("Desktop Test (Apple M2)", "Apple M2 @ 3.49GHz", 33.5, 0.5, 1.0, 5.0),
}

@dataclass
class PipelineMetrics:
    receive_time_ns: int
    parse_us: float
    verify_us: float
    logic_us: float
    output_us: float
    total_us: float
    deadline_met: bool
    frame_valid: bool

class GOOSEPublisher:
    """Emulates a GOOSE Publisher transmitting IEC 61850 frames."""
    def __init__(self, node_id: str, bus_port: BusPort, gocb_ref: str, dat_set: str, profile: RelayProfile):
        self.node_id = node_id
        self.bus_port = bus_port
        self.gocb_ref = gocb_ref
        self.dat_set = dat_set
        self.profile = profile
        
        self.stNum = 1
        self.sqNum = 0
        self.is_trip = False
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._event = threading.Event()
        
        self.frames_published = 0
        self.trips_sent = 0
        
        # Retransmission timings (ms)
        self.T0 = 1
        self.TMax = 1000
        self.current_t = self.TMax

    def _simulate_computation(self, latency_us: float):
        if latency_us > 0:
            time.sleep(latency_us / 1_000_000.0)

    def _publish_loop(self):
        while self._running:
            # Create a simple JSON representation of a GOOSE frame for emulation
            frame = {
                "gocb_ref": self.gocb_ref,
                "dat_set": self.dat_set,
                "stNum": self.stNum,
                "sqNum": self.sqNum,
                "trip": self.is_trip,
                "signature": "RSA2048-VALID" # Simplified for simulation
            }
            
            frame_bytes = json.dumps(frame).encode('utf-8')
            
            # Simulate signature creation
            self._simulate_computation(self.profile.verify_latency_us)
            
            self.bus_port.send(frame_bytes)
            self.frames_published += 1
            if self.is_trip:
                self.trips_sent += 1
                
            self.sqNum += 1
            
            # Wait for next transmission or state change
            wait_time = self.current_t / 1000.0
            triggered = self._event.wait(wait_time)
            
            if triggered:
                self._event.clear()
            else:
                # Double the retransmission time up to TMax
                if self.current_t < self.TMax:
                    self.current_t = min(self.current_t * 2, self.TMax)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._publish_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._event.set()
        if self._thread:
            self._thread.join(timeout=1.0)

    def trigger_trip(self):
        """Simulate a trip event (stNum++, burst retransmit)."""
        self.stNum += 1
        self.sqNum = 0
        self.is_trip = True
        self.current_t = self.T0
        self._event.set()

    def trigger_normal(self):
        """Return to normal state."""
        self.stNum += 1
        self.sqNum = 0
        self.is_trip = False
        self.current_t = self.T0
        self._event.set()

class GOOSESubscriber:
    """Emulates an IEC 61850 IED receiving and processing GOOSE frames."""
    def __init__(self, node_id: str, bus_port: BusPort, profile: RelayProfile, verification_enabled: bool = True):
        self.node_id = node_id
        self.bus_port = bus_port
        self.profile = profile
        self.verification_enabled = verification_enabled
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        self.metrics_history: List[PipelineMetrics] = []
        
        self._on_trip_callback: Optional[Callable] = None
        self._on_deadline_callback: Optional[Callable] = None
        self._on_invalid_callback: Optional[Callable] = None
        
        self.expected_stNum = 0
        self.expected_sqNum = 0

    def on_trip_received(self, callback: Callable):
        self._on_trip_callback = callback

    def on_deadline_missed(self, callback: Callable):
        self._on_deadline_callback = callback

    def on_invalid_frame(self, callback: Callable):
        self._on_invalid_callback = callback

    def _simulate_computation(self, latency_us: float):
        if latency_us > 0:
            time.sleep(latency_us / 1_000_000.0)

    def _process_frame(self, frame_bytes: bytes):
        receive_time_ns = time.perf_counter_ns()
        
        # 1. Parse
        start = time.perf_counter_ns()
        self._simulate_computation(self.profile.parse_latency_us)
        try:
            frame = json.loads(frame_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            return # Drop invalid format
        parse_us = (time.perf_counter_ns() - start) / 1000.0
        
        # 2. Verify
        start = time.perf_counter_ns()
        frame_valid = True
        if self.verification_enabled:
            self._simulate_computation(self.profile.verify_latency_us)
            if frame.get("signature") != "RSA2048-VALID":
                frame_valid = False
                if self._on_invalid_callback:
                    self._on_invalid_callback()
        verify_us = (time.perf_counter_ns() - start) / 1000.0
        
        if not frame_valid:
            return
            
        # 3. Logic
        start = time.perf_counter_ns()
        self._simulate_computation(self.profile.logic_latency_us)
        is_trip = frame.get("trip", False)
        logic_us = (time.perf_counter_ns() - start) / 1000.0
        
        # 4. Output
        start = time.perf_counter_ns()
        if is_trip:
            self._simulate_computation(self.profile.output_latency_us)
            if self._on_trip_callback:
                self._on_trip_callback()
        output_us = (time.perf_counter_ns() - start) / 1000.0
        
        total_us = parse_us + verify_us + logic_us + output_us
        deadline_met = total_us < 3000.0 # 3ms standard deadline
        
        if not deadline_met and self._on_deadline_callback:
            self._on_deadline_callback()
            
        metric = PipelineMetrics(
            receive_time_ns=receive_time_ns,
            parse_us=parse_us,
            verify_us=verify_us,
            logic_us=logic_us,
            output_us=output_us,
            total_us=total_us,
            deadline_met=deadline_met,
            frame_valid=frame_valid
        )
        
        self.metrics_history.append(metric)
        if len(self.metrics_history) > 1000:
            self.metrics_history.pop(0)

    def _receive_loop(self):
        while self._running:
            frame_bytes = self.bus_port.receive(timeout=0.1)
            if frame_bytes:
                self._process_frame(frame_bytes)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._receive_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def get_latency_stats(self) -> dict:
        if not self.metrics_history:
            return {"mean": 0, "p95": 0, "p99": 0, "miss_ratio": 0.0}
            
        latencies = sorted([m.total_us for m in self.metrics_history])
        misses = sum(1 for m in self.metrics_history if not m.deadline_met)
        
        def p(percentile):
            idx = int(len(latencies) * percentile)
            return latencies[min(idx, len(latencies)-1)]
            
        return {
            "mean": sum(latencies) / len(latencies),
            "p95": p(0.95),
            "p99": p(0.99),
            "miss_ratio": misses / len(self.metrics_history)
        }

class AttackerNode:
    """Emulates a compromised node injecting CIL-DoS attacks."""
    def __init__(self, node_id: str, bus_port: BusPort, algorithm: str = "flood"):
        self.node_id = node_id
        self.bus_port = bus_port
        self.algorithm = algorithm
        self.frames_sent = 0
        self.current_rate = 0.0
        self.elapsed_time = 0.0
        
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start_flood(self, rate_pps: float, duration: float):
        """Send CIL-DoS frames through bus."""
        self._running = True
        self.current_rate = rate_pps
        
        def flood():
            start_time = time.time()
            end_time = start_time + duration
            delay = 1.0 / rate_pps if rate_pps > 0 else 0
            
            frame = {"gocb_ref": "ATTACK", "dat_set": "ATTACK", "trip": False, "signature": "INVALID"}
            frame_bytes = json.dumps(frame).encode('utf-8')
            
            while self._running and time.time() < end_time:
                self.bus_port.send(frame_bytes)
                self.frames_sent += 1
                self.elapsed_time = time.time() - start_time
                if delay > 0:
                    time.sleep(delay)
            self._running = False
            self.current_rate = 0.0
            
        self._thread = threading.Thread(target=flood, daemon=True)
        self._thread.start()

    def stop_flood(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def ramp_up(self, start_rate: float, end_rate: float, ramp_duration: float):
        """Gradually increase attack rate."""
        self._running = True
        
        def ramp():
            start_time = time.time()
            frame = {"gocb_ref": "ATTACK", "dat_set": "ATTACK", "trip": False, "signature": "INVALID"}
            frame_bytes = json.dumps(frame).encode('utf-8')
            
            while self._running:
                now = time.time()
                elapsed = now - start_time
                if elapsed > ramp_duration:
                    self.current_rate = end_rate
                else:
                    self.current_rate = start_rate + (end_rate - start_rate) * (elapsed / ramp_duration)
                
                self.elapsed_time = elapsed
                self.bus_port.send(frame_bytes)
                self.frames_sent += 1
                
                if self.current_rate > 0:
                    time.sleep(1.0 / self.current_rate)
                else:
                    time.sleep(0.1)
                    
        self._thread = threading.Thread(target=ramp, daemon=True)
        self._thread.start()
