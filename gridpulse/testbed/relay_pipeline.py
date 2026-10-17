import time
import json
import threading
from queue import Queue
from dataclasses import dataclass, field
from typing import Dict, List
from .ied import RelayProfile

@dataclass
class PipelineResult:
    stage_timings: Dict[str, float]
    total_us: float
    queue_depth_at_arrival: int
    queue_wait_us: float
    deadline_met: bool
    frame_type: str  # "legitimate" / "attack" / "unknown"
    action_taken: str  # "trip_executed" / "normal" / "dropped"

@dataclass
class PipelineStats:
    total_processed: int = 0
    total_deadline_misses: int = 0
    mean_total_us: float = 0.0
    p95_total_us: float = 0.0
    p99_total_us: float = 0.0
    legitimate_frames: int = 0
    attack_frames: int = 0
    queue_depth_histogram: Dict[int, int] = field(default_factory=dict)
    
class VerificationQueue:
    """Thread-safe queue of frames waiting for signature verification."""
    def __init__(self, profile: RelayProfile):
        self.profile = profile
        self._queue = Queue()
        self._lock = threading.Lock()
        self._processing_time_us = profile.verify_latency_us

    def enqueue(self, frame_data: dict) -> int:
        """Add to queue and return the depth at arrival."""
        depth = self._queue.qsize()
        self._queue.put(frame_data)
        return depth
        
    def get_wait_time_us(self, depth: int) -> float:
        """Calculate wait time based on queue depth."""
        return depth * self._processing_time_us

class RelayPipeline:
    """Detailed pipeline simulation with per-stage timing."""
    def __init__(self, profile: RelayProfile):
        self.profile = profile
        self.verification_queue = VerificationQueue(profile)
        self.results_history: List[PipelineResult] = []
        self._lock = threading.Lock()

    def process_frame(self, raw_bytes: bytes) -> PipelineResult:
        stage_timings = {}
        
        # 1. Parse Stage
        start_ns = time.perf_counter_ns()
        time.sleep(self.profile.parse_latency_us / 1_000_000.0)
        try:
            frame = json.loads(raw_bytes.decode('utf-8'))
            frame_type = "legitimate" if frame.get("signature") == "RSA2048-VALID" else "attack"
        except Exception:
            frame = {}
            frame_type = "unknown"
        stage_timings['parse'] = (time.perf_counter_ns() - start_ns) / 1000.0

        # 2. Queueing & Verification Stage (The CIL-DoS Mechanism)
        queue_depth = self.verification_queue.enqueue(frame)
        queue_wait_us = self.verification_queue.get_wait_time_us(queue_depth)
        
        # Simulate the wait time caused by queue backlog
        if queue_wait_us > 0:
            time.sleep(queue_wait_us / 1_000_000.0)
            
        start_ns = time.perf_counter_ns()
        # Simulate the actual verification of this frame
        time.sleep(self.profile.verify_latency_us / 1_000_000.0)
        self.verification_queue._queue.get() # Dequeue
        stage_timings['verify'] = (time.perf_counter_ns() - start_ns) / 1000.0

        # 3. Logic Stage
        start_ns = time.perf_counter_ns()
        action_taken = "dropped"
        if frame_type == "legitimate":
            time.sleep(self.profile.logic_latency_us / 1_000_000.0)
            if frame.get("trip"):
                action_taken = "trip_executed"
            else:
                action_taken = "normal"
        stage_timings['logic'] = (time.perf_counter_ns() - start_ns) / 1000.0

        # 4. Output Stage
        start_ns = time.perf_counter_ns()
        if action_taken == "trip_executed":
            time.sleep(self.profile.output_latency_us / 1_000_000.0)
        stage_timings['output'] = (time.perf_counter_ns() - start_ns) / 1000.0

        total_us = sum(stage_timings.values()) + queue_wait_us
        deadline_met = total_us < 3000.0

        result = PipelineResult(
            stage_timings=stage_timings,
            total_us=total_us,
            queue_depth_at_arrival=queue_depth,
            queue_wait_us=queue_wait_us,
            deadline_met=deadline_met,
            frame_type=frame_type,
            action_taken=action_taken
        )
        
        with self._lock:
            self.results_history.append(result)
            if len(self.results_history) > 1000:
                self.results_history.pop(0)
                
        return result

    def get_stats(self) -> PipelineStats:
        with self._lock:
            if not self.results_history:
                return PipelineStats()
                
            stats = PipelineStats()
            stats.total_processed = len(self.results_history)
            
            latencies = sorted([r.total_us for r in self.results_history])
            stats.mean_total_us = sum(latencies) / len(latencies)
            
            def p(percentile):
                idx = int(len(latencies) * percentile)
                return latencies[min(idx, len(latencies)-1)]
                
            stats.p95_total_us = p(0.95)
            stats.p99_total_us = p(0.99)
            
            for r in self.results_history:
                if not r.deadline_met:
                    stats.total_deadline_misses += 1
                if r.frame_type == "legitimate":
                    stats.legitimate_frames += 1
                elif r.frame_type == "attack":
                    stats.attack_frames += 1
                    
                depth = r.queue_depth_at_arrival
                stats.queue_depth_histogram[depth] = stats.queue_depth_histogram.get(depth, 0) + 1
                
            return stats
