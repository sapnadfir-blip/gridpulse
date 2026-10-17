import threading
import queue
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict

@dataclass
class BusStats:
    total_frames: int = 0
    total_bytes: int = 0
    frames_per_node: Dict[str, int] = field(default_factory=dict)

@dataclass
class XDPFilterConfig:
    allowed_macs: List[str]
    rate_limit_pps: int
    enable_sequence_check: bool

@dataclass
class XDPStats:
    received: int = 0
    dropped: int = 0
    forwarded: int = 0
    drop_by_mac: int = 0
    drop_by_rate: int = 0
    drop_by_sequence: int = 0

class BusPort:
    def __init__(self, node_id: str, bus: 'SoftwareBus'):
        self.node_id = node_id
        self._bus = bus
        self._queue = queue.Queue()

    def send(self, frame_bytes: bytes):
        """Sends a frame to the bus."""
        self._bus._broadcast(self.node_id, frame_bytes)

    def receive(self, timeout: float) -> Optional[bytes]:
        """Receives a frame from the bus, blocking up to timeout seconds."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

class LatencyInjector:
    def __init__(self, latency_sec: float = 0.0):
        self.latency_sec = latency_sec
        
    def delay(self):
        if self.latency_sec > 0:
            time.sleep(self.latency_sec)

class SoftwareBus:
    """A software-only message bus that emulates a substation Ethernet LAN."""
    
    def __init__(self):
        self._ports: Dict[str, BusPort] = {}
        self._lock = threading.Lock()
        self._stats = BusStats()
        self._xdp_config: Optional[XDPFilterConfig] = None
        self._xdp_stats = XDPStats()
        self.latency_injector = LatencyInjector()
        
        # Simple rate limiting state for XDP emulation
        self._last_packet_times: Dict[str, List[float]] = {}

    def connect(self, node_id: str) -> BusPort:
        """Register a node and return a BusPort for communication."""
        with self._lock:
            port = BusPort(node_id, self)
            self._ports[node_id] = port
            self._stats.frames_per_node[node_id] = 0
            return port

    def _apply_xdp_filter(self, sender_id: str, frame_bytes: bytes) -> bool:
        """Applies XDP filtering rules. Returns True if frame should be forwarded, False if dropped."""
        if not self._xdp_config:
            return True
            
        self._xdp_stats.received += 1
        
        # 1. MAC Filter (simplified by using node_id as MAC for emulation)
        if sender_id not in self._xdp_config.allowed_macs:
            self._xdp_stats.dropped += 1
            self._xdp_stats.drop_by_mac += 1
            return False
            
        # 2. Rate Limiting Filter
        now = time.time()
        if sender_id not in self._last_packet_times:
            self._last_packet_times[sender_id] = []
            
        # Keep only timestamps within the last second
        self._last_packet_times[sender_id] = [t for t in self._last_packet_times[sender_id] if now - t < 1.0]
        
        if len(self._last_packet_times[sender_id]) >= self._xdp_config.rate_limit_pps:
            self._xdp_stats.dropped += 1
            self._xdp_stats.drop_by_rate += 1
            return False
            
        self._last_packet_times[sender_id].append(now)
        
        # 3. Sequence Check Filter (placeholder for actual payload inspection)
        if self._xdp_config.enable_sequence_check:
            # Emulate deep packet inspection sequence check
            # For this testbed, we'll assume valid sequence unless flagged
            pass

        self._xdp_stats.forwarded += 1
        return True

    def _broadcast(self, sender_id: str, frame_bytes: bytes):
        """Multicasts the frame to all connected nodes except the sender."""
        with self._lock:
            if not self._apply_xdp_filter(sender_id, frame_bytes):
                return

            self._stats.total_frames += 1
            self._stats.total_bytes += len(frame_bytes)
            if sender_id in self._stats.frames_per_node:
                self._stats.frames_per_node[sender_id] += 1
                
            ports = list(self._ports.values())
            
        # Inject artificial network latency outside the lock
        self.latency_injector.delay()
        
        for port in ports:
            if port.node_id != sender_id:
                port._queue.put(frame_bytes)

    def inject_attack_traffic(self, frame_bytes: bytes, rate_pps: float, duration: float):
        """Flood method for CIL-DoS attack emulation."""
        def flood():
            end_time = time.time() + duration
            delay = 1.0 / rate_pps if rate_pps > 0 else 0
            while time.time() < end_time:
                self._broadcast("attacker", frame_bytes)
                if delay > 0:
                    time.sleep(delay)
                    
        threading.Thread(target=flood, daemon=True).start()

    def enable_xdp_filter(self, config: XDPFilterConfig):
        """Enables software emulation of XDP filtering."""
        with self._lock:
            self._xdp_config = config
            self._xdp_stats = XDPStats()
            self._last_packet_times.clear()

    def disable_xdp_filter(self):
        """Disables XDP filtering."""
        with self._lock:
            self._xdp_config = None

    def get_xdp_stats(self) -> XDPStats:
        """Returns a snapshot of the current XDP statistics."""
        with self._lock:
            return XDPStats(
                received=self._xdp_stats.received,
                dropped=self._xdp_stats.dropped,
                forwarded=self._xdp_stats.forwarded,
                drop_by_mac=self._xdp_stats.drop_by_mac,
                drop_by_rate=self._xdp_stats.drop_by_rate,
                drop_by_sequence=self._xdp_stats.drop_by_sequence
            )
