import time
import csv
from dataclasses import dataclass, field
from typing import Dict
from rich.console import Console
from rich.table import Table
from rich.live import Live

@dataclass
class StatsSnapshot:
    """Point-in-time snapshot of XDP statistics."""
    timestamp: float
    total_packets: int = 0
    goose_packets: int = 0
    passed_packets: int = 0
    dropped_mac: int = 0
    dropped_rate: int = 0
    dropped_seq: int = 0
    dropped_malformed: int = 0
    errors: int = 0

class XDPStatsReader:
    """Reads BPF map counters in real-time."""
    def __init__(self, map_manager):
        self.map_manager = map_manager
        self.history = []

    def poll(self) -> StatsSnapshot:
        """Poll BPF map counters."""
        stats = self.map_manager.dump_stats()
        snapshot = StatsSnapshot(
            timestamp=time.time(),
            **stats
        )
        self.history.append(snapshot)
        if len(self.history) > 100:
            self.history.pop(0)
        return snapshot

    def get_rates(self):
        """Calculate rates (packets/sec)."""
        if len(self.history) < 2:
            return {}
        latest = self.history[-1]
        prev = self.history[0]
        dt = latest.timestamp - prev.timestamp
        if dt == 0:
            return {}
        
        return {
            "total_pps": (latest.total_packets - prev.total_packets) / dt,
            "drop_rate": (
                (latest.dropped_mac + latest.dropped_rate + latest.dropped_seq + latest.dropped_malformed) - 
                (prev.dropped_mac + prev.dropped_rate + prev.dropped_seq + prev.dropped_malformed)
            ) / dt
        }

class XDPDashboard:
    """Live terminal dashboard showing XDP stats."""
    def __init__(self, reader: XDPStatsReader, refresh_interval: float = 1.0):
        self.reader = reader
        self.refresh_interval = refresh_interval
        self.console = Console()

    def generate_table(self) -> Table:
        snapshot = self.reader.poll()
        rates = self.reader.get_rates()

        table = Table(title="GridPulse XDP Defense Dashboard")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row("Total Packets", str(snapshot.total_packets))
        table.add_row("GOOSE Packets", str(snapshot.goose_packets))
        table.add_row("Passed", str(snapshot.passed_packets))
        table.add_row("Dropped (MAC)", str(snapshot.dropped_mac))
        table.add_row("Dropped (Rate)", str(snapshot.dropped_rate))
        table.add_row("Dropped (Seq)", str(snapshot.dropped_seq))
        
        total_drops = snapshot.dropped_mac + snapshot.dropped_rate + snapshot.dropped_seq + snapshot.dropped_malformed
        total_goose = snapshot.goose_packets

        if total_goose > 0:
            ratio = ((total_goose - total_drops) / total_goose) * 100
        else:
            ratio = 100.0
            
        table.add_row("Defense Ratio", f"{ratio:.2f}%")
        table.add_row("PPS", f"{rates.get('total_pps', 0.0):.2f}")

        return table

    def run(self):
        """Run the live dashboard."""
        with Live(self.generate_table(), refresh_per_second=1/self.refresh_interval) as live:
            try:
                while True:
                    time.sleep(self.refresh_interval)
                    live.update(self.generate_table())
            except KeyboardInterrupt:
                pass

    def export_csv(self, filename: str):
        """Export history to CSV."""
        if not self.reader.history:
            return
        
        keys = self.reader.history[0].__dict__.keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for snap in self.reader.history:
                writer.writerow(snap.__dict__)
