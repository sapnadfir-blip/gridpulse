"""
GridPulse Demo Dashboard
=========================

Rich terminal dashboard showing:
  - Latency graph (ASCII sparkline)
  - Attack & defense metrics
  - Protocol field display
  - Operator console narrative

  ╔══════════════════════════════════════════════════════════════╗
  ║  WHEN CRYPTOGRAPHY BECOMES THE ATTACK SURFACE               ║
  ║  Phase: CIL-DoS RAMP-UP                                     ║
  ╠══════════════════════════════════════════════════════════════╣
  ║                                                              ║
  ║  LATENCY: ▁▁▂▃▄▅▆▇█████████████  2847 µs   DEADLINE: 3ms  ║
  ║                                                              ║
  ║  ┌─ ATTACK ──────────┐  ┌─ XDP DEFENSE ─────────┐           ║
  ║  │ Rate: 12,450 pps  │  │ Received:  125,000    │           ║
  ║  │ Total: 245,000    │  │ Dropped:   124,500    │           ║
  ║  │ Algorithm: RSA    │  │ Forwarded:     500    │           ║
  ║  └───────────────────┘  │ Drop Rate:   99.6%    │           ║
  ║                         └────────────────────────┘           ║
  ║  ┌─ LAST PACKET ────────────────────────────────┐           ║
  ║  │ Type: CIL-DoS (ATTACK)                       │           ║
  ║  │ Src MAC:  de:ad:be:ef:00:01                   │           ║
  ║  │ stNum: 17  sqNum: 44  confRev: 1              │           ║
  ║  │ Signature: RSA-2048 → INVALID ❌               │           ║
  ║  │ Action: DROPPED by XDP                         │           ║
  ║  └───────────────────────────────────────────────┘           ║
  ║                                                              ║
  ║  ┌─ OPERATOR CONSOLE ──────────────────────────┐            ║
  ║  │ 21:45:01  System nominal                     │            ║
  ║  │ 21:45:15  ⚠ Verification latency increasing  │            ║
  ║  │ 21:45:22  🔴 PROTECTION DELAYED - 4.2ms      │            ║
  ║  │ 21:45:30  🛡️ XDP defense activated           │            ║
  ║  │ 21:45:31  🟢 System recovering               │            ║
  ║  └──────────────────────────────────────────────┘            ║
  ╚══════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gridpulse.demo.orchestrator import DemoOrchestrator, DemoSnapshot

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ============================================================================
# Sparkline Generator
# ============================================================================

SPARK_CHARS = "▁▂▃▄▅▆▇█"

def sparkline(values: list[float], width: int = 40, max_val: float = 0) -> str:
    """Generate an ASCII sparkline from a list of values."""
    if not values:
        return " " * width

    if max_val <= 0:
        max_val = max(values) if max(values) > 0 else 1

    # Resample to fit width
    if len(values) > width:
        step = len(values) / width
        resampled = [values[int(i * step)] for i in range(width)]
    else:
        resampled = values + [0] * (width - len(values))

    result = ""
    for v in resampled[-width:]:
        idx = int(min(v / max_val, 1.0) * (len(SPARK_CHARS) - 1))
        result += SPARK_CHARS[idx]

    return result


# ============================================================================
# Operator Console Log
# ============================================================================

class OperatorLog:
    """Maintains the operator console narrative."""

    def __init__(self, max_lines: int = 12):
        self._lines: list[tuple[str, str, str]] = []  # (time, icon, message)
        self._max_lines = max_lines
        self._last_status = ""

    def add(self, icon: str, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self._lines.append((timestamp, icon, message))
        if len(self._lines) > self._max_lines:
            self._lines = self._lines[-self._max_lines:]

    def update_from_snapshot(self, snapshot: 'DemoSnapshot'):
        """Auto-generate operator log entries from demo state."""
        status = snapshot.relay_status
        if status == self._last_status:
            return
        self._last_status = status

        if status == "HEALTHY" and snapshot.defense_enabled:
            self.add("🛡️", "XDP defense active — system protected")
        elif status == "HEALTHY":
            self.add("🟢", "System nominal — all deadlines met")
        elif status == "DEGRADED":
            self.add("🟡", f"⚠ Verification latency increasing — "
                          f"{snapshot.legit_latency_us:.0f}µs")
        elif status == "CRITICAL":
            self.add("🔴", f"PROTECTION DELAYED — "
                          f"{snapshot.legit_latency_us:.0f}µs > 3000µs deadline")
        elif status == "PROTECTED":
            self.add("🛡️", "XDP defense holding — attack mitigated")

    def render(self) -> str:
        if not self._lines:
            return "  Awaiting events..."
        return "\n".join(
            f"  {ts}  {icon} {msg}" for ts, icon, msg in self._lines
        )


# ============================================================================
# Dashboard Renderer
# ============================================================================

class DemoDashboard:
    """Rich terminal dashboard for the live demo."""

    def __init__(self, orchestrator: 'DemoOrchestrator'):
        self.orchestrator = orchestrator
        self.operator_log = OperatorLog()
        self._latency_history: list[float] = []
        self._last_snapshot: 'DemoSnapshot | None' = None
        self._console = Console() if HAS_RICH else None
        self._narrative_index = 0

    def run(self):
        """Run the dashboard with Rich Live display."""
        if not HAS_RICH:
            # Fallback to simple mode
            self.orchestrator.on_dashboard_update(self._simple_update)
            self.orchestrator.run()
            return

        # Register callback
        self.orchestrator.on_dashboard_update(self._on_snapshot)

        # Start orchestrator in background
        demo_thread = threading.Thread(target=self.orchestrator.run, daemon=True)
        demo_thread.start()

        # Render loop
        try:
            with Live(self._render(), console=self._console, refresh_per_second=8,
                       screen=False) as live:
                while demo_thread.is_alive():
                    live.update(self._render())
                    time.sleep(0.125)
                # Final render
                live.update(self._render())
        except KeyboardInterrupt:
            self.orchestrator.stop()

    def _on_snapshot(self, snapshot: 'DemoSnapshot'):
        """Callback from orchestrator."""
        self._last_snapshot = snapshot
        self._latency_history.append(snapshot.legit_latency_us)
        if len(self._latency_history) > 200:
            self._latency_history = self._latency_history[-200:]
        self.operator_log.update_from_snapshot(snapshot)

    def _simple_update(self, snapshot: 'DemoSnapshot'):
        """Simple text fallback."""
        self._on_snapshot(snapshot)
        icon = {"HEALTHY": "🟢", "DEGRADED": "🟡", "CRITICAL": "🔴",
                "PROTECTED": "🛡️"}.get(snapshot.relay_status, "⚪")
        print(
            f"\r  {icon} {snapshot.phase:<30} │ "
            f"Lat: {snapshot.legit_latency_us:>7.0f}µs │ "
            f"Atk: {snapshot.attack_rate_pps:>8,.0f}pps │ "
            f"Q: {snapshot.queue_depth:>4} │ "
            f"XDP: {snapshot.xdp_drop_ratio:>5.1%} │ "
            f"Miss: {snapshot.deadline_miss_count}",
            end="", flush=True,
        )

    def _render(self) -> 'Panel':
        """Render the full dashboard."""
        s = self._last_snapshot
        if s is None:
            return Panel(
                Align.center(Text("Initializing...", style="dim")),
                title="[bold cyan]GridPulse Demo[/]",
                border_style="cyan",
            )

        # ── Title ────────────────────────────────────────────
        phase = self.orchestrator._current_phase
        phase_name = phase.name if phase else "—"
        phase_desc = phase.description if phase else ""

        status_style = {
            "HEALTHY": "bold green",
            "DEGRADED": "bold yellow",
            "CRITICAL": "bold red blink",
            "PROTECTED": "bold cyan",
        }.get(s.relay_status, "white")

        status_icon = {
            "HEALTHY": "🟢", "DEGRADED": "🟡",
            "CRITICAL": "🔴", "PROTECTED": "🛡️",
        }.get(s.relay_status, "⚪")

        # ── Latency Sparkline ────────────────────────────────
        spark = sparkline(self._latency_history, width=50, max_val=5000)
        deadline_color = "green" if s.deadline_met else "red"

        # ── Build panels ─────────────────────────────────────
        content_parts = []

        # Title line
        content_parts.append(
            f"  [bold cyan]WHEN CRYPTOGRAPHY BECOMES THE ATTACK SURFACE[/]\n"
            f"  Phase: [bold]{phase_name}[/] — {phase_desc}\n"
            f"  Relay: [{status_style}]{status_icon} {s.relay_status}[/]"
            f"    Elapsed: {s.elapsed_seconds:.1f}s\n"
        )

        # Latency graph
        lat_color = "green" if s.legit_latency_us < 1500 else \
                    "yellow" if s.legit_latency_us < 3000 else "red"
        content_parts.append(
            f"  [bold]LATENCY[/]  {spark}  "
            f"[{lat_color}]{s.legit_latency_us:>7.0f}µs[/]  "
            f"Deadline: [{deadline_color}]3000µs[/]  "
            f"Misses: [red]{s.deadline_miss_count}[/] "
            f"({s.deadline_miss_ratio:.1%})\n"
        )

        # Narrative
        if phase and phase.narrative:
            idx = min(
                int(s.elapsed_seconds / max(phase.duration_seconds, 1) * len(phase.narrative)),
                len(phase.narrative) - 1
            )
            content_parts.append(
                f"  [italic dim]» {phase.narrative[idx]}[/]\n"
            )

        # Attack + Defense side by side
        content_parts.append(
            f"  ┌─ ATTACK ─────────────────────┐  ┌─ XDP DEFENSE ──────────────────┐\n"
            f"  │ Rate:    {s.attack_rate_pps:>12,.0f} pps  │  │ Received:  {s.xdp_received:>12,}    │\n"
            f"  │ Total:   {s.attack_frames_total:>12,}      │  │ Dropped:   {s.xdp_dropped:>12,}    │\n"
            f"  │ Queue:   {s.queue_depth:>12}      │  │ Forwarded: {s.xdp_forwarded:>12,}    │\n"
            f"  │ ρ:       {s.queue_utilization:>12.3f}      │  │ Drop Rate: {s.xdp_drop_ratio:>11.1%}    │\n"
            f"  └───────────────────────────────┘  └────────────────────────────────┘\n"
        )

        # Operator console
        content_parts.append(
            f"  ┌─ OPERATOR CONSOLE ──────────────────────────────────────────────┐\n"
        )
        for line in self.operator_log.render().split("\n"):
            content_parts.append(f"  │{line:<66}│\n")
        content_parts.append(
            f"  └──────────────────────────────────────────────────────────────────┘"
        )

        full_content = "".join(content_parts)

        return Panel(
            Text.from_markup(full_content),
            title="[bold cyan]⚡ GridPulse Demo[/]",
            subtitle=f"[dim]stNum: {s.publisher_stnum} → {s.subscriber_last_stnum}[/]",
            border_style="cyan",
            padding=(0, 1),
        )


if __name__ == "__main__":
    from gridpulse.demo.orchestrator import DemoOrchestrator
    orch = DemoOrchestrator(relay_profile="mid_range")
    dash = DemoDashboard(orch)
    dash.run()
