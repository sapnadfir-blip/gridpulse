"""
GridPulse CLI — Command-Line Interface
=======================================

Click-based CLI for the GridPulse smart grid security research toolkit.
Provides subcommands for protocol analysis, attack execution, defense
management, IDS monitoring, and benchmarking.

Usage:
    gridpulse --help
    gridpulse parse <file>
    gridpulse inject --interface eth0
    gridpulse cil-dos --interface eth0 --rate 50000
    gridpulse defend --interface eth0
    gridpulse ids --interface eth0
    gridpulse bench --algorithm all
    gridpulse stats
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ============================================================================
# Banner
# ============================================================================

BANNER = r"""
   ██████╗ ██████╗ ██╗██████╗ ██████╗ ██╗   ██╗██╗     ███████╗███████╗
  ██╔════╝ ██╔══██╗██║██╔══██╗██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
  ██║  ███╗██████╔╝██║██║  ██║██████╔╝██║   ██║██║     ███████╗█████╗
  ██║   ██║██╔══██╗██║██║  ██║██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝
  ╚██████╔╝██║  ██║██║██████╔╝██║     ╚██████╔╝███████╗███████║███████╗
   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝

  Smart Grid Security Research Toolkit
  CIL-DoS Attack & eBPF/XDP Defense Framework
  IEC 61850 GOOSE | IEC 62351-6 | DNP3
"""


def print_banner():
    """Print the GridPulse banner."""
    if HAS_RICH:
        console = Console()
        console.print(BANNER, style="bold cyan")
    else:
        print(BANNER)


# ============================================================================
# CLI Entry Point
# ============================================================================

if not HAS_CLICK:
    def cli():
        """Fallback when click is not installed."""
        print("GridPulse requires 'click' library.")
        print("Install with: pip install click rich")
        sys.exit(1)
else:

    @click.group(invoke_without_command=True)
    @click.version_option(version="0.1.0", prog_name="GridPulse")
    @click.pass_context
    def cli(ctx):
        """GridPulse — Smart Grid Security Research Toolkit"""
        if ctx.invoked_subcommand is None:
            print_banner()
            click.echo(ctx.get_help())

    # ========================================================================
    # Parse Command
    # ========================================================================

    @cli.command()
    @click.argument("file", type=click.Path(exists=True))
    @click.option("--format", "-f", type=click.Choice(["goose", "dnp3", "auto"]),
                  default="auto", help="Protocol format to parse")
    @click.option("--hex", "show_hex", is_flag=True, help="Show hex dump")
    def parse(file, format, show_hex):
        """Parse protocol frames from a binary file or pcap."""
        from gridpulse.protocols.goose import GOOSEFrame, GOOSEParseError
        from gridpulse.protocols.dnp3 import DNP3Frame, DNP3ParseError

        data = Path(file).read_bytes()
        click.echo(f"[*] Loaded {len(data)} bytes from {file}")

        if format in ("goose", "auto"):
            try:
                frame = GOOSEFrame.parse(data)
                click.echo("\n[+] GOOSE Frame Parsed Successfully:")
                click.echo(str(frame))
                return
            except (GOOSEParseError, Exception) as e:
                if format == "goose":
                    click.echo(f"[-] GOOSE parse error: {e}", err=True)
                    sys.exit(1)

        if format in ("dnp3", "auto"):
            try:
                frame = DNP3Frame.parse(data)
                click.echo("\n[+] DNP3 Frame Parsed Successfully:")
                click.echo(str(frame))
                return
            except (DNP3ParseError, Exception) as e:
                if format == "dnp3":
                    click.echo(f"[-] DNP3 parse error: {e}", err=True)
                    sys.exit(1)

        click.echo("[-] Could not parse file with any known protocol", err=True)
        sys.exit(1)

    # ========================================================================
    # CIL-DoS Command
    # ========================================================================

    @cli.command("cil-dos")
    @click.option("--interface", "-i", required=True, help="Network interface")
    @click.option("--target-mac", "-t", default="01:0c:cd:01:00:01",
                  help="Target MAC address")
    @click.option("--src-mac", "-s", default="08:00:27:aa:bb:cc",
                  help="Source MAC address")
    @click.option("--algorithm", "-a",
                  type=click.Choice(["hmac", "rsa", "ecdsa"]),
                  default="hmac", help="Signature algorithm to exploit")
    @click.option("--rate", "-r", type=int, default=10000,
                  help="Target packets per second")
    @click.option("--duration", "-d", type=float, default=30.0,
                  help="Attack duration in seconds")
    def cil_dos(interface, target_mac, src_mac, algorithm, rate, duration):
        """Launch CIL-DoS (Crypto-Induced Latency DoS) attack."""
        from gridpulse.protocols.goose_security import SecurityAlgorithm
        from gridpulse.attacks.cil_dos import CILDoSAttack

        algo_map = {
            "hmac": SecurityAlgorithm.HMAC_SHA256,
            "rsa": SecurityAlgorithm.RSA_2048_SHA256,
            "ecdsa": SecurityAlgorithm.ECDSA_P256_SHA256,
        }

        print_banner()
        click.echo(f"[*] CIL-DoS Attack Configuration:")
        click.echo(f"    Interface:  {interface}")
        click.echo(f"    Target:     {target_mac}")
        click.echo(f"    Algorithm:  {algorithm}")
        click.echo(f"    Rate:       {rate:,} pps")
        click.echo(f"    Duration:   {duration}s")
        click.echo()

        attack = CILDoSAttack(
            interface=interface,
            target_mac=target_mac,
            src_mac=src_mac,
            algorithm=algo_map[algorithm],
            rate_pps=rate,
            duration_seconds=duration,
        )

        click.echo("[!] Starting CIL-DoS flood...")
        attack.start()

        try:
            while attack.is_running:
                time.sleep(1)
                stats = attack.get_stats()
                click.echo(
                    f"\r  ⚡ {stats.packets_sent:>10,} pkts | "
                    f"{stats.actual_rate_pps:>8,.0f} pps | "
                    f"{stats.duration_seconds:>6.1f}s",
                    nl=False,
                )
        except KeyboardInterrupt:
            click.echo("\n[*] Stopping attack...")

        final = attack.stop()
        click.echo(f"\n\n{final}")

    # ========================================================================
    # Inject Command
    # ========================================================================

    @cli.command()
    @click.option("--interface", "-i", required=True, help="Network interface")
    @click.option("--dst-mac", default="01:0c:cd:01:00:01", help="Destination MAC")
    @click.option("--src-mac", default="08:00:27:aa:bb:cc", help="Source MAC")
    @click.option("--count", "-n", type=int, default=1, help="Number of frames")
    @click.option("--delay", type=float, default=0, help="Inter-frame delay (µs)")
    def inject(interface, dst_mac, src_mac, count, delay):
        """Inject crafted GOOSE frames."""
        from gridpulse.attacks.cil_dos import CILDoSFrameBuilder

        builder = CILDoSFrameBuilder(dst_mac=dst_mac, src_mac=src_mac)
        frame = builder.build_template()

        click.echo(f"[*] Frame size: {len(frame)} bytes")
        click.echo(f"[*] Injecting {count} frames on {interface}...")

        from gridpulse.attacks.goose_inject import GOOSEInjector
        with GOOSEInjector(interface) as injector:
            stats = injector.send_burst(frame, count, delay)
            click.echo(f"[+] {stats}")

    # ========================================================================
    # Replay Command
    # ========================================================================

    @cli.command()
    @click.option("--interface", "-i", required=True, help="Network interface")
    @click.option("--capture-file", "-f", type=click.Path(), help="Capture file to replay")
    @click.option("--capture-duration", type=float, default=10.0,
                  help="Duration to capture (if no file)")
    @click.option("--speed", type=float, default=1.0, help="Replay speed factor")
    @click.option("--loops", type=int, default=1, help="Number of replay loops")
    def replay(interface, capture_file, capture_duration, speed, loops):
        """Capture and replay GOOSE traffic."""
        from gridpulse.attacks.goose_replay import GOOSECapture, GOOSEReplay, CaptureSession

        if capture_file and Path(capture_file).exists():
            click.echo(f"[*] Loading capture from {capture_file}")
            session = CaptureSession.load(capture_file)
        else:
            click.echo(f"[*] Capturing GOOSE traffic for {capture_duration}s...")
            capturer = GOOSECapture(interface)
            session = capturer.capture(duration_seconds=capture_duration)
            if capture_file:
                session.save(capture_file)
                click.echo(f"[+] Saved {session.frame_count} frames to {capture_file}")

        click.echo(f"[*] {session}")
        click.echo(f"[*] Replaying at {speed}x speed, {loops} loop(s)...")

        replayer = GOOSEReplay(interface)
        stats = replayer.replay(session, speed_factor=speed, loop_count=loops)
        click.echo(f"[+] {stats}")

    # ========================================================================
    # Defend Command
    # ========================================================================

    @cli.command()
    @click.option("--interface", "-i", required=True, help="Network interface")
    @click.option("--action", type=click.Choice(["attach", "detach", "status"]),
                  default="attach", help="XDP action")
    @click.option("--allow-mac", "-m", multiple=True, help="MAC addresses to allow")
    @click.option("--rate-limit", type=int, default=1000,
                  help="Max GOOSE frames/sec per source")
    def defend(interface, action, allow_mac, rate_limit):
        """Manage eBPF/XDP GOOSE defense."""
        from gridpulse.defense.xdp_loader import XDPLoader, MapManager, XDPConfig

        config = XDPConfig(
            interface=interface,
            allowed_macs=list(allow_mac),
            rate_limit_pps=rate_limit,
        )

        loader = XDPLoader()

        if action == "attach":
            click.echo(f"[*] Compiling XDP filter...")
            src = Path(__file__).parent.parent / "defense" / "xdp_goose_filter.c"
            obj = Path(__file__).parent.parent / "defense" / "xdp_goose_filter.o"
            loader.compile(str(src), str(obj))

            click.echo(f"[*] Attaching XDP to {interface}...")
            loader.attach(interface, str(obj))

            if allow_mac:
                mgr = MapManager()
                for mac in allow_mac:
                    mgr.add_mac(mac)
                    click.echo(f"    ✓ Allowed: {mac}")

            click.echo(f"[+] XDP defense ACTIVE on {interface}")

        elif action == "detach":
            loader.detach(interface)
            click.echo(f"[+] XDP defense REMOVED from {interface}")

        elif action == "status":
            attached = loader.is_attached(interface)
            click.echo(f"[*] XDP on {interface}: {'ACTIVE' if attached else 'NOT ACTIVE'}")

    # ========================================================================
    # IDS Command
    # ========================================================================

    @cli.command()
    @click.option("--interface", "-i", required=True, help="Network interface")
    @click.option("--known-macs", "-m", multiple=True,
                  help="Known legitimate publisher MACs")
    @click.option("--burst-threshold", type=int, default=1000,
                  help="Burst detection threshold (frames/sec)")
    @click.option("--duration", "-d", type=float, default=0,
                  help="Monitoring duration (0 = indefinite)")
    def ids(interface, known_macs, burst_threshold, duration):
        """Start GOOSE Intrusion Detection System."""
        from gridpulse.ids.goose_ids import GOOSEIDSEngine, IDSConfig
        from gridpulse.attacks.goose_inject import GOOSEListener
        from gridpulse.protocols.goose import GOOSEFrame

        config = IDSConfig(
            burst_threshold_pps=burst_threshold,
            known_publishers=list(known_macs),
        )

        engine = GOOSEIDSEngine(config)
        listener = GOOSEListener(interface)

        print_banner()
        click.echo(f"[*] GOOSE IDS active on {interface}")
        click.echo(f"    Burst threshold: {burst_threshold} fps")
        click.echo(f"    Known publishers: {len(known_macs)}")
        click.echo(f"    Monitoring{'...' if duration == 0 else f' for {duration}s...'}")
        click.echo()

        start = time.monotonic()
        try:
            while True:
                if duration > 0 and (time.monotonic() - start) >= duration:
                    break

                raw = listener.recv_frame(timeout=1.0)
                if raw is None:
                    continue

                try:
                    frame = GOOSEFrame.parse(raw)
                    alerts = engine.process_frame(frame, raw)

                    for alert in alerts:
                        severity_colors = {
                            "CRITICAL": "🔴",
                            "HIGH": "🟠",
                            "MEDIUM": "🟡",
                            "LOW": "🟢",
                            "INFO": "⚪",
                        }
                        icon = severity_colors.get(alert.severity.name, "⚪")
                        click.echo(
                            f"  {icon} [{alert.severity.name}] "
                            f"{alert.rule_id}: {alert.description} "
                            f"(src={alert.source_mac})"
                        )
                        if alert.mitre_technique:
                            click.echo(f"       MITRE: {alert.mitre_technique}")

                except Exception:
                    pass

        except KeyboardInterrupt:
            click.echo("\n[*] IDS stopped.")

        finally:
            listener.close()
            click.echo(f"\n[*] IDS Stats: {engine.stats}")

    # ========================================================================
    # Bench Command
    # ========================================================================

    @cli.command()
    @click.option("--algorithm", "-a",
                  type=click.Choice(["hmac", "rsa", "ecdsa", "all"]),
                  default="all", help="Algorithm to benchmark")
    @click.option("--iterations", "-n", type=int, default=1000,
                  help="Number of iterations")
    @click.option("--output", "-o", type=click.Path(), help="CSV output path")
    def bench(algorithm, iterations, output):
        """Run cryptographic verification benchmarks."""
        from gridpulse.bench.crypto_bench import CryptoBenchmark, export_csv

        print_banner()
        click.echo(f"[*] Running cryptographic benchmarks...")
        click.echo(f"    Iterations: {iterations:,}")
        click.echo()

        benchmark = CryptoBenchmark()

        if algorithm == "all":
            results = benchmark.benchmark_all(iterations=iterations)
            for name, result in results.items():
                click.echo(str(result))
                click.echo()
        elif algorithm == "hmac":
            result = benchmark.benchmark_hmac_sha256(iterations)
            click.echo(str(result))
        elif algorithm == "rsa":
            result = benchmark.benchmark_rsa_2048(iterations)
            click.echo(str(result))
        elif algorithm == "ecdsa":
            result = benchmark.benchmark_ecdsa_p256(iterations)
            click.echo(str(result))

        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            if algorithm == "all":
                export_csv(list(results.values()), output)
            else:
                export_csv([result], output)
            click.echo(f"[+] Results saved to {output}")

    # ========================================================================
    # Queue Model Command
    # ========================================================================

    @cli.command("queue-model")
    @click.option("--service-rate", "-mu", type=float, required=True,
                  help="Verification service rate µ (ops/sec)")
    @click.option("--attack-rates", "-r", type=str,
                  default="1000,5000,10000,50000,100000",
                  help="Comma-separated attack rates to analyze")
    @click.option("--deadline", type=float, default=3000.0,
                  help="Safety deadline in microseconds")
    @click.option("--model", type=click.Choice(["mm1", "md1", "both"]),
                  default="both", help="Queueing model to use")
    def queue_model(service_rate, attack_rates, deadline, model):
        """Run queueing theory analysis for CIL-DoS."""
        from gridpulse.bench.queue_model import MM1Queue, MD1Queue

        rates = [float(r) for r in attack_rates.split(",")]
        deadline_sec = deadline / 1_000_000

        print_banner()
        click.echo(f"[*] Queueing Theory Analysis")
        click.echo(f"    Service rate (µ): {service_rate:,.0f} ops/sec")
        click.echo(f"    Safety deadline:  {deadline} µs")
        click.echo()

        for rate in rates:
            click.echo(f"  λ = {rate:>10,.0f} pps:")
            if model in ("mm1", "both"):
                try:
                    q = MM1Queue(rate, service_rate)
                    click.echo(f"    M/M/1: ρ={q.utilization_rho:.3f}, "
                              f"Wq={q.mean_wait_time*1e6:.1f}µs, "
                              f"P(violation)={q.prob_deadline_violation(deadline_sec):.4f}")
                except ValueError as e:
                    click.echo(f"    M/M/1: {e}")
            if model in ("md1", "both"):
                try:
                    q = MD1Queue(rate, service_rate)
                    click.echo(f"    M/D/1: ρ={q.utilization_rho:.3f}, "
                              f"Wq={q.mean_wait_time*1e6:.1f}µs, "
                              f"P(violation)={q.prob_deadline_violation(deadline_sec):.4f}")
                except ValueError as e:
                    click.echo(f"    M/D/1: {e}")

    # ========================================================================
    # Stats Command
    # ========================================================================

    @cli.command()
    @click.option("--interface", "-i", default="eth0", help="Network interface")
    @click.option("--interval", type=float, default=1.0, help="Refresh interval (sec)")
    def stats(interface, interval):
        """Display real-time XDP defense statistics."""
        from gridpulse.defense.xdp_stats import XDPStatsReader, XDPDashboard

        print_banner()
        click.echo(f"[*] Starting XDP stats dashboard for {interface}...")

        try:
            dashboard = XDPDashboard(interface=interface, interval=interval)
            dashboard.run()
        except KeyboardInterrupt:
            click.echo("\n[*] Dashboard stopped.")

    # ========================================================================
    # Spoof Command
    # ========================================================================

    @cli.command()
    @click.option("--interface", "-i", required=True, help="Network interface")
    @click.option("--monitor-duration", type=float, default=5.0,
                  help="Time to observe traffic before spoofing")
    @click.option("--target-mac", "-t", default=None,
                  help="Specific publisher MAC to target")
    @click.option("--trip/--no-trip", default=False,
                  help="Inject false trip command")
    @click.option("--st-advance", type=int, default=100,
                  help="stNum advance over observed value")
    def spoof(interface, monitor_duration, target_mac, trip, st_advance):
        """GOOSE state spoofing attack."""
        from gridpulse.attacks.goose_spoof import GOOSESpoofAttack, TripInjector

        print_banner()

        if trip:
            click.echo("[*] Auto-trip mode: monitor → learn → inject trip command")
            injector = TripInjector(interface)
            stats = injector.auto_trip(
                monitor_duration=monitor_duration,
                target_mac=target_mac,
                st_advance=st_advance,
            )
            click.echo(f"[+] Trip injection complete: {stats}")
        else:
            click.echo(f"[*] Monitoring for publishers ({monitor_duration}s)...")
            attack = GOOSESpoofAttack(interface, target_mac)
            publishers = attack.monitor(duration=monitor_duration)

            if not publishers:
                click.echo("[-] No GOOSE publishers found.")
                return

            for mac, pub in publishers.items():
                click.echo(f"  Found: {pub}")

            target = list(publishers.values())[0]
            click.echo(f"\n[*] Spoofing {target.source_mac} with stNum+{st_advance}")
            stats = attack.spoof_state(target, st_num_advance=st_advance)
            click.echo(f"[+] {stats}")

    # ========================================================================
    # Demo Command
    # ========================================================================

    @cli.command()
    @click.option("--interactive", is_flag=True, help="Interactive mode")
    @click.option("--headless", is_flag=True, help="No dashboard (for testing)")
    @click.option("--profile", default="mid_range",
                  type=click.Choice(["high_performance", "mid_range",
                                     "resource_constrained", "gateway", "desktop_test"]),
                  help="Relay profile to simulate")
    @click.option("--save", type=click.Path(), default=None,
                  help="Save recording to JSON file")
    def demo(interactive, headless, profile, save):
        """Run the Black Hat live demonstration."""
        from gridpulse.demo.orchestrator import DemoOrchestrator

        print_banner()
        click.echo("  \"When Cryptography Becomes the Attack Surface\"")
        click.echo(f"  Relay Profile: {profile}")
        click.echo()

        orchestrator = DemoOrchestrator(
            interactive=interactive,
            headless=headless,
            relay_profile=profile,
        )

        if not headless:
            try:
                from gridpulse.demo.dashboard import DemoDashboard
                dashboard = DemoDashboard(orchestrator)
                dashboard.run()
            except ImportError:
                def simple_cb(snapshot):
                    icon = {"HEALTHY": "🟢", "DEGRADED": "🟡",
                            "CRITICAL": "🔴", "PROTECTED": "🛡️"
                           }.get(snapshot.relay_status, "⚪")
                    click.echo(
                        f"\r  {icon} {snapshot.phase:<30} │ "
                        f"Lat: {snapshot.legit_latency_us:>7.0f}µs │ "
                        f"Atk: {snapshot.attack_rate_pps:>8,.0f}pps │ "
                        f"Miss: {snapshot.deadline_miss_count}",
                        nl=False,
                    )
                orchestrator.on_dashboard_update(simple_cb)
                orchestrator.run()
        else:
            orchestrator.run()

        if save:
            orchestrator.save_recording(save)
            click.echo(f"\n  Recording saved to {save}")

        click.echo("\n  Demo complete.\n")

    # ========================================================================
    # Defense Compare Command
    # ========================================================================

    @cli.command("defense-compare")
    @click.option("--attack-rate", "-r", type=float, default=25000,
                  help="Attack rate in pps")
    @click.option("--service-rate", "-mu", type=float, default=29783,
                  help="Verification service rate (ops/sec)")
    @click.option("--deadline", type=float, default=3000,
                  help="Safety deadline in µs")
    def defense_compare(attack_rate, service_rate, deadline):
        """Compare defense approaches against CIL-DoS."""
        from gridpulse.bench.defense_comparison import (
            run_comparison, DEFENSE_PROFILES, print_lessons_for_defenders,
        )

        print_banner()
        click.echo(f"[*] Defense Comparison")
        click.echo(f"    Attack rate: {attack_rate:,.0f} pps")
        click.echo(f"    Service rate: {service_rate:,.0f} ops/sec")
        click.echo()

        results = run_comparison(
            service_rates={"RSA-2048": service_rate},
            attack_rates=[attack_rate],
        )

        click.echo()
        print_lessons_for_defenders()


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    cli()

