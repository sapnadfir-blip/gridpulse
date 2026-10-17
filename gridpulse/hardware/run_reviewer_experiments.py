#!/usr/bin/env python3
"""
GridPulse Reviewer Revision Experiments v4
Addresses all reviewer concerns with new experiments:
  A: Threshold sensitivity sweep (T_FLOOD: 20-2000)
  B: False positive evaluation (multi-publisher)
  C: Multi-publisher scalability
  D: MAC spoofing resilience
"""

import subprocess
import os
import shutil
import time
import json
import csv

HARDWARE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HARDWARE_DIR, "results")
COMPOSE_FILE = os.path.join(HARDWARE_DIR, "docker-compose.yml")

DURATION = 25  # seconds per experiment

# ── GROUP A: Threshold Sensitivity ──────────────────────────────
# Sweep T_FLOOD at 100K pps to find optimal threshold
THRESHOLD_SWEEP = [
    {"id": "A01", "label": "T_FLOOD=20 (very aggressive)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 20},
    {"id": "A02", "label": "T_FLOOD=50",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 50},
    {"id": "A03", "label": "T_FLOOD=100",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 100},
    {"id": "A04", "label": "T_FLOOD=200",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 200},
    {"id": "A05", "label": "T_FLOOD=500",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 500},
    {"id": "A06", "label": "T_FLOOD=1000 (default)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000},
    {"id": "A07", "label": "T_FLOOD=2000 (permissive)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 2000},
]

# ── GROUP B: False Positive Evaluation ─────────────────────────
# Multiple publishers + attack → measure FP rate
FALSE_POSITIVE = [
    {"id": "B01", "label": "4-pub no attack (FP baseline)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 0,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000},
    {"id": "B02", "label": "4-pub + 50K attack",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 50000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000},
    {"id": "B03", "label": "4-pub + 100K attack",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000},
]

# ── GROUP C: Scalability (simulated with higher legit rate) ────
# Single publisher at different heartbeat rates to simulate multi-pub load
SCALABILITY = [
    {"id": "C01", "label": "1-pub equivalent (1 Hz)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000,
     "heartbeat_ms": 1000},
    {"id": "C02", "label": "4-pub equivalent (4 Hz)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000,
     "heartbeat_ms": 250},
    {"id": "C03", "label": "8-pub equivalent (8 Hz)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000,
     "heartbeat_ms": 125},
    {"id": "C04", "label": "16-pub equivalent (16 Hz)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000,
     "heartbeat_ms": 62},
]

# ── GROUP D: MAC Spoofing ──────────────────────────────────────
MAC_SPOOFING = [
    {"id": "D01", "label": "No spoof baseline 100K",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000,
     "spoof_mac": None},
    {"id": "D02", "label": "Spoof publisher MAC 100K",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000,
     "spoof_mac": "PUBLISHER"},
    {"id": "D03", "label": "Spoof publisher MAC 10K",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 10000,
     "algo": "RSA-2048", "t_normal": 50, "t_burst": 500, "t_flood": 1000,
     "spoof_mac": "PUBLISHER"},
]

ALL_EXPERIMENTS = THRESHOLD_SWEEP + FALSE_POSITIVE + SCALABILITY + MAC_SPOOFING


def cleanup():
    """Stop all containers and clean volumes."""
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "--profile", "attack",
         "down", "-v", "--remove-orphans"],
        cwd=HARDWARE_DIR, capture_output=True, timeout=30
    )
    time.sleep(2)


def get_publisher_mac():
    """Get the publisher container's MAC address."""
    try:
        result = subprocess.run(
            ["docker", "exec", "ied-publisher", "cat", "/sys/class/net/eth0/address"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except Exception:
        return "02:42:ac:14:00:0a"  # Docker default for 172.20.0.10


def run_experiment(exp):
    """Run a single experiment and return results."""
    exp_id = exp["id"]
    label = exp["label"]

    print(f"\n{'='*60}")
    print(f"  {exp_id}: {label}")
    print(f"  Mode: {exp['mode']}, Attack: {exp['attack_rate']} pps")
    if "t_flood" in exp:
        print(f"  Thresholds: N={exp['t_normal']} B={exp['t_burst']} F={exp['t_flood']}")
    if exp.get("spoof_mac"):
        print(f"  Spoof MAC: {exp['spoof_mac']}")
    print(f"{'='*60}\n")

    cleanup()

    env = os.environ.copy()
    env["DURATION"] = str(DURATION)
    env["GOOSE_ALGORITHM"] = exp["algo"]
    env["QUEUE_MODE"] = exp["mode"]
    env["WORKERS"] = str(exp["workers"])
    env["QUEUE_SIZE"] = str(exp["queue_size"])
    env["ATTACK_RATE"] = str(exp["attack_rate"])
    env["T_NORMAL"] = str(exp.get("t_normal", 50))
    env["T_BURST"] = str(exp.get("t_burst", 500))
    env["T_FLOOD"] = str(exp.get("t_flood", 1000))

    if exp.get("heartbeat_ms"):
        env["HEARTBEAT_MS"] = str(exp["heartbeat_ms"])

    # Handle MAC spoofing
    spoof = exp.get("spoof_mac")
    if spoof and spoof != "PUBLISHER":
        env["SPOOF_MAC"] = spoof
    elif spoof == "PUBLISHER":
        # Will be resolved after publisher starts
        env["_SPOOF_PUBLISHER"] = "1"

    profile = "attack" if exp["attack_rate"] > 0 else "default"

    # For MAC spoofing, start publisher first then get its MAC
    if exp.get("spoof_mac") == "PUBLISHER":
        # Start publisher only first
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d", "publisher"],
            cwd=HARDWARE_DIR, env=env, capture_output=True, timeout=30
        )
        time.sleep(3)
        pub_mac = get_publisher_mac()
        print(f"  Publisher MAC discovered: {pub_mac}")
        env["SPOOF_MAC"] = pub_mac
        # Now start remaining services
        cmd = ["docker", "compose", "-f", COMPOSE_FILE, "--profile", "attack",
               "up", "--abort-on-container-exit"]
    else:
        cmd = ["docker", "compose", "-f", COMPOSE_FILE]
        if profile == "attack":
            cmd += ["--profile", "attack"]
        cmd += ["up", "--abort-on-container-exit"]

    try:
        result = subprocess.run(
            cmd, cwd=HARDWARE_DIR, env=env,
            capture_output=True, text=True,
            timeout=DURATION + 60
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        print(f"  ⚠ Timeout — forcing stop")
        cleanup()
        output = ""

    # Parse output for key metrics
    metrics = parse_output(output, exp)

    # Save raw output
    exp_dir = os.path.join(RESULTS_DIR, f"v4_{exp_id}")
    os.makedirs(exp_dir, exist_ok=True)

    with open(os.path.join(exp_dir, "output.txt"), "w") as f:
        f.write(output)

    csv_src = os.path.join(RESULTS_DIR, "subscriber_timing.csv")
    if os.path.exists(csv_src):
        shutil.copy2(csv_src, os.path.join(exp_dir, "subscriber_timing.csv"))

    with open(os.path.join(exp_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print_metrics(metrics)
    return metrics


def parse_output(output, exp):
    """Parse subscriber output for key metrics."""
    metrics = {
        "id": exp["id"],
        "label": exp["label"],
        "mode": exp["mode"],
        "workers": exp["workers"],
        "queue_size": exp["queue_size"],
        "attack_rate": exp["attack_rate"],
        "algo": exp["algo"],
        "t_flood": exp.get("t_flood", 1000),
        "spoof_mac": exp.get("spoof_mac"),
        "heartbeat_ms": exp.get("heartbeat_ms", 1000),
        "total_frames": 0,
        "valid_frames": 0,
        "invalid_frames": 0,
        "mean_latency_us": 0,
        "p95_latency_us": 0,
        "p99_latency_us": 0,
        "deadline_miss_pct": 0,
        "queue_peak": 0,
        "queue_drops": 0,
        "scheduler_overhead_us": 0,
        "classified_high": 0,
        "classified_normal": 0,
        "classified_low": 0,
        "classified_dropped": 0,
    }

    for line in output.split("\n"):
        line = line.strip()

        if "Total:" in line and "Valid:" in line:
            parts = line.split(",")
            for p in parts:
                p = p.strip()
                if "Total:" in p:
                    try: metrics["total_frames"] = int(p.split(":")[-1].strip())
                    except: pass
                elif "Valid:" in p:
                    try: metrics["valid_frames"] = int(p.split(":")[-1].strip())
                    except: pass
                elif "Invalid:" in p:
                    try: metrics["invalid_frames"] = int(p.split(":")[-1].strip())
                    except: pass

        if "Mean:" in line and "p95:" in line:
            try:
                parts = line.split(",")
                for p in parts:
                    p = p.strip()
                    if "Mean:" in p:
                        metrics["mean_latency_us"] = float(p.split(":")[-1].strip())
                    elif "p95:" in p:
                        metrics["p95_latency_us"] = float(p.split(":")[-1].strip())
                    elif "p99:" in p:
                        metrics["p99_latency_us"] = float(p.split(":")[-1].strip())
            except: pass

        if "Deadline miss:" in line:
            try:
                pct = line.split(":")[-1].strip().rstrip("%")
                metrics["deadline_miss_pct"] = float(pct)
            except: pass

        if "Queue peak:" in line or "Peak depth:" in line:
            try: metrics["queue_peak"] = int(line.split(":")[-1].strip())
            except: pass

        if "Queue drops:" in line or "Overflow drops:" in line:
            try: metrics["queue_drops"] = int(line.split(":")[-1].strip())
            except: pass

        if "Scheduler overhead:" in line:
            try: metrics["scheduler_overhead_us"] = float(line.split(":")[1].strip().split()[0])
            except: pass

        if "HIGH=" in line:
            try:
                for tok in line.split(","):
                    tok = tok.strip()
                    if "HIGH=" in tok: metrics["classified_high"] = int(tok.split("=")[-1])
                    elif "NORMAL=" in tok: metrics["classified_normal"] = int(tok.split("=")[-1])
                    elif "LOW=" in tok: metrics["classified_low"] = int(tok.split("=")[-1])
                    elif "DROPPED=" in tok: metrics["classified_dropped"] = int(tok.split("=")[-1])
            except: pass

    return metrics


def print_metrics(m):
    """Print formatted metrics."""
    print(f"\n  ┌─ Results ─────────────────────────────────────┐")
    print(f"  │ Frames: Total={m['total_frames']:,}, Valid={m['valid_frames']:,}")
    print(f"  │ Latency: Mean={m['mean_latency_us']:.1f}µs, P99={m['p99_latency_us']:.1f}µs")
    print(f"  │ Deadline miss: {m['deadline_miss_pct']:.2f}%")
    if m.get("classified_high", 0) > 0 or m.get("classified_dropped", 0) > 0:
        print(f"  │ Classified: H={m['classified_high']:,} N={m['classified_normal']:,} "
              f"L={m['classified_low']:,} D={m['classified_dropped']:,}")
    print(f"  └────────────────────────────────────────────────┘\n")


def save_summary(all_results, filename="v4_summary.csv"):
    """Save summary CSV."""
    csv_path = os.path.join(RESULTS_DIR, filename)
    if not all_results:
        return

    keys = all_results[0].keys()
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(all_results)
    print(f"\n✅ Summary saved: {csv_path}")


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    all_results = []

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  GridPulse Reviewer Revision Experiments v4             ║")
    print(f"║  Total experiments: {len(ALL_EXPERIMENTS)}                               ║")
    print("╚══════════════════════════════════════════════════════════╝")

    for i, exp in enumerate(ALL_EXPERIMENTS, 1):
        print(f"\n{'#'*60}")
        print(f"  Experiment {i}/{len(ALL_EXPERIMENTS)}")
        print(f"{'#'*60}")

        try:
            metrics = run_experiment(exp)
            all_results.append(metrics)
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            all_results.append({"id": exp["id"], "label": exp["label"], "error": str(e)})

    save_summary(all_results)

    # Final cleanup
    cleanup()

    print("\n")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  ALL EXPERIMENTS COMPLETE                               ║")
    print(f"║  Successful: {sum(1 for r in all_results if 'error' not in r)}/{len(all_results)}                                    ║")
    print("╚══════════════════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
