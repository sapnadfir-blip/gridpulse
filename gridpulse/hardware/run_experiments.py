#!/usr/bin/env python3
"""
GridPulse Comprehensive Evaluation Suite v3
IEEE Access — Full Comparison Matrix

Configurations tested:
  1. FIFO + 1 worker (baseline — proves CIL-DoS)
  2. FIFO + large queue (shows buffering doesn't help)
  3. FIFO + 4 workers (shows parallelization doesn't fully help)
  4. PRIORITY + 1 worker (our defense)
  5. PRIORITY + 4 workers (combined defense)

Attack rates: 0, 10K, 50K, 100K, 500K pps
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

# ── Experiment Matrix ──────────────────────────────────────────
EXPERIMENTS = [
    # --- Group 1: FIFO Baseline (1 worker, default queue) ---
    {"id": "E01", "label": "FIFO baseline (no attack)",
     "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 0, "algo": "RSA-2048"},
    {"id": "E02", "label": "FIFO 10K pps attack",
     "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 10000, "algo": "RSA-2048"},
    {"id": "E03", "label": "FIFO 50K pps attack",
     "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 50000, "algo": "RSA-2048"},
    {"id": "E04", "label": "FIFO 100K pps attack",
     "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 100000, "algo": "RSA-2048"},
    {"id": "E05", "label": "FIFO 500K pps attack",
     "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 500000, "algo": "RSA-2048"},

    # --- Group 2: FIFO + Large Queue (does buffering help?) ---
    {"id": "E06", "label": "FIFO large-queue 100K",
     "mode": "fifo", "workers": 1, "queue_size": 16384, "attack_rate": 100000, "algo": "RSA-2048"},

    # --- Group 3: FIFO + Multi-Worker (does parallelism help?) ---
    {"id": "E07", "label": "FIFO 2-workers 100K",
     "mode": "fifo", "workers": 2, "queue_size": 4096, "attack_rate": 100000, "algo": "RSA-2048"},
    {"id": "E08", "label": "FIFO 4-workers 100K",
     "mode": "fifo", "workers": 4, "queue_size": 4096, "attack_rate": 100000, "algo": "RSA-2048"},

    # --- Group 4: PRIORITY Queue (our defense) ---
    {"id": "E09", "label": "PRIORITY baseline (no attack)",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 0, "algo": "RSA-2048"},
    {"id": "E10", "label": "PRIORITY 10K pps defense",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 10000, "algo": "RSA-2048"},
    {"id": "E11", "label": "PRIORITY 50K pps defense",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 50000, "algo": "RSA-2048"},
    {"id": "E12", "label": "PRIORITY 100K pps defense",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000, "algo": "RSA-2048"},
    {"id": "E13", "label": "PRIORITY 500K pps defense",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 500000, "algo": "RSA-2048"},

    # --- Group 5: Algorithm comparison at 100K ---
    {"id": "E14", "label": "FIFO HMAC 100K",
     "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 100000, "algo": "HMAC-SHA256"},
    {"id": "E15", "label": "PRIORITY HMAC 100K",
     "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000, "algo": "HMAC-SHA256"},
]


def cleanup():
    """Stop all containers and clean volumes."""
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "--profile", "attack",
         "down", "-v", "--remove-orphans"],
        cwd=HARDWARE_DIR, capture_output=True, timeout=30
    )
    time.sleep(2)


def run_experiment(exp):
    """Run a single experiment and return results."""
    exp_id = exp["id"]
    label = exp["label"]
    
    print(f"\n{'='*60}")
    print(f"  {exp_id}: {label}")
    print(f"  Mode: {exp['mode']}, Workers: {exp['workers']}, "
          f"Queue: {exp['queue_size']}, Attack: {exp['attack_rate']} pps")
    print(f"{'='*60}\n")
    
    cleanup()
    
    env = os.environ.copy()
    env["DURATION"] = str(DURATION)
    env["GOOSE_ALGORITHM"] = exp["algo"]
    env["QUEUE_MODE"] = exp["mode"]
    env["WORKERS"] = str(exp["workers"])
    env["QUEUE_SIZE"] = str(exp["queue_size"])
    env["ATTACK_RATE"] = str(exp["attack_rate"])
    
    # Choose profile based on whether attack is needed
    profile = "attack" if exp["attack_rate"] > 0 else "default"
    
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
    exp_dir = os.path.join(RESULTS_DIR, f"v3_{exp_id}")
    os.makedirs(exp_dir, exist_ok=True)
    
    with open(os.path.join(exp_dir, "output.txt"), "w") as f:
        f.write(output)
    
    # Copy CSV results
    csv_src = os.path.join(RESULTS_DIR, "subscriber_timing.csv")
    if os.path.exists(csv_src):
        shutil.copy2(csv_src, os.path.join(exp_dir, "subscriber_timing.csv"))
    
    # Save parsed metrics
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
        
        # Find the FINAL REPORT section
        if "FINAL REPORT" in line:
            continue
            
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
                        metrics["p95_latency_us"] = float(p.split(":")[-1].strip().replace(" us", ""))
                    elif "p99:" in p:
                        metrics["p99_latency_us"] = float(p.split(":")[-1].strip().replace(" us", ""))
            except: pass
        
        if "Deadline Miss:" in line:
            try:
                val = line.split("Deadline Miss:")[-1].strip().split("%")[0].strip().split(",")[0]
                metrics["deadline_miss_pct"] = float(val)
            except: pass
            
            if "Peak:" in line:
                try: metrics["queue_peak"] = int(line.split("Peak:")[-1].split(",")[0].strip())
                except: pass
            if "Drops:" in line:
                try: metrics["queue_drops"] = int(line.split("Drops:")[-1].strip())
                except: pass
        
        if "H=" in line and "N=" in line and "L=" in line:
            try:
                for seg in line.split():
                    if seg.startswith("H="):
                        metrics["classified_high"] = int(seg.split("=")[1])
                    elif seg.startswith("N="):
                        metrics["classified_normal"] = int(seg.split("=")[1])
                    elif seg.startswith("L="):
                        metrics["classified_low"] = int(seg.split("=")[1])
                    elif seg.startswith("DROP="):
                        metrics["classified_dropped"] = int(seg.split("=")[1])
            except: pass
        
        if "Scheduler overhead:" in line:
            try:
                metrics["scheduler_overhead_us"] = float(
                    line.split("overhead:")[-1].strip().split("us")[0].strip())
            except: pass
        
        if "Queue drops:" in line or "Queue Drops:" in line:
            try: metrics["queue_drops"] = int(line.split(":")[-1].strip())
            except: pass
    
    return metrics


def print_metrics(m):
    """Print a summary of experiment metrics."""
    print(f"\n  ┌─ Results ─────────────────────────────────────────┐")
    print(f"  │ Total: {m['total_frames']:>8}  Valid: {m['valid_frames']:>6}  Invalid: {m['invalid_frames']:>8} │")
    print(f"  │ Latency: Mean={m['mean_latency_us']:>12.1f} µs                  │")
    print(f"  │          P95 ={m['p95_latency_us']:>12.1f} µs                  │")
    print(f"  │          P99 ={m['p99_latency_us']:>12.1f} µs                  │")
    print(f"  │ Deadline Miss: {m['deadline_miss_pct']:>6.2f}%                        │")
    if m["mode"] == "fifo":
        print(f"  │ Queue Peak: {m['queue_peak']:>6}  Drops: {m['queue_drops']:>8}          │")
    else:
        print(f"  │ Classified: H={m['classified_high']} N={m['classified_normal']} L={m['classified_low']} D={m['classified_dropped']}│")
        print(f"  │ Scheduler: {m['scheduler_overhead_us']:.2f} µs/call                   │")
    print(f"  └────────────────────────────────────────────────────┘")


def write_summary_csv(all_metrics):
    """Write summary CSV with all experiments."""
    summary_path = os.path.join(RESULTS_DIR, "v3_summary.csv")
    
    fields = ["id", "label", "mode", "workers", "queue_size", "attack_rate", "algo",
              "total_frames", "valid_frames", "invalid_frames",
              "mean_latency_us", "p95_latency_us", "p99_latency_us",
              "deadline_miss_pct", "queue_peak", "queue_drops",
              "scheduler_overhead_us",
              "classified_high", "classified_normal", "classified_low", "classified_dropped"]
    
    with open(summary_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for m in all_metrics:
            writer.writerow({k: m.get(k, "") for k in fields})
    
    print(f"\n📊 Summary saved: {summary_path}")


def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  GridPulse Comprehensive Evaluation Suite v3            ║")
    print("║  IEEE Access — Full Comparison Matrix                   ║")
    print(f"║  {len(EXPERIMENTS)} experiments × {DURATION}s each = ~{len(EXPERIMENTS)*DURATION//60} min total         ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    all_metrics = []
    
    for i, exp in enumerate(EXPERIMENTS):
        print(f"\n{'▓'*60}")
        print(f"  EXPERIMENT {i+1}/{len(EXPERIMENTS)}")
        print(f"{'▓'*60}")
        
        metrics = run_experiment(exp)
        all_metrics.append(metrics)
        
        # Brief cooldown between experiments
        time.sleep(3)
    
    # Final cleanup
    cleanup()
    
    # Write summary
    write_summary_csv(all_metrics)
    
    # Print comparison table
    print("\n" + "="*90)
    print("  COMPREHENSIVE COMPARISON TABLE")
    print("="*90)
    print(f"{'ID':<5} {'Config':<30} {'Attack':>8} {'Mean(µs)':>12} {'P99(µs)':>12} {'Miss%':>8} {'Peak':>6}")
    print("-"*90)
    for m in all_metrics:
        config = f"{m['mode']}+{m['workers']}w+q{m['queue_size']}"
        print(f"{m['id']:<5} {config:<30} {m['attack_rate']:>8} "
              f"{m['mean_latency_us']:>12.1f} {m['p99_latency_us']:>12.1f} "
              f"{m['deadline_miss_pct']:>7.2f}% {m['queue_peak']:>6}")
    print("="*90)
    
    print(f"\n✅ All {len(EXPERIMENTS)} experiments complete!")
    print(f"📁 Results: {RESULTS_DIR}/v3_*/")


if __name__ == "__main__":
    main()
