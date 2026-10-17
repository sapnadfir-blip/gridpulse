#!/usr/bin/env python3
"""
GridPulse Post-Quantum Cryptography (PQC) Evaluation Suite
Evaluates CIL-DoS Vulnerability & PQAC Defense Across:
  - NIST ML-DSA-44 (Dilithium2) - Lattice-based Primary Standard
  - NIST ML-DSA-87 (Dilithium5) - Lattice-based High-Security
  - NIST SLH-DSA (SPHINCS+-128s) - Stateless Hash-based Signature
  - FALCON-512 - Fast Lattice-based Signature

Generates empirical evidence for IEEE Transactions on Smart Grid.
"""

import subprocess
import os
import time
import json
import re

HARDWARE_DIR = "/Users/apple/GridPulse-BlackHat-Project/gridpulse/hardware"
RESULTS_DIR = os.path.join(HARDWARE_DIR, "results")
COMPOSE_FILE = os.path.join(HARDWARE_DIR, "docker-compose.yml")
DOCKER = "/usr/local/bin/docker"
DURATION = 15  # seconds per experiment for fast and reliable runs

PQC_EXPERIMENTS = [
    # ── Group 1: Dilithium2 (ML-DSA-44) ───────────────────────────
    {"id": "PQC-D2-BASE", "label": "Dilithium2 Baseline (No Attack)",
     "algo": "Dilithium2", "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 0},
    {"id": "PQC-D2-FIFO", "label": "Dilithium2 CIL-DoS (100K pps, FIFO)",
     "algo": "Dilithium2", "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 100000},
    {"id": "PQC-D2-PQAC", "label": "Dilithium2 PQAC Defense (100K pps, Priority)",
     "algo": "Dilithium2", "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000},

    # ── Group 2: Dilithium5 (ML-DSA-87) ───────────────────────────
    {"id": "PQC-D5-BASE", "label": "Dilithium5 Baseline (No Attack)",
     "algo": "Dilithium5", "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 0},
    {"id": "PQC-D5-FIFO", "label": "Dilithium5 CIL-DoS (100K pps, FIFO)",
     "algo": "Dilithium5", "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 100000},
    {"id": "PQC-D5-PQAC", "label": "Dilithium5 PQAC Defense (100K pps, Priority)",
     "algo": "Dilithium5", "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000},

    # ── Group 3: SPHINCS+-128s (SLH-DSA) ──────────────────────────
    {"id": "PQC-SP-BASE", "label": "SPHINCS+-128s Baseline (No Attack)",
     "algo": "SPHINCS-128s", "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 0},
    {"id": "PQC-SP-FIFO", "label": "SPHINCS+-128s CIL-DoS (100K pps, FIFO)",
     "algo": "SPHINCS-128s", "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 100000},
    {"id": "PQC-SP-PQAC", "label": "SPHINCS+-128s PQAC Defense (100K pps, Priority)",
     "algo": "SPHINCS-128s", "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000},

    # ── Group 4: FALCON-512 ───────────────────────────────────────
    {"id": "PQC-FA-BASE", "label": "FALCON-512 Baseline (No Attack)",
     "algo": "FALCON-512", "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 0},
    {"id": "PQC-FA-FIFO", "label": "FALCON-512 CIL-DoS (100K pps, FIFO)",
     "algo": "FALCON-512", "mode": "fifo", "workers": 1, "queue_size": 4096, "attack_rate": 100000},
    {"id": "PQC-FA-PQAC", "label": "FALCON-512 PQAC Defense (100K pps, Priority)",
     "algo": "FALCON-512", "mode": "priority", "workers": 1, "queue_size": 4096, "attack_rate": 100000},
]


def cleanup():
    subprocess.run(
        [DOCKER, "compose", "-f", COMPOSE_FILE, "--profile", "attack",
         "down", "-v", "--remove-orphans"],
        cwd=HARDWARE_DIR, capture_output=True, timeout=30
    )
    time.sleep(2)


def parse_output(output, exp):
    metrics = {
        "id": exp["id"],
        "label": exp["label"],
        "algo": exp["algo"],
        "mode": exp["mode"],
        "workers": exp["workers"],
        "attack_rate": exp["attack_rate"],
        "total_frames": 0,
        "valid_frames": 0,
        "invalid_frames": 0,
        "mean_latency_us": 0.0,
        "p95_latency_us": 0.0,
        "p99_latency_us": 0.0,
        "deadline_miss_pct": 0.0,
        "queue_peak": 0,
        "queue_drops": 0,
        "classified_high": 0,
        "classified_normal": 0,
        "classified_low": 0,
        "classified_dropped": 0,
    }

    in_report = False
    for line in output.split("\n"):
        line = line.strip()
        if "FINAL REPORT" in line:
            in_report = True
            continue

        if in_report:
            if "Total:" in line and "Valid:" in line:
                m = re.search(r"Total:\s*(\d+),\s*Valid:\s*(\d+),\s*Invalid:\s*(\d+)", line)
                if m:
                    metrics["total_frames"] = int(m.group(1))
                    metrics["valid_frames"] = int(m.group(2))
                    metrics["invalid_frames"] = int(m.group(3))

            if "Mean:" in line and "p95:" in line:
                m = re.search(r"Mean:\s*([\d\.]+)\s*us,\s*p95:\s*([\d\.]+)\s*us,\s*p99:\s*([\d\.]+)\s*us", line)
                if m:
                    metrics["mean_latency_us"] = float(m.group(1))
                    metrics["p95_latency_us"] = float(m.group(2))
                    metrics["p99_latency_us"] = float(m.group(3))

            if "Deadline Miss:" in line:
                m = re.search(r"Deadline Miss:\s*([\d\.]+)%", line)
                if m:
                    metrics["deadline_miss_pct"] = float(m.group(1))
                m_peak = re.search(r"Queue Peak:\s*(\d+)", line)
                if m_peak:
                    metrics["queue_peak"] = int(m_peak.group(1))
                m_drops = re.search(r"Drops:\s*(\d+)", line)
                if m_drops:
                    metrics["queue_drops"] = int(m_drops.group(1))

            if "Classification:" in line:
                m = re.search(r"H=(\d+)\s+N=(\d+)\s+L=(\d+)\s+DROP=(\d+)", line)
                if m:
                    metrics["classified_high"] = int(m.group(1))
                    metrics["classified_normal"] = int(m.group(2))
                    metrics["classified_low"] = int(m.group(3))
                    metrics["classified_dropped"] = int(m.group(4))

    return metrics


def run_experiment(exp):
    exp_id = exp["id"]
    label = exp["label"]

    print(f"\n{'='*65}")
    print(f"  RUNNING {exp_id}: {label}")
    print(f"  Algorithm: {exp['algo']}, Mode: {exp['mode']}, Attack: {exp['attack_rate']} pps")
    print(f"{'='*65}\n")

    cleanup()

    env = os.environ.copy()
    env["DURATION"] = str(DURATION)
    env["PUB_DURATION"] = str(DURATION + 30)
    env["GOOSE_ALGORITHM"] = exp["algo"]
    env["QUEUE_MODE"] = exp["mode"]
    env["WORKERS"] = str(exp["workers"])
    env["QUEUE_SIZE"] = str(exp["queue_size"])
    env["ATTACK_RATE"] = str(exp["attack_rate"])
    env["HEARTBEAT_MS"] = "200"
    env["TRIP_INTERVAL"] = "5"

    profile = "attack" if exp["attack_rate"] > 0 else "default"
    cmd = [DOCKER, "compose", "-f", COMPOSE_FILE]
    if profile == "attack":
        cmd += ["--profile", "attack"]
    cmd += ["up", "--abort-on-container-exit"]

    try:
        proc = subprocess.run(
            cmd, cwd=HARDWARE_DIR, env=env,
            capture_output=True, text=True,
            timeout=DURATION + 45
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        print("  [WARN] Timeout reached, cleaning up...")
        cleanup()
        output = ""

    metrics = parse_output(output, exp)
    print(f"  Results -> Total: {metrics['total_frames']} | Mean: {metrics['mean_latency_us']:.2f} µs | "
          f"P99: {metrics['p99_latency_us']:.2f} µs | Deadline Miss: {metrics['deadline_miss_pct']:.2f}%")

    cleanup()
    return metrics


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    all_metrics = []

    print("\n" + "#"*65)
    print("  GRIDPULSE POST-QUANTUM CRYPTOGRAPHY CIL-DOS TESTBED RUNNER")
    print(f"  Total Experiments: {len(PQC_EXPERIMENTS)} | Duration: {DURATION}s each")
    print("#"*65)

    start_all = time.time()
    for exp in PQC_EXPERIMENTS:
        m = run_experiment(exp)
        all_metrics.append(m)

    elapsed = time.time() - start_all
    print(f"\nAll experiments finished in {elapsed/60.0:.2f} minutes.")

    # Save JSON summary
    out_json = os.path.join(RESULTS_DIR, "pqc_experiment_summary.json")
    with open(out_json, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"Results saved to: {out_json}")

    # Print summary table
    print("\n" + "="*80)
    print(f"{'ID':<14} | {'Algorithm':<13} | {'Attack':<9} | {'Mode':<8} | {'Mean (µs)':<10} | {'P99 (µs)':<10} | {'Miss %':<8}")
    print("="*80)
    for m in all_metrics:
        print(f"{m['id']:<14} | {m['algo']:<13} | {m['attack_rate']:<9} | {m['mode']:<8} | {m['mean_latency_us']:<10.2f} | {m['p99_latency_us']:<10.2f} | {m['deadline_miss_pct']:<8.2f}%")
    print("="*80)


if __name__ == "__main__":
    main()
