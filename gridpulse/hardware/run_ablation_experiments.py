#!/usr/bin/env python3
"""
GridPulse Ablation Study Suite
Evaluates individual contributions of PQAC components:
  1. Full PQAC (MAC + Rate + Priority Queue)
  2. No MAC Allowlist (--no-mac)
  3. No Rate Anomaly Detection (--no-rate)
  4. No Priority Scheduling (--no-priority)
  5. Pure FIFO Baseline (No defense)
Under 100K pps RSA-2048 CIL-DoS attack.
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
DURATION = 15

ABLATION_CONFIGS = [
    {
        "id": "ABL-01",
        "label": "Full PQAC (All Mechanisms)",
        "mode": "priority",
        "attack_rate": 100000,
        "algo": "RSA-2048",
        "env_flags": {}
    },
    {
        "id": "ABL-02",
        "label": "No MAC Allowlist (Rate + Priority only)",
        "mode": "priority",
        "attack_rate": 100000,
        "algo": "RSA-2048",
        "env_flags": {"ABLATION_NO_MAC": "1"}
    },
    {
        "id": "ABL-03",
        "label": "No Rate Anomaly (MAC + Priority only)",
        "mode": "priority",
        "attack_rate": 100000,
        "algo": "RSA-2048",
        "env_flags": {"ABLATION_NO_RATE": "1"}
    },
    {
        "id": "ABL-04",
        "label": "No Priority Scheduling (MAC + Rate in FIFO)",
        "mode": "priority",
        "attack_rate": 100000,
        "algo": "RSA-2048",
        "env_flags": {"ABLATION_NO_PRIORITY": "1"}
    },
    {
        "id": "ABL-05",
        "label": "Pure FIFO (No Defense)",
        "mode": "fifo",
        "attack_rate": 100000,
        "algo": "RSA-2048",
        "env_flags": {}
    },
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
        "mode": exp["mode"],
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
    print(f"  Mode: {exp['mode']}, Attack: {exp['attack_rate']} pps")
    print(f"{'='*65}\n")

    cleanup()

    env = os.environ.copy()
    env["DURATION"] = str(DURATION)
    env["PUB_DURATION"] = str(DURATION + 30)
    env["GOOSE_ALGORITHM"] = exp["algo"]
    env["QUEUE_MODE"] = exp["mode"]
    env["WORKERS"] = "1"
    env["QUEUE_SIZE"] = "4096"
    env["ATTACK_RATE"] = str(exp["attack_rate"])
    env["HEARTBEAT_MS"] = "200"
    env["TRIP_INTERVAL"] = "5"
    env.update(exp["env_flags"])

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
          f"P99: {metrics['p99_latency_us']:.2f} µs | Deadline Miss: {metrics['deadline_miss_pct']:.2f}% | "
          f"Peak: {metrics['queue_peak']}")

    cleanup()
    return metrics


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    all_metrics = []

    print("\n" + "#"*65)
    print("  GRIDPULSE ABLATION STUDY RUNNER")
    print(f"  Total Experiments: {len(ABLATION_CONFIGS)} | Duration: {DURATION}s each")
    print("#"*65)

    start_all = time.time()
    for exp in ABLATION_CONFIGS:
        m = run_experiment(exp)
        all_metrics.append(m)

    elapsed = time.time() - start_all
    print(f"\nAll ablation experiments finished in {elapsed/60.0:.2f} minutes.")

    # Save JSON summary
    out_json = os.path.join(RESULTS_DIR, "ablation_experiment_summary.json")
    with open(out_json, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"Results saved to: {out_json}")

    # Print summary table
    print("\n" + "="*85)
    print(f"{'ID':<10} | {'Configuration':<38} | {'Mean (µs)':<10} | {'P99 (µs)':<10} | {'Miss %':<8} | {'Queue Peak':<10}")
    print("="*85)
    for m in all_metrics:
        print(f"{m['id']:<10} | {m['label']:<38} | {m['mean_latency_us']:<10.2f} | {m['p99_latency_us']:<10.2f} | {m['deadline_miss_pct']:<8.2f}% | {m['queue_peak']:<10}")
    print("="*85)


if __name__ == "__main__":
    main()
