#!/usr/bin/env python3
"""
Multi-source (random-MAC) flood experiment (reviewer #3).

With a single attacker MAC, per-source rate tracking drops 99% of the flood and
priority ordering is unnecessary. A randomized-MAC flood defeats per-source rate
tracking (each MAC appears once, low-rate -> admitted to LOW for discovery), so
the ONLY thing that keeps trip frames on time is priority isolation (Class H
bypasses the flooded LOW queue). This is the empirical test of Theorems 1-3.

Configs (emulated Cortex-A9, 573 us, 100K pps, random-MAC flood):
  MS-FIFO   : fifo baseline            -> expect ~2.3 s, 100% miss
  MS-PQAC   : full priority            -> expect bounded p99, low miss
  MS-NOPRIO : priority, NO_PRIORITY    -> expect high miss (priority removed)
"""
import subprocess, os, time, csv, re, statistics

HW = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HW, "results")
COMPOSE = os.path.join(HW, "docker-compose.yml")
DURATION = int(os.environ.get("MS_DURATION", "20"))
REPS = int(os.environ.get("MS_REPS", "3"))
A9 = "573"

# id, mode, ablation
CONFIGS = [
    ("MS-FIFO",   "fifo",     None),
    ("MS-PQAC",   "priority", None),
    ("MS-NOPRIO", "priority", "ABLATION_NO_PRIORITY"),
]


def cleanup():
    subprocess.run(["docker", "compose", "-f", COMPOSE, "--profile", "attack",
                    "down", "-v", "--remove-orphans"], cwd=HW,
                   capture_output=True, timeout=60)
    time.sleep(1)


def parse(output):
    m = {"valid": 0, "mean_us": 0.0, "p99_us": 0.0, "miss_pct": 0.0,
         "cls_high": 0, "cls_normal": 0, "cls_low": 0, "cls_drop": 0,
         "queue_peak": 0, "drops": 0}
    final = output.split("FINAL REPORT")[-1] if "FINAL REPORT" in output else output
    t = re.search(r"Total:\s*(\d+),\s*Valid:\s*(\d+)", final)
    if t:
        m["valid"] = int(t[2])
    lat = re.search(r"Mean:\s*([\d.]+)\s*us,\s*p95:\s*[\d.]+\s*us,\s*p99:\s*([\d.]+)", final)
    if lat:
        m["mean_us"], m["p99_us"] = float(lat[1]), float(lat[2])
    mi = re.search(r"Deadline Miss:\s*([\d.]+)%", final)
    if mi:
        m["miss_pct"] = float(mi[1])
    q = re.search(r"Queue Peak:\s*(\d+),\s*Drops:\s*(\d+)", final)
    if q:
        m["queue_peak"], m["drops"] = int(q[1]), int(q[2])
    c = re.search(r"Classification:\s*H=(\d+)\s*N=(\d+)\s*L=(\d+)\s*DROP=(\d+)", final)
    if c:
        m["cls_high"], m["cls_normal"], m["cls_low"], m["cls_drop"] = \
            int(c[1]), int(c[2]), int(c[3]), int(c[4])
    return m


def run_one(cfg, rep):
    cid, mode, abl = cfg
    cleanup()
    env = os.environ.copy()
    env.update({
        "DURATION": str(DURATION), "PUB_DURATION": str(DURATION + 20),
        "GOOSE_ALGORITHM": "RSA-2048", "QUEUE_MODE": mode,
        "WORKERS": "1", "QUEUE_SIZE": "4096", "ATTACK_RATE": "100000",
        "SERVICE_TIME_US": A9, "T_NORMAL": "50", "T_BURST": "500",
        "T_FLOOD": "1000", "HEARTBEAT_MS": "200", "TRIP_INTERVAL": "5",
        "RANDOM_MAC": "1",
        "ABLATION_NO_MAC": "", "ABLATION_NO_RATE": "", "ABLATION_NO_PRIORITY": "",
    })
    if abl:
        env[abl] = "1"
    cmd = ["docker", "compose", "-f", COMPOSE, "--profile", "attack",
           "up", "--abort-on-container-exit"]
    try:
        r = subprocess.run(cmd, cwd=HW, env=env, capture_output=True,
                           text=True, timeout=DURATION + 90)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        cleanup(); out = ""
    m = parse(out)
    m.update({"id": cid, "rep": rep, "mode": mode, "ablation": abl or ""})
    d = os.path.join(RES, f"ms_{cid}_r{rep}")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "output.txt"), "w") as f:
        f.write(out)
    return m


def main():
    rows = []
    n = 0; total = len(CONFIGS) * REPS
    for cfg in CONFIGS:
        for rep in range(1, REPS + 1):
            n += 1
            print(f"[{n}/{total}] {cfg[0]} rep{rep} ...", flush=True)
            m = run_one(cfg, rep)
            print(f"   valid={m['valid']} mean={m['mean_us']:.1f} p99={m['p99_us']:.1f} "
                  f"miss={m['miss_pct']:.2f}% cls(H/N/L/D)="
                  f"{m['cls_high']}/{m['cls_normal']}/{m['cls_low']}/{m['cls_drop']}",
                  flush=True)
            rows.append(m)
            with open(os.path.join(RES, "ms_raw.csv"), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader(); w.writerows(rows)
    cleanup()
    agg = {}
    for r in rows:
        agg.setdefault(r["id"], []).append(r)
    with open(os.path.join(RES, "ms_summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "reps", "mean_us", "p99_us", "miss_pct", "miss_sd",
                    "cls_high", "cls_low", "cls_drop"])
        for cid, lst in agg.items():
            misses = [x["miss_pct"] for x in lst]
            w.writerow([cid, len(lst),
                        round(statistics.mean([x["mean_us"] for x in lst]), 1),
                        round(statistics.mean([x["p99_us"] for x in lst]), 1),
                        round(statistics.mean(misses), 3),
                        round(statistics.pstdev(misses), 3) if len(misses) > 1 else 0.0,
                        round(statistics.mean([x["cls_high"] for x in lst]), 0),
                        round(statistics.mean([x["cls_low"] for x in lst]), 0),
                        round(statistics.mean([x["cls_drop"] for x in lst]), 0)])
    print("\nDONE -> results/ms_summary.csv")


if __name__ == "__main__":
    main()
