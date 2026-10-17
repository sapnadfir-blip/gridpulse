#!/usr/bin/env python3
"""
Reviewer-revision experiments (v5): measured embedded-relay emulation.

Converts the previously ANALYTICAL Cortex-A9 Panel B into MEASURED data using
a calibrated busy-wait (SERVICE_TIME_US=573) that throttles the verifier to
mu = 1745 fps, as suggested by the TSG reviewer. Also runs the slow-relay
ablation (does priority matter once the host is slow?) and a first-class
MAC-spoofing evaluation.

Emulation caveat: a busy-wait on M2 silicon reproduces the A9 *service rate*,
not its cache/memory microarchitecture. Results are labelled "emulated relay".
"""
import subprocess, os, shutil, time, json, csv, re, statistics

HW = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HW, "results")
COMPOSE = os.path.join(HW, "docker-compose.yml")

DURATION = int(os.environ.get("ER_DURATION", "20"))
REPS = int(os.environ.get("ER_REPS", "3"))
A9 = "573"   # calibrated Cortex-A9 pipeline service time (us)

# id, mode, workers, queue, attack, service_us, ablation flag, spoof
EXPERIMENTS = [
    # --- Embedded-relay Panel B (MEASURED via 573us emulation), 100K pps ---
    ("ER-FIFO-1W-4K",  "fifo",     1, 4096,  100000, A9,  None,            None),
    ("ER-FIFO-1W-16K", "fifo",     1, 16384, 100000, A9,  None,            None),
    ("ER-FIFO-4W-4K",  "fifo",     4, 4096,  100000, A9,  None,            None),
    ("ER-PQAC-1W-4K",  "priority", 1, 4096,  100000, A9,  None,            None),
    # --- Slow-relay ablation: does PRIORITY matter when host is slow? ---
    ("ER-ABL-NOMAC",   "priority", 1, 4096,  100000, A9,  "ABLATION_NO_MAC",      None),
    ("ER-ABL-NORATE",  "priority", 1, 4096,  100000, A9,  "ABLATION_NO_RATE",     None),
    ("ER-ABL-NOPRIO",  "priority", 1, 4096,  100000, A9,  "ABLATION_NO_PRIORITY", None),
    # --- First-class MAC spoofing evaluation (emulated relay) ---
    ("SP-NOSPOOF-100K","priority", 1, 4096,  100000, A9,  None,            None),
    ("SP-SPOOF-100K",  "priority", 1, 4096,  100000, A9,  None,            "PUBLISHER"),
    ("SP-SPOOF-10K",   "priority", 1, 4096,  10000,  A9,  None,            "PUBLISHER"),
]


def cleanup():
    subprocess.run(["docker", "compose", "-f", COMPOSE, "--profile", "attack",
                    "down", "-v", "--remove-orphans"],
                   cwd=HW, capture_output=True, timeout=60)
    time.sleep(1)


def pub_mac():
    try:
        r = subprocess.run(["docker", "exec", "ied-publisher", "cat",
                            "/sys/class/net/eth0/address"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or "02:42:ac:14:00:0a"
    except Exception:
        return "02:42:ac:14:00:0a"


def parse(output):
    m = {"total": 0, "valid": 0, "invalid": 0, "mean_us": 0.0,
         "p95_us": 0.0, "p99_us": 0.0, "miss_pct": 0.0,
         "queue_peak": 0, "drops": 0,
         "cls_high": 0, "cls_normal": 0, "cls_low": 0, "cls_drop": 0}
    # Use the FINAL REPORT block (legit-frame stats)
    final = output.split("FINAL REPORT")[-1] if "FINAL REPORT" in output else output
    t = re.search(r"Total:\s*(\d+),\s*Valid:\s*(\d+),\s*Invalid:\s*(\d+)", final)
    if t:
        m["total"], m["valid"], m["invalid"] = int(t[1]), int(t[2]), int(t[3])
    lat = re.search(r"Mean:\s*([\d.]+)\s*us,\s*p95:\s*([\d.]+)\s*us,\s*p99:\s*([\d.]+)", final)
    if lat:
        m["mean_us"], m["p95_us"], m["p99_us"] = float(lat[1]), float(lat[2]), float(lat[3])
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


def run_one(exp, rep):
    eid, mode, workers, queue, attack, svc, abl, spoof = exp
    cleanup()
    env = os.environ.copy()
    env.update({
        "DURATION": str(DURATION), "PUB_DURATION": str(DURATION + 20),
        "GOOSE_ALGORITHM": "RSA-2048", "QUEUE_MODE": mode,
        "WORKERS": str(workers), "QUEUE_SIZE": str(queue),
        "ATTACK_RATE": str(attack), "SERVICE_TIME_US": svc,
        "T_NORMAL": "50", "T_BURST": "500", "T_FLOOD": "1000",
        "HEARTBEAT_MS": "200", "TRIP_INTERVAL": "5",
        "ABLATION_NO_MAC": "", "ABLATION_NO_RATE": "", "ABLATION_NO_PRIORITY": "",
    })
    if abl:
        env[abl] = "1"

    if spoof == "PUBLISHER":
        subprocess.run(["docker", "compose", "-f", COMPOSE, "up", "-d", "publisher"],
                       cwd=HW, env=env, capture_output=True, timeout=40)
        time.sleep(3)
        env["SPOOF_MAC"] = pub_mac()
    cmd = ["docker", "compose", "-f", COMPOSE, "--profile", "attack",
           "up", "--abort-on-container-exit"]
    try:
        r = subprocess.run(cmd, cwd=HW, env=env, capture_output=True,
                           text=True, timeout=DURATION + 90)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        cleanup()
        out = ""
    m = parse(out)
    m.update({"id": eid, "rep": rep, "mode": mode, "workers": workers,
              "queue": queue, "attack": attack, "service_us": svc,
              "ablation": abl or "", "spoof": spoof or ""})
    d = os.path.join(RES, f"v5_{eid}_r{rep}")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "output.txt"), "w") as f:
        f.write(out)
    return m


def main():
    os.makedirs(RES, exist_ok=True)
    rows = []
    total = len(EXPERIMENTS) * REPS
    n = 0
    for exp in EXPERIMENTS:
        for rep in range(1, REPS + 1):
            n += 1
            print(f"\n[{n}/{total}] {exp[0]} rep {rep} ...", flush=True)
            m = run_one(exp, rep)
            print(f"   valid={m['valid']} mean={m['mean_us']:.1f}us "
                  f"p99={m['p99_us']:.1f}us miss={m['miss_pct']:.2f}% "
                  f"peak={m['queue_peak']} drops={m['drops']} "
                  f"cls(H/N/L/D)={m['cls_high']}/{m['cls_normal']}/{m['cls_low']}/{m['cls_drop']}",
                  flush=True)
            rows.append(m)
            # incremental save
            with open(os.path.join(RES, "v5_raw.csv"), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader(); w.writerows(rows)
    cleanup()

    # aggregate mean +/- across reps
    agg = {}
    for r in rows:
        agg.setdefault(r["id"], []).append(r)
    with open(os.path.join(RES, "v5_summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "reps", "mean_us", "p99_us", "miss_pct", "miss_sd",
                    "valid_total", "queue_peak", "drops",
                    "cls_high", "cls_drop"])
        for eid, lst in agg.items():
            misses = [x["miss_pct"] for x in lst]
            w.writerow([
                eid, len(lst),
                round(statistics.mean([x["mean_us"] for x in lst]), 1),
                round(statistics.mean([x["p99_us"] for x in lst]), 1),
                round(statistics.mean(misses), 3),
                round(statistics.pstdev(misses), 3) if len(misses) > 1 else 0.0,
                sum(x["valid"] for x in lst),
                max(x["queue_peak"] for x in lst),
                round(statistics.mean([x["drops"] for x in lst]), 0),
                round(statistics.mean([x["cls_high"] for x in lst]), 0),
                round(statistics.mean([x["cls_drop"] for x in lst]), 0),
            ])
    print("\nDONE. Summary -> results/v5_summary.csv")


if __name__ == "__main__":
    main()
