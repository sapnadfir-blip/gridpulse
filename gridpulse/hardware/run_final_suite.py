#!/usr/bin/env python3
"""
Revision-2 suite: capture delivered AND offered (publisher Sent) for true
delivery ratios, re-run HOST configs with variance (real measured, not K*S),
and re-run host+relay ablations consistently. 5 reps for CIs on key configs.
"""
import subprocess, os, time, csv, re, statistics

HW = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HW, "results")
COMPOSE = os.path.join(HW, "docker-compose.yml")
DURATION = int(os.environ.get("FS_DURATION", "20"))
REPS = int(os.environ.get("FS_REPS", "5"))

# id, service_us, mode, attack, ablation, spoof, random_mac
CFG = [
    # HOST (measured, S=0) core + ablations  -> fixes P4/P5
    ("H-FIFO",     "0",   "fifo",     100000, None,                   None, 0),
    ("H-PQAC",     "0",   "priority", 100000, None,                   None, 0),
    ("H-NOMAC",    "0",   "priority", 100000, "ABLATION_NO_MAC",      None, 0),
    ("H-NORATE",   "0",   "priority", 100000, "ABLATION_NO_RATE",     None, 0),
    ("H-NOPRIO",   "0",   "priority", 100000, "ABLATION_NO_PRIORITY", None, 0),
    # RELAY core for delivered/offered (S=573)
    ("R-FIFO",     "573", "fifo",     100000, None,                   None, 0),
    ("R-PQAC",     "573", "priority", 100000, None,                   None, 0),
    # Spoofing + multi-source for delivered/offered
    ("R-SPOOF",    "573", "priority", 100000, None,                   "PUBLISHER", 0),
    ("R-RANDMAC",  "573", "priority", 100000, None,                   None, 1),
    ("R-RANDNOPRIO","573","priority", 100000, "ABLATION_NO_PRIORITY", None, 1),
]


def cleanup():
    subprocess.run(["docker","compose","-f",COMPOSE,"--profile","attack",
                    "down","-v","--remove-orphans"], cwd=HW, capture_output=True, timeout=60)
    time.sleep(1)


def pub_mac():
    try:
        r = subprocess.run(["docker","exec","ied-publisher","cat",
                            "/sys/class/net/eth0/address"], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or "02:42:ac:14:00:0a"
    except Exception:
        return "02:42:ac:14:00:0a"


def parse(output):
    m = {"delivered":0,"offered":0,"mean_us":0.0,"p99_us":0.0,"miss_pct":0.0}
    final = output.split("FINAL REPORT")[-1] if "FINAL REPORT" in output else output
    t = re.search(r"Total:\s*\d+,\s*Valid:\s*(\d+)", final)
    if t: m["delivered"] = int(t[1])
    lat = re.search(r"Mean:\s*([\d.]+)\s*us,\s*p95:\s*[\d.]+\s*us,\s*p99:\s*([\d.]+)", final)
    if lat: m["mean_us"], m["p99_us"] = float(lat[1]), float(lat[2])
    mi = re.search(r"Deadline Miss:\s*([\d.]+)%", final)
    if mi: m["miss_pct"] = float(mi[1])
    # offered = max publisher "Sent: N" across the whole combined log
    sents = [int(x) for x in re.findall(r"Sent:\s*(\d+)", output)]
    if sents: m["offered"] = max(sents)
    return m


def run_one(cfg, rep):
    cid, svc, mode, attack, abl, spoof, rnd = cfg
    cleanup()
    env = os.environ.copy()
    env.update({
        "DURATION":str(DURATION),"PUB_DURATION":str(DURATION+20),
        "GOOSE_ALGORITHM":"RSA-2048","QUEUE_MODE":mode,"WORKERS":"1",
        "QUEUE_SIZE":"4096","ATTACK_RATE":str(attack),"SERVICE_TIME_US":svc,
        "T_NORMAL":"50","T_BURST":"500","T_FLOOD":"1000",
        "HEARTBEAT_MS":"200","TRIP_INTERVAL":"5",
        "ABLATION_NO_MAC":"","ABLATION_NO_RATE":"","ABLATION_NO_PRIORITY":"",
        "RANDOM_MAC":"1" if rnd else "",
    })
    if abl: env[abl] = "1"
    if spoof == "PUBLISHER":
        subprocess.run(["docker","compose","-f",COMPOSE,"up","-d","publisher"],
                       cwd=HW, env=env, capture_output=True, timeout=40)
        time.sleep(3); env["SPOOF_MAC"] = pub_mac()
    cmd = ["docker","compose","-f",COMPOSE,"--profile","attack","up","--abort-on-container-exit"]
    try:
        r = subprocess.run(cmd, cwd=HW, env=env, capture_output=True, text=True, timeout=DURATION+90)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        cleanup(); out = ""
    m = parse(out); m.update({"id":cid,"rep":rep})
    d = os.path.join(RES, f"fs_{cid}_r{rep}"); os.makedirs(d, exist_ok=True)
    open(os.path.join(d,"output.txt"),"w").write(out)
    return m


def main():
    rows=[]; n=0; total=len(CFG)*REPS
    for cfg in CFG:
        for rep in range(1,REPS+1):
            n+=1; print(f"[{n}/{total}] {cfg[0]} r{rep}",flush=True)
            m=run_one(cfg,rep)
            ratio = (m["delivered"]/m["offered"]*100) if m["offered"] else 0
            print(f"   deliv={m['delivered']} offered={m['offered']} "
                  f"({ratio:.0f}%) mean={m['mean_us']:.1f} p99={m['p99_us']:.1f} miss={m['miss_pct']:.2f}%",flush=True)
            rows.append(m)
            with open(os.path.join(RES,"fs_raw.csv"),"w",newline="") as f:
                w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    cleanup()
    agg={}
    for r in rows: agg.setdefault(r["id"],[]).append(r)
    with open(os.path.join(RES,"fs_summary.csv"),"w",newline="") as f:
        w=csv.writer(f)
        w.writerow(["id","reps","mean_us","mean_sd","p99_us","miss_pct","miss_sd",
                    "delivered_mean","offered_mean","delivery_ratio_pct"])
        for cid,lst in agg.items():
            means=[x["mean_us"] for x in lst]; misses=[x["miss_pct"] for x in lst]
            dl=[x["delivered"] for x in lst]; of=[x["offered"] for x in lst]
            om=statistics.mean(of) if of else 0
            w.writerow([cid,len(lst),
                        round(statistics.mean(means),1),
                        round(statistics.pstdev(means),1) if len(means)>1 else 0,
                        round(statistics.mean([x["p99_us"] for x in lst]),1),
                        round(statistics.mean(misses),3),
                        round(statistics.pstdev(misses),3) if len(misses)>1 else 0,
                        round(statistics.mean(dl),1), round(om,1),
                        round(statistics.mean(dl)/om*100,1) if om else 0])
    print("DONE -> results/fs_summary.csv")


if __name__=="__main__":
    main()
