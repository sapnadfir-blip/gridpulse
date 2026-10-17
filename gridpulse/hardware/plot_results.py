#!/usr/bin/env python3
"""Generate IEEE Access figures from v3 experiment results."""

import json
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 10,
    'axes.labelsize': 11,
    'axes.titlesize': 12,
    'legend.fontsize': 9,
    'figure.dpi': 300,
    'savefig.dpi': 300,
})

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
FIG_DIR = os.path.join(RESULTS_DIR, "figures_v3")
os.makedirs(FIG_DIR, exist_ok=True)

def load_metrics():
    """Load all v3 metrics."""
    metrics = {}
    for d in sorted(os.listdir(RESULTS_DIR)):
        if d.startswith("v3_E"):
            mpath = os.path.join(RESULTS_DIR, d, "metrics.json")
            if os.path.exists(mpath):
                with open(mpath) as f:
                    m = json.load(f)
                    metrics[m["id"]] = m
    return metrics

def fig1_attack_rate_vs_latency(metrics):
    """Fig 1: Mean latency vs attack rate — FIFO vs Priority."""
    rates = [0, 10000, 50000, 100000, 500000]
    fifo_ids = ["E01", "E02", "E03", "E04", "E05"]
    prio_ids = ["E09", "E10", "E11", "E12", "E13"]
    
    fifo_lat = [metrics[i]["mean_latency_us"] / 1000 for i in fifo_ids]  # ms
    prio_lat = [metrics[i]["mean_latency_us"] / 1000 for i in prio_ids]  # ms
    
    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    
    x = np.arange(len(rates))
    w = 0.35
    
    bars1 = ax.bar(x - w/2, fifo_lat, w, label='FIFO (No Defense)', color='#dc3545', alpha=0.85)
    bars2 = ax.bar(x + w/2, prio_lat, w, label='Priority Queue', color='#28a745', alpha=0.85)
    
    ax.axhline(y=3.0, color='black', linestyle='--', linewidth=1.5, label='3ms Deadline')
    
    ax.set_xlabel('Attack Rate (pps)')
    ax.set_ylabel('Mean End-to-End Latency (ms)')
    ax.set_title('CIL-DoS Attack: FIFO vs Priority Queue Defense')
    ax.set_xticks(x)
    ax.set_xticklabels(['0', '10K', '50K', '100K', '500K'])
    ax.set_yscale('log')
    ax.set_ylim(0.5, 20000)
    ax.legend(loc='upper left')
    ax.grid(axis='y', alpha=0.3)
    
    plt.savefig(os.path.join(FIG_DIR, "fig1_latency_vs_attack_rate.pdf"))
    plt.savefig(os.path.join(FIG_DIR, "fig1_latency_vs_attack_rate.png"))
    plt.close()
    print("  ✅ Fig 1: Latency vs Attack Rate")

def fig2_deadline_miss(metrics):
    """Fig 2: Deadline miss ratio — FIFO vs Priority."""
    rates = [0, 10000, 50000, 100000, 500000]
    fifo_ids = ["E01", "E02", "E03", "E04", "E05"]
    prio_ids = ["E09", "E10", "E11", "E12", "E13"]
    
    fifo_miss = [metrics[i]["deadline_miss_pct"] for i in fifo_ids]
    prio_miss = [metrics[i]["deadline_miss_pct"] for i in prio_ids]
    
    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    
    x = np.arange(len(rates))
    w = 0.35
    
    ax.bar(x - w/2, fifo_miss, w, label='FIFO (No Defense)', color='#dc3545', alpha=0.85)
    ax.bar(x + w/2, prio_miss, w, label='Priority Queue', color='#28a745', alpha=0.85)
    
    ax.axhline(y=1.0, color='orange', linestyle=':', linewidth=1.5, label='1% Threshold')
    
    ax.set_xlabel('Attack Rate (pps)')
    ax.set_ylabel('Deadline Miss Ratio (%)')
    ax.set_title('Protection Deadline Violation Rate Under CIL-DoS')
    ax.set_xticks(x)
    ax.set_xticklabels(['0', '10K', '50K', '100K', '500K'])
    ax.set_ylim(0, 110)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for i, (f, p) in enumerate(zip(fifo_miss, prio_miss)):
        ax.text(i - w/2, f + 2, f'{f:.1f}%', ha='center', va='bottom', fontsize=7, color='#dc3545')
        ax.text(i + w/2, p + 2, f'{p:.1f}%', ha='center', va='bottom', fontsize=7, color='#28a745')
    
    plt.savefig(os.path.join(FIG_DIR, "fig2_deadline_miss.pdf"))
    plt.savefig(os.path.join(FIG_DIR, "fig2_deadline_miss.png"))
    plt.close()
    print("  ✅ Fig 2: Deadline Miss Ratio")

def fig3_baseline_comparison(metrics):
    """Fig 3: Why simple solutions don't work — comparison at 100K pps."""
    configs = [
        ("FIFO\n1 worker", "E04"),
        ("FIFO\nLarge Queue", "E06"),
        ("FIFO\n2 workers", "E07"),
        ("FIFO\n4 workers", "E08"),
        ("Priority\n1 worker", "E12"),
    ]
    
    labels = [c[0] for c in configs]
    latencies = [metrics[c[1]]["mean_latency_us"] / 1000 for c in configs]  # ms
    misses = [metrics[c[1]]["deadline_miss_pct"] for c in configs]
    
    colors = ['#dc3545', '#ff6b35', '#ffa500', '#ffd700', '#28a745']
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7, 3.5))
    
    # Latency
    bars = ax1.bar(range(len(configs)), latencies, color=colors, alpha=0.85)
    ax1.axhline(y=3.0, color='black', linestyle='--', linewidth=1.5)
    ax1.set_ylabel('Mean Latency (ms)')
    ax1.set_title('(a) Mean Latency at 100K pps')
    ax1.set_xticks(range(len(configs)))
    ax1.set_xticklabels(labels, fontsize=8)
    ax1.set_yscale('log')
    ax1.set_ylim(0.5, 20000)
    ax1.grid(axis='y', alpha=0.3)
    
    # Deadline miss
    bars2 = ax2.bar(range(len(configs)), misses, color=colors, alpha=0.85)
    ax2.axhline(y=1.0, color='orange', linestyle=':', linewidth=1.5)
    ax2.set_ylabel('Deadline Miss (%)')
    ax2.set_title('(b) Deadline Violation at 100K pps')
    ax2.set_xticks(range(len(configs)))
    ax2.set_xticklabels(labels, fontsize=8)
    ax2.set_ylim(0, 110)
    ax2.grid(axis='y', alpha=0.3)
    
    for i, m in enumerate(misses):
        ax2.text(i, m + 2, f'{m:.1f}%', ha='center', va='bottom', fontsize=7, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "fig3_baseline_comparison.pdf"))
    plt.savefig(os.path.join(FIG_DIR, "fig3_baseline_comparison.png"))
    plt.close()
    print("  ✅ Fig 3: Baseline Comparison (why simple solutions fail)")

def fig4_algorithm_comparison(metrics):
    """Fig 4: RSA vs HMAC under attack."""
    configs = [
        ("FIFO\nRSA-2048", "E04"),
        ("FIFO\nHMAC-SHA256", "E14"),
        ("Priority\nRSA-2048", "E12"),
        ("Priority\nHMAC-SHA256", "E15"),
    ]
    
    labels = [c[0] for c in configs]
    latencies = [metrics[c[1]]["mean_latency_us"] / 1000 for c in configs]
    misses = [metrics[c[1]]["deadline_miss_pct"] for c in configs]
    
    colors = ['#dc3545', '#17a2b8', '#28a745', '#20c997']
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.5, 3.5))
    
    ax1.bar(range(len(configs)), latencies, color=colors, alpha=0.85)
    ax1.axhline(y=3.0, color='black', linestyle='--', linewidth=1.5, label='3ms Deadline')
    ax1.set_ylabel('Mean Latency (ms)')
    ax1.set_title('(a) Algorithm Impact on Latency')
    ax1.set_xticks(range(len(configs)))
    ax1.set_xticklabels(labels, fontsize=8)
    ax1.set_yscale('log')
    ax1.legend(fontsize=8)
    ax1.grid(axis='y', alpha=0.3)
    
    ax2.bar(range(len(configs)), misses, color=colors, alpha=0.85)
    ax2.set_ylabel('Deadline Miss (%)')
    ax2.set_title('(b) Algorithm Impact on Safety')
    ax2.set_xticks(range(len(configs)))
    ax2.set_xticklabels(labels, fontsize=8)
    ax2.set_ylim(0, 110)
    ax2.grid(axis='y', alpha=0.3)
    
    for i, m in enumerate(misses):
        ax2.text(i, m + 2, f'{m:.1f}%', ha='center', va='bottom', fontsize=7, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "fig4_algorithm_comparison.pdf"))
    plt.savefig(os.path.join(FIG_DIR, "fig4_algorithm_comparison.png"))
    plt.close()
    print("  ✅ Fig 4: Algorithm Comparison (RSA vs HMAC)")

def fig5_queue_larger_doesnt_help(metrics):
    """Fig 5: Queue size doesn't help — larger queue = longer wait."""
    configs = [
        ("Queue=4K\n(Default)", "E04", '#dc3545'),
        ("Queue=16K\n(4× Larger)", "E06", '#8b0000'),
    ]
    
    fig, ax = plt.subplots(figsize=(4, 3.5))
    
    labels = [c[0] for c in configs]
    latencies = [metrics[c[1]]["mean_latency_us"] / 1000 for c in configs]
    colors = [c[2] for c in configs]
    
    bars = ax.bar(range(len(configs)), latencies, color=colors, alpha=0.85, width=0.5)
    ax.axhline(y=3.0, color='black', linestyle='--', linewidth=1.5, label='3ms Deadline')
    
    ax.set_ylabel('Mean Latency (ms)')
    ax.set_title('Larger Queue = Longer Wait\n(100K pps RSA-2048 Attack)')
    ax.set_xticks(range(len(configs)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    for i, l in enumerate(latencies):
        ax.text(i, l + 200, f'{l:.0f} ms', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    plt.savefig(os.path.join(FIG_DIR, "fig5_queue_size.pdf"))
    plt.savefig(os.path.join(FIG_DIR, "fig5_queue_size.png"))
    plt.close()
    print("  ✅ Fig 5: Queue Size Analysis")

def fig6_workers_not_enough(metrics):
    """Fig 6: Multi-worker still fails."""
    workers = [1, 2, 4]
    ids = ["E04", "E07", "E08"]
    
    latencies = [metrics[i]["mean_latency_us"] / 1000 for i in ids]
    misses = [metrics[i]["deadline_miss_pct"] for i in ids]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6, 3.2))
    
    colors = ['#dc3545', '#ffa500', '#ffd700']
    
    ax1.bar(range(len(workers)), latencies, color=colors, alpha=0.85, width=0.5)
    ax1.axhline(y=3.0, color='black', linestyle='--', linewidth=1.5, label='3ms Deadline')
    ax1.set_xlabel('Verification Workers')
    ax1.set_ylabel('Mean Latency (ms)')
    ax1.set_title('(a) Latency vs Workers')
    ax1.set_xticks(range(len(workers)))
    ax1.set_xticklabels([str(w) for w in workers])
    ax1.legend(fontsize=8)
    ax1.grid(axis='y', alpha=0.3)
    
    ax2.bar(range(len(workers)), misses, color=colors, alpha=0.85, width=0.5)
    ax2.set_xlabel('Verification Workers')
    ax2.set_ylabel('Deadline Miss (%)')
    ax2.set_title('(b) Still 100% Failure')
    ax2.set_xticks(range(len(workers)))
    ax2.set_xticklabels([str(w) for w in workers])
    ax2.set_ylim(95, 101)
    ax2.grid(axis='y', alpha=0.3)
    
    for i, m in enumerate(misses):
        ax2.text(i, m + 0.2, f'{m:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold', color='red')
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, "fig6_workers.pdf"))
    plt.savefig(os.path.join(FIG_DIR, "fig6_workers.png"))
    plt.close()
    print("  ✅ Fig 6: Multi-Worker Analysis")


def main():
    print("Generating IEEE Access figures from v3 results...\n")
    metrics = load_metrics()
    print(f"  Loaded {len(metrics)} experiment results\n")
    
    fig1_attack_rate_vs_latency(metrics)
    fig2_deadline_miss(metrics)
    fig3_baseline_comparison(metrics)
    fig4_algorithm_comparison(metrics)
    fig5_queue_larger_doesnt_help(metrics)
    fig6_workers_not_enough(metrics)
    
    print(f"\n✅ All figures saved to: {FIG_DIR}/")


if __name__ == "__main__":
    main()
