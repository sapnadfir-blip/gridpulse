#!/usr/bin/env python3
"""
Generate new figures for reviewer revision:
  Fig 7: Threshold sensitivity analysis
  Fig 8: Warm-up timeline from CSV data
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import csv
import os
import re

RESULTS_DIR = '/Users/apple/GridPulse-BlackHat-Project/gridpulse/hardware/results'
PAPER_DIR = '/Users/apple/GridPulse-BlackHat-Project/paper'

# IEEE styling
plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 9,
    'axes.labelsize': 10,
    'axes.titlesize': 10,
    'legend.fontsize': 8,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'lines.linewidth': 1.5,
    'lines.markersize': 6,
})


def parse_experiment_stats(exp_dir):
    """Parse all periodic stats from an experiment output."""
    output_file = os.path.join(exp_dir, 'output.txt')
    if not os.path.exists(output_file):
        return {}
    with open(output_file) as f:
        output = f.read()

    miss_matches = re.findall(r'Deadline Miss: ([\d.]+)%', output)
    mean_matches = re.findall(r'Mean: ([\d.]+)', output)
    p99_matches = re.findall(r'p99: ([\d.]+)', output)

    return {
        'miss_all': [float(x) for x in miss_matches],
        'mean_all': [float(x) for x in mean_matches],
        'p99_all': [float(x) for x in p99_matches],
        'miss_final': float(miss_matches[-1]) if miss_matches else 0,
        'mean_final': float(mean_matches[-1]) if mean_matches else 0,
        'p99_final': float(p99_matches[-1]) if p99_matches else 0,
    }


def fig7_threshold_sensitivity():
    """Fig 7: Threshold sensitivity — deadline miss vs T_FLOOD."""
    thresholds = [20, 50, 100, 200, 500, 1000, 2000]
    miss_rates = []
    mean_latencies = []
    p99_latencies = []

    for i, t in enumerate(thresholds):
        stats = parse_experiment_stats(os.path.join(RESULTS_DIR, f'v4_A0{i+1}'))
        miss_rates.append(stats.get('miss_final', 0))
        mean_latencies.append(stats.get('mean_final', 0) / 1000)  # Convert to ms
        p99_latencies.append(stats.get('p99_final', 0) / 1000)

    fig, ax1 = plt.subplots(figsize=(3.5, 2.5))

    color1 = '#1f77b4'
    color2 = '#d62728'

    ax1.set_xlabel(r'$T_{\mathrm{flood}}$ Threshold (pps)')
    ax1.set_ylabel('Deadline Miss Rate (%)', color=color1)
    line1 = ax1.plot(thresholds, miss_rates, 'o-', color=color1, label='Deadline Miss %')
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.set_xscale('log')
    ax1.set_ylim(bottom=0)

    # Mark the 3ms deadline zone
    ax1.axhline(y=3.0, color='gray', linestyle='--', alpha=0.5, linewidth=0.8)
    ax1.text(25, 3.3, '3% target', fontsize=7, color='gray')

    ax2 = ax1.twinx()
    ax2.set_ylabel('P99 Latency (ms)', color=color2)
    line2 = ax2.plot(thresholds, p99_latencies, 's--', color=color2, label='P99 Latency')
    ax2.tick_params(axis='y', labelcolor=color2)

    # Mark the 3ms deadline
    ax2.axhline(y=3.0, color=color2, linestyle=':', alpha=0.3, linewidth=0.8)

    # Combined legend
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc='upper left', fontsize=7)

    # Annotate optimal region
    ax1.axvspan(500, 2000, alpha=0.08, color='green')
    ax1.text(800, max(miss_rates) * 0.8, 'Optimal\nRegion', fontsize=7, color='green',
             ha='center', style='italic')

    fig.tight_layout()
    out_path = os.path.join(PAPER_DIR, 'fig7_threshold_sensitivity.pdf')
    fig.savefig(out_path)
    print(f'✅ Fig 7 saved: {out_path}')
    plt.close()

    # Also save PNG for artifact
    fig2, ax1 = plt.subplots(figsize=(3.5, 2.5))
    ax1.set_xlabel(r'$T_{\mathrm{flood}}$ Threshold (pps)')
    ax1.set_ylabel('Deadline Miss Rate (%)', color=color1)
    ax1.plot(thresholds, miss_rates, 'o-', color=color1, label='Deadline Miss %')
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.set_xscale('log')
    ax1.set_ylim(bottom=0)
    ax1.axhline(y=3.0, color='gray', linestyle='--', alpha=0.5, linewidth=0.8)
    ax2 = ax1.twinx()
    ax2.set_ylabel('P99 Latency (ms)', color=color2)
    ax2.plot(thresholds, p99_latencies, 's--', color=color2, label='P99 Latency')
    ax2.tick_params(axis='y', labelcolor=color2)
    ax1.axvspan(500, 2000, alpha=0.08, color='green')
    fig2.tight_layout()
    fig2.savefig(os.path.join(PAPER_DIR, 'fig7_threshold_sensitivity.png'))
    plt.close()


def fig8_warmup_timeline():
    """Fig 8: Per-frame latency over time showing warm-up period."""
    # Use E10 data (PQAC at 10K pps) which had the warm-up anomaly
    csv_path = os.path.join(RESULTS_DIR, 'v3_E10', 'subscriber_timing.csv')
    if not os.path.exists(csv_path):
        # Try A01 as fallback
        csv_path = os.path.join(RESULTS_DIR, 'v4_A01', 'subscriber_timing.csv')

    if not os.path.exists(csv_path):
        print('⚠ No CSV data found for warm-up timeline')
        return

    timestamps = []
    latencies = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = float(row.get('timestamp_ns', row.get('recv_ns', 0)))
                lat = float(row.get('total_us', row.get('latency_us', 0)))
                timestamps.append(ts)
                latencies.append(lat)
            except (ValueError, TypeError):
                continue

    if not timestamps:
        print('⚠ No data parsed from CSV')
        return

    # Convert to relative time in seconds
    t0 = timestamps[0]
    times_s = [(t - t0) / 1e9 for t in timestamps]

    # Only show first 5 seconds for warm-up analysis
    mask = [i for i, t in enumerate(times_s) if t <= 5.0]
    if len(mask) < 10:
        mask = list(range(min(len(times_s), 500)))

    times_plot = [times_s[i] for i in mask]
    lat_plot = [latencies[i] / 1000 for i in mask]  # to ms

    fig, ax = plt.subplots(figsize=(3.5, 2.2))

    # Scatter with small points
    ax.scatter(times_plot, lat_plot, s=2, alpha=0.5, color='#1f77b4', label='Per-frame latency')

    # 3ms deadline line
    ax.axhline(y=3.0, color='red', linestyle='--', linewidth=1, label='3 ms deadline')

    # Moving average
    window = min(20, len(lat_plot) // 5)
    if window > 1:
        moving_avg = np.convolve(lat_plot, np.ones(window)/window, mode='valid')
        ma_times = times_plot[window-1:][:len(moving_avg)]
        ax.plot(ma_times, moving_avg, color='#ff7f0e', linewidth=1.5, label=f'Moving avg ({window})')

    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('End-to-End Latency (ms)')
    ax.set_ylim(bottom=0, top=min(max(lat_plot) * 1.1, 50))
    ax.legend(fontsize=7, loc='upper right')

    fig.tight_layout()
    out_path = os.path.join(PAPER_DIR, 'fig8_warmup_timeline.pdf')
    fig.savefig(out_path)
    fig.savefig(os.path.join(PAPER_DIR, 'fig8_warmup_timeline.png'))
    print(f'✅ Fig 8 saved: {out_path}')
    plt.close()


if __name__ == '__main__':
    fig7_threshold_sensitivity()
    fig8_warmup_timeline()
    print('\nAll figures generated!')
