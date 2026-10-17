#!/usr/bin/env python3
"""
Transient-stability simulation (reviewer #5): numerically integrate the
single-machine-infinite-bus (SMIB) swing equation for the paper's benchmark
case, producing time-domain rotor-angle trajectories delta(t) for three fault
clearing times:
  - nominal primary clearance  (t_clear = 56 ms)  -> stable
  - ANSI 50BF backup clearance (t_clear = 216 ms) -> marginal/unstable
  - CIL-DoS-delayed clearance  (t_clear = 350 ms) -> pole slip (loss of synchronism)

This replaces the single hand-calculated equal-area point with an actual
time-domain integration and a critical-clearing-time (CCT) bisection, and
also prints a verification of the equal-area CCT (~201.6 ms).

SMIB parameters (identical to the paper):
  H = 4.0 s, Xd' = 0.25 pu, Pm = 0.8 pu, delta0 = 32.5 deg,
  Pmax = Pm/sin(delta0) = 1.4888 pu, f0 = 60 Hz, omega_s = 120*pi rad/s.
During a bolted 3-phase fault Pe ~ 0 (Pmax_fault = 0); post-fault Pe = Pmax*sin(delta).
Classical model, no damping (conservative).
"""
import numpy as np
from scipy.integrate import solve_ivp
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os

H = 4.0
Pm = 0.8
delta0_deg = 32.5
delta0 = np.radians(delta0_deg)
Pmax = Pm / np.sin(delta0)          # 1.4888 pu
f0 = 60.0
omega_s = 2 * np.pi * f0            # 376.99 rad/s
D = 0.0                             # no damping (conservative)

# Critical clearing angle from equal-area criterion:
# cos(delta_cr) = sin(delta0)*(pi - 2*delta0) - cos(delta0)
cos_dcr = np.sin(delta0) * (np.pi - 2 * delta0) - np.cos(delta0)
delta_cr = np.arccos(cos_dcr)
delta_max = np.pi - delta0          # unstable equilibrium (post-fault)

print(f"Pmax = {Pmax:.4f} pu")
print(f"delta_cr = {np.degrees(delta_cr):.2f} deg  (equal-area)")
print(f"delta_max (UEP) = {np.degrees(delta_max):.2f} deg")


def swing(t, y, t_clear):
    """State y = [delta, omega(rel)]. Fault on for t < t_clear."""
    delta, dω = y
    Pe = 0.0 if t < t_clear else Pmax * np.sin(delta)
    ddelta = dω
    ddω = (omega_s / (2 * H)) * (Pm - Pe - D * dω)
    return [ddelta, ddω]


def simulate(t_clear, t_end=1.5):
    sol = solve_ivp(swing, [0, t_end], [delta0, 0.0], args=(t_clear,),
                    max_step=1e-4, rtol=1e-8, atol=1e-10, dense_output=True)
    t = np.linspace(0, t_end, 4000)
    d = np.degrees(sol.sol(t)[0])
    return t, d


def is_stable(t_clear):
    """A run is unstable if the angle runs away past the UEP monotonically."""
    _, d = simulate(t_clear, t_end=2.0)
    return d.max() < np.degrees(delta_max) + 1.0 and d[-1] < 150.0


# Critical clearing time via bisection (time-domain)
lo, hi = 0.0, 0.5
for _ in range(40):
    mid = 0.5 * (lo + hi)
    if is_stable(mid):
        lo = mid
    else:
        hi = mid
cct = 0.5 * (lo + hi)
print(f"CCT (time-domain bisection) = {cct*1000:.1f} ms")

# Analytical CCT for bolted fault (Pe=0): delta(t)=delta0 + (omega_s*Pm/(4H))t^2
# t_crit = sqrt((delta_cr-delta0)*4H/(omega_s*Pm))
cct_analytic = np.sqrt((delta_cr - delta0) * 4 * H / (omega_s * Pm))
print(f"CCT (analytic equal-area) = {cct_analytic*1000:.1f} ms")

# ---- Figure: three clearing scenarios ----
scenarios = [
    (0.056, "Nominal primary clearance (56 ms)", "#2ca02c", "-"),
    (0.216, "ANSI 50BF backup (216 ms)", "#ff7f0e", "--"),
    (0.350, "CIL-DoS delayed (350 ms)", "#d62728", "-"),
]

fig, ax = plt.subplots(figsize=(5.2, 3.2))
for tc, label, color, ls in scenarios:
    t, d = simulate(tc, t_end=1.2)
    ax.plot(t * 1000, d, color=color, linestyle=ls, linewidth=1.6, label=label)

ax.axhline(np.degrees(delta_cr), color="black", linestyle=":", linewidth=1.0)
ax.text(1150, np.degrees(delta_cr) + 2,
        rf"$\delta_{{cr}}$ = {np.degrees(delta_cr):.1f}°",
        ha="right", fontsize=8)
ax.axhline(np.degrees(delta_max), color="gray", linestyle=":", linewidth=0.8)
ax.text(1150, np.degrees(delta_max) + 2,
        rf"$\delta_{{max}}$ = {np.degrees(delta_max):.1f}° (UEP)",
        ha="right", fontsize=7.5, color="gray")

ax.set_xlabel("Time (ms)")
ax.set_ylabel("Rotor angle  δ (deg)")
ax.set_ylim(0, 200)
ax.set_xlim(0, 1200)
ax.grid(alpha=0.3)
ax.legend(loc="upper left", fontsize=7.5, framealpha=0.9)
ax.set_title(f"SMIB transient stability (CCT ≈ {cct*1000:.0f} ms)", fontsize=9)
fig.tight_layout()

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))
PAPER = os.path.abspath(os.path.join(OUT, "..", "..", "paper"))
for d_ in (OUT, PAPER):
    fig.savefig(os.path.join(d_, "fig9_transient_stability.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(d_, "fig9_transient_stability.png"), dpi=200, bbox_inches="tight")
print(f"Saved fig9_transient_stability to {PAPER}")

# Report peak angles for the paper text
for tc, label, _, _ in scenarios:
    _, d = simulate(tc, t_end=1.5)
    print(f"  {label}: peak delta = {d.max():.1f} deg, "
          f"{'STABLE' if is_stable(tc) else 'UNSTABLE (pole slip)'}")
