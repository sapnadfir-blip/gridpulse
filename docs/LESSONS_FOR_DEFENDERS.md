# Lessons for Defenders

> Operational guidance from the GridPulse CIL-DoS research.
> For substation engineers, ICS security teams, and NERC CIP practitioners.

---

## The Core Problem

IEC 62351-6 adds cryptographic signatures to GOOSE messages for authentication.
Each signature verification consumes CPU time on the protection relay.

**An attacker who can flood the substation LAN with structurally valid but
cryptographically invalid GOOSE frames forces the relay to spend its limited
CPU on signature verification — delaying legitimate protection commands.**

This is a **Crypto-Induced Latency Denial of Service (CIL-DoS)**.

---

## Operational Lessons

### ✓ 1. Enable Layer-2 Filtering

GOOSE operates at Layer 2 (EtherType 0x88B8). Most firewalls and IDS
systems cannot inspect it because they operate at Layer 3+.

**Deploy MAC-based allowlists on process bus switches.**
Only known publisher MACs should be permitted to send GOOSE frames.

> Note: MAC filtering alone is insufficient — a sophisticated attacker
> can spoof MAC addresses. But it raises the bar significantly.

### ✓ 2. Rate-Limit GOOSE Sources

No legitimate GOOSE publisher sends more than ~1,000 frames/second,
even during rapid retransmission bursts after a state change.

**Configure per-source rate limits at the switch or relay level.**

| Scenario | Normal Rate | Safe Limit |
|:---|---:|---:|
| Heartbeat only | 1 fps | 100 fps |
| State change burst | 100-500 fps | 1,000 fps |
| Maximum ever needed | ~1,000 fps | 2,000 fps |

Anything above 2,000 fps from a single source is anomalous.

### ✓ 3. Monitor Verification Queue Depth

Protection relays should expose the verification queue depth as a
diagnostic metric. If the queue is consistently non-zero, something
is wrong.

**Alarm thresholds:**
- Queue depth > 5: **WARNING** — unusual traffic
- Queue depth > 20: **ALERT** — likely attack or misconfiguration
- Queue depth > 100: **CRITICAL** — protection delays imminent

### ✓ 4. Monitor End-to-End Protection Latency

The IEC 61850 protection deadline is 3ms. If measured latency
approaches this threshold, investigate immediately.

**Recommended monitoring points:**
- Frame arrival → verification complete (should be < 1ms)
- Frame arrival → relay decision output (should be < 3ms)
- Verification throughput (ops/sec) vs. expected baseline

### ✓ 5. Use eBPF/XDP Where Available

If the relay or gateway runs a Linux kernel (4.8+), eBPF/XDP
filtering can drop attack traffic **at the NIC driver level**
before it reaches the verification queue.

This eliminates the CIL-DoS vector entirely because attack
packets never consume CPU for signature verification.

### ✓ 6. Segment Engineering Workstations

The most likely attack vector is a compromised engineering laptop
or workstation connected to the process bus.

**Recommendations:**
- Engineering workstations should NOT be on the same VLAN as GOOSE publishers
- Use separate VLANs for engineering access, GOOSE, and SV traffic
- Apply strict access control to process bus switch ports

### ✓ 7. Consider Algorithm Selection

Not all signature algorithms are equally vulnerable:

| Algorithm | Verify Time | Saturation Rate | Vulnerability |
|:---|---:|---:|:---|
| HMAC-SHA256 | ~1.4 µs | ~700K pps | Low (very fast) |
| RSA-2048 | ~34 µs | ~30K pps | Medium |
| ECDSA-P256 | ~59 µs | ~17K pps | **High** (slowest) |

If your deployment uses ECDSA-P256, the CIL-DoS attack surface is
significantly larger. Consider whether HMAC-SHA256 (symmetric) provides
sufficient security for your threat model.

### ✓ 8. Plan for Constrained Hardware

Protection relays often use ARM Cortex-R or Cortex-M class processors.
On these platforms, verification times are **10-300× longer** than
desktop measurements.

| Relay Class | RSA-2048 Verify | Saturation at |
|:---|---:|---:|
| Desktop (M2) | 34 µs | 30K pps |
| Gateway (Atom) | 271 µs | 3.7K pps |
| Mid-range (Cortex-R5) | 2,705 µs | 370 pps |
| Low-end (Cortex-M4) | 10,142 µs | 99 pps |

**On a Cortex-M4 relay, just 100 invalid packets per second can cause
complete service denial.** This rate is trivially achievable by any
device on the substation LAN.

---

## What NOT to Rely On

| Defense | Why It's Insufficient |
|:---|:---|
| IP firewall | GOOSE is Layer 2. Firewalls don't see it. |
| Standard IDS (Snort) | Adds latency; can itself be overwhelmed |
| VLAN alone | A compromised IED on the same VLAN bypasses it |
| "Crypto will protect us" | Crypto **is** the attack surface |

---

## Defense-in-Depth Recommendation

```
Layer 1: VLAN segmentation (process bus isolation)
Layer 2: MAC allowlisting on switches
Layer 3: Per-source rate limiting (≤ 2,000 pps)
Layer 4: eBPF/XDP pre-filtering (if Linux-based)
Layer 5: Verification queue monitoring + alerting
Layer 6: Algorithm selection (prefer faster verification)
```

No single layer is sufficient. Deploy all layers appropriate for
your deployment.

---

## Responsible Disclosure

This research is conducted to improve the security of critical
infrastructure. The tools and techniques described are intended for
authorized security testing and defense development only.

If you have questions about deploying these mitigations, contact
your relay vendor's security team and your regional CERT.
