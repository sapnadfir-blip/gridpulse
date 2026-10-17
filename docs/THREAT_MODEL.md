# GridPulse Threat Model

## Attack: Crypto-Induced Latency Denial of Service (CIL-DoS)

### Overview

CIL-DoS exploits the fact that IEC 62351-6 cryptographic verification
on protection relays consumes CPU time. By flooding the substation LAN
with structurally valid but cryptographically invalid GOOSE frames, an
attacker forces the relay to spend its limited CPU on signature
verification — delaying or preventing legitimate protection commands.

### Threat Actors

| Actor | Capability | Access Required | Motivation |
|:---|:---|:---|:---|
| **Nation-state** | High (DPDK, custom hardware) | Remote or physical | Sabotage, espionage |
| **Insider** | Medium (laptop on LAN) | Physical LAN access | Disgruntled employee |
| **Supply chain** | High (compromised firmware) | Embedded in device | Persistent access |
| **Malware** | Medium (compromised IED) | Via IT/OT boundary | Automated attack |

### Prerequisites

1. **LAN access**: Attacker must be on the substation process bus
   (physical or via compromised device)
2. **Protocol knowledge**: Must know GOOSE frame structure (publicly documented)
3. **No cryptographic keys**: The attack does NOT require valid keys —
   invalid signatures are the weapon

### Attack Surface

```
Substation Process Bus (Ethernet)
        │
        ├── Publisher IED (sends legitimate GOOSE)
        ├── Subscriber IED (verifies signatures) ← TARGET
        └── Attacker (floods invalid GOOSE)      ← THREAT
```

GOOSE operates at Layer 2 (EtherType 0x88B8). It is:
- Multicast (all devices on the VLAN receive it)
- Not routable (stays on the LAN segment)
- Not inspectable by most firewalls (no IP header)

### Attack Mechanism

```
Attacker generates GOOSE frames:
  ✓ Valid Ethernet header (EtherType 0x88B8)
  ✓ Valid GOOSE PDU structure
  ✓ Plausible gocbRef, stNum, sqNum
  ✗ INVALID cryptographic signature (random bytes)
      │
      ├── Frame arrives at subscriber relay
      ├── Relay parses GOOSE PDU (fast: ~5-50µs)
      ├── Relay attempts signature verification (SLOW: 34-10,142µs)
      ├── Verification fails → frame rejected
      └── But CPU time was consumed → queue grows
          │
          ├── Legitimate frames queue behind attack frames
          ├── Wait time = queue_depth × verify_time
          └── When wait > 3ms → PROTECTION DEADLINE MISSED
```

### Impact

| Consequence | Description |
|:---|:---|
| **Delayed trip** | Protection relay cannot respond within 3ms |
| **Equipment damage** | Overcurrent/fault not cleared in time |
| **Cascading failure** | Upstream relays may cascade-trip |
| **Blackout** | Worst case: uncontrolled island or grid section loss |

### Assumptions

1. Relay processes GOOSE frames in FIFO order
2. Signature verification is serialized (single-threaded)
3. Attacker can sustain required packet rate for attack duration
4. No pre-existing defense filters attack traffic

### Limitations

- Requires LAN access (not remotely exploitable without prior compromise)
- Effect is temporary (stops when flood stops)
- Does not compromise relay logic or data integrity
- Does not extract sensitive information

### MITRE ATT&CK for ICS Mapping

| Technique | ID | Description |
|:---|:---|:---|
| Denial of Service | T0814 | Denial of service via GOOSE flooding |
| Manipulation of Control | T0831 | Delayed relay response |
| Loss of Protection | T0837 | Protection system unable to respond |
| Exploitation of Remote Services | T0866 | Exploitation of IEC 61850 GOOSE |

### Risk Assessment

| Factor | Assessment |
|:---|:---|
| **Likelihood** | Medium (requires LAN access) |
| **Impact** | Critical (protection system failure) |
| **Detectability** | Medium (unusual traffic volume) |
| **Reversibility** | High (stops when attack stops) |
| **Overall Risk** | **HIGH** |

---

## Responsible Disclosure & Authorized Use Policy

> [!WARNING]
> **Strictly Authorized Research & Testing Only**
> GridPulse is developed and distributed solely for academic research, defensive benchmarking, and authorized security evaluation in isolated laboratory environments.
>
> 1. **No Live OT Deployment:** Under no circumstances should GridPulse or its raw packet generation utilities (`goose_attacker`, `deploy_xdp.sh`) be executed against live, energized electrical substations, operational utility networks, or critical infrastructure systems.
> 2. **Controlled Environments:** All experimental attack evaluations must be conducted within isolated software testbeds (e.g., Docker bridge networks with MTU 9,000) or physically air-gapped hardware-in-the-loop (HIL) testbenches.
> 3. **Coordinated Vulnerability Disclosure:** This research adheres to responsible disclosure principles. The findings regarding IEC 62351-6 queue starvation and mitigation specifications have been shared with standard working groups (IEC TC 57 WG15) and national cybersecurity coordination agencies.
