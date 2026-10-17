# Cover Letter — IEEE Transactions on Smart Grid

**Date:** 7 October 2026

**To:** The Editor-in-Chief, IEEE Transactions on Smart Grid

**Manuscript title:** *Crypto-Induced Latency Denial of Service in IEC 61850 Substation Communications: Cyber-Physical Impact Analysis, Priority Admission Defense, and Post-Quantum Evaluation*

**Authors:** Sapna Vikram Mewundi, Prajwal Chowdary M., Prasad B. Honnavalli (Department of Computer Science and Engineering, PES University, Bengaluru, India)

**Corresponding author:** Sapna Vikram Mewundi (sapnavm@pes.edu)

---

Dear Editor,

We respectfully submit the above manuscript for consideration as a Research Paper in the IEEE Transactions on Smart Grid.

**Problem and contribution.** As digital substations migrate to IEC 61850 GOOSE over Ethernet process buses secured by IEC 62351-6, the cryptographic authentication intended to prevent spoofing introduces a new availability hazard. We identify and analyze *Crypto-Induced Latency Denial of Service* (CIL-DoS): an adversary floods the process bus with syntactically valid but cryptographically invalid GOOSE frames, saturating the receiver's verification queue and delaying protection trip commands beyond the 3 ms Class P2/P3 safety deadline. The paper makes four contributions that we believe are of direct interest to the Transactions readership:

1. **Cyber-physical linkage.** We connect the communication-layer delay to power-system transient stability through a numerically integrated single-machine swing-equation model (critical clearing time 201.6 ms), ANSI 50BF breaker-failure escalation, and transformer I²t stress—showing the attack can manufacture a breaker-failure-equivalent condition on a healthy breaker and simultaneously defeat the backup path, since 50BF trips traverse the same saturated bus.

2. **A real-time admission defense.** We propose the Priority Queue Admission Controller (PQAC), whose novel core is GOOSE-semantic: RFC 1982 serial-arithmetic stNum plausibility gating and verify-before-commit state handling that prevent state poisoning and trip suppression. We prove queue stability and delay-isolation bounds.

3. **Measured evaluation.** On a measured testbed and a service-time-calibrated Cortex-A9 relay emulation (5 repetitions), PQAC reduces mean trip latency from 2,388 ms to 760 µs (0.00% deadline miss), with a component ablation that quantifies when rate-dropping versus priority isolation is decisive, and an honest first-class treatment of the spoofed-MAC limitation (≈95% trip loss, requiring Layer-2 port security/MACsec). We additionally validate the cryptographic service times on real embedded silicon (ESP32), and benchmark NIST post-quantum signatures (ML-DSA, FALCON, SLH-DSA) under the same flood.

**Originality and ethics.** This manuscript is original, has not been published previously, and is not under consideration for publication elsewhere, in whole or in part. All authors have read and approved the submission and agree to its content. The work involves no human or animal subjects. All artifacts (testbed, scripts, and firmware) are open-sourced to support reproducibility.

**Scope fit.** The paper addresses communication, cyber-physical security, and protection-system resilience in digital substations—core topics of the Transactions on Smart Grid.

We thank you and the reviewers for your time and consideration.

Sincerely,

Sapna Vikram Mewundi, on behalf of all authors
Department of Computer Science and Engineering, PES University, Bengaluru, India
sapnavm@pes.edu
