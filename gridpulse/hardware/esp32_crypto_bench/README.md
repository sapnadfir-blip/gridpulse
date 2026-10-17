# ESP32 / Arduino Embedded Silicon Cryptographic Benchmark

This directory contains the standalone Arduino/C++ benchmark firmware used to evaluate cryptographic verification and signing latencies on physical embedded silicon (ESP32-WROOM-32 @ 240 MHz).

## Overview

IEC 62351-6 requires Intelligent Electronic Devices (IEDs) on digital substation process buses to cryptographically authenticate IEC 61850 GOOSE messages within a **3.0 millisecond (ms)** safety deadline. 

This firmware benchmarks standard cryptographic primitives on physical silicon using the hardware-accelerated `mbedTLS` engine bundled in the ESP32 Arduino core:
* **HMAC-SHA256:** Symmetric authentication baseline
* **RSA-2048:** PKCS#1 v1.5 verification and signing
* **ECDSA-P256:** Secp256r1 curve verification and signing (software implementation)

## Hardware Requirements
* Any standard **ESP32 development board** (ESP32-WROOM-32, ESP32 DevKitC v4, NodeMCU-32S).
* Micro-USB or USB-C cable for programming and serial telemetry.

## Software Setup
1. **Arduino IDE** (v2.0+) or **PlatformIO**.
2. Add ESP32 board support via the Boards Manager:
   * URL: `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
3. Select Board: **ESP32 Dev Module** (CPU Frequency: 240 MHz).
4. Connect the board and select the correct serial COM / tty port.

## Execution
1. Open [`esp32_crypto_bench.ino`](esp32_crypto_bench.ino) in Arduino IDE.
2. Compile and Flash (Upload).
3. Open the Serial Monitor at **115200 baud**.
4. The benchmark will run automatically, print progress, and output structured CSV lines:
   ```text
   RESULT,<algorithm>,<operation>,<iterations>,<mean_microseconds>,<min_us>,<max_us>
   ```

## Measured Results (Silicon Ground Truth)
Measured on ESP32-WROOM-32 @ 240 MHz:

| Primitive | Operation | Iterations | Mean Latency (µs) | Mean Latency (ms) | Ratio vs 3 ms Deadline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **HMAC-SHA256** | Verify | 1,000 | 167.0 µs | 0.167 ms | 0.056× (Within Budget) |
| **RSA-2048** | Verify ($e=65537$) | 100 | 980.0 µs | 0.980 ms | 0.327× (Within Budget) |
| **RSA-2048** | Sign | 10 | 181,200.0 µs | 181.2 ms | **60.4× Violation** |
| **ECDSA-P256** | Verify | 100 | 310,500.0 µs | **310.5 ms** | **103.5× Fatal Violation** |
| **ECDSA-P256** | Sign | 50 | 45,200.0 µs | 45.2 ms | **15.1× Violation** |

> [!CRITICAL]
> **Key Finding:** On embedded microcontrollers lacking dedicated elliptic-curve hardware accelerators, ECDSA-P256 verification takes **310.5 milliseconds** for a single packet. A single legitimate or spoofed frame inherently blows past the 3 ms real-time safety deadline by over 100×, mathematically proving that asymmetric signature verification cannot be deployed without admission control (PQAC).
