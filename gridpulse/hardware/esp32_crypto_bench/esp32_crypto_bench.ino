/*
 * GridPulse ESP32 crypto benchmark (reviewer hardware-realism item).
 * Measures real signature VERIFY (subscriber) and SIGN (publisher) latency
 * for RSA-2048, ECDSA-P256, and HMAC-SHA256 on real embedded silicon,
 * using the mbedTLS bundled with the Arduino-ESP32 core (ESP32 HW-accelerated
 * bignum/SHA where available). Prints mean/min/max microseconds over serial.
 *
 * Output is machine-parseable lines:  RESULT,<algo>,<op>,<n>,<mean_us>,<min_us>,<max_us>
 */
#include <Arduino.h>
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "esp_timer.h"

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

// Realistic GOOSE payload size (~350-byte frame) for symmetric-MAC timing.
static uint8_t msg[350];
static uint8_t hash[32];

static inline int64_t now_us() { return esp_timer_get_time(); }

static void report(const char* algo, const char* op, int n,
                   double mean, int64_t mn, int64_t mx) {
  Serial.printf("RESULT,%s,%s,%d,%.1f,%lld,%lld\n", algo, op, n, mean, mn, mx);
}

static void bench_rsa() {
  mbedtls_pk_context pk; mbedtls_pk_init(&pk);
  if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
    Serial.println("ERR rsa setup"); return;
  }
  Serial.println("INFO,RSA-2048 keygen (one-time)...");
  int64_t t0 = now_us();
  int ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random,
                                &ctr_drbg, 2048, 65537);
  Serial.printf("INFO,RSA keygen took %lld ms (ret=%d)\n", (now_us()-t0)/1000, ret);
  if (ret != 0) { mbedtls_pk_free(&pk); return; }

  uint8_t sig[512]; size_t sig_len = 0;
  // one sign to get a signature
  if (mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig),
                      &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
    Serial.println("ERR rsa sign"); mbedtls_pk_free(&pk); return;
  }

  // VERIFY benchmark
  int N = 100; double sum = 0; int64_t mn = INT64_MAX, mx = 0;
  for (int i = 0; i < N; i++) {
    int64_t t = now_us();
    int r = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sig_len);
    int64_t dt = now_us() - t;
    if (r != 0) { Serial.println("ERR rsa verify"); break; }
    sum += dt; if (dt < mn) mn = dt; if (dt > mx) mx = dt;
  }
  report("RSA-2048", "verify", N, sum / N, mn, mx);

  // SIGN benchmark
  N = 20; sum = 0; mn = INT64_MAX; mx = 0;
  for (int i = 0; i < N; i++) {
    int64_t t = now_us();
    mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig),
                    &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    int64_t dt = now_us() - t;
    sum += dt; if (dt < mn) mn = dt; if (dt > mx) mx = dt;
  }
  report("RSA-2048", "sign", N, sum / N, mn, mx);
  mbedtls_pk_free(&pk);
}

static void bench_ecdsa() {
  mbedtls_pk_context pk; mbedtls_pk_init(&pk);
  if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
    Serial.println("ERR ec setup"); return;
  }
  int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk),
                                mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) { Serial.printf("ERR ec keygen %d\n", ret); mbedtls_pk_free(&pk); return; }

  uint8_t sig[128]; size_t sig_len = 0;
  if (mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig),
                      &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
    Serial.println("ERR ec sign"); mbedtls_pk_free(&pk); return;
  }

  int N = 10; double sum = 0; int64_t mn = INT64_MAX, mx = 0;
  for (int i = 0; i < N; i++) {
    int64_t t = now_us();
    int r = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sig_len);
    int64_t dt = now_us() - t;
    if (r != 0) { Serial.println("ERR ec verify"); break; }
    sum += dt; if (dt < mn) mn = dt; if (dt > mx) mx = dt;
  }
  report("ECDSA-P256", "verify", N, sum / N, mn, mx);

  N = 10; sum = 0; mn = INT64_MAX; mx = 0;
  for (int i = 0; i < N; i++) {
    int64_t t = now_us();
    mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig),
                    &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    int64_t dt = now_us() - t;
    sum += dt; if (dt < mn) mn = dt; if (dt > mx) mx = dt;
  }
  report("ECDSA-P256", "sign", N, sum / N, mn, mx);
  mbedtls_pk_free(&pk);
}

static void bench_hmac() {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = i;
  uint8_t out[32];
  int N = 2000; double sum = 0; int64_t mn = INT64_MAX, mx = 0;
  for (int i = 0; i < N; i++) {
    int64_t t = now_us();
    mbedtls_md_hmac(info, key, 32, msg, sizeof(msg), out);
    int64_t dt = now_us() - t;
    sum += dt; if (dt < mn) mn = dt; if (dt > mx) mx = dt;
  }
  report("HMAC-SHA256", "verify", N, sum / N, mn, mx);
}

static void bench_gmac() {
  // AES-128-GMAC: GCM tag over the frame as additional authenticated data
  // (no ciphertext) -- the IEC 62351-6 Ed.2 recommended symmetric profile.
  uint8_t key[16]; for (int i = 0; i < 16; i++) key[i] = i;
  uint8_t iv[12];  for (int i = 0; i < 12; i++) iv[i] = i;
  uint8_t tag[16];
  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
    Serial.println("ERR gmac setkey"); mbedtls_gcm_free(&gcm); return;
  }
  static uint8_t ct[sizeof(msg)];
  int N = 2000; double sum = 0; int64_t mn = INT64_MAX, mx = 0;
  for (int i = 0; i < N; i++) {
    int64_t t = now_us();
    // AES-GCM over the 350-byte frame (upper bound on GMAC/authentication cost)
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(msg), iv, 12,
                              NULL, 0, msg, ct, 16, tag);
    int64_t dt = now_us() - t;
    sum += dt; if (dt < mn) mn = dt; if (dt > mx) mx = dt;
  }
  report("AES-128-GCM", "verify", N, sum / N, mn, mx);
  mbedtls_gcm_free(&gcm);
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("\n==== GridPulse ESP32 crypto benchmark ====");
  Serial.printf("INFO,chip=%s,cores=%d,cpu_mhz=%d\n",
                ESP.getChipModel(), ESP.getChipCores(), getCpuFrequencyMhz());

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char* pers = "gridpulse";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char*)pers, strlen(pers));
  for (int i = 0; i < (int)sizeof(msg); i++) msg[i] = (uint8_t)i;
  mbedtls_sha256(msg, sizeof(msg), hash, 0);

  bench_hmac();
  bench_gmac();
  bench_rsa();
  bench_ecdsa();

  Serial.println("DONE");
}

void loop() { delay(1000); }
