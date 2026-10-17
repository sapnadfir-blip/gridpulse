#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

static double get_time_us(struct timespec *t0, struct timespec *t1) {
    return (t1->tv_sec - t0->tv_sec) * 1e6 + (t1->tv_nsec - t0->tv_nsec) / 1e3;
}

void test_rsa(void) {
    printf("=== Testing RSA-2048 ===\n");
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    uint8_t msg[128] = "Hello IEC 61850 GOOSE!";
    size_t msg_len = sizeof(msg);
    uint8_t sig[512];
    size_t sig_len = sizeof(sig);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(mctx, sig, &sig_len, msg, msg_len);

    struct timespec t0, t1;

    // 1. Valid signature
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int N = 1000;
    for (int i = 0; i < N; i++) {
        EVP_MD_CTX_reset(mctx);
        EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("RSA-2048 Valid Verify: %.2f us\n", get_time_us(&t0, &t1) / N);

    // 2. Random bytes signature
    uint8_t rand_sig[256];
    RAND_bytes(rand_sig, sizeof(rand_sig));
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        EVP_MD_CTX_reset(mctx);
        EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestVerify(mctx, rand_sig, sizeof(rand_sig), msg, msg_len);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("RSA-2048 Random Bytes Verify: %.2f us\n", get_time_us(&t0, &t1) / N);

    // 3. Bit-flipped message (valid signature structure, wrong message)
    uint8_t corrupt_msg[128];
    memcpy(corrupt_msg, msg, sizeof(msg));
    corrupt_msg[0] ^= 0x01;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        EVP_MD_CTX_reset(mctx);
        EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestVerify(mctx, sig, sig_len, corrupt_msg, sizeof(corrupt_msg));
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("RSA-2048 Corrupt Msg Verify (Full Math): %.2f us\n", get_time_us(&t0, &t1) / N);

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
}

void test_pqc(const char *alg_name) {
    printf("=== Testing PQC: %s ===\n", alg_name);
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) { printf("Failed to create %s\n", alg_name); return; }

    uint8_t *pub = malloc(sig->length_public_key);
    uint8_t *priv = malloc(sig->length_secret_key);
    OQS_SIG_keypair(sig, pub, priv);

    uint8_t msg[128] = "Hello IEC 61850 GOOSE PQC!";
    size_t msg_len = sizeof(msg);
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = sig->length_signature;

    struct timespec t0, t1;

    // Measure Sign
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int sign_trials = (strstr(alg_name, "sphincs") != NULL) ? 5 : 200;
    for (int i = 0; i < sign_trials; i++) {
        sig_len = sig->length_signature;
        OQS_SIG_sign(sig, signature, &sig_len, msg, msg_len, priv);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("%s Sign Time: %.2f us\n", alg_name, get_time_us(&t0, &t1) / sign_trials);

    // Measure Valid Verify
    int verify_trials = (strstr(alg_name, "sphincs") != NULL) ? 50 : 500;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < verify_trials; i++) {
        OQS_SIG_verify(sig, msg, msg_len, signature, sig_len, pub);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("%s Valid Verify Time: %.2f us\n", alg_name, get_time_us(&t0, &t1) / verify_trials);

    // Measure Random Bytes Verify
    uint8_t *rand_sig = malloc(sig->length_signature);
    RAND_bytes(rand_sig, sig->length_signature);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < verify_trials; i++) {
        OQS_SIG_verify(sig, msg, msg_len, rand_sig, sig->length_signature, pub);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("%s Random Bytes Verify Time: %.2f us\n", alg_name, get_time_us(&t0, &t1) / verify_trials);

    // Measure Corrupt Msg Verify (Full Math)
    uint8_t corrupt_msg[128];
    memcpy(corrupt_msg, msg, sizeof(msg));
    corrupt_msg[0] ^= 0x01;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < verify_trials; i++) {
        OQS_SIG_verify(sig, corrupt_msg, sizeof(corrupt_msg), signature, sig_len, pub);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("%s Corrupt Msg Verify (Full Math): %.2f us\n", alg_name, get_time_us(&t0, &t1) / verify_trials);

    free(pub);
    free(priv);
    free(signature);
    free(rand_sig);
    OQS_SIG_free(sig);
}

int main(void) {
    test_rsa();
    test_pqc("ML-DSA-44");
    test_pqc("ML-DSA-87");
    test_pqc("Falcon-512");
    test_pqc("SPHINCS+-SHA2-128s-simple");
    return 0;
}
