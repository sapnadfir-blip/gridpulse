/* goose_common.h - Shared definitions for GridPulse Hardware Testbed
 *
 * Common data structures, constants, and helper functions used by
 * the GOOSE publisher, subscriber, and traffic generator.
 *
 * Part of GridPulse: IEC 61850 CIL-DoS Research Testbed
 * Authors: Dr. Sapna V. M., Prasad B. H., Prajwal Chowdary M.
 * PES University, Bengaluru, India
 */

#ifndef GOOSE_COMMON_H
#define GOOSE_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>

/* Post-Quantum Cryptography (liboqs) */
#ifdef OQS_ENABLED
#include <oqs/oqs.h>
#endif

/* ---- Protocol Constants ---- */
#define GOOSE_ETHERTYPE      0x88B8
#define GOOSE_DST_MAC_BYTES  {0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01}
#define GOOSE_MAX_PDU_SIZE   1500
#define GOOSE_APPID_DEFAULT  0x0001
#define DEADLINE_US          3000.0  /* 3 ms IEC 61850 Class P2/P3 */

/* Algorithm identifiers */
#define ALG_HMAC_SHA256  1
#define ALG_RSA_2048     2
#define ALG_ECDSA_P256   3
#define ALG_DILITHIUM2   4   /* ML-DSA-44 (NIST PQC Level 2) */
#define ALG_DILITHIUM5   5   /* ML-DSA-87 (NIST PQC Level 5) */
#define ALG_SPHINCS128S  6   /* SLH-DSA-SHAKE-128s (hash-based) */
#define ALG_FALCON512    7   /* FALCON-512 (lattice-based) */

/* ---- CSV Header ---- */
#define CSV_HEADER "timestamp_ns,frame_id,frame_type,stNum,sqNum,parse_us,verify_us,logic_us,total_us,queue_depth,deadline_met,xdp_active,attack_rate_pps\n"

/* ---- Data Structures ---- */

/* Ethernet header (packed for raw socket) */
typedef struct __attribute__((packed)) {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} eth_header_t;

/* Simplified GOOSE PDU structure
 * In production, this would be ASN.1 BER encoded.
 * For the research testbed, we use a fixed binary layout
 * that preserves the essential fields for timing measurement.
 */
typedef struct __attribute__((packed)) {
    /* GOOSE header */
    uint16_t appid;          /* Application ID */
    uint16_t length;         /* PDU length */
    uint16_t reserved1;
    uint16_t reserved2;

    /* GOOSE PDU fields */
    uint8_t  gocb_ref[64];   /* GOOSE Control Block Reference */
    uint8_t  dat_set[64];    /* Data Set reference */
    uint32_t st_num;         /* State Number */
    uint32_t sq_num;         /* Sequence Number */
    uint8_t  test;           /* Test flag */
    uint8_t  needs_commissioning;
    uint32_t conf_rev;       /* Configuration revision */

    /* Simplified allData (trip signal) */
    uint8_t  trip_status;    /* 0=normal, 1=trip */
    uint8_t  all_data[32];   /* Sensor/status data */

    /* IEC 62351-6 Security Extension */
    uint16_t sig_algo;       /* Signature algorithm ID */
    uint16_t sig_len;        /* Signature length in bytes */
    uint8_t  signature[8192]; /* Digital signature (RSA=256, ECDSA=72, HMAC=32, Dilithium=2420, SPHINCS+=7856) */
} goose_pdu_t;

/* Full GOOSE Ethernet frame */
typedef struct __attribute__((packed)) {
    eth_header_t eth;
    goose_pdu_t  pdu;
} goose_frame_t;

/* Per-frame pipeline timing measurement */
typedef struct {
    uint64_t receive_ns;      /* Timestamp when frame was received */
    uint64_t frame_id;        /* Monotonic frame counter */
    double   parse_us;        /* PDU parsing time (microseconds) */
    double   verify_us;       /* Signature verification time (microseconds) */
    double   logic_us;        /* Protection logic evaluation (microseconds) */
    double   total_us;        /* Total end-to-end processing time */
    uint32_t queue_depth;     /* Queue depth at time of arrival */
    int      deadline_met;    /* 1 if total_us < DEADLINE_US */
    int      sig_valid;       /* 1 if signature verified successfully */
    uint32_t st_num;          /* stNum from frame */
    uint32_t sq_num;          /* sqNum from frame */
    char     frame_type[16];  /* "legitimate" or "attack" */
} pipeline_timing_t;

/* Rolling statistics window */
#define STATS_WINDOW 1000

typedef struct {
    double   values[STATS_WINDOW];
    uint32_t count;
    uint32_t index;
    uint64_t total_frames;
    uint64_t deadline_misses;
    uint64_t valid_frames;
    uint64_t invalid_frames;
} rolling_stats_t;

/* ---- Global Shutdown Flag ---- */
static volatile sig_atomic_t g_running = 1;

static void signal_handler(int signum) {
    (void)signum;
    g_running = 0;
}

static void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ---- Timing Helpers ---- */

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline double ns_to_us(uint64_t ns) {
    return (double)ns / 1000.0;
}

/* ---- Rolling Statistics ---- */

static inline void stats_init(rolling_stats_t *s) {
    memset(s, 0, sizeof(rolling_stats_t));
}

static inline void stats_add(rolling_stats_t *s, double value) {
    s->values[s->index % STATS_WINDOW] = value;
    s->index++;
    if (s->count < STATS_WINDOW) s->count++;
    s->total_frames++;
}

static inline double stats_mean(const rolling_stats_t *s) {
    if (s->count == 0) return 0.0;
    double sum = 0;
    for (uint32_t i = 0; i < s->count; i++)
        sum += s->values[i];
    return sum / s->count;
}

static int compare_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static inline double stats_percentile(const rolling_stats_t *s, double pct) {
    if (s->count == 0) return 0.0;
    double sorted[STATS_WINDOW];
    memcpy(sorted, s->values, s->count * sizeof(double));
    qsort(sorted, s->count, sizeof(double), compare_double);
    uint32_t idx = (uint32_t)((pct / 100.0) * (s->count - 1));
    if (idx >= s->count) idx = s->count - 1;
    return sorted[idx];
}

/* ---- OpenSSL Key Management ---- */

static inline void openssl_init(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

/* Generate RSA-2048 key pair */
static inline EVP_PKEY *generate_rsa_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto err;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto err;
err:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Generate ECDSA P-256 key pair */
static inline EVP_PKEY *generate_ec_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) goto err;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto err;
err:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Generate HMAC key (random 32 bytes) */
static inline int generate_hmac_key(uint8_t *key, size_t key_len) {
    return RAND_bytes(key, key_len);
}

/* Save public key to PEM file (for shared key exchange between publisher/subscriber) */
static inline int save_pubkey(EVP_PKEY *pkey, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    PEM_write_PUBKEY(f, pkey);
    fclose(f);
    return 0;
}

/* Load public key from PEM file */
static inline EVP_PKEY *load_pubkey(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

/* Save private key to PEM file */
static inline int save_privkey(EVP_PKEY *pkey, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    return 0;
}

/* Load private key from PEM file */
static inline EVP_PKEY *load_privkey(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

/* Sign data with RSA-2048 or ECDSA-P256 */
static inline int sign_data(EVP_PKEY *pkey, const uint8_t *data, size_t data_len,
                             uint8_t *sig, size_t *sig_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return -1;
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    if (EVP_DigestSign(md_ctx, sig, sig_len, data, data_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

/* Verify signature with RSA-2048 or ECDSA-P256 */
static inline int verify_signature(EVP_PKEY *pkey, const uint8_t *data, size_t data_len,
                                    const uint8_t *sig, size_t sig_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return -1;
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    int result = EVP_DigestVerify(md_ctx, sig, sig_len, data, data_len);
    EVP_MD_CTX_free(md_ctx);
    return result; /* 1=valid, 0=invalid, -1=error */
}

/*
 * Worst-case cryptographic verification: performs full RSA/ECDSA verification.
 * For validly formatted attack signatures, OpenSSL performs complete modular
 * exponentiation / elliptic curve point multiplication before checking padding/digest.
 */
static inline int verify_signature_constant_time(EVP_PKEY *pkey, EVP_PKEY *sign_key,
                                                  const uint8_t *data, size_t data_len,
                                                  const uint8_t *sig, size_t sig_len) {
    (void)sign_key; /* Sign key not needed by a verifier */
    return verify_signature(pkey, data, data_len, sig, sig_len);
}

/* HMAC-SHA256 sign */
static inline int hmac_sign(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t *mac, unsigned int *mac_len) {
    HMAC(EVP_sha256(), key, key_len, data, data_len, mac, mac_len);
    return (*mac_len > 0) ? 0 : -1;
}

/* HMAC-SHA256 verify */
static inline int hmac_verify(const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               const uint8_t *expected_mac, unsigned int mac_len) {
    uint8_t computed_mac[32];
    unsigned int computed_len = 0;
    HMAC(EVP_sha256(), key, key_len, data, data_len, computed_mac, &computed_len);
    if (computed_len != mac_len) return 0;
    return (CRYPTO_memcmp(computed_mac, expected_mac, mac_len) == 0) ? 1 : 0;
}

/* ---- Post-Quantum Cryptography (liboqs) ---- */

#ifdef OQS_ENABLED

/* PQC key holder */
typedef struct {
    OQS_SIG *sig;          /* liboqs signature object */
    uint8_t *pubkey;       /* Public key bytes */
    uint8_t *privkey;      /* Private key bytes (NULL for verifier-only) */
    size_t   pubkey_len;
    size_t   privkey_len;
    size_t   sig_len;      /* Max signature length */
    char     alg_name[64]; /* Algorithm name */
} pqc_key_t;

/* Map algorithm ID to liboqs algorithm name */
static inline const char *pqc_oqs_name(int algo) {
    switch (algo) {
        case ALG_DILITHIUM2:  return OQS_SIG_alg_ml_dsa_44;
        case ALG_DILITHIUM5:  return OQS_SIG_alg_ml_dsa_87;
        case ALG_SPHINCS128S: return OQS_SIG_alg_sphincs_shake_128s_simple;
        case ALG_FALCON512:   return OQS_SIG_alg_falcon_512;
        default:              return NULL;
    }
}

/* Generate PQC key pair */
static inline pqc_key_t *pqc_keygen(int algo) {
    const char *name = pqc_oqs_name(algo);
    if (!name) return NULL;

    pqc_key_t *key = (pqc_key_t *)calloc(1, sizeof(pqc_key_t));
    if (!key) return NULL;

    key->sig = OQS_SIG_new(name);
    if (!key->sig) { free(key); return NULL; }

    key->pubkey_len  = key->sig->length_public_key;
    key->privkey_len = key->sig->length_secret_key;
    key->sig_len     = key->sig->length_signature;
    snprintf(key->alg_name, sizeof(key->alg_name), "%s", name);

    key->pubkey  = (uint8_t *)malloc(key->pubkey_len);
    key->privkey = (uint8_t *)malloc(key->privkey_len);
    if (!key->pubkey || !key->privkey) {
        OQS_SIG_free(key->sig);
        free(key->pubkey); free(key->privkey); free(key);
        return NULL;
    }

    if (OQS_SIG_keypair(key->sig, key->pubkey, key->privkey) != OQS_SUCCESS) {
        OQS_SIG_free(key->sig);
        free(key->pubkey); free(key->privkey); free(key);
        return NULL;
    }

    return key;
}

/* Sign data with PQC algorithm */
static inline int pqc_sign(pqc_key_t *key, const uint8_t *data, size_t data_len,
                            uint8_t *sig, size_t *sig_len) {
    if (!key || !key->sig || !key->privkey) return -1;
    if (OQS_SIG_sign(key->sig, sig, sig_len, data, data_len, key->privkey) != OQS_SUCCESS)
        return -1;
    return 0;
}

/* Verify signature with PQC algorithm */
static inline int pqc_verify(pqc_key_t *key, const uint8_t *data, size_t data_len,
                              const uint8_t *sig, size_t sig_len) {
    if (!key || !key->sig || !key->pubkey) return -1;
    OQS_STATUS rc = OQS_SIG_verify(key->sig, data, data_len, sig, sig_len, key->pubkey);
    return (rc == OQS_SUCCESS) ? 1 : 0;
}

/*
 * PQC verification wrapper: performs full lattice / hash-based verification.
 * For validly formatted attack signatures with mismatched digests, liboqs
 * executes the complete mathematical verification algorithm.
 */
static inline int pqc_verify_constant_time(pqc_key_t *key,
                                            const uint8_t *data, size_t data_len,
                                            const uint8_t *sig, size_t sig_len) {
    return pqc_verify(key, data, data_len, sig, sig_len);
}

/* Save PQC public key to file */
static inline int pqc_save_pubkey(pqc_key_t *key, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(&key->pubkey_len, sizeof(size_t), 1, f);
    fwrite(key->pubkey, 1, key->pubkey_len, f);
    fclose(f);
    return 0;
}

/* Save PQC private key to file */
static inline int pqc_save_privkey(pqc_key_t *key, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(&key->privkey_len, sizeof(size_t), 1, f);
    fwrite(key->privkey, 1, key->privkey_len, f);
    fclose(f);
    return 0;
}

/* Load PQC key from files */
static inline pqc_key_t *pqc_load_keys(int algo, const char *pub_path, const char *priv_path) {
    const char *name = pqc_oqs_name(algo);
    if (!name) return NULL;

    pqc_key_t *key = (pqc_key_t *)calloc(1, sizeof(pqc_key_t));
    if (!key) return NULL;

    key->sig = OQS_SIG_new(name);
    if (!key->sig) { free(key); return NULL; }

    key->pubkey_len  = key->sig->length_public_key;
    key->privkey_len = key->sig->length_secret_key;
    key->sig_len     = key->sig->length_signature;
    snprintf(key->alg_name, sizeof(key->alg_name), "%s", name);

    /* Load public key */
    FILE *f = fopen(pub_path, "rb");
    if (f) {
        size_t len;
        fread(&len, sizeof(size_t), 1, f);
        key->pubkey = (uint8_t *)malloc(len);
        if (key->pubkey) fread(key->pubkey, 1, len, f);
        fclose(f);
    }

    /* Load private key (optional, only publisher has it) */
    if (priv_path) {
        f = fopen(priv_path, "rb");
        if (f) {
            size_t len;
            fread(&len, sizeof(size_t), 1, f);
            key->privkey = (uint8_t *)malloc(len);
            if (key->privkey) fread(key->privkey, 1, len, f);
            fclose(f);
        }
    }

    return key;
}

/* Free PQC key */
static inline void pqc_free(pqc_key_t *key) {
    if (!key) return;
    if (key->sig)     OQS_SIG_free(key->sig);
    if (key->pubkey)  { OQS_MEM_cleanse(key->pubkey, key->pubkey_len); free(key->pubkey); }
    if (key->privkey) { OQS_MEM_cleanse(key->privkey, key->privkey_len); free(key->privkey); }
    free(key);
}

#endif /* OQS_ENABLED */

/* ---- Raw Socket Helpers ---- */

#ifdef __linux__
static inline int create_raw_socket(const char *ifname, int *ifindex) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(sockfd);
        return -1;
    }
    *ifindex = ifr.ifr_ifindex;

    /* Get interface MAC */
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sockfd);
        return -1;
    }

    /* Bind to interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = *ifindex;

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static inline int get_if_mac(int sockfd, const char *ifname, uint8_t *mac) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) return -1;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}
#endif /* __linux__ */

/* ---- Printing Helpers ---- */

static inline void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static inline const char *algo_name(int algo) {
    switch (algo) {
        case ALG_HMAC_SHA256: return "HMAC-SHA256";
        case ALG_RSA_2048:    return "RSA-2048";
        case ALG_ECDSA_P256:  return "ECDSA-P256";
#ifdef OQS_ENABLED
        case ALG_DILITHIUM2:  return "Dilithium2 (ML-DSA-44)";
        case ALG_DILITHIUM5:  return "Dilithium5 (ML-DSA-87)";
        case ALG_SPHINCS128S: return "SPHINCS+-128s (SLH-DSA)";
        case ALG_FALCON512:   return "FALCON-512";
#endif
        default:              return "UNKNOWN";
    }
}

static inline int parse_algo(const char *name) {
    if (strcasecmp(name, "HMAC-SHA256") == 0 || strcasecmp(name, "HMAC") == 0)
        return ALG_HMAC_SHA256;
    if (strcasecmp(name, "RSA-2048") == 0 || strcasecmp(name, "RSA") == 0)
        return ALG_RSA_2048;
    if (strcasecmp(name, "ECDSA-P256") == 0 || strcasecmp(name, "ECDSA") == 0)
        return ALG_ECDSA_P256;
#ifdef OQS_ENABLED
    if (strcasecmp(name, "Dilithium2") == 0 || strcasecmp(name, "ML-DSA-44") == 0)
        return ALG_DILITHIUM2;
    if (strcasecmp(name, "Dilithium5") == 0 || strcasecmp(name, "ML-DSA-87") == 0)
        return ALG_DILITHIUM5;
    if (strcasecmp(name, "SPHINCS") == 0 || strcasecmp(name, "SPHINCS-128s") == 0 || strcasecmp(name, "SLH-DSA") == 0)
        return ALG_SPHINCS128S;
    if (strcasecmp(name, "FALCON") == 0 || strcasecmp(name, "FALCON-512") == 0)
        return ALG_FALCON512;
#endif
    return ALG_RSA_2048; /* default */
}

/* Check if algorithm is PQC */
static inline int is_pqc_algo(int algo) {
    return (algo >= ALG_DILITHIUM2 && algo <= ALG_FALCON512);
}

#endif /* GOOSE_COMMON_H */
