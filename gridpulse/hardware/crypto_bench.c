#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <getopt.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

/* Constants */
#define DEFAULT_TRIALS 5
#define DEFAULT_ITERATIONS 5000
#define DEFAULT_OUTPUT_FILE "results/native_crypto_benchmark.csv"
#define WARMUP_ITERATIONS 100
#define MSG_LEN 200
#define T_VALUE_DF4 2.776

/* Global configs */
int g_trials = DEFAULT_TRIALS;
int g_iterations = DEFAULT_ITERATIONS;
char g_output_file[1024] = DEFAULT_OUTPUT_FILE;
char g_algo_filter[256] = "";

/* Data structs */
typedef struct {
    double mean_us;
    double stddev_us;
    double min_us;
    double max_us;
} TrialResult;

typedef struct {
    char name[32];
    TrialResult *trials;
    
    double grand_mean_us;
    double grand_stddev_us; // StdDev of trial means
    double ci95_lower_us;
    double ci95_upper_us;
    double cv_pct;
    double min_mean_us;
    double max_mean_us;
    
    double mean_throughput;
    double throughput_ci95_lower;
    double throughput_ci95_upper;
} BenchmarkStats;

/* Helper functions */
void handle_openssl_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

double get_time_diff_us(struct timespec *start, struct timespec *end) {
    long seconds = end->tv_sec - start->tv_sec;
    long nanoseconds = end->tv_nsec - start->tv_nsec;
    return (double)seconds * 1e6 + (double)nanoseconds / 1e3;
}

void compute_stats(BenchmarkStats *stats, int num_trials) {
    double sum = 0.0;
    double min = stats->trials[0].mean_us;
    double max = stats->trials[0].mean_us;
    
    for (int i = 0; i < num_trials; i++) {
        double val = stats->trials[i].mean_us;
        sum += val;
        if (val < min) min = val;
        if (val > max) max = val;
    }
    
    stats->grand_mean_us = sum / num_trials;
    stats->min_mean_us = min;
    stats->max_mean_us = max;
    
    double variance_sum = 0.0;
    for (int i = 0; i < num_trials; i++) {
        double diff = stats->trials[i].mean_us - stats->grand_mean_us;
        variance_sum += diff * diff;
    }
    stats->grand_stddev_us = sqrt(variance_sum / (num_trials > 1 ? (num_trials - 1) : 1));
    
    // 95% CI
    double margin_of_error = T_VALUE_DF4 * (stats->grand_stddev_us / sqrt(num_trials));
    if (num_trials != 5) {
        // Fallback to normal approx if not 5 trials
        margin_of_error = 1.96 * (stats->grand_stddev_us / sqrt(num_trials));
    }
    
    stats->ci95_lower_us = stats->grand_mean_us - margin_of_error;
    stats->ci95_upper_us = stats->grand_mean_us + margin_of_error;
    
    stats->cv_pct = (stats->grand_stddev_us / stats->grand_mean_us) * 100.0;
    
    stats->mean_throughput = 1e6 / stats->grand_mean_us;
    
    // Throughput CI (inverse)
    stats->throughput_ci95_lower = 1e6 / stats->ci95_upper_us;
    stats->throughput_ci95_upper = 1e6 / stats->ci95_lower_us;
}

void print_help(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  --trials N        Number of independent trials (default: %d)\n", DEFAULT_TRIALS);
    printf("  --iterations N    Number of iterations per trial (default: %d)\n", DEFAULT_ITERATIONS);
    printf("  --output PATH     Path to output CSV file (default: %s)\n", DEFAULT_OUTPUT_FILE);
    printf("  --algorithm ALGO  Run only specific algorithm (HMAC-SHA256, RSA-2048, ECDSA-P256)\n");
    printf("  --help            Print this help message\n");
}

/* Benchmarking routines */
void benchmark_hmac_sha256(BenchmarkStats *stats, unsigned char *msg, size_t msg_len) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) handle_openssl_error("Failed to fetch HMAC");
    
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) handle_openssl_error("Failed to create MAC context");
    
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) handle_openssl_error("RAND_bytes failed");
    
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    
    if (EVP_MAC_init(ctx, key, sizeof(key), params) != 1) handle_openssl_error("EVP_MAC_init failed");
    if (EVP_MAC_update(ctx, msg, msg_len) != 1) handle_openssl_error("EVP_MAC_update failed");
    
    size_t out_len = 0;
    unsigned char tag[32];
    if (EVP_MAC_final(ctx, tag, &out_len, sizeof(tag)) != 1) handle_openssl_error("EVP_MAC_final failed");
    
    for (int t = 0; t < g_trials; t++) {
        struct timespec start, end;
        
        // Warmup
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            EVP_MAC_init(ctx, key, sizeof(key), params);
            EVP_MAC_update(ctx, msg, msg_len);
            unsigned char dummy_tag[32];
            size_t dummy_len = 0;
            EVP_MAC_final(ctx, dummy_tag, &dummy_len, sizeof(dummy_tag));
        }
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < g_iterations; i++) {
            EVP_MAC_init(ctx, key, sizeof(key), params);
            EVP_MAC_update(ctx, msg, msg_len);
            unsigned char dummy_tag[32];
            size_t dummy_len = 0;
            EVP_MAC_final(ctx, dummy_tag, &dummy_len, sizeof(dummy_tag));
            // In a real scenario we'd do a memcmp, but EVP_MAC doesn't have a verify func in 3.0 out of the box
            // The generation cost equals verification cost for HMAC.
            // CRYPTO_memcmp(tag, dummy_tag, sizeof(tag));
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        double total_us = get_time_diff_us(&start, &end);
        stats->trials[t].mean_us = total_us / g_iterations;
    }
    
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    compute_stats(stats, g_trials);
}

void benchmark_rsa_2048(BenchmarkStats *stats, unsigned char *msg, size_t msg_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) handle_openssl_error("Failed to create RSA context");
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_openssl_error("EVP_PKEY_keygen_init failed");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) handle_openssl_error("Failed to set RSA bits");
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handle_openssl_error("EVP_PKEY_keygen failed");
    EVP_PKEY_CTX_free(pctx);
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_openssl_error("EVP_MD_CTX_new failed");
    
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) handle_openssl_error("EVP_DigestSignInit failed");
    
    size_t sig_len = 0;
    if (EVP_DigestSign(mdctx, NULL, &sig_len, msg, msg_len) <= 0) handle_openssl_error("EVP_DigestSign get length failed");
    
    unsigned char *sig = malloc(sig_len);
    if (!sig) handle_openssl_error("malloc failed");
    
    if (EVP_DigestSign(mdctx, sig, &sig_len, msg, msg_len) <= 0) handle_openssl_error("EVP_DigestSign failed");
    
    for (int t = 0; t < g_trials; t++) {
        struct timespec start, end;
        
        // Warmup
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            EVP_MD_CTX_reset(mdctx);
            EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < g_iterations; i++) {
            EVP_MD_CTX_reset(mdctx);
            EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        double total_us = get_time_diff_us(&start, &end);
        stats->trials[t].mean_us = total_us / g_iterations;
    }
    
    free(sig);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    compute_stats(stats, g_trials);
}

void benchmark_ecdsa_p256(BenchmarkStats *stats, unsigned char *msg, size_t msg_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) handle_openssl_error("Failed to create EC context");
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_openssl_error("EVP_PKEY_keygen_init failed");
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) handle_openssl_error("Failed to set EC curve");
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handle_openssl_error("EVP_PKEY_keygen failed");
    EVP_PKEY_CTX_free(pctx);
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_openssl_error("EVP_MD_CTX_new failed");
    
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) handle_openssl_error("EVP_DigestSignInit failed");
    
    size_t sig_len = 0;
    if (EVP_DigestSign(mdctx, NULL, &sig_len, msg, msg_len) <= 0) handle_openssl_error("EVP_DigestSign get length failed");
    
    unsigned char *sig = malloc(sig_len);
    if (!sig) handle_openssl_error("malloc failed");
    
    if (EVP_DigestSign(mdctx, sig, &sig_len, msg, msg_len) <= 0) handle_openssl_error("EVP_DigestSign failed");
    
    for (int t = 0; t < g_trials; t++) {
        struct timespec start, end;
        
        // Warmup
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            EVP_MD_CTX_reset(mdctx);
            EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < g_iterations; i++) {
            EVP_MD_CTX_reset(mdctx);
            EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        double total_us = get_time_diff_us(&start, &end);
        stats->trials[t].mean_us = total_us / g_iterations;
    }
    
    free(sig);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    compute_stats(stats, g_trials);
}

int main(int argc, char **argv) {
    int c;
    while (1) {
        static struct option long_options[] = {
            {"trials", required_argument, 0, 't'},
            {"iterations", required_argument, 0, 'i'},
            {"output", required_argument, 0, 'o'},
            {"algorithm", required_argument, 0, 'a'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long(argc, argv, "t:i:o:a:h", long_options, &option_index);
        if (c == -1) break;
        
        switch (c) {
            case 't': g_trials = atoi(optarg); break;
            case 'i': g_iterations = atoi(optarg); break;
            case 'o': strncpy(g_output_file, optarg, sizeof(g_output_file) - 1); break;
            case 'a': strncpy(g_algo_filter, optarg, sizeof(g_algo_filter) - 1); break;
            case 'h': print_help(argv[0]); exit(0);
            default: exit(1);
        }
    }
    
    if (g_trials < 2) {
        fprintf(stderr, "Number of trials must be at least 2 to compute stats\n");
        exit(1);
    }
    
    unsigned char msg[MSG_LEN];
    if (RAND_bytes(msg, MSG_LEN) != 1) handle_openssl_error("RAND_bytes failed");
    
    BenchmarkStats hmac_stats = {.name = "HMAC-SHA256", .trials = calloc(g_trials, sizeof(TrialResult))};
    BenchmarkStats rsa_stats = {.name = "RSA-2048", .trials = calloc(g_trials, sizeof(TrialResult))};
    BenchmarkStats ecdsa_stats = {.name = "ECDSA-P256", .trials = calloc(g_trials, sizeof(TrialResult))};
    
    if (!hmac_stats.trials || !rsa_stats.trials || !ecdsa_stats.trials) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    
    int run_hmac = (strlen(g_algo_filter) == 0 || strcmp(g_algo_filter, "HMAC-SHA256") == 0);
    int run_rsa = (strlen(g_algo_filter) == 0 || strcmp(g_algo_filter, "RSA-2048") == 0);
    int run_ecdsa = (strlen(g_algo_filter) == 0 || strcmp(g_algo_filter, "ECDSA-P256") == 0);
    
    printf("Starting Native Crypto Benchmark\n");
    printf("Trials: %d | Iterations per trial: %d | Message size: %d bytes\n\n", g_trials, g_iterations, MSG_LEN);
    
    printf("%-15s | %-12s | %-12s | %-15s | %-10s\n", "Algorithm", "Mean (us)", "StdDev (us)", "95%% CI (us)", "Ops/sec");
    printf("--------------------------------------------------------------------------------\n");
    
    if (run_hmac) {
        benchmark_hmac_sha256(&hmac_stats, msg, MSG_LEN);
        printf("%-15s | %-12.2f | %-12.4f | [%.2f, %.2f] | %-10.0f\n", 
               hmac_stats.name, hmac_stats.grand_mean_us, hmac_stats.grand_stddev_us, 
               hmac_stats.ci95_lower_us, hmac_stats.ci95_upper_us, hmac_stats.mean_throughput);
    }
    
    if (run_rsa) {
        benchmark_rsa_2048(&rsa_stats, msg, MSG_LEN);
        printf("%-15s | %-12.2f | %-12.4f | [%.2f, %.2f] | %-10.0f\n", 
               rsa_stats.name, rsa_stats.grand_mean_us, rsa_stats.grand_stddev_us, 
               rsa_stats.ci95_lower_us, rsa_stats.ci95_upper_us, rsa_stats.mean_throughput);
    }
    
    if (run_ecdsa) {
        benchmark_ecdsa_p256(&ecdsa_stats, msg, MSG_LEN);
        printf("%-15s | %-12.2f | %-12.4f | [%.2f, %.2f] | %-10.0f\n", 
               ecdsa_stats.name, ecdsa_stats.grand_mean_us, ecdsa_stats.grand_stddev_us, 
               ecdsa_stats.ci95_lower_us, ecdsa_stats.ci95_upper_us, ecdsa_stats.mean_throughput);
    }
    
    // Write CSV
    FILE *fp = fopen(g_output_file, "w");
    if (!fp) {
        // Try creating directory and retrying? Let's just create it.
        char cmd[1200];
        snprintf(cmd, sizeof(cmd), "mkdir -p $(dirname %s)", g_output_file);
        system(cmd);
        fp = fopen(g_output_file, "w");
    }
    
    if (fp) {
        fprintf(fp, "Algorithm,Trials,Iterations,Grand_Mean_us,CI95_Lower_us,CI95_Upper_us,StdDev_us,CV_pct,Mean_Throughput,Throughput_CI95_Lower,Throughput_CI95_Upper\n");
        
        BenchmarkStats *all_stats[] = {&hmac_stats, &rsa_stats, &ecdsa_stats};
        int to_run[] = {run_hmac, run_rsa, run_ecdsa};
        
        for (int i = 0; i < 3; i++) {
            if (to_run[i]) {
                BenchmarkStats *s = all_stats[i];
                fprintf(fp, "%s,%d,%d,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,%.2f,%.2f\n",
                        s->name, g_trials, g_iterations, s->grand_mean_us, s->ci95_lower_us, s->ci95_upper_us,
                        s->grand_stddev_us, s->cv_pct, s->mean_throughput, s->throughput_ci95_lower, s->throughput_ci95_upper);
            }
        }
        fclose(fp);
        printf("\nResults saved to %s\n", g_output_file);
    } else {
        fprintf(stderr, "\nFailed to open %s for writing.\n", g_output_file);
    }
    
    free(hmac_stats.trials);
    free(rsa_stats.trials);
    free(ecdsa_stats.trials);
    
    return 0;
}
