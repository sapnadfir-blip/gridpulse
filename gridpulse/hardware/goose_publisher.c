#include "goose_common.h"
#include <sys/stat.h>

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  --interface <if>       Interface to bind (default: eth0)\n");
    printf("  --algorithm <algo>     RSA-2048, ECDSA-P256, HMAC-SHA256 (default: RSA-2048)\n");
    printf("  --duration <sec>       Duration in seconds (default: 60)\n");
    printf("  --trip-interval <sec>  Trip interval in seconds (default: 30)\n");
    printf("  --heartbeat-ms <ms>    Heartbeat interval in ms (default: 1000)\n");
}

int main(int argc, char **argv) {
    char interface[64] = "eth0";
    int algo = ALG_RSA_2048;
    int duration = 60;
    int trip_interval = 30;
    int heartbeat_ms = 1000;

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"algorithm", required_argument, 0, 'a'},
        {"duration", required_argument, 0, 'd'},
        {"trip-interval", required_argument, 0, 't'},
        {"heartbeat-ms", required_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:a:d:t:h:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': strncpy(interface, optarg, sizeof(interface)-1); break;
            case 'a': algo = parse_algo(optarg); break;
            case 'd': duration = atoi(optarg); break;
            case 't': trip_interval = atoi(optarg); break;
            case 'h': heartbeat_ms = atoi(optarg); break;
            default: print_usage(argv[0]); return 1;
        }
    }

    setup_signals();
    openssl_init();

    mkdir("/shared", 0777);

    EVP_PKEY *pkey = NULL;
    uint8_t hmac_key[32];
#ifdef OQS_ENABLED
    pqc_key_t *pqc_key = NULL;
#endif

    printf("Initializing publisher with %s...\n", algo_name(algo));
    if (algo == ALG_RSA_2048) {
        pkey = generate_rsa_key();
        save_privkey(pkey, "/shared/privkey.pem");
        save_pubkey(pkey, "/shared/pubkey.pem");
    } else if (algo == ALG_ECDSA_P256) {
        pkey = generate_ec_key();
        save_privkey(pkey, "/shared/privkey.pem");
        save_pubkey(pkey, "/shared/pubkey.pem");
    } else if (algo == ALG_HMAC_SHA256) {
        generate_hmac_key(hmac_key, sizeof(hmac_key));
        FILE *f = fopen("/shared/hmac.key", "wb");
        if (f) {
            fwrite(hmac_key, 1, sizeof(hmac_key), f);
            fclose(f);
        }
    }
#ifdef OQS_ENABLED
    else if (is_pqc_algo(algo)) {
        pqc_key = pqc_keygen(algo);
        if (!pqc_key) {
            fprintf(stderr, "Failed to generate PQC key for %s\n", algo_name(algo));
            return 1;
        }
        pqc_save_pubkey(pqc_key, "/shared/pqc_pubkey.bin");
        pqc_save_privkey(pqc_key, "/shared/pqc_privkey.bin");
        printf("PQC key generated: pubkey=%zu bytes, privkey=%zu bytes, max_sig=%zu bytes\n",
               pqc_key->pubkey_len, pqc_key->privkey_len, pqc_key->sig_len);
    }
#endif

    int ifindex = 0;
    int sockfd = create_raw_socket(interface, &ifindex);
    if (sockfd < 0) return 1;

    uint8_t src_mac[6];
    if (get_if_mac(sockfd, interface, src_mac) < 0) return 1;

    FILE *fmac = fopen("/shared/publisher_mac.txt", "w");
    if (fmac) {
        fprintf(fmac, "%02x:%02x:%02x:%02x:%02x:%02x\n",
                src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        fclose(fmac);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    uint8_t dst_mac[6] = GOOSE_DST_MAC_BYTES;
    memcpy(sll.sll_addr, dst_mac, 6);

    goose_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    memcpy(frame.eth.dst_mac, dst_mac, 6);
    memcpy(frame.eth.src_mac, src_mac, 6);
    frame.eth.ethertype = htons(GOOSE_ETHERTYPE);

    frame.pdu.appid = htons(GOOSE_APPID_DEFAULT);
    strncpy((char*)frame.pdu.gocb_ref, "IEDP1/LLN0$GO$gcb01", sizeof(frame.pdu.gocb_ref));
    strncpy((char*)frame.pdu.dat_set, "IEDP1/LLN0$Dataset1", sizeof(frame.pdu.dat_set));
    frame.pdu.conf_rev = htonl(1);
    frame.pdu.sig_algo = htons(algo);

    uint32_t st_num = 1;
    uint32_t sq_num = 1;
    
    uint64_t start_time = get_time_ns();
    uint64_t last_stats_time = start_time;
    uint64_t last_trip_time = start_time;
    uint64_t last_heartbeat = start_time;
    
    uint64_t frames_sent = 0;
    uint64_t trips_triggered = 0;

    int burst_mode = 0;
    int burst_idx = 0;
    int burst_delays[] = {1, 2, 4, 8, 16};
    uint64_t next_burst_time = 0;

    while (g_running) {
        uint64_t now = get_time_ns();
        
        if (now - start_time >= (uint64_t)duration * 1000000000ULL) {
            break;
        }

        if (now - last_stats_time >= 5000000000ULL) {
            printf("[Stats] Sent: %lu, Trips: %lu, stNum: %u, sqNum: %u\n", 
                   frames_sent, trips_triggered, st_num, sq_num);
            last_stats_time = now;
        }

        int send_frame = 0;

        if (burst_mode) {
            if (now >= next_burst_time) {
                send_frame = 1;
                burst_idx++;
                if (burst_idx < 5) {
                    next_burst_time = now + (burst_delays[burst_idx] * 1000000ULL);
                } else {
                    burst_mode = 0;
                    st_num++;
                    sq_num = 1;
                    frame.pdu.trip_status = 0;
                    last_heartbeat = now;
                }
            }
        } else {
            if (now - last_trip_time >= (uint64_t)trip_interval * 1000000000ULL) {
                st_num++;
                sq_num = 1;
                frame.pdu.trip_status = 1;
                trips_triggered++;
                burst_mode = 1;
                burst_idx = 0;
                next_burst_time = now + (burst_delays[0] * 1000000ULL);
                last_trip_time = now;
                send_frame = 1;
            } else if (now - last_heartbeat >= (uint64_t)heartbeat_ms * 1000000ULL) {
                send_frame = 1;
                last_heartbeat = now;
            }
        }

        if (send_frame) {
            frame.pdu.st_num = htonl(st_num);
            frame.pdu.sq_num = htonl(sq_num);
            
            size_t data_len = offsetof(goose_pdu_t, sig_algo) - offsetof(goose_pdu_t, gocb_ref);
            uint8_t *data_ptr = &frame.pdu.gocb_ref[0];
            
            if (algo == ALG_HMAC_SHA256) {
                unsigned int mac_len = 0;
                hmac_sign(hmac_key, 32, data_ptr, data_len, frame.pdu.signature, &mac_len);
                frame.pdu.sig_len = htons(mac_len);
            }
#ifdef OQS_ENABLED
            else if (is_pqc_algo(algo) && pqc_key) {
                size_t sig_len = sizeof(frame.pdu.signature);
                pqc_sign(pqc_key, data_ptr, data_len, frame.pdu.signature, &sig_len);
                frame.pdu.sig_len = htons(sig_len);
            }
#endif
            else {
                size_t sig_len = sizeof(frame.pdu.signature);
                sign_data(pkey, data_ptr, data_len, frame.pdu.signature, &sig_len);
                frame.pdu.sig_len = htons(sig_len);
            }
            
            size_t frame_len = sizeof(eth_header_t) + offsetof(goose_pdu_t, signature) + ntohs(frame.pdu.sig_len);
            frame.pdu.length = htons(frame_len - sizeof(eth_header_t));
            
            ssize_t sent = sendto(sockfd, &frame, frame_len, 0, (struct sockaddr*)&sll, sizeof(sll));
            if (sent > 0) {
                frames_sent++;
                sq_num++;
            } else {
                perror("[PUBLISHER] sendto failed");
            }
        } else {
            usleep(100);
        }
    }

    if (pkey) EVP_PKEY_free(pkey);
#ifdef OQS_ENABLED
    if (pqc_key) pqc_free(pqc_key);
#endif
    close(sockfd);
    printf("Publisher shutting down gracefully.\n");
    return 0;
}
