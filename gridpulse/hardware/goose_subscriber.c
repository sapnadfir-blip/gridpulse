#include "goose_common.h"
#include <stdatomic.h>
#include <sys/stat.h>

/* ============================================================
 * GridPulse GOOSE Subscriber — Configurable Architecture
 * 
 * Supports:
 *   --mode fifo|priority     Queue scheduling mode
 *   --workers N              Number of verification threads (1-8)
 *   --queue-size N           Queue capacity (256-16384)
 *
 * Configurations for paper:
 *   FIFO + 1 worker         = Baseline (proves CIL-DoS)
 *   FIFO + N workers        = "Just parallelize" baseline  
 *   FIFO + large queue      = "Just buffer more" baseline
 *   PRIORITY + 1 worker     = Our defense
 *   PRIORITY + N workers    = Combined defense
 * ============================================================ */

/* ---- Queue Mode ---- */
#define MODE_FIFO     0
#define MODE_PRIORITY 1

/* ---- Mutex-Protected Queue (supports multi-consumer) ---- */
#define MAX_QUEUE_SIZE 16384
#define MAX_FRAME_SIZE 10240

typedef struct {
    uint8_t data[MAX_FRAME_SIZE];
    int len;
    uint64_t enqueue_ns;
    int priority;
} queued_frame_t;

typedef struct {
    queued_frame_t *frames;  /* Heap-allocated array */
    int capacity;            /* Runtime-configurable */
    int mask;                /* capacity - 1, for fast modulo */
    uint64_t head;           /* Write position */
    uint64_t tail;           /* Read position */
    pthread_mutex_t lock;    /* For multi-consumer safety */
    _Atomic uint64_t dropped;
    _Atomic uint64_t peak_depth;
} mt_queue_t;

static int queue_init(mt_queue_t *q, int capacity) {
    /* Round up to power of 2 */
    int cap = 256;
    while (cap < capacity && cap < MAX_QUEUE_SIZE) cap <<= 1;
    
    q->frames = (queued_frame_t *)calloc(cap, sizeof(queued_frame_t));
    if (!q->frames) return -1;
    
    q->capacity = cap;
    q->mask = cap - 1;
    q->head = 0;
    q->tail = 0;
    pthread_mutex_init(&q->lock, NULL);
    atomic_store(&q->dropped, 0);
    atomic_store(&q->peak_depth, 0);
    return 0;
}

static void queue_destroy(mt_queue_t *q) {
    if (q->frames) free(q->frames);
    pthread_mutex_destroy(&q->lock);
}

static uint64_t queue_depth_unlocked(mt_queue_t *q) {
    return q->head - q->tail;
}

/* Single-producer push (only receiver thread calls this) */
static int queue_push(mt_queue_t *q, const uint8_t *data, int len, int priority) {
    pthread_mutex_lock(&q->lock);
    
    if (q->head - q->tail >= (uint64_t)q->capacity) {
        pthread_mutex_unlock(&q->lock);
        atomic_fetch_add(&q->dropped, 1);
        return -1;
    }
    
    uint64_t idx = q->head & q->mask;
    memcpy(q->frames[idx].data, data, len);
    q->frames[idx].len = len;
    q->frames[idx].enqueue_ns = get_time_ns();
    q->frames[idx].priority = priority;
    q->head++;
    
    uint64_t depth = q->head - q->tail;
    uint64_t peak = atomic_load(&q->peak_depth);
    if (depth > peak) atomic_store(&q->peak_depth, depth);
    
    pthread_mutex_unlock(&q->lock);
    return 0;
}

/* Multi-consumer pop (multiple worker threads can call this) */
static int queue_pop(mt_queue_t *q, queued_frame_t *out) {
    pthread_mutex_lock(&q->lock);
    
    if (q->tail >= q->head) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    
    uint64_t idx = q->tail & q->mask;
    memcpy(out, &q->frames[idx], sizeof(queued_frame_t));
    q->tail++;
    
    pthread_mutex_unlock(&q->lock);
    return 0;
}

#define MAX_SCD_PUBLISHERS    256
#define MAX_LRU_ENTRIES       1024
#define PLAUSIBILITY_WINDOW   16
#define MAX_TRANS_TOKENS      5.0
#define TRANS_TOKEN_REFILL_R  2.0    /* 2 transition tokens per second */
#define AGGREGATE_HIGH_CAP    500    /* max aggregate frames admitted to HIGH per second */

typedef struct {
    uint8_t  mac[6];
    uint32_t last_verified_st;
    int      has_verified_st;
    double   trans_tokens;
    uint64_t last_token_refill_ns;
    _Atomic uint64_t count;
    uint64_t window_start_ns;
    uint64_t last_access_ns;
    int      is_provisioned;
} publisher_state_t;

/* ---- Priority Queue Manager (PQAC v3) ---- */
typedef struct {
    mt_queue_t high;     /* Critical protection messages */
    mt_queue_t normal;   /* Regular operational messages */
    mt_queue_t low;      /* Suspicious / unknown traffic */
    int queue_capacity;
    
    /* Provisioned SCD Publishers (up to 256) */
    publisher_state_t scd_publishers[MAX_SCD_PUBLISHERS];
    int num_scd_publishers;
    pthread_mutex_t scd_lock;
    
    /* Dynamic / Unknown MAC LRU Table (1024 entries, O(1) memory bound) */
    publisher_state_t lru_table[MAX_LRU_ENTRIES];
    int num_lru_entries;
    pthread_mutex_t lru_lock;
    
    /* Aggregate HIGH admission rate limiter */
    _Atomic uint64_t high_admitted_count;
    uint64_t high_window_start_ns;
    pthread_mutex_t high_cap_lock;

    /* Thresholds (configurable for sensitivity analysis) */
    int t_normal;   /* pps below this = normal heartbeat */
    int t_burst;    /* pps below this = legitimate burst */
    int t_flood;    /* pps above this = flood */
    
    /* Stats */
    _Atomic uint64_t classified_high;
    _Atomic uint64_t classified_normal;
    _Atomic uint64_t classified_low;
    _Atomic uint64_t classified_dropped;
    _Atomic uint64_t scheduler_time_ns;  /* Total classifier overhead */
    _Atomic uint64_t scheduler_calls;
} priority_queue_mgr_t;

static int pqm_init(priority_queue_mgr_t *pqm, int capacity) {
    if (queue_init(&pqm->high, capacity) < 0) return -1;
    if (queue_init(&pqm->normal, capacity) < 0) return -1;
    if (queue_init(&pqm->low, capacity) < 0) return -1;
    pqm->queue_capacity = capacity;
    pqm->num_scd_publishers = 0;
    pqm->num_lru_entries = 0;
    pthread_mutex_init(&pqm->scd_lock, NULL);
    pthread_mutex_init(&pqm->lru_lock, NULL);
    pthread_mutex_init(&pqm->high_cap_lock, NULL);
    
    pqm->high_window_start_ns = get_time_ns();
    atomic_store(&pqm->high_admitted_count, 0);

    /* Default thresholds (IEC 61850 justified) */
    pqm->t_normal = 50;    /* Heartbeat ~1/s, burst ~10 frames */
    pqm->t_burst = 500;    /* No legitimate IED exceeds this */
    pqm->t_flood = 1000;   /* Definite flood indicator */
    
    atomic_store(&pqm->classified_high, 0);
    atomic_store(&pqm->classified_normal, 0);
    atomic_store(&pqm->classified_low, 0);
    atomic_store(&pqm->classified_dropped, 0);
    atomic_store(&pqm->scheduler_time_ns, 0);
    atomic_store(&pqm->scheduler_calls, 0);
    return 0;
}

static void pqm_destroy(priority_queue_mgr_t *pqm) {
    queue_destroy(&pqm->high);
    queue_destroy(&pqm->normal);
    queue_destroy(&pqm->low);
    pthread_mutex_destroy(&pqm->scd_lock);
    pthread_mutex_destroy(&pqm->lru_lock);
    pthread_mutex_destroy(&pqm->high_cap_lock);
}

static void pqm_register_mac(priority_queue_mgr_t *pqm, const uint8_t *mac) {
    uint64_t now = get_time_ns();
    pthread_mutex_lock(&pqm->scd_lock);
    for (int i = 0; i < pqm->num_scd_publishers; i++) {
        if (memcmp(pqm->scd_publishers[i].mac, mac, 6) == 0) {
            pthread_mutex_unlock(&pqm->scd_lock);
            return;
        }
    }
    if (pqm->num_scd_publishers < MAX_SCD_PUBLISHERS) {
        int idx = pqm->num_scd_publishers++;
        memcpy(pqm->scd_publishers[idx].mac, mac, 6);
        pqm->scd_publishers[idx].last_verified_st = 0;
        pqm->scd_publishers[idx].has_verified_st = 0;
        pqm->scd_publishers[idx].trans_tokens = MAX_TRANS_TOKENS;
        pqm->scd_publishers[idx].last_token_refill_ns = now;
        atomic_store(&pqm->scd_publishers[idx].count, 0);
        pqm->scd_publishers[idx].window_start_ns = now;
        pqm->scd_publishers[idx].last_access_ns = now;
        pqm->scd_publishers[idx].is_provisioned = 1;
    }
    pthread_mutex_unlock(&pqm->scd_lock);
}

static int pqm_is_known_mac(priority_queue_mgr_t *pqm, const uint8_t *mac) {
    pthread_mutex_lock(&pqm->scd_lock);
    for (int i = 0; i < pqm->num_scd_publishers; i++) {
        if (memcmp(pqm->scd_publishers[i].mac, mac, 6) == 0) {
            pthread_mutex_unlock(&pqm->scd_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&pqm->scd_lock);
    return 0;
}

/* Find or allocate publisher in SCD or bounded LRU cache (O(1) memory bound) */
static publisher_state_t *pqm_get_publisher(priority_queue_mgr_t *pqm, const uint8_t *mac) {
    uint64_t now = get_time_ns();
    
    pthread_mutex_lock(&pqm->scd_lock);
    for (int i = 0; i < pqm->num_scd_publishers; i++) {
        if (memcmp(pqm->scd_publishers[i].mac, mac, 6) == 0) {
            pqm->scd_publishers[i].last_access_ns = now;
            pthread_mutex_unlock(&pqm->scd_lock);
            return &pqm->scd_publishers[i];
        }
    }
    pthread_mutex_unlock(&pqm->scd_lock);
    
    pthread_mutex_lock(&pqm->lru_lock);
    for (int i = 0; i < pqm->num_lru_entries; i++) {
        if (memcmp(pqm->lru_table[i].mac, mac, 6) == 0) {
            pqm->lru_table[i].last_access_ns = now;
            pthread_mutex_unlock(&pqm->lru_lock);
            return &pqm->lru_table[i];
        }
    }
    
    /* Allocate new entry in bounded LRU table */
    int idx;
    if (pqm->num_lru_entries < MAX_LRU_ENTRIES) {
        idx = pqm->num_lru_entries++;
    } else {
        /* Evict LRU */
        idx = 0;
        uint64_t oldest = pqm->lru_table[0].last_access_ns;
        for (int i = 1; i < MAX_LRU_ENTRIES; i++) {
            if (pqm->lru_table[i].last_access_ns < oldest) {
                oldest = pqm->lru_table[i].last_access_ns;
                idx = i;
            }
        }
    }
    
    memcpy(pqm->lru_table[idx].mac, mac, 6);
    pqm->lru_table[idx].last_verified_st = 0;
    pqm->lru_table[idx].has_verified_st = 0;
    pqm->lru_table[idx].trans_tokens = MAX_TRANS_TOKENS;
    pqm->lru_table[idx].last_token_refill_ns = now;
    atomic_store(&pqm->lru_table[idx].count, 0);
    pqm->lru_table[idx].window_start_ns = now;
    pqm->lru_table[idx].last_access_ns = now;
    pqm->lru_table[idx].is_provisioned = 0;
    
    publisher_state_t *res = &pqm->lru_table[idx];
    pthread_mutex_unlock(&pqm->lru_lock);
    return res;
}

/* Commit verified stNum strictly upon cryptographically verified legitimate frame */
static void pqm_commit_verified_st(priority_queue_mgr_t *pqm, const uint8_t *mac, uint32_t st_num) {
    publisher_state_t *pub = pqm_get_publisher(pqm, mac);
    if (!pub) return;
    
    /* RFC 1982 Serial Number Arithmetic update */
    if (!pub->has_verified_st) {
        pub->last_verified_st = st_num;
        pub->has_verified_st = 1;
    } else {
        int32_t diff = (int32_t)(st_num - pub->last_verified_st);
        if (diff > 0) {
            pub->last_verified_st = st_num;
        }
    }
}

/* Plausibility check: RFC 1982 serial comparison */
static int pqm_is_st_num_plausible(publisher_state_t *pub, uint32_t st_num) {
    if (!pub->has_verified_st) return 1; /* Initial bootstrap */
    int32_t diff = (int32_t)(st_num - pub->last_verified_st);
    return (diff > 0 && diff <= PLAUSIBILITY_WINDOW);
}

/* Transition budget token bucket check */
static int pqm_consume_trans_token(publisher_state_t *pub) {
    uint64_t now = get_time_ns();
    double elapsed_s = (double)(now - pub->last_token_refill_ns) / 1e9;
    if (elapsed_s > 0) {
        pub->trans_tokens = fmin(MAX_TRANS_TOKENS, pub->trans_tokens + elapsed_s * TRANS_TOKEN_REFILL_R);
        pub->last_token_refill_ns = now;
    }
    if (pub->trans_tokens >= 1.0) {
        pub->trans_tokens -= 1.0;
        return 1;
    }
    return 0;
}

/* Aggregate HIGH admission cap check (prevents multi-publisher queue overload) */
static int pqm_check_high_cap(priority_queue_mgr_t *pqm) {
    uint64_t now = get_time_ns();
    pthread_mutex_lock(&pqm->high_cap_lock);
    if (now - pqm->high_window_start_ns >= 1000000000ULL) {
        atomic_store(&pqm->high_admitted_count, 0);
        pqm->high_window_start_ns = now;
    }
    uint64_t count = atomic_load(&pqm->high_admitted_count);
    if (count < AGGREGATE_HIGH_CAP) {
        atomic_fetch_add(&pqm->high_admitted_count, 1);
        pthread_mutex_unlock(&pqm->high_cap_lock);
        return 1;
    }
    pthread_mutex_unlock(&pqm->high_cap_lock);
    return 0;
}

static uint64_t pqm_get_source_rate(publisher_state_t *pub) {
    uint64_t now = get_time_ns();
    uint64_t elapsed_ns = now - pub->window_start_ns;
    if (elapsed_ns > 1000000000ULL) {
        atomic_store(&pub->count, 1);
        pub->window_start_ns = now;
        return 1;
    }
    uint64_t c = atomic_fetch_add(&pub->count, 1) + 1;
    double elapsed_sec = (double)elapsed_ns / 1e9;
    return (uint64_t)((double)c / (elapsed_sec > 0.001 ? elapsed_sec : 0.001));
}

/* ---- Ablation Study Flags ---- */
static int g_ablation_no_mac = 0;
static int g_ablation_no_rate = 0;
static int g_ablation_no_priority = 0;

/* ---- Calibrated service-time emulation ----
 * When >0, each verification is padded with a busy-wait so the worker's
 * per-frame occupancy equals this target (microseconds). This emulates a
 * slower embedded relay (e.g., ARM Cortex-A9 pipeline S-bar = 573 us,
 * mu = 1745 fps) on fast host silicon, per reviewer request. Reported
 * verify_us reflects the emulated service cost. NOT real A9 silicon. */
static double g_service_time_us = 0.0;

/* 3-Stage Admission Controller */
static int pqm_classify_and_enqueue(priority_queue_mgr_t *pqm,
                                     const uint8_t *frame, int len) {
    uint64_t t_start = get_time_ns();
    
    eth_header_t *eth = (eth_header_t *)frame;
    goose_pdu_t *pdu = (goose_pdu_t *)(frame + sizeof(eth_header_t));
    
    uint8_t *src_mac = eth->src_mac;
    int is_known = pqm_is_known_mac(pqm, src_mac);
    publisher_state_t *pub = pqm_get_publisher(pqm, src_mac);
    uint64_t src_rate = pqm_get_source_rate(pub);
    
    if (g_ablation_no_mac) is_known = 0;
    if (g_ablation_no_rate) src_rate = 0;
    
    int result = -1;
    
    if (is_known) {
        uint32_t st_num = ntohl(pdu->st_num);
        int is_plausible = pqm_is_st_num_plausible(pub, st_num);
        
        /* Protection state change priority: legitimate trip burst advances stNum.
         * Crucially, we DO NOT commit stNum here (verify-before-commit).
         * Gate admission with plausibility window, token bucket, and aggregate HIGH cap. */
        if (is_plausible && !g_ablation_no_rate && pqm_consume_trans_token(pub) && pqm_check_high_cap(pqm)) {
            mt_queue_t *target_q = g_ablation_no_priority ? &pqm->normal : &pqm->high;
            if (queue_push(target_q, frame, len, 0) == 0) {
                atomic_fetch_add(&pqm->classified_high, 1);
                result = 0;
            }
        } else if (src_rate <= (uint64_t)pqm->t_normal) {
            /* Normal heartbeat from known publisher → HIGH (subject to aggregate cap) */
            mt_queue_t *target_q = (g_ablation_no_priority || !pqm_check_high_cap(pqm)) ? &pqm->normal : &pqm->high;
            if (queue_push(target_q, frame, len, (target_q == &pqm->high) ? 0 : 1) == 0) {
                if (target_q == &pqm->high) atomic_fetch_add(&pqm->classified_high, 1);
                else atomic_fetch_add(&pqm->classified_normal, 1);
                result = (target_q == &pqm->high) ? 0 : 1;
            }
        } else if (src_rate <= (uint64_t)pqm->t_burst) {
            /* Legitimate burst (fault event retransmissions) → NORMAL */
            if (queue_push(&pqm->normal, frame, len, 1) == 0) {
                atomic_fetch_add(&pqm->classified_normal, 1);
                result = 1;
            }
        } else {
            /* Known MAC rate anomaly (> t_burst) → sampled 1% to LOW, 99% wire-speed drop */
            static _Atomic uint64_t known_flood_counter = 0;
            uint64_t fc = atomic_fetch_add(&known_flood_counter, 1);
            if (fc % 100 == 0) {
                mt_queue_t *target_q = g_ablation_no_priority ? &pqm->normal : &pqm->low;
                if (queue_push(target_q, frame, len, 2) == 0) {
                    atomic_fetch_add(&pqm->classified_low, 1);
                    result = 2;
                }
            } else {
                atomic_fetch_add(&pqm->classified_dropped, 1);
                result = -1;
            }
        }
    } else {
        /* Stage 2 & 3: Unknown source */
        if (src_rate <= (uint64_t)pqm->t_normal) {
            /* Low-rate unknown → LOW (isolated monitoring) */
            mt_queue_t *target_q = g_ablation_no_priority ? &pqm->normal : &pqm->low;
            if (queue_push(target_q, frame, len, 2) == 0) {
                atomic_fetch_add(&pqm->classified_low, 1);
                result = 2;
            }
        } else {
            /* Flood from unknown → sampled 1% to LOW for telemetry, 99% wire-speed drop */
            static _Atomic uint64_t unknown_flood_counter = 0;
            uint64_t fc = atomic_fetch_add(&unknown_flood_counter, 1);
            if (fc % 100 == 0) {
                mt_queue_t *target_q = g_ablation_no_priority ? &pqm->normal : &pqm->low;
                if (queue_push(target_q, frame, len, 2) == 0) {
                    atomic_fetch_add(&pqm->classified_low, 1);
                    result = 2;
                }
            } else {
                atomic_fetch_add(&pqm->classified_dropped, 1);
                result = -1;
            }
        }
    }
    
    /* Track scheduler overhead */
    uint64_t t_end = get_time_ns();
    atomic_fetch_add(&pqm->scheduler_time_ns, t_end - t_start);
    atomic_fetch_add(&pqm->scheduler_calls, 1);
    
    return result;
}

/* Priority-ordered pop: HIGH → NORMAL → LOW */
static int pqm_pop(priority_queue_mgr_t *pqm, queued_frame_t *out) {
    if (queue_pop(&pqm->high, out) == 0) return 0;
    if (queue_pop(&pqm->normal, out) == 0) return 1;
    if (queue_pop(&pqm->low, out) == 0) return 2;
    return -1;
}

/* ---- Shared State ---- */
typedef struct {
    mt_queue_t fifo_queue;
    priority_queue_mgr_t pqm;
    
    int mode;
    int num_workers;
    int queue_capacity;
    int sockfd;
    int algo;
    int duration;
    uint64_t start_time;
    EVP_PKEY *pkey;
    uint8_t hmac_key[32];
#ifdef OQS_ENABLED
    pqc_key_t *pqc_key;
#endif
    FILE *csv;
    pthread_mutex_t csv_lock;
    rolling_stats_t stats;        /* All dequeued frames */
    rolling_stats_t legit_stats;  /* Legitimate protection frames */
    pthread_mutex_t stats_lock;
} shared_state_t;

/* ---- Receiver Thread ---- */
void *receiver_thread(void *arg) {
    shared_state_t *state = (shared_state_t *)arg;
    uint64_t recv_count = 0;
    
    printf("[RECEIVER] Started — filling verification queue...\n");
    fflush(stdout);
    
    int rcvbuf = 16 * 1024 * 1024;
    setsockopt(state->sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(state->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    while (g_running) {
        uint8_t buf[MAX_FRAME_SIZE];
        struct sockaddr_ll sll;
        socklen_t sll_len = sizeof(sll);
        
        int n = recvfrom(state->sockfd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&sll, &sll_len);
        
        uint64_t now = get_time_ns();
        if (now - state->start_time >= (uint64_t)state->duration * 1000000000ULL)
            break;

        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        
        eth_header_t *eth = (eth_header_t *)buf;
        if (eth->ethertype != htons(GOOSE_ETHERTYPE))
            continue;
        
        recv_count++;
        
        if (state->mode == MODE_FIFO) {
            queue_push(&state->fifo_queue, buf, n, 0);
        } else {
            pqm_classify_and_enqueue(&state->pqm, buf, n);
        }
    }
    
    printf("[RECEIVER] Done. Received %lu GOOSE frames\n", recv_count);
    if (state->mode == MODE_FIFO) {
        printf("  Queue drops: %lu\n",
               (uint64_t)atomic_load(&state->fifo_queue.dropped));
    } else {
        printf("  HIGH=%lu, NORMAL=%lu, LOW=%lu, DROPPED=%lu\n",
               (uint64_t)atomic_load(&state->pqm.classified_high),
               (uint64_t)atomic_load(&state->pqm.classified_normal),
               (uint64_t)atomic_load(&state->pqm.classified_low),
               (uint64_t)atomic_load(&state->pqm.classified_dropped));
        uint64_t calls = atomic_load(&state->pqm.scheduler_calls);
        uint64_t time_ns = atomic_load(&state->pqm.scheduler_time_ns);
        if (calls > 0) {
            printf("  Scheduler overhead: %.2f us/call (%lu calls)\n",
                   (double)time_ns / (double)calls / 1000.0, calls);
        }
    }
    fflush(stdout);
    return NULL;
}

/* ---- Worker Thread (Processor) ---- */
typedef struct {
    shared_state_t *state;
    int worker_id;
} worker_arg_t;

void *worker_thread(void *arg) {
    worker_arg_t *warg = (worker_arg_t *)arg;
    shared_state_t *state = warg->state;
    int worker_id = warg->worker_id;
    uint64_t frame_counter = 0;
    uint32_t last_st_num = 0;
    uint8_t last_trip = 0;
    uint64_t last_stats_time = state->start_time;
    
    printf("[WORKER-%d] Started — verifying frames...\n", worker_id);
    fflush(stdout);
    
    while (g_running) {
        queued_frame_t qf;
        int pop_result;
        
        if (state->mode == MODE_FIFO) {
            pop_result = queue_pop(&state->fifo_queue, &qf);
        } else {
            pop_result = pqm_pop(&state->pqm, &qf);
        }
        
        if (pop_result < 0) {
            uint64_t now = get_time_ns();
            if (now - state->start_time >= (uint64_t)state->duration * 1000000000ULL)
                break;
            usleep(10);
            continue;
        }
        
        /* ---- PIPELINE ---- */
        pipeline_timing_t pt;
        memset(&pt, 0, sizeof(pt));
        pt.receive_ns = qf.enqueue_ns;
        pt.frame_id = ++frame_counter;
        
        uint64_t dequeue_ns = get_time_ns();
        double queue_wait_us = ns_to_us(dequeue_ns - qf.enqueue_ns);
        
        /* Parse */
        uint64_t t0 = get_time_ns();
        uint64_t proc_start_ns = t0;   /* worker occupancy starts here */
        goose_pdu_t *pdu = (goose_pdu_t *)(qf.data + sizeof(eth_header_t));
        pt.st_num = ntohl(pdu->st_num);
        pt.sq_num = ntohl(pdu->sq_num);
        uint16_t sig_algo = ntohs(pdu->sig_algo);
        uint16_t sig_len = ntohs(pdu->sig_len);
        uint64_t t1 = get_time_ns();
        pt.parse_us = ns_to_us(t1 - t0);
        
        /* Verify */
        t0 = get_time_ns();
        size_t data_len = offsetof(goose_pdu_t, sig_algo) - offsetof(goose_pdu_t, gocb_ref);
        uint8_t *data_ptr = &pdu->gocb_ref[0];
        
        int valid = 0;
        if (sig_algo == ALG_HMAC_SHA256) {
            valid = hmac_verify(state->hmac_key, 32, data_ptr, data_len,
                               pdu->signature, sig_len);
        }
#ifdef OQS_ENABLED
        else if (is_pqc_algo(sig_algo) && state->pqc_key) {
            valid = pqc_verify(state->pqc_key, data_ptr, data_len,
                               pdu->signature, sig_len);
        }
#endif
        else if (state->pkey) {
            valid = verify_signature(state->pkey, data_ptr, data_len,
                                     pdu->signature, sig_len);
        }
        t1 = get_time_ns();
        pt.verify_us = ns_to_us(t1 - t0);
        pt.sig_valid = valid;
        
        /* If valid and priority mode, commit verified stNum and register MAC */
        if (valid && state->mode == MODE_PRIORITY) {
            eth_header_t *eth = (eth_header_t *)qf.data;
            pqm_commit_verified_st(&state->pqm, eth->src_mac, pt.st_num);
            pqm_register_mac(&state->pqm, eth->src_mac);
        }
        
        strcpy(pt.frame_type, valid ? "legitimate" : "attack");
        
        /* Logic */
        t0 = get_time_ns();
        if (valid) {
            if (pt.st_num > last_st_num) last_st_num = pt.st_num;
            if (pdu->trip_status != last_trip) last_trip = pdu->trip_status;
        }
        t1 = get_time_ns();
        pt.logic_us = ns_to_us(t1 - t0);

        /* Calibrated service-time emulation: pad worker occupancy to the
         * configured per-frame service time (e.g., 573 us for Cortex-A9),
         * so throughput is throttled to mu = 1/S and the queue builds up
         * exactly as it would on a slower relay. The pad is attributed to
         * verify_us so the frame's own latency reflects the emulated cost. */
        if (g_service_time_us > 0.0) {
            while (ns_to_us(get_time_ns() - proc_start_ns) < g_service_time_us) {
                /* busy-wait (relay keeps the core occupied during crypto) */
            }
            double occupied_us = ns_to_us(get_time_ns() - proc_start_ns);
            pt.verify_us = occupied_us - pt.parse_us - pt.logic_us;
            if (pt.verify_us < 0.0) pt.verify_us = 0.0;
        }

        /* Total includes queue wait */
        pt.total_us = queue_wait_us + pt.parse_us + pt.verify_us + pt.logic_us;
        pt.deadline_met = (pt.total_us < DEADLINE_US) ? 1 : 0;
        
        /* Get queue depth snapshot */
        if (state->mode == MODE_FIFO) {
            pt.queue_depth = (uint32_t)queue_depth_unlocked(&state->fifo_queue);
        } else {
            pt.queue_depth = (uint32_t)(queue_depth_unlocked(&state->pqm.high) +
                                        queue_depth_unlocked(&state->pqm.normal) +
                                        queue_depth_unlocked(&state->pqm.low));
        }
        
        /* Thread-safe stats update */
        pthread_mutex_lock(&state->stats_lock);
        if (valid) {
            state->stats.valid_frames++;
            state->legit_stats.valid_frames++;
            if (!pt.deadline_met) state->legit_stats.deadline_misses++;
            stats_add(&state->legit_stats, pt.total_us);
        } else {
            state->stats.invalid_frames++;
        }
        if (!pt.deadline_met) state->stats.deadline_misses++;
        stats_add(&state->stats, pt.total_us);
        pthread_mutex_unlock(&state->stats_lock);
        
        /* Thread-safe CSV write */
        pthread_mutex_lock(&state->csv_lock);
        fprintf(state->csv, "%lu,%lu,%s,%u,%u,%.2f,%.2f,%.2f,%.2f,%u,%d,%d,%d\n",
                pt.receive_ns, pt.frame_id, pt.frame_type, pt.st_num, pt.sq_num,
                pt.parse_us, pt.verify_us, pt.logic_us, pt.total_us,
                pt.queue_depth, pt.deadline_met, 0, worker_id);
        pthread_mutex_unlock(&state->csv_lock);
        
        /* Worker 0 prints stats every 5 seconds */
        if (worker_id == 0) {
            uint64_t now = get_time_ns();
            if (now - last_stats_time >= 5000000000ULL) {
                pthread_mutex_lock(&state->stats_lock);
                double mean = stats_mean(&state->stats);
                double p95 = stats_percentile(&state->stats, 95.0);
                double p99 = stats_percentile(&state->stats, 99.0);
                double miss_ratio = state->stats.total_frames > 0
                    ? (double)state->stats.deadline_misses / state->stats.total_frames * 100.0
                    : 0.0;
                uint64_t total = state->stats.total_frames;
                uint64_t valid_f = state->stats.valid_frames;
                uint64_t invalid_f = state->stats.invalid_frames;
                pthread_mutex_unlock(&state->stats_lock);
                
                printf("[Stats] Total: %lu, Valid: %lu, Invalid: %lu\n",
                       total, valid_f, invalid_f);
                printf("  Latency (us) -> Mean: %.2f, p95: %.2f, p99: %.2f\n",
                       mean, p95, p99);
                
                if (state->mode == MODE_FIFO) {
                    printf("  Deadline Miss: %.2f%%, Queue: %lu, Peak: %lu, Dropped: %lu\n",
                           miss_ratio,
                           queue_depth_unlocked(&state->fifo_queue),
                           (uint64_t)atomic_load(&state->fifo_queue.peak_depth),
                           (uint64_t)atomic_load(&state->fifo_queue.dropped));
                } else {
                    printf("  Deadline Miss: %.2f%%, Q[H:%lu N:%lu L:%lu]\n",
                           miss_ratio,
                           queue_depth_unlocked(&state->pqm.high),
                           queue_depth_unlocked(&state->pqm.normal),
                           queue_depth_unlocked(&state->pqm.low));
                }
                fflush(stdout);
                last_stats_time = now;
            }
        }
    }
    
    printf("[WORKER-%d] Done. Processed %lu frames.\n", worker_id, frame_counter);
    fflush(stdout);
    return NULL;
}

/* ---- Usage ---- */
static void print_usage(const char *prog) {
    printf("GridPulse GOOSE Subscriber — Configurable Architecture\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  --interface <if>       Interface (default: eth0)\n");
    printf("  --algorithm <algo>     RSA-2048, ECDSA-P256, HMAC-SHA256\n");
    printf("  --duration <sec>       Duration (default: 60)\n");
    printf("  --output <csv>         Output CSV file\n");
    printf("  --mode <fifo|priority> Queue mode (default: fifo)\n");
    printf("  --workers <N>          Verification threads 1-8 (default: 1)\n");
    printf("  --queue-size <N>       Queue capacity 256-16384 (default: 4096)\n");
    printf("  --t-normal <N>          Rate threshold for NORMAL (default: 50)\n");
    printf("  --t-burst <N>           Rate threshold for BURST (default: 500)\n");
    printf("  --t-flood <N>           Rate threshold for FLOOD (default: 1000)\n");
}

int main(int argc, char **argv) {
    char interface[64] = "eth0";
    int algo = ALG_RSA_2048;
    int duration = 60;
    char output[256] = "/results/subscriber_timing.csv";
    int mode = MODE_FIFO;
    int num_workers = 1;
    int queue_capacity = 4096;
    int t_normal = 50;
    int t_burst = 500;
    int t_flood = 1000;

    static struct option long_options[] = {
        {"interface",  required_argument, 0, 'i'},
        {"algorithm",  required_argument, 0, 'a'},
        {"duration",   required_argument, 0, 'd'},
        {"output",     required_argument, 0, 'o'},
        {"mode",       required_argument, 0, 'm'},
        {"workers",    required_argument, 0, 'w'},
        {"queue-size", required_argument, 0, 'q'},
        {"t-normal",   required_argument, 0, 'N'},
        {"t-burst",    required_argument, 0, 'B'},
        {"t-flood",    required_argument, 0, 'F'},
        {"no-mac",      no_argument, 0, 1001},
        {"no-rate",     no_argument, 0, 1002},
        {"no-priority", no_argument, 0, 1003},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:a:d:o:m:w:q:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': strncpy(interface, optarg, sizeof(interface)-1); break;
            case 'a': algo = parse_algo(optarg); break;
            case 'd': duration = atoi(optarg); break;
            case 'o': strncpy(output, optarg, sizeof(output)-1); break;
            case 'm':
                if (strcmp(optarg, "priority") == 0) mode = MODE_PRIORITY;
                else mode = MODE_FIFO;
                break;
            case 'w': num_workers = atoi(optarg); break;
            case 'q': queue_capacity = atoi(optarg); break;
            case 'N': t_normal = atoi(optarg); break;
            case 'B': t_burst = atoi(optarg); break;
            case 'F': t_flood = atoi(optarg); break;
            case 1001: g_ablation_no_mac = 1; break;
            case 1002: g_ablation_no_rate = 1; break;
            case 1003: g_ablation_no_priority = 1; break;
            default: print_usage(argv[0]); return 1;
        }
    }
    
    const char *abl_mac = getenv("ABLATION_NO_MAC");
    const char *abl_rate = getenv("ABLATION_NO_RATE");
    const char *abl_prio = getenv("ABLATION_NO_PRIORITY");
    if (abl_mac && abl_mac[0] && abl_mac[0] != '0') g_ablation_no_mac = 1;
    if (abl_rate && abl_rate[0] && abl_rate[0] != '0') g_ablation_no_rate = 1;
    if (abl_prio && abl_prio[0] && abl_prio[0] != '0') g_ablation_no_priority = 1;
    if (getenv("SERVICE_TIME_US")) {
        g_service_time_us = atof(getenv("SERVICE_TIME_US"));
        if (g_service_time_us > 0.0)
            printf("[CONFIG] Calibrated service-time emulation: %.1f us/frame "
                   "(mu = %.0f fps) — emulated embedded relay\n",
                   g_service_time_us, 1e6 / g_service_time_us);
    }
    
    if (num_workers < 1) num_workers = 1;
    if (num_workers > 8) num_workers = 8;
    if (queue_capacity < 256) queue_capacity = 256;
    if (queue_capacity > MAX_QUEUE_SIZE) queue_capacity = MAX_QUEUE_SIZE;

    setup_signals();
    openssl_init();

    /* ---- Initialize shared state ---- */
    shared_state_t *state = (shared_state_t *)calloc(1, sizeof(shared_state_t));
    if (!state) { fprintf(stderr, "malloc failed\n"); return 1; }
    
    state->algo = algo;
    state->duration = duration;
    state->mode = mode;
    state->num_workers = num_workers;
    state->queue_capacity = queue_capacity;
    pthread_mutex_init(&state->csv_lock, NULL);
    pthread_mutex_init(&state->stats_lock, NULL);
    stats_init(&state->stats);
    stats_init(&state->legit_stats);
    
    if (mode == MODE_FIFO) {
        if (queue_init(&state->fifo_queue, queue_capacity) < 0) {
            fprintf(stderr, "Queue init failed\n"); return 1;
        }
    } else {
        if (pqm_init(&state->pqm, queue_capacity) < 0) {
            fprintf(stderr, "PQM init failed\n"); return 1;
        }
        state->pqm.t_normal = t_normal;
        state->pqm.t_burst = t_burst;
        state->pqm.t_flood = t_flood;

        /* Pre-register publisher MAC if available */
        FILE *fmac = fopen("/shared/publisher_mac.txt", "r");
        if (fmac) {
            unsigned int m[6];
            if (fscanf(fmac, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                uint8_t pub_mac[6];
                for (int i = 0; i < 6; i++) pub_mac[i] = (uint8_t)m[i];
                pqm_register_mac(&state->pqm, pub_mac);
                printf("[PQAC] Pre-registered publisher MAC from configuration: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       pub_mac[0], pub_mac[1], pub_mac[2], pub_mac[3], pub_mac[4], pub_mac[5]);
            }
            fclose(fmac);
        }
    }

    const char *mode_str = (mode == MODE_PRIORITY) ? "PRIORITY" : "FIFO";
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  GridPulse GOOSE Subscriber                             ║\n");
    printf("║  Algorithm: %-10s  Mode: %-10s               ║\n", algo_name(algo), mode_str);
    printf("║  Workers: %d            Queue: %d                      ║\n", num_workers, queue_capacity);
    if (mode == MODE_PRIORITY)
        printf("║  Thresholds: N=%d B=%d F=%d                       ║\n", t_normal, t_burst, t_flood);
    if (g_ablation_no_mac || g_ablation_no_rate || g_ablation_no_priority)
        printf("║  Ablation: no_mac=%d no_rate=%d no_priority=%d          ║\n",
               g_ablation_no_mac, g_ablation_no_rate, g_ablation_no_priority);
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    fflush(stdout);

    /* Wait for keys */
    while (g_running) {
        if (algo == ALG_HMAC_SHA256) {
            FILE *f = fopen("/shared/hmac.key", "rb");
            if (f) { (void)fread(state->hmac_key, 1, 32, f); fclose(f); break; }
        }
#ifdef OQS_ENABLED
        else if (is_pqc_algo(algo)) {
            state->pqc_key = pqc_load_keys(algo, "/shared/pqc_pubkey.bin", NULL);
            if (state->pqc_key && state->pqc_key->pubkey) {
                printf("PQC key loaded: %s (pubkey=%zu bytes, max_sig=%zu bytes)\n",
                       state->pqc_key->alg_name, state->pqc_key->pubkey_len, state->pqc_key->sig_len);
                break;
            }
            if (state->pqc_key) { pqc_free(state->pqc_key); state->pqc_key = NULL; }
        }
#endif
        else {
            state->pkey = load_pubkey("/shared/pubkey.pem");
            if (state->pkey) {
                break;
            }
        }
        sleep(1);
    }
    if (!g_running) { free(state); return 0; }

    int ifindex = 0;
    state->sockfd = create_raw_socket(interface, &ifindex);
    if (state->sockfd < 0) { free(state); return 1; }

    char *last_slash = strrchr(output, '/');
    if (last_slash) { *last_slash = '\0'; mkdir(output, 0777); *last_slash = '/'; }
    
    state->csv = fopen(output, "w");
    if (!state->csv) { perror("fopen csv"); free(state); return 1; }
    fprintf(state->csv, CSV_HEADER);
    fflush(state->csv);

    state->start_time = get_time_ns();
    printf("Listening on %s with %d worker(s)...\n\n", interface, num_workers);
    fflush(stdout);

    /* ---- Launch threads ---- */
    pthread_t recv_tid;
    pthread_t worker_tids[8];
    worker_arg_t worker_args[8];
    
    pthread_create(&recv_tid, NULL, receiver_thread, state);
    
    for (int i = 0; i < num_workers; i++) {
        worker_args[i].state = state;
        worker_args[i].worker_id = i;
        pthread_create(&worker_tids[i], NULL, worker_thread, &worker_args[i]);
    }
    
    pthread_join(recv_tid, NULL);
    g_running = 0;
    
    for (int i = 0; i < num_workers; i++) {
        pthread_join(worker_tids[i], NULL);
    }

    /* ---- Final Report ---- */
    rolling_stats_t *rep = (state->legit_stats.total_frames > 0) ? &state->legit_stats : &state->stats;
    double miss_ratio = rep->total_frames > 0
        ? (double)rep->deadline_misses / rep->total_frames * 100.0
        : 0.0;
    
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("  FINAL REPORT: %s mode, %d worker(s), queue=%d\n",
           mode_str, num_workers, queue_capacity);
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  Total: %lu, Valid: %lu, Invalid: %lu\n",
           state->stats.total_frames, state->stats.valid_frames,
           state->stats.invalid_frames);
    printf("  Latency -> Mean: %.2f us, p95: %.2f us, p99: %.2f us\n",
           stats_mean(rep), stats_percentile(rep, 95.0),
           stats_percentile(rep, 99.0));
    printf("  Deadline Miss: %.2f%%\n", miss_ratio);
    
    if (mode == MODE_FIFO) {
        printf("  Queue Peak: %lu, Drops: %lu\n",
               (uint64_t)atomic_load(&state->fifo_queue.peak_depth),
               (uint64_t)atomic_load(&state->fifo_queue.dropped));
    } else {
        printf("  Classification: H=%lu N=%lu L=%lu DROP=%lu\n",
               (uint64_t)atomic_load(&state->pqm.classified_high),
               (uint64_t)atomic_load(&state->pqm.classified_normal),
               (uint64_t)atomic_load(&state->pqm.classified_low),
               (uint64_t)atomic_load(&state->pqm.classified_dropped));
        uint64_t calls = atomic_load(&state->pqm.scheduler_calls);
        uint64_t time_ns = atomic_load(&state->pqm.scheduler_time_ns);
        if (calls > 0) {
            printf("  Scheduler overhead: %.2f us/call\n",
                   (double)time_ns / (double)calls / 1000.0);
        }
    }
    printf("═══════════════════════════════════════════════════════════\n");
    fflush(stdout);

    if (state->csv) { fflush(state->csv); fclose(state->csv); }
    if (state->pkey) EVP_PKEY_free(state->pkey);
#ifdef OQS_ENABLED
    if (state->pqc_key) pqc_free(state->pqc_key);
#endif
    close(state->sockfd);
    
    if (mode == MODE_FIFO) queue_destroy(&state->fifo_queue);
    else pqm_destroy(&state->pqm);
    pthread_mutex_destroy(&state->csv_lock);
    pthread_mutex_destroy(&state->stats_lock);
    free(state);
    
    printf("Subscriber shutdown complete.\n");
    return 0;
}
