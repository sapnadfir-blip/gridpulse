/* xdp_goose_filter.c - eBPF/XDP Pre-Verification Filter for IEC 61850 GOOSE
 *
 * This BPF program runs at the NIC driver level (XDP hook) and filters
 * GOOSE frames BEFORE they reach the kernel network stack or userspace.
 *
 * Decision Pipeline:
 * 1. EtherType Check: Pass non-GOOSE traffic immediately
 * 2. MAC Allowlist: Drop frames from unauthorized source MACs
 * 3. Rate Limiting: Token-bucket per-source rate limiter
 *
 * Compile: clang -O2 -target bpf -c xdp_goose_filter.c -o xdp_goose_filter.o
 * Load:    ip link set dev eth0 xdpgeneric obj xdp_goose_filter.o sec xdp_goose
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GOOSE_ETHERTYPE 0x88B8
#define MAX_SOURCES     64
#define RATE_LIMIT_PPS  1000   /* Max packets/sec per source MAC */
#define NSEC_PER_SEC    1000000000ULL
#define TOKEN_REFILL_NS (NSEC_PER_SEC / RATE_LIMIT_PPS)

/* ---- BPF Maps ---- */

/* Statistics counters */
struct xdp_stats {
    __u64 packets_received;
    __u64 packets_passed;
    __u64 packets_dropped;
    __u64 drop_by_ethertype;    /* Non-GOOSE (should be 0, we pass these) */
    __u64 drop_by_mac;          /* Unauthorized source MAC */
    __u64 drop_by_rate;         /* Rate limit exceeded */
    __u64 goose_frames_seen;    /* Total GOOSE frames inspected */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} xdp_stats SEC(".maps");

/* MAC allowlist: key = 6-byte MAC (padded to 8), value = 1 if allowed */
struct mac_key {
    __u8 addr[8]; /* 6 bytes MAC + 2 padding */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOURCES);
    __type(key, struct mac_key);
    __type(value, __u32);
} allowed_macs SEC(".maps");

/* Per-source rate limiter state */
struct rate_state {
    __u64 last_seen_ns;   /* Timestamp of last packet */
    __u64 tokens;         /* Available tokens */
    __u64 last_refill_ns; /* Last token refill timestamp */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOURCES);
    __type(key, struct mac_key);
    __type(value, struct rate_state);
} rate_limiter SEC(".maps");

/* ---- Helper Functions ---- */

static __always_inline void update_stats(struct xdp_stats *stats,
                                          int received, int passed,
                                          int dropped, int drop_mac,
                                          int drop_rate, int goose_seen)
{
    if (received) __sync_fetch_and_add(&stats->packets_received, 1);
    if (passed)   __sync_fetch_and_add(&stats->packets_passed, 1);
    if (dropped)  __sync_fetch_and_add(&stats->packets_dropped, 1);
    if (drop_mac) __sync_fetch_and_add(&stats->drop_by_mac, 1);
    if (drop_rate)__sync_fetch_and_add(&stats->drop_by_rate, 1);
    if (goose_seen) __sync_fetch_and_add(&stats->goose_frames_seen, 1);
}

/* ---- XDP Program ---- */

SEC("xdp_goose")
int xdp_goose_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Get stats map entry */
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats, &key);
    if (!stats)
        return XDP_PASS;

    update_stats(stats, 1, 0, 0, 0, 0, 0);

    /* Bounds check: ensure we can read Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Step 1: EtherType Check
     * Pass all non-GOOSE traffic immediately (don't interfere with ARP, IP, etc.)
     */
    __u16 eth_type = bpf_ntohs(eth->h_proto);
    if (eth_type != GOOSE_ETHERTYPE) {
        update_stats(stats, 0, 1, 0, 0, 0, 0);
        return XDP_PASS;
    }

    /* This is a GOOSE frame */
    update_stats(stats, 0, 0, 0, 0, 0, 1);

    /* Step 2: MAC Allowlist Check
     * Only allow GOOSE frames from pre-authorized source MACs
     */
    struct mac_key src_key = {};
    __builtin_memcpy(src_key.addr, eth->h_source, 6);

    __u32 *allowed = bpf_map_lookup_elem(&allowed_macs, &src_key);
    if (!allowed || *allowed != 1) {
        /* Source MAC not in allowlist -> DROP */
        update_stats(stats, 0, 0, 1, 1, 0, 0);
        return XDP_DROP;
    }

    /* Step 3: Per-Source Rate Limiting (Token Bucket)
     * Allow max RATE_LIMIT_PPS packets/second per source MAC
     */
    __u64 now = bpf_ktime_get_ns();
    struct rate_state *rs = bpf_map_lookup_elem(&rate_limiter, &src_key);

    if (rs) {
        /* Refill tokens based on elapsed time */
        __u64 elapsed = now - rs->last_refill_ns;
        __u64 new_tokens = elapsed / TOKEN_REFILL_NS;

        if (new_tokens > 0) {
            rs->tokens += new_tokens;
            if (rs->tokens > RATE_LIMIT_PPS)
                rs->tokens = RATE_LIMIT_PPS;
            rs->last_refill_ns = now;
        }

        if (rs->tokens > 0) {
            rs->tokens--;
            rs->last_seen_ns = now;
            update_stats(stats, 0, 1, 0, 0, 0, 0);
            return XDP_PASS;
        } else {
            /* Rate limit exceeded -> DROP */
            update_stats(stats, 0, 0, 1, 0, 1, 0);
            return XDP_DROP;
        }
    } else {
        /* First packet from this source: initialize rate state */
        struct rate_state new_rs = {
            .last_seen_ns = now,
            .tokens = RATE_LIMIT_PPS - 1,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&rate_limiter, &src_key, &new_rs, BPF_ANY);
        update_stats(stats, 0, 1, 0, 0, 0, 0);
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
