#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_8021Q 0x8100
#define ETH_P_GOOSE 0x88B8

#define MAX_MACS 256
#define MAX_TLV_FIELDS 32

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MACS);
    __type(key, __u8[6]);
    __type(value, __u64);
} mac_allowlist SEC(".maps");

struct rate_limit_data {
    __u64 tokens;
    __u64 last_refill_ns;
    __u64 max_tokens;
    __u64 refill_rate;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_MACS);
    __type(key, __u8[6]);
    __type(value, struct rate_limit_data);
} rate_limiter SEC(".maps");

struct seq_state {
    __u32 last_st_num;
    __u32 last_sq_num;
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MACS);
    __type(key, __u8[6]);
    __type(value, struct seq_state);
} seq_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} filter_stats SEC(".maps");

// Stat indices
#define STAT_TOTAL 0
#define STAT_GOOSE 1
#define STAT_PASSED 2
#define STAT_DROP_MAC 3
#define STAT_DROP_RATE 4
#define STAT_DROP_SEQ 5
#define STAT_DROP_MALF 6
#define STAT_ERRORS 7

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static __always_inline void inc_stat(__u32 idx) {
    __u64 *value = bpf_map_lookup_elem(&filter_stats, &idx);
    if (value) {
        *value += 1;
    }
}

// BPF program for GOOSE filter
SEC("xdp")
int xdp_goose_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    inc_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *payload = eth + 1;

    // Handle VLAN
    if (h_proto == ETH_P_8021Q) {
        struct vlan_hdr *vlan = payload;
        if ((void *)(vlan + 1) > data_end) {
            return XDP_PASS;
        }
        h_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        payload = vlan + 1;
    }

    if (h_proto != ETH_P_GOOSE) {
        return XDP_PASS; // Transparent to non-GOOSE traffic
    }

    inc_stat(STAT_GOOSE);

    // MAC Allowlist check
    __u8 src_mac[6];
    __builtin_memcpy(src_mac, eth->h_source, 6);
    __u64 *allowed = bpf_map_lookup_elem(&mac_allowlist, src_mac);
    if (!allowed) {
        inc_stat(STAT_DROP_MAC);
        return XDP_DROP;
    }

    // Rate limiter check
    struct rate_limit_data *rl = bpf_map_lookup_elem(&rate_limiter, src_mac);
    if (rl) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed = now - rl->last_refill_ns;
        // Simple token bucket logic
        __u64 add_tokens = (elapsed * rl->refill_rate) / 1000000000;
        if (add_tokens > 0) {
            rl->tokens += add_tokens;
            if (rl->tokens > rl->max_tokens) {
                rl->tokens = rl->max_tokens;
            }
            rl->last_refill_ns = now;
        }

        if (rl->tokens > 0) {
            rl->tokens -= 1;
        } else {
            inc_stat(STAT_DROP_RATE);
            return XDP_DROP;
        }
    }

    // Parse GOOSE Header (APPID, Length, Reserved 1&2)
    // payload points to GOOSE header
    if (payload + 8 > data_end) {
        inc_stat(STAT_DROP_MALF);
        return XDP_DROP;
    }
    
    // Jump over GOOSE Header
    void *asn1_data = payload + 8;
    if (asn1_data > data_end) {
        inc_stat(STAT_DROP_MALF);
        return XDP_DROP;
    }

    // Basic TLV parser to find stNum and sqNum
    // This is a simplified TLV parser that looks for tags 0x85 (stNum) and 0x86 (sqNum)
    __u32 parsed_st_num = 0;
    __u32 parsed_sq_num = 0;
    __u8 found_st = 0;
    __u8 found_sq = 0;

    void *cursor = asn1_data;

    // Bounded loop
    #pragma unroll
    for (int i = 0; i < MAX_TLV_FIELDS; i++) {
        if (cursor + 2 > data_end) {
            break;
        }
        __u8 tag = *(__u8 *)cursor;
        __u8 len = *(__u8 *)(cursor + 1);

        if (cursor + 2 + len > data_end) {
            break;
        }

        if (tag == 0x85) {
            if (len == 1) {
                parsed_st_num = *(__u8 *)(cursor + 2);
            } else if (len == 2) {
                parsed_st_num = bpf_ntohs(*(__u16 *)(cursor + 2));
            } else if (len == 4) {
                parsed_st_num = bpf_ntohl(*(__u32 *)(cursor + 2));
            }
            found_st = 1;
        } else if (tag == 0x86) {
             if (len == 1) {
                parsed_sq_num = *(__u8 *)(cursor + 2);
            } else if (len == 2) {
                parsed_sq_num = bpf_ntohs(*(__u16 *)(cursor + 2));
            } else if (len == 4) {
                parsed_sq_num = bpf_ntohl(*(__u32 *)(cursor + 2));
            }
            found_sq = 1;
        }

        if (found_st && found_sq) {
            break;
        }

        cursor += 2 + len;
    }

    if (found_st && found_sq) {
        struct seq_state *seq = bpf_map_lookup_elem(&seq_tracker, src_mac);
        if (seq) {
            if (parsed_st_num < seq->last_st_num) {
                inc_stat(STAT_DROP_SEQ);
                return XDP_DROP;
            } else if (parsed_st_num == seq->last_st_num) {
                if (parsed_sq_num <= seq->last_sq_num && parsed_sq_num != 0) {
                    inc_stat(STAT_DROP_SEQ);
                    return XDP_DROP;
                }
            }
            seq->last_st_num = parsed_st_num;
            seq->last_sq_num = parsed_sq_num;
            seq->last_seen_ns = bpf_ktime_get_ns();
        } else {
            struct seq_state new_seq = {0};
            new_seq.last_st_num = parsed_st_num;
            new_seq.last_sq_num = parsed_sq_num;
            new_seq.last_seen_ns = bpf_ktime_get_ns();
            bpf_map_update_elem(&seq_tracker, src_mac, &new_seq, BPF_ANY);
        }
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
