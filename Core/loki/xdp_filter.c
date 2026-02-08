/*
 * XDP Fast Filter for Loki IDS
 * Purpose: Block known attackers at NIC level before reaching Python
 * 
 * Compile: clang -O2 -target bpf -c xdp_filter.c -o xdp_filter.o
 * Load: sudo ip link set dev eth0 xdpgeneric obj xdp_filter.o sec xdp
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map: IP Blacklist (updated by Python when attack detected) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);      /* IP address (network byte order) */
    __type(value, __u64);    /* Timestamp when blocked */
} blacklist SEC(".maps");

/* Map: Rate limiting per IP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);      /* Source IP */
    __type(value, __u64);    /* Packet count */
} rate_limit SEC(".maps");

/* Map: Statistics (for monitoring) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Statistics indices */
#define STAT_TOTAL_PACKETS   0
#define STAT_DROPPED_PACKETS 1
#define STAT_BLACKLIST_HITS  2
#define STAT_RATE_LIMIT_HITS 3

/* Helper: Update statistics */
static __always_inline void update_stat(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    update_stat(STAT_TOTAL_PACKETS);
    
    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    /* Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    
    /* === Check 1: Blacklist (Instant Block) === */
    __u64 *blocked_time = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (blocked_time) {
        /* IP is blacklisted! Drop immediately */
        update_stat(STAT_DROPPED_PACKETS);
        update_stat(STAT_BLACKLIST_HITS);
        return XDP_DROP;  /* Instant block! No userspace processing! */
    }
    
    /* === Check 2: Rate Limiting (Fast Auto-Block) === */
    __u64 *count = bpf_map_lookup_elem(&rate_limit, &src_ip);
    __u64 current_count = 1;
    
    if (count) {
        current_count = *count + 1;
        
        /* Extremely high rate? Auto-block without waiting for Python */
        if (current_count > 10000) {
            /* Add to blacklist automatically */
            __u64 now = bpf_ktime_get_ns();
            bpf_map_update_elem(&blacklist, &src_ip, &now, BPF_ANY);
            
            update_stat(STAT_DROPPED_PACKETS);
            update_stat(STAT_RATE_LIMIT_HITS);
            return XDP_DROP;
        }
    }
    
    /* Update rate counter */
    bpf_map_update_elem(&rate_limit, &src_ip, &current_count, BPF_ANY);
    
    /* === Check 3: Protocol-specific checks === */
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        /* Could add more TCP-specific checks here */
        /* For now, just pass to Python for deep inspection */
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        /* Could add UDP-specific checks here */
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
        if ((void *)(icmp + 1) > data_end)
            return XDP_PASS;
        
        /* Could add ICMP-specific checks here */
    }
    
    /* Not in blacklist, not over extreme rate limit */
    /* Pass to kernel -> nfqueue -> Python IDS for deep inspection */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
