#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//#include <linux/if_ether.h>
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

// #include <linux/pkt_cls.h
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_SHOT		2

u8 rc_allow     = TC_ACT_UNSPEC;
u8 rc_disallow  = TC_ACT_SHOT;


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u16);
    __uint(max_entries, 10);
} ports SEC(".maps");


static bool allow_port(__be16 port)
{
    u16 hport = bpf_ntohs(port);
    u32 i = 0;
    for (i = 0; i < 10; i++) {
        u32 key = i;
        u16 *allow_port = bpf_map_lookup_elem(&ports, &key);
        if (allow_port && hport == *allow_port) {
            return true;
        }
    }

    return false;
}


SEC("tc")
int handle_tc(struct __sk_buff *skb)
{
    int rc = rc_disallow;

    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    struct ethhdr *eth = (struct ethhdr *) data;

    __be16 dst  = 0;
    __be16 src  = 0;
    __be16 port = 0;
    __u8 proto  = 0;

    void *trans_data;
    if (eth + 1 > data_end) {
        return TC_ACT_UNSPEC;
    }

    if (eth->h_proto = bpf_htons(ETH_P_IP)) {   // ipv4
        struct iphdr *iph = (struct iphdr *) (eth + 1);
        if ((void *) (iph + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        proto = iph->protocol;
        trans_data = (void *) iph + (iph->ihl << 2);
    } else if (eth->h_proto = bpf_htons(ETH_P_IPV6)) { // ipv6
        struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
        if ((void *) (ipv6 + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        proto = ipv6->nexthdr;
        trans_data = (void *) (ipv6 + 1);
    }

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *) trans_data;
        if ((void *) (tcph + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        dst = tcph->dest;
        src = tcph->source;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *) trans_data;
        if ((void *) (udph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        dst = udph->dest;
        src = udph->source;
    } else {
        goto found_unknow;
    }

    if (allow_port(src) || allow_port(dst)) {
        rc = rc_allow;
    }

    if (skb->ingress_ifindex) {
        bpf_printk("b ingress on -- src %d dst %d", bpf_ntohs(src), bpf_ntohs(dst));
    } else {
        bpf_printk("b egress on -- src %d dst %d", bpf_ntohs(src), bpf_ntohs(dst));
    }

    return rc;
found_unknow:
    rc = TC_ACT_UNSPEC;
    return rc;
}