#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// #include <linux/if_ether.h>
// #include <linux/pkt_cls.h>
// #include <linux/bpf.h>
/* Define constants not captured by BTF */
#define BPF_F_CURRENT_NETNS	(-1L)
#define TC_ACT_OK		0
#define TC_ACT_SHOT		2
#define ETH_P_IP		(0x0800)


volatile const __be16 target_port = 0;
volatile const __be32 proxy_addr  = 0;
volatile const __be16 proxy_port  = 0;



static inline
struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb)
{
    void *data_end = (void *) (long) skb->data_end;
    void *data = (void *) (long) skb->data;
    struct bpf_sock_tuple *result;
    struct ethhdr *eth;
    __u64 tuple_len;
    __u8 proto = 0;
    __u64 ihl_len;

    eth = (struct ethhdr *) data;
    if (eth + 1 > data_end) {
        return NULL;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return NULL;
    
    struct iphdr *iph = (struct iphdr *) (data + sizeof(*eth));
    if (iph + 1 > data_end)
        return NULL;
    if (iph->ihl != 5)
        return NULL;

    ihl_len = iph->ihl << 2;
    proto = iph->protocol;
    result = (struct bpf_sock_tuple *) &iph->saddr;

    if (proto != IPPROTO_TCP)
        return NULL;

    return result;
}

static inline
int handle_tcp(struct __sk_buff *skb, struct bpf_sock_tuple *tuple)
{
    struct bpf_sock_tuple server = {};
    struct bpf_sock *sk;
    const int zero = 0;
    size_t tuple_len;
    int ret;

    tuple_len = sizeof(tuple->ipv4);
    if ((void *) tuple + tuple_len > (void *) (long) skb->data_end)
        return TC_ACT_SHOT;
    
    if (tuple->ipv4.dport != target_port)
        return TC_ACT_OK;

    sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
    if (sk) {
        if (sk->state != BPF_TCP_LISTEN)
            goto assign;

        bpf_sk_release(sk);
    }

    server.ipv4.saddr = tuple->ipv4.saddr;
    server.ipv4.daddr = proxy_addr;
    server.ipv4.sport = tuple->ipv4.sport;
    server.ipv4.dport = proxy_port;

    sk = bpf_skc_lookup_tcp(skb, &server, tuple_len, BPF_F_CURRENT_NETNS, 0);
    if (!sk)
        return TC_ACT_SHOT;

    if (sk->state != BPF_TCP_LISTEN) {
        bpf_sk_release(sk);
        return TC_ACT_SHOT;
    }

assign:
    ret = bpf_sk_assign(skb, sk, 0);
    bpf_sk_release(sk);
    return ret;
}


SEC("tc")
int tproxy(struct __sk_buff *skb)
{
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int ret = 0;

    bpf_printk("target_port: %d", bpf_htons(target_port));
    bpf_printk("proxy_port: %d", bpf_htons(proxy_port));
    bpf_printk("proxy_addr: 0x%x", bpf_htonl(proxy_addr));

    tuple = get_tuple(skb);
    if (!tuple) {
        return TC_ACT_SHOT;
    }

    ret = handle_tcp(skb, tuple);

    return ret == 0 ? TC_ACT_OK : TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
