#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// #include "vmlinux.h"



#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif
#ifndef memset
#define memset(s, c, n)     __builtin_memset((s), (c), (n))
#endif


volatile const __be32 target_addr   = 0x0564a8c0;
volatile const __be32 current_addr  = 0x0364a8c0;


static __always_inline
__u16 csum_fold_helper(__u64 csum)
{
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}


static __always_inline
void set_ipv4_csum(struct iphdr *iph)
{
	__u16 *iph16 = (__u16 *) iph;
	__u64 csum = 0;

	iph->check = 0;

#pragma clang loop unroll(full)
	for (int i = 0; i < sizeof(*iph) >> 1; i++)
		csum += *iph16++;

    iph->check = csum_fold_helper(csum);
}


SEC("xdp")
//SEC("xdp_fwd")
int xdp_fwd_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *)(long) ctx->data;

    int rc;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct icmphdr *icmph;

    eth = data;
    if ((void *) (eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    iph = data + sizeof(struct ethhdr);
    if ((void *) (iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    icmph = (void *) iph + (iph->ihl << 2);
    if ((void *) (icmph + 1) > data_end) {
        return XDP_PASS;
    }

    bpf_printk("")

    struct bpf_fib_lookup fib_params = {
        .family = AF_INET,
        .tos = iph->tos,
        .l4_protocol = iph->protocol,
        .tot_len = bpf_ntohs(iph->tot_len),
        .ipv4_src = current_addr,
        .ipv4_dst = target_addr,
        // .ifindex = ctx->ingress_ifindex,
    };


    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
        bpf_printk("bpf_fib_lookup: %d", rc);
        return XDP_PASS;
    }

    iph->saddr = current_addr;
    iph->daddr = target_addr;
    set_ipv4_csum(iph);
    memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
    memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);

    if (ctx->ingress_ifindex == fib_params.ifindex) {
        return XDP_TX;
    } else {
        return bpf_redirect(fib_params.ifindex, 0);
    }

    // return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
