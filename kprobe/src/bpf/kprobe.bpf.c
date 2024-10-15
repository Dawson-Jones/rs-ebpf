// // +build ignore

// // #include "common.h"
// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>

// char __license[] SEC("license") = "Dual MIT/GPL";

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, __u32);
// 	__type(value, __u64);
// 	__uint(max_entries, 1);
// } kprobe_map SEC(".maps");


// SEC("kprobe/sys_execve")
// int kprobe_execve() {
// 	__u32 key     = 0;
// 	__u64 initval = 1, *valp;

// 	valp = bpf_map_lookup_elem(&kprobe_map, &key);
// 	if (!valp) {
// 		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
// 		return 0;
// 	}
// 	__sync_fetch_and_add(valp, 1);

// 	return 0;
// }


/* Copyright (c) 2015 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "vmlinux.h"
// #include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct pair {
	__u64 val;
	__u64 ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, struct pair);
	__uint(max_entries, 1000000);
} my_map SEC(".maps");

/* kprobe is NOT a stable ABI. If kernel internals change this bpf+kprobe
 * example will no longer be meaningful
 */
SEC("kprobe/kmem_cache_free")
int bpf_prog1(struct pt_regs *ctx)
{
	bpf_printk("-------");
	long ptr = PT_REGS_PARM2(ctx);

	bpf_map_delete_elem(&my_map, &ptr);
	return 0;
}

SEC("kretprobe/kmem_cache_alloc_node")
int bpf_prog2(struct pt_regs *ctx)
{
	long ptr = PT_REGS_RC(ctx);
	long ip = 0;

	/* get ip address of kmem_cache_alloc_node() caller */
	BPF_KRETPROBE_READ_RET_IP(ip, ctx);

	struct pair v = {
		.val = bpf_ktime_get_ns(),
		.ip = ip,
	};

	bpf_map_update_elem(&my_map, &ptr, &v, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
// 
