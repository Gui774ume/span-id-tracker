/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <linux/kconfig.h>
#include <linux/version.h>

#include <uapi/linux/perf_event.h>
#include <uapi/linux/bpf_perf_event.h>
/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif
/* Before bpf_helpers.h is included, uapi bpf.h has been
 * included, which references linux/types.h. This may bring
 * in asm_volatile_goto definition if permitted based on
 * compiler setup and kernel configs.
 *
 * clang does not support "asm volatile goto" yet.
 * So redefine asm_volatile_goto to some invalid asm code.
 * If asm_volatile_goto is actually used by the bpf program,
 * a compilation error will appear.
 */
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#pragma clang diagnostic pop

// Custom eBPF helpers
#include "bpf/bpf.h"
#include "bpf/bpf_map.h"
#include "bpf/bpf_helpers.h"

SEC("uprobe/empty_probe")
int uprobe_empty_probe(struct pt_regs *ctx)
{
    return 0;
};

struct coroutine_ctx_t {
    u8 type;
    char data[230];
};

struct bpf_map_def SEC("maps/coroutine_ctx") coroutine_ctx = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct coroutine_ctx_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/coroutine_ids") coroutine_ids = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

SEC("uprobe/complex_probe")
int uprobe_complex_probe(struct pt_regs *ctx)
{
    void *input_struct;
    u64 value, offset;
    u64 id = bpf_get_current_pid_tgid();

    // fetch the pointer to the goroutine about to be scheduled on the current thread
    bpf_probe_read(&input_struct, sizeof(input_struct), (void *) PT_REGS_SP(ctx) + 8);
    if (input_struct == NULL) {
        return 0;
    }

    // fetch the coroutine data for the current thread, it contains the offset used to dereference the goroutine id
    u32 key = 0;
    struct coroutine_ctx_t *co_ctx = bpf_map_lookup_elem(&coroutine_ctx, &key);
    if (co_ctx == NULL) {
        return 0;
    }

    bpf_probe_read(&offset, sizeof(offset), co_ctx->data);

    // fetch goroutine id
    bpf_probe_read(&value, sizeof(value), (void *) input_struct + offset);

    // update the thread id <-> coroutine id mapping
    bpf_map_update_elem(&coroutine_ids, &id, &value, BPF_ANY);
    return 0;
};

#define GOLANG 1
#define PYTHON 2

struct span_key_t {
    u64 coroutine_id;
    u32 id;
    u32 padding;
};

struct span_t {
    u64 span_id;
    u64 trace_id;
};

struct bpf_map_def SEC("maps/span_ids") span_ids = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct span_key_t),
    .value_size = sizeof(struct span_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

SEC("kprobe/do_vfs_ioctl")
int kprobe__do_vfs_ioctl(struct pt_regs *ctx) {
    void *req = (void *)PT_REGS_PARM4(ctx);
    u8 op;
    bpf_probe_read(&op, sizeof(op), req);
    void *data = req + sizeof(op);

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    struct span_key_t key = {};
    struct span_t span = {};
    struct coroutine_ctx_t co_ctx = {};

    // parse the provided data (span id, trace id, coroutine id, language specific data)
    bpf_probe_read(&span.span_id, sizeof(span.span_id), data);
    bpf_probe_read(&span.trace_id, sizeof(span.trace_id), data + 8);
    bpf_probe_read(&key.coroutine_id, sizeof(key.coroutine_id), data + 16);
    bpf_probe_read(&co_ctx.type, sizeof(co_ctx.type), data + 24);
    bpf_probe_read(&co_ctx.data, sizeof(co_ctx.data), data + 25);

    // set key id based on coroutine type
    switch (co_ctx.type) {
        case (GOLANG): {
            key.id = pid;
        }
        case (PYTHON): {
            key.id = id;
        }
    }

    // save span id and co_data context for future use
    bpf_map_update_elem(&span_ids, &key, &span, BPF_ANY);
    bpf_map_update_elem(&coroutine_ctx, &pid, &co_ctx, BPF_ANY);

    // update thread id <-> coroutine id mapping
    bpf_map_update_elem(&coroutine_ids, &id, &key.coroutine_id, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
