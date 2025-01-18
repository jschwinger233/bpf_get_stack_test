// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"


char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_STACK_DEPTH 50
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} print_stack_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<29);
} event_ringbuf SEC(".maps");

struct event_helper {
	__u32 stackid;
};

const struct event_helper *___event_helper __attribute__((unused));

struct event_manual_meta {
	__u64 depth;
};

struct event_manual {
	__u64 pcs[MAX_STACK_DEPTH];
};

const struct event_manual_meta *__event_manual_meta __attribute__((unused));


SEC("kprobe")
int helper_get_stack(struct pt_regs *ctx)
{
	struct event_helper event = {};
	event.stackid = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
	bpf_ringbuf_output(&event_ringbuf, &event, sizeof(event), 0);
	return 0;
}

SEC("kprobe")
int manual_get_stack(struct pt_regs *ctx)
{
	u64 depth = 0;
	u64 fps[MAX_STACK_DEPTH];
	fps[0] = PT_REGS_FP(ctx);
	for (depth = 0; depth < MAX_STACK_DEPTH-3; depth++) {
		if (bpf_probe_read_kernel(&fps[depth+1],
					  sizeof(fps[depth+1]),
					  (void *)fps[depth]) < 0)
			break;

		if (fps[depth+1] == 0)
			break;
	}

	depth += 3;

	void *ringbuf = bpf_ringbuf_reserve(
		&event_ringbuf,
		sizeof(u64) + depth * sizeof(u64),
		0);
	if (!ringbuf)
		return 0;

	struct event_manual_meta *meta = ringbuf;
	meta->depth = depth;

	struct event_manual *event = ringbuf + sizeof(*meta);
	event->pcs[0] = PT_REGS_IP(ctx);
	u64 sp = PT_REGS_SP(ctx);
	bpf_probe_read_kernel(&event->pcs[1],
			      sizeof(event->pcs[1]),
			      (void *)sp);
	for (u64 i = 0; i < depth - 2; i++) {
		bpf_probe_read_kernel(&event->pcs[i+2],
				      sizeof(event->pcs[i+2]),
				      (void *)(fps[i] + 8));
	}
	bpf_ringbuf_submit(ringbuf, 0);
	return 0;
}
