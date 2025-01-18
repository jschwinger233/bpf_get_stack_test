// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"


char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_STACK_DEPTH 50
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} print_stack_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<29);
} event_ringbuf SEC(".maps");

struct event_helper {
	__u64 stackid;
};

struct event_manually {
	__u64 depth;
	__u64 pcs[MAX_STACK_DEPTH];
};

SEC("kprobe")
int helper_get_stack(struct pt_regs *ctx)
{
	struct event_helper event = {};
	event.stackid = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
	bpf_ringbuf_output(&event_ringbuf, &event, sizeof(event), 0);
	return 0;
}

SEC("kprobe")
int manually_get_stack(struct pt_regs *ctx)
{
	u64 depth = 0;
	u64 fps[MAX_STACK_DEPTH];
	fps[0] = PT_REGS_FP(ctx);
	for (depth = 0; depth < MAX_STACK_DEPTH-1; depth++) {
		if (bpf_probe_read_kernel(&fps[depth+1],
					  sizeof(fps[depth+1]),
					  (void *)fps[depth]) < 0)
			break;

		if (fps[depth+1] == 0)
			break;
	}

	struct event_manually *event = (struct event_manually *)bpf_ringbuf_reserve(
		&event_ringbuf,
		sizeof(u64) + (depth + 1) * sizeof(u64),
		0);
	if (!event)
		return 0;

	event->depth = depth;
	for (u64 i = 0; i <= depth; i++) {
		bpf_probe_read_kernel(&event->pcs[i],
				      sizeof(event->pcs[i]),
				      (void *)(fps[i] + 8));
	}
	bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);
	return 0;
}
