#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 2,
};

struct data_t {
    
};

SEC("kprobe/sys_sendto")
int kprobe_sendto(struct pt_regs *ctx) {
    struct data_t data;

    bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));


    return 0;
}