#include "common.h"
#include "bpf_helpers.h"
#include "stddef.h"
#include <sys/socket.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 2,
};

struct data_t {
    char comm[16];
};

SEC("kprobe/sys_sendmsg")
int kprobe_sendmsg(struct pt_regs *ctx,int sockfd, const struct msghdr *msg, int flags) {
    struct data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));


    return 0;
}

SEC("kprobe/sys_sendto")
int kprobe_sendto(struct pt_regs *ctx,int sockfd, const void *buf, size_t len, int flags) {
    struct data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));


    return 0;
}
SEC("kprobe/sys_send")
int kprobe_send(struct pt_regs *ctx,int fd, const void *buf, size_t count) {
    struct data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));


    return 0;
}

SEC("kprobe/sys_write")
int kprobe_write(struct pt_regs *ctx,int fd, const void *buf, size_t count) {
    struct data_t data;


    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));


    return 0;
}