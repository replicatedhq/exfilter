#include "common.h"
#include "bpf_helpers.h"
#include "stddef.h"
#include <sys/socket.h>
#include <sys/sendfile.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/* sendmsg */
struct sendmsg_data_t {
    char comm[16];
};
struct bpf_map_def SEC("maps") sendmsg_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 10,  // the size of the ring buffer, this is a wild guess for now
};

SEC("kprobe/sys_sendmsg")
int kprobe_sendmsg(struct pt_regs *ctx,int sockfd, const struct msghdr *msg, int flags) {
    struct sendmsg_data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_perf_event_output(ctx, &sendmsg_events, 0, &data, sizeof(data));

    return 0;
}


/* sendmmsg */
struct sendmmsg_data_t {
    char comm[16];
};
struct bpf_map_def SEC("maps") sendmmsg_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 10,  // the size of the ring buffer, this is a wild guess for now
};

SEC("kprobe/sys_sendmmsg")
int kprobe_sendmmsg(struct pt_regs *ctx,int sockfd, struct mmsghdr *msgs, unsigned int vlen, int flags) {
    struct sendmmsg_data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_perf_event_output(ctx, &sendmmsg_events, 0, &data, sizeof(data));

    return 0;
}


/* sendfile */
struct sendfile_data_t {
    char comm[16];
};
struct bpf_map_def SEC("maps") sendfile_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 10,  // the size of the ring buffer, this is a wild guess for now
};

SEC("kprobe/sys_sendfile")
int kprobe_sendfile(struct pt_regs *ctx,int sockoutfd, int sockinfd, off_t *offset, size_t count) {
    struct sendfile_data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_perf_event_output(ctx, &sendfile_events, 0, &data, sizeof(data));

    return 0;
}


/* sendto */
struct sendto_data_t {
    char comm[16];
};
struct bpf_map_def SEC("maps") sendto_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 2,
};

SEC("kprobe/sys_sendto")
int kprobe_sendto(struct pt_regs *ctx,int sockfd, const void *buf, size_t len, int flags) {
    struct sendto_data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_perf_event_output(ctx, &sendto_events, 0, &data, sizeof(data));

    return 0;
}

/* send */
struct send_data_t {
    char comm[16];
};
struct bpf_map_def SEC("maps") send_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 2,
};

SEC("kprobe/sys_send")
int kprobe_send(struct pt_regs *ctx,int fd, const void *buf, size_t count) {
    struct send_data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_perf_event_output(ctx, &send_events, 0, &data, sizeof(data));

    return 0;
}

/* write */
struct write_data_t {
    char comm[16];
};
struct bpf_map_def SEC("maps") write_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 2,
};


SEC("kprobe/sys_write")
int kprobe_write(struct pt_regs *ctx,int fd, const void *buf, size_t count) {
    struct write_data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_perf_event_output(ctx, &write_events, 0, &data, sizeof(data));

    return 0;
}


/* writev */
struct writev_data_t {
    char comm[16];
};
struct bpf_map_def SEC("maps") writev_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 2,
};


SEC("kprobe/sys_writev")
int kprobe_writev(struct pt_regs *ctx,int fd, const struct iovec *iovec, int count) {
    struct writev_data_t data;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_perf_event_output(ctx, &writev_events, 0, &data, sizeof(data));

    return 0;
}

