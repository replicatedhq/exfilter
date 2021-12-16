#include <linux/sched.h>
#include <linux/skbuff.h>

struct xmit_event {
    u64 ts;
    u32 pid;
    u32 tgid;
    u32 len;
    u32 datalen;
    u32 packet_buf_ptr;
    char comm[TASK_COMM_LEN];
    
    u64 head;
    u64 data;
    u64 tail;
    u64 end;
};
BPF_PERF_OUTPUT(xmits);

#define PACKET_BUF_SIZE 32768
# define PACKET_BUFS_PER_CPU 15

struct packet_buf {
    unsigned char data[PACKET_BUF_SIZE];
};
BPF_PERCPU_ARRAY(packet_buf, struct packet_buf, PACKET_BUFS_PER_CPU);
BPF_PERCPU_ARRAY(packet_buf_head, u32, 1);

int kprobe____dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb, void *accel_priv) {
    if (skb == NULL || skb->data == NULL)
        return 0;
    struct xmit_event data = { };
    u64 both = bpf_get_current_pid_tgid();

    data.pid = both;
    if (data.pid == 0)
        return 0;
    data.tgid = both >> 32;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.len = skb->len;
    
    // Copy packet contents
    int slot = 0;
    u32 *packet_buf_ptr = packet_buf_head.lookup(&slot);
    if (packet_buf_ptr == NULL)
        return 0;
    u32 buf_head = *packet_buf_ptr;
    u32 next_buf_head = (buf_head + 1) % PACKET_BUFS_PER_CPU;
    packet_buf_head.update(&slot, &next_buf_head);
    
    struct packet_buf *ringbuf = packet_buf.lookup(&buf_head);
    if (ringbuf == NULL)
        return 0;
    
    u32 skb_data_len = skb->data_len;
    u32 headlen = data.len - skb_data_len;
    headlen &= 0xffffff; // Useless, but validator demands it because "this unsigned(!) variable could otherwise be negative"
    bpf_probe_read_kernel(ringbuf->data, headlen < PACKET_BUF_SIZE ? headlen : PACKET_BUF_SIZE, skb->data);
    data.packet_buf_ptr = buf_head;
    
    // data.len = headlen;
    data.datalen = skb_data_len;
    
    data.head = (u64) skb->head;
    data.data = (u64) skb->data;
    data.tail = (u64) skb->tail;
    data.end = (u64) skb->end;
    
    // xmits.perf_submit(ctx, &data, sizeof(data));
    xmits.perf_submit(ctx, &data, sizeof(data));
    return 0;
}