#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define SS_MAX_SEG_SIZE     1024 * 50
#define SS_MAX_SEGS_PER_MSG 10

struct packet {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    char data[SS_MAX_SEG_SIZE];
    u32 len;
};

// /* Structure for scatter/gather I/O.  */
// struct myiovec
//   {
//     void *iov_base;	/* Pointer to data.  */
//     size_t iov_len;	/* Length of data.  */
//   };
// /* Structure describing messages sent by
//    `sendmsg' and received by `recvmsg'.  */
// struct mymsghdr
//   {
//     void *msg_name;		/* Address to send to/receive from.  */
//     u32 msg_namelen;	/* Length of address data.  */

//     struct myiovec *msg_iov;	/* Vector of data to send/receive into.  */
//     size_t msg_iovlen;		/* Number of elements in the vector.  */

//     void *msg_control;		/* Ancillary data (eg BSD filedesc passing). */
//     size_t msg_controllen;	/* Ancillary data buffer length.
// 				   !! The type should be socklen_t but the
// 				   definition of the kernel is incompatible
// 				   with this.  */

//     int msg_flags;		/* Flags on received message.  */
//   };


BPF_PERF_OUTPUT(ipv4_send_events);
BPF_ARRAY(packet_array, struct packet, 4);
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    if (pid == 8283)
      return 0;
    u16 dport = 0, family = sk->__sk_common.skc_family;
  
    int iovlen;
    struct iov_iter *iter;
    const struct kvec *iov;
    struct packet *packet;
    unsigned int n, offset;
    char* buf;
    
    if (family == AF_INET) {
        n = bpf_get_smp_processor_id();
        packet = packet_array.lookup(&n);
        if(packet == NULL)
          return 0;
        
        packet->pid = pid;
        iter = &msg->msg_iter;
        if (iter->iov_offset != 0) {
          packet->len = size;
          ipv4_send_events.perf_submit(ctx, packet, offsetof(struct packet, data));
          return 0;
        }

        iov = iter->kvec;
        
        #pragma unroll
        for (int i = 0; i < SS_MAX_SEGS_PER_MSG; i++) {
          if (i >= iter->nr_segs)
            break;
          packet->len = iov->iov_len;
          buf = iov->iov_base;
          n = iov->iov_len;

          packet->saddr = sk->__sk_common.skc_rcv_saddr;
          packet->daddr = sk->__sk_common.skc_daddr;
          packet->lport = sk->__sk_common.skc_num;
          dport = sk->__sk_common.skc_dport;
          packet->dport =  ntohs(dport);
          bpf_probe_read(&packet->data, n > sizeof(packet->data) ? sizeof(packet->data): n, buf);
          n += offsetof(struct packet, data);
          ipv4_send_events.perf_submit(ctx, packet, n > sizeof(*packet) ? sizeof(*packet) : n);
          iov++;
        }
    }
    return 0;
}
