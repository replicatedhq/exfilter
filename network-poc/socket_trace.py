#!/usr/bin/env python
# coding=utf-8
from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse
from collections import namedtuple, defaultdict
from threading import Thread, currentThread, Lock
from socket import inet_ntop, AF_INET
from struct import pack

# lock = Lock()
# arguments
def range_check(string):
    value = int(string)
    if value < 1:
        msg = "value must be stricly positive, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value

examples = """examples:
    ./flow          # trace send/recv flow by host 
    ./flow -p 100   # only trace PID 100
"""

parser = argparse.ArgumentParser(
    description = "Summarize send and recv flow by host",
    formatter_class = argparse.RawDescriptionHelpFormatter,
    epilog = examples
)
parser.add_argument("-p", "--pid", 
    help = "Trace this pid only")
parser.add_argument("interval", nargs="?", default=1, type=range_check,
	help = "output interval, in second (default 1)")
parser.add_argument("count", nargs="?", default=-1, type=range_check,
	help="number of outputs")
args = parser.parse_args()

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_key_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u16 dport = 0, family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_send_bytes.increment(ipv4_key, size);
    }
    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero =0;

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_recv_bytes.increment(ipv4_key, copied);
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
    }
    return 0;
}
"""

# code substitutions
if args.pid:
    bpf_program = bpf_program.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_program = bpf_program.replace('FILTER_PID','')

SessionKey = namedtuple('Session',['pid', 'laddr', 'lport', 'daddr', 'dport'])

def pid_to_comm(pid):
    try:
        comm = open("/proc/%s/comm" % pid, "r").read().rstrip()
        return comm
    except IOError:
        return str(pid)

def get_ipv4_session_key(k):
	return SessionKey(pid=k.pid, laddr=inet_ntop(AF_INET, pack("I", k.saddr)),lport=k.lport, daddr=inet_ntop(AF_INET, pack("I", k.daddr)), dport=k.dport)

# init bpf
# b = BPF(text=bpf_program)
b = BPF(src_file="socket_trace.c")

ipv4_send_bytes = b["ipv4_send_bytes"]
ipv4_recv_bytes = b["ipv4_recv_bytes"]

# header
print("%-10s %-12s %-10s %-10s %-10s %-10s %-10s %-21s %-21s" % ("PID", "COMM", 
	"RX_KB", "TX_KB", "RXSUM_KB", "TXSUM_KB", "SUM_KB", "LADDR", "RADDR"))

# output
sumrecv = 0
sumsend = 0
sum_kb = 0
i = 0
exiting = False
while i != args.count and not exiting:
	try:
		sleep(args.interval)
	except KeyboardInterrupt:
		exiting = True

	ipv4_throughput = defaultdict(lambda:[0,0])
	for k, v in ipv4_send_bytes.items():
		key=get_ipv4_session_key(k)
		ipv4_throughput[key][0] = v.value
	ipv4_send_bytes.clear()

	for k,v in ipv4_recv_bytes.items():
		key = get_ipv4_session_key(k)
		ipv4_throughput[key][1] = v.value
	ipv4_recv_bytes.clear()
	#lock.acquire()
	if ipv4_throughput:
		for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
			key=lambda kv: sum(kv[1]),
			reverse=True):
			recv_bytes = int(recv_bytes / 1024)
			send_bytes = int(send_bytes / 1024)
			sumrecv += recv_bytes
			sumsend += send_bytes
			sum_kb = sumrecv + sumsend
			print("%-10d %-12.12s %-10d %-10d %-10d %-10d %-10d %-21s %-21s" % 
				(k.pid, pid_to_comm(k.pid), 
				recv_bytes, send_bytes, sumrecv, sumsend, sum_kb, 
				k.laddr + ":" + str(k.lport), 
				k.daddr + ":" + str(k.dport),))
	#lock.release()
	i += 1
