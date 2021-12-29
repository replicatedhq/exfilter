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
bpf_program=open(r"kprobe_tcp_sendmsg.c", "r").read()
# code substitutions
if args.pid:
    bpf_program = bpf_program.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_program = bpf_program.replace('FILTER_PID','')

# SessionKey = namedtuple('Session',['pid', 'laddr', 'lport', 'daddr', 'dport'])

def pid_to_comm(pid):
    try:
        comm = open("/proc/%s/comm" % pid, "r").read().rstrip()
        return comm
    except IOError:
        return str(pid)

# def get_ipv4_session_key(k):
# 	return SessionKey(pid=k.pid, laddr=inet_ntop(AF_INET, pack("I", k.saddr)),lport=k.lport, daddr=inet_ntop(AF_INET, pack("I", k.daddr)), dport=k.dport)

def print_events(cpu, data, size):
	event = b["ipv4_send_events"].event(data)
	print("%-10d %-12s %-21s %-21s %-40s" % (event.pid, pid_to_comm(event.pid), inet_ntop(AF_INET, pack("I", event.saddr)) + ":" + str(event.lport), inet_ntop(AF_INET, pack("I", event.daddr))+ ":" + str(event.dport), event.data))
# init bpf
b = BPF(text=bpf_program)

b["ipv4_send_events"].open_perf_buffer(print_events)

# header
print("%-10s %-12s %-21s %-21s %-40s" % ("PID", "COMM", "LADDR", "RADDR", "DATA"))

while True:
	try:
		b.perf_buffer_poll()
	except KeyboardInterrupt:
		exit()