from bcc import BPF
from ctypes import cast, POINTER, c_char
import argparse

examples = """examples:
    ./socket_egress.py          # trace send/recv flow by host 
    ./socket_egress.py -p 100   # only trace PID 100
"""

parser = argparse.ArgumentParser(
    description = "Capture egress packets",
    formatter_class = argparse.RawDescriptionHelpFormatter,
    epilog = examples
)

parser.add_argument("-p", "--pid", 
    help = "Trace this pid only")

args = parser.parse_args()
global b

def xmit_received(cpu, data, size):
    global b
    global py_packet_buf
    ev = b["xmits"].event(data)
    print("%-18d %-25s %-8d %-10d %-10d %-12d %-12d" % (ev.ts, ev.comm.decode(), ev.pid, ev.len, ev.datalen, ev.head, ev.data))
    bs = cast(py_packet_buf[ev.packet_buf_ptr][cpu].data, POINTER(c_char))[:ev.len]
    c = bytes(bs)
    print(c.hex())


def observe_kernel():
    # load BPF program
    global b
    bpf_program=open(r"socket_egress.c", "r").read()
    if args.pid:
        bpf_program = bpf_program.replace('FILTER_PID',
            'if (pid != %s) { return 0; }' % args.pid)
    else:
        bpf_program = bpf_program.replace('FILTER_PID','')
    b = BPF(text=bpf_program)

    print("%-18s %-25s %-8s %-10s %-10s %-12s %-12s" % ("TS", "COMM", "PID", "LEN", "DATALEN", "HEAD", "DATA"))

    b["xmits"].open_perf_buffer(xmit_received)
    global py_packet_buf
    py_packet_buf = b["packet_buf"]

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Kernel observer thread stopped.")

observe_kernel()