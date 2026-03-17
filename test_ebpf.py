#!/usr/bin/env python3
from bcc import BPF

# Simple eBPF program to test
bpf_program = """
int hello(void *ctx) {
    bpf_trace_printk("Hello from eBPF!\\n");
    return 0;
}
"""

try:
    b = BPF(text=bpf_program)
    b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
    print("✅ eBPF integration working!")
    b.detach_kprobe(event=b.get_syscall_fnname("clone"))
except Exception as e:
    print(f"❌ eBPF integration failed: {e}")
