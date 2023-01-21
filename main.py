#!/usr/bin/env python

from bcc import BPF

print("Tracing sys_sync... Press Ctrl + C to stop.")
BPF(text='int kprobe__sys_sync(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()