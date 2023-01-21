#!/usr/bin/env python

from bcc import BPF

program = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h> 
#include <linux/sched.h>

enum event_kind {
    EVENT_SCHED_PROCESS_EXEC = 0,
    EVENT_SCHED_PROCESS_EXIT = 1
};

struct event_t {
    u64 ts;
    u32 pid;
    u32 tgid;
    u32 exit_code; // exit_code >> 8がいわゆるexit codeで、下位8ビットはシグナル
    enum event_kind kind;
    char filename[NAME_MAX];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // メインスレッドではない場合は処理しない
    if (args->pid != task->tgid) {
        return 0;
    }

    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = args->pid;
    event.tgid = task->tgid;
    event.exit_code = task->exit_code;
    event.kind = EVENT_SCHED_PROCESS_EXEC;
    TP_DATA_LOC_READ_CONST(&event.filename, filename, NAME_MAX);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(args, &event, sizeof(event));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // メインスレッドではない場合は処理しない
    if (args->pid != task->tgid) {
        return 0;
    }

    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = args->pid;
    event.tgid = task->tgid;
    event.exit_code = task->exit_code;
    event.kind = EVENT_SCHED_PROCESS_EXIT;
    // TP_DATA_LOC_READ_CONST(&event.filename, filename, NAME_MAX);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(args, &event, sizeof(event));

    return 0;
}

// TODO: send arbitrary size
#define ARG_SIZE 128

struct execve_event_t {
    u32 pid;
    u32 task_pid;
    u32 argv_index;
    char comm[TASK_COMM_LEN];
    char argv[ARG_SIZE];
};
BPF_PERF_OUTPUT(execve_events);

int syscall__execve(
    struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp
) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct execve_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.task_pid = task->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    for (u32 i = 0; i < 20; i++) {
        char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &__argv[i]);
        if (argp == NULL) {
            break;
        }

        event.argv_index = i;
        // これstrlenとか無しで大丈夫?
        bpf_probe_read_user(event.argv, sizeof(event.argv), argp);
        execve_events.perf_submit(ctx, &event, sizeof(event));
    }

    return 0;
}
"""


b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

kinds = ["EXEC", "EXIT"]
fmt = "%-18s %-10s %-10s %-6s %-6s %-6s %-32s %-32s"
print(fmt % ("TIME(s)", "PID", "TGID", "KIND", "CODE", "SIGNAL", "COMM", "FILE NAME"))

def print_event(_cpu, data, _size):
    event = b["events"].event(data)
    exit_code = event.exit_code >> 8
    signal = event.exit_code & 0b11111111
    print(fmt % (event.ts, event.pid, event.tgid, kinds[event.kind], exit_code, signal, event.comm.decode("utf-8"), event.filename.decode("utf-8")))


def print_execve_event(_cpu, data, _size):
    event = b["execve_events"].event(data)
    fields = { field: getattr(event, field) for field, _ in event._fields_ }
    print(fields)

b["events"].open_perf_buffer(print_event)
b["execve_events"].open_perf_buffer(print_execve_event)
while True:
    b.perf_buffer_poll()
