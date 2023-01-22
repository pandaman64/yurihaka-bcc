#!/usr/bin/env python

from dataclasses import asdict, dataclass
import json
import logging
import sys
from typing import Optional
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

enum execve_event_kind {
    EXECVE_CALL = 0,
    EXECVE_ARG = 1,
    EXECVE_RETURN = 2,
};

struct execve_event_t {
    u64 ts;
    u32 pid;
    int retval;
    enum execve_event_kind kind;
    u32 argv_index;
    char filename[NAME_MAX];
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
    event.ts = bpf_ktime_get_ns();
    event.pid = task->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.kind = EXECVE_CALL;
    bpf_probe_read_user(event.filename, sizeof(event.filename), filename);
    execve_events.perf_submit(ctx, &event, sizeof(event));

    for (u32 i = 0; i < 20; i++) {
        char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &__argv[i]);
        if (argp == NULL) {
            break;
        }

        event.kind = EXECVE_ARG;
        event.argv_index = i;
        // これstrlenとか無しで大丈夫?
        bpf_probe_read_user(event.argv, sizeof(event.argv), argp);
        execve_events.perf_submit(ctx, &event, sizeof(event));
    }

    return 0;
}

int syscall__execve_ret(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct execve_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = task->tgid;
    event.kind = EXECVE_RETURN;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.retval = PT_REGS_RC(ctx);
    execve_events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
"""


b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name=b"syscall__execve")
b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name=b"syscall__execve_ret")


@dataclass
class Execution:
    pid: int
    comm: str
    arguments: Optional[dict[int, str]] = None
    execve_filename: Optional[str] = None
    task_filename: Optional[str] = None
    exit_code: Optional[int] = None
    exit_signal: Optional[int] = None

    # timestamps
    execve_ts: Optional[int] = None
    execve_ret_ts: Optional[int] = None
    sched_process_exec_ts: Optional[int] = None
    sched_process_exit_ts: Optional[int] = None

# execveの呼び出し
execs: dict[int, Execution] = {}


EVENT_SCHED_PROCESS_EXEC = 0
EVENT_SCHED_PROCESS_EXIT = 1
def print_event(_cpu, data, _size):
    event = b["events"].event(data)

    if event.kind == EVENT_SCHED_PROCESS_EXEC:
        if event.pid not in execs:
            execs[event.pid] = Execution(
                pid=event.pid,
                comm=event.comm.decode("utf-8", "replace")
            )
        execs[event.pid].sched_process_exec_ts = event.ts
        execs[event.pid].task_filename = event.filename.decode("utf-8")
    elif event.kind == EVENT_SCHED_PROCESS_EXIT:
        # 0以外のステータスコードかシグナルで死んだプロセスだけ出力
        if event.exit_code != 0:
            if event.pid not in execs:
                execs[event.pid] = Execution(
                    pid=event.pid,
                    comm=event.comm.decode("utf-8", "replace")
                )
            execs[event.pid].sched_process_exit_ts = event.ts
            execs[event.pid].exit_code = event.exit_code >> 8
            execs[event.pid].exit_signal = event.exit_code & 0b11111111
            json.dump(asdict(execs[event.pid]), sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()

        execs.pop(event.pid, None)
    else:
        logging.warning("unknown sched event kind: {}", { field: getattr(event, field) for field, _ in event._fields_ })


EXECVE_CALL = 0
EXECVE_ARG = 1
EXECVE_RETURN = 2
def print_execve_event(_cpu, data, _size):
    event = b["execve_events"].event(data)
    if event.kind == EXECVE_CALL:
        if event.pid not in execs:
            execs[event.pid] = Execution(
                pid=event.pid,
                comm=event.comm.decode("utf-8", "replace")
            )
        # 最後のexecveの情報でリセットする
        execs[event.pid].execve_ts = event.ts
        execs[event.pid].execve_filename = event.filename.decode("utf-8")
        execs[event.pid].arguments = {}
    elif event.kind == EXECVE_ARG:
        if event.pid not in execs:
            execs[event.pid] = Execution(
                pid=event.pid,
                comm=event.comm.decode("utf-8", "replace")
            )
        execs[event.pid].arguments[event.argv_index] = event.argv.decode("utf-8", "replace")
    elif event.kind == EXECVE_RETURN:
        if event.retval != 0:
            if event.pid not in execs:
                execs[event.pid] = Execution(
                    pid=event.pid,
                    comm=event.comm.decode("utf-8", "replace")
                )
            execs[event.pid].execve_ret_ts = event.ts
        else:
            if event.pid not in execs:
                execs[event.pid] = Execution(
                    pid=event.pid,
                    comm=event.comm.decode("utf-8", "replace")
                )
            execs[event.pid].execve_ret_ts = event.ts
    else:
        logging.warning("unknown execve event kind: {}", { field: getattr(event, field) for field, _ in event._fields_ })

b["events"].open_perf_buffer(print_event)
b["execve_events"].open_perf_buffer(print_execve_event)
while True:
    b.perf_buffer_poll()