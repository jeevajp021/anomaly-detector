#undef __HAVE_BUILTIN_BSWAP16__
#undef __HAVE_BUILTIN_BSWAP32__
#undef __HAVE_BUILTIN_BSWAP64__

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ns_common.h>

struct conn_metadata {
    u64 start_ts;            
    u32 container_id;        
    u64 cpu_time_start;      
    u32 pid;                 
    char comm[16];           
    u64 last_alert_ts;      // Throttling: prevents spamming alerts on every syscall
};

struct alert_event {
    u32 pid;
    u32 container_id;
    u64 duration_us;
    u64 cpu_time_us;
    char comm[16];
    u64 timestamp; 
};

BPF_HASH(connection_map, u32, struct conn_metadata);
BPF_HASH(threshold_map, u32, u64);
BPF_PERF_OUTPUT(events); 

static inline u64 get_cpu_time() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 runtime = 0;
    // Safe read of the scheduler entity's total runtime
    bpf_probe_read_kernel(&runtime, sizeof(runtime), &task->se.sum_exec_runtime);
    return runtime;
}

static inline u32 get_container_id() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns;
    struct pid_namespace *pid_ns;
    u32 inum = 0;

    if (bpf_probe_read_kernel(&ns, sizeof(ns), &task->nsproxy)) return 0;
    if (!ns) return 0;
    if (bpf_probe_read_kernel(&pid_ns, sizeof(pid_ns), &ns->pid_ns_for_children)) return 0;
    if (!pid_ns) return 0;
    if (bpf_probe_read_kernel(&inum, sizeof(inum), &pid_ns->ns.inum)) return 0;

    // Filter host namespace (Example: 4026531836). 
    // In production, pass this value from Python as a MACRO.
    if (inum == 4026531836) return 0;

    return inum;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 container_id = get_container_id();
    if (container_id == 0) return 0; 
    
    struct conn_metadata meta = {};
    meta.start_ts = bpf_ktime_get_ns();
    meta.container_id = container_id;
    meta.cpu_time_start = get_cpu_time(); 
    meta.pid = pid;
    meta.last_alert_ts = 0;
    bpf_get_current_comm(&meta.comm, sizeof(meta.comm));
    
    connection_map.update(&pid, &meta);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct conn_metadata *meta = connection_map.lookup(&pid);
    if (!meta) return 0;
    
    u64 now_ns = bpf_ktime_get_ns();
    u64 now_cpu = get_cpu_time();
    u64 cpu_used_us = (now_cpu - meta->cpu_time_start) / 1000;
    
    // Map Key 0 is the global threshold set from userspace
    u32 key = 0;
    u64 *threshold_ms = threshold_map.lookup(&key);

    if (threshold_ms && cpu_used_us > (*threshold_ms * 1000)) {
        // Only submit an event if 500ms has passed since the last one
        // This prevents the perf buffer from being overwhelmed
        if (now_ns - meta->last_alert_ts > 500000000) {
            struct alert_event event = {};
            event.pid = pid;
            event.container_id = meta->container_id;
            event.duration_us = (now_ns - meta->start_ts) / 1000;
            event.cpu_time_us = cpu_used_us;
            event.timestamp = now_ns;
            __builtin_memcpy(&event.comm, &meta->comm, sizeof(event.comm));
            
            events.perf_submit(args, &event, sizeof(event));
            meta->last_alert_ts = now_ns;
        }
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct conn_metadata *meta = connection_map.lookup(&pid);
    if (!meta) return 0;
    
    struct alert_event event = {};
    event.pid = pid;
    event.container_id = meta->container_id;
    event.duration_us = (bpf_ktime_get_ns() - meta->start_ts) / 1000;
    event.cpu_time_us = (get_cpu_time() - meta->cpu_time_start) / 1000;
    event.timestamp = bpf_ktime_get_ns();
    __builtin_memcpy(&event.comm, &meta->comm, sizeof(event.comm));
    
    events.perf_submit(args, &event, sizeof(event));
    connection_map.delete(&pid);
    return 0;
}
