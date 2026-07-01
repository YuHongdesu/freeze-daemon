// SPDX-License-Identifier: GPL-2.0
// freeze_monitor.bpf.c — 内核侧 eBPF 探针 (修复版)
//
// 针对 Android 16 + 5.15 GKI + 骁龙 8 Gen 2
//
// 变更说明：
// 1. 前后台检测改用 cgroup_migrate tracepoint，彻底解决 sched_switch 无法获取
//    next 进程 cgroup 的致命 bug（bpf_get_current_cgroup_id 在 sched_switch 中
//    返回的是 prev 进程的 cgroup）。
// 2. 修正 get_task_uid 的 uid 字段读取方式，使用 BPF_CORE_READ(task, cred, uid.val)
//    确保跨版本兼容。
// 3. 移除无用的 last_cgroup_map，cgroup_migrate 本身提供精确的状态变化，无需去重。
// 4. uid_pid_map、suspend_resume、cgroup_freeze 等其余逻辑保持不变。

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── 事件类型（与用户态 constants.h 完全一致）────────────────
#define EVT_APP_FOREGROUND  1
#define EVT_APP_BACKGROUND  2
#define EVT_SCREEN_ON       3
#define EVT_SCREEN_OFF      4
#define EVT_SYS_UNFREEZE    5
#define EVT_PROC_DIED       6

struct freeze_event {
    __u8  type;
    __u32 uid;
    __u32 pid;
} __attribute__((packed)); // 实际大小 9 字节，用户态注意对齐

// ── Maps ─────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// top-app cgroup id（用户态写入，BPF 只读）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} top_app_cgroup_id SEC(".maps");

// 我们管理的已冻结 cgroup id
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,   __u64);
    __type(value, __u8);
} our_frozen_cgroups SEC(".maps");

// uid → pid 集合（用户态读取，消除 /proc 遍历）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key,   __u64);   // (uid << 32) | pid
    __type(value, __u8);    // 1 = 存活
} uid_pid_map SEC(".maps");

// ── 辅助函数 ─────────────────────────────────────────────────

static __always_inline void emit_ev(__u8 type, __u32 uid, __u32 pid) {
    struct freeze_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out) return;
    out->type = type;
    out->uid  = uid;
    out->pid  = pid;
    bpf_ringbuf_submit(out, 0);
}

// 从 task_struct 读取进程真实 uid（备用，当前未直接调用）
static __always_inline __u32 get_task_uid(struct task_struct *task) {
    // 直接读取 kuid_t.val，避免依赖结构体内部字段名变化
    return BPF_CORE_READ(task, cred, uid.val);
}

// ── cgroup_migrate：精确感知进程进出 top-app cgroup ─────────
// 替代有缺陷的 sched_switch 方案，直接给出 src/dst cgroup id，
// 可准确判断是否跨越 top-app 边界。
SEC("tracepoint/cgroup/cgroup_migrate")
int on_cgroup_migrate(struct trace_event_raw_cgroup_migrate *ctx) {
    __u32 key = 0;
    __u64 *top_cg = bpf_map_lookup_elem(&top_app_cgroup_id, &key);
    if (!top_cg || *top_cg == 0)
        return 0; // top-app cgroup 未设置

    __u64 src_id = BPF_CORE_READ(ctx->src_cgrp, kn, id);
    __u64 dst_id = BPF_CORE_READ(ctx->dst_cgrp, kn, id);

    bool from_top_app = (src_id == *top_cg);
    bool to_top_app   = (dst_id == *top_cg);

    // 无变化，跳过
    if (from_top_app == to_top_app)
        return 0;

    struct task_struct *task = ctx->task;
    __u32 uid = BPF_CORE_READ(task, cred, uid.val);
    __u32 pid = BPF_CORE_READ(task, pid);

    if (to_top_app) {
        emit_ev(EVT_APP_FOREGROUND, uid, pid);
    } else {
        emit_ev(EVT_APP_BACKGROUND, uid, pid);
    }

    return 0;
}

// ── sched_process_fork：追踪新进程 uid ───────────────────────
SEC("tracepoint/sched/sched_process_fork")
int on_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 child_pid = ctx->child_pid;
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 10000) return 0;

    __u64 key = ((__u64)uid << 32) | child_pid;
    __u8 val = 1;
    bpf_map_update_elem(&uid_pid_map, &key, &val, BPF_ANY);
    return 0;
}

// ── sched_process_exit：清理退出进程 ─────────────────────────
SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid < 10000) return 0;

    __u32 pid = ctx->pid;

    // 从 uid_pid_map 移除
    __u64 key = ((__u64)uid << 32) | pid;
    bpf_map_delete_elem(&uid_pid_map, &key);

    emit_ev(EVT_PROC_DIED, uid, pid);
    return 0;
}

// ── suspend_resume：屏幕亮灭 ─────────────────────────────────
SEC("tracepoint/power/suspend_resume")
int on_suspend_resume(struct trace_event_raw_power_suspend_resume *ctx) {
    __u8 type = ctx->val ? EVT_SCREEN_OFF : EVT_SCREEN_ON;
    emit_ev(type, 0, 0);
    return 0;
}

// ── kprobe/cgroup_freeze：感知系统解冻 ───────────────────────
SEC("kprobe/cgroup_freeze")
int on_cgroup_freeze(struct pt_regs *ctx) {
    struct cgroup *cgrp = (struct cgroup *)PT_REGS_PARM1(ctx);
    bool freeze = (bool)PT_REGS_PARM2(ctx);
    if (freeze) return 0;

    __u64 cg_id = BPF_CORE_READ(cgrp, kn, id);
    __u8 *managed = bpf_map_lookup_elem(&our_frozen_cgroups, &cg_id);
    if (!managed) return 0;

    __u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    emit_ev(EVT_SYS_UNFREEZE, 0, pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";