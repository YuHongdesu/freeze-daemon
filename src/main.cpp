// freeze_daemon — 主入口
// 职责：初始化各层，连接事件管道，阻塞运行

#include <csignal>
#include <fstream>
#include <functional>
#include <memory>
#include <unistd.h>
#include <atomic>
#include "util/constants.h"
#include "util/logger.h"
#include "util/timer.h"
#include "util/reboot_flag.h"
#include "core/config_store.h"
#include "core/app_list.h"
#include "core/app_label_cache.h"
#include "core/freeze_engine.h"
#include "platform/cgroup_manager.h"
#include "platform/bpf_loader.h"
#include "platform/foreground_fallback.h"
#include "api/event_dispatcher.h"
#include "api/http_server.h"

constexpr const char* TAG = "Main";

static std::atomic<bool> g_running{true};

static void on_signal(int /*sig*/) { g_running = false; }

static void register_signals() {
    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);
    signal(SIGPIPE, SIG_IGN);
}

static void write_pid_file() {
    std::ofstream f(Path::PID_FILE);
    if (f.is_open()) f << getpid();
}

static void remove_pid_file() {
    ::unlink(Path::PID_FILE);
}

static bool init_cgroup() {
    if (!CgroupManager::init_cgroup_tree()) {
        LOG_E(TAG, "Cgroup init failed");
        return false;
    }
    return true;
}

static bool init_bpf(BpfLoader& loader, EventDispatcher& dispatcher) {
    bool ok = loader.load([&dispatcher](const FreezeEvent& ev) {
        dispatcher.dispatch(ev);
    });
    if (!ok) {
        LOG_W(TAG, "eBPF load failed, daemon will run without BPF events");
        return false;
    }
    return true;
}

static void init_lists(EventDispatcher& dispatcher) {
    AppList::instance().reload();
    dispatcher.refresh_uid_cache();
}

// 通过 shell fallback 维持前后台状态，并驱动冻结引擎
static void schedule_top_app_refresh(BpfLoader& loader) {
    constexpr int REFRESH_INTERVAL_MS = 30000;

    struct SharedState {
        std::string last_foreground_pkg;
    };
    auto state = std::make_shared<SharedState>();

    auto refresh_fn = std::make_shared<std::function<void()>>();
    *refresh_fn = [&loader, state, refresh_fn]() {
        // 尝试刷新 eBPF cgroup id（如果可用），失败也无妨
        loader.refresh_top_app_cgroup();

        std::string current_pkg = ForegroundFallback::detect_foreground_package();
        if (current_pkg.empty()) {
            TimerManager::instance().schedule(REFRESH_INTERVAL_MS, *refresh_fn);
            return;
        }

        // 前后台切换逻辑
        if (current_pkg != state->last_foreground_pkg) {
            if (!state->last_foreground_pkg.empty()) {
                LOG_I("Main", "App switched to background: " + state->last_foreground_pkg);
                FreezeEngine::instance().on_app_background(state->last_foreground_pkg);
            }
            LOG_I("Main", "App switched to foreground: " + current_pkg);
            FreezeEngine::instance().on_app_foreground(current_pkg);
            state->last_foreground_pkg = current_pkg;
        } else {
            // 前台未变，但保持 RunningCache 中有该应用（防止被其他逻辑清空）
            FreezeEngine::instance().on_app_foreground(current_pkg);
        }

        TimerManager::instance().schedule(REFRESH_INTERVAL_MS, *refresh_fn);
    };
    (*refresh_fn)();
}

int main() {
    register_signals();
    write_pid_file();

    LOG_I(TAG, "freeze_daemon starting");
    RebootFlag::clear_all();

    ConfigStore::instance().load();

    if (!init_cgroup()) return 1;

    // 构建应用标签缓存（需在启动 HTTP 之前完成）
    AppLabelCache::instance().build();

    TimerManager::instance().start();

    BpfLoader       bpf_loader;
    EventDispatcher dispatcher;
    bool bpf_ok = init_bpf(bpf_loader, dispatcher);

    if (bpf_ok) {
        FreezeEngine::instance().set_frozen_cgroups_map(bpf_loader.frozen_cgroup_map());
    }

    // 启动前台检测调度（无论 BPF 是否成功）
    schedule_top_app_refresh(bpf_loader);

    init_lists(dispatcher);
    FreezeEngine::instance().start_freezer_guard();

    HttpServer http;
    if (!http.start()) return 1;

    LOG_I(TAG, "Running. PID=" + std::to_string(getpid()));
    if (bpf_ok) {
        bpf_loader.start_loop();
    }

    while (g_running) { pause(); }

    LOG_I(TAG, "Shutting down");
    if (bpf_ok) bpf_loader.stop();
    http.stop();
    TimerManager::instance().stop();
    remove_pid_file();
    return 0;
}