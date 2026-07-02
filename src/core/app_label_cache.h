#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <sys/stat.h>
#include "util/logger.h"

// 关键修复：原来的 get_label_internal 跑的是
// "dumpsys package <pkg> | grep 'application-label:'"——但
// "application-label:" 实际上是 aapt/aapt2 的 `dump badging` 输出格式，
// 不是 dumpsys package 的输出字段。dumpsys package 的真实输出里根本
//没有这一行，grep 永远匹配不到任何内容，管道读不到任何数据，
// get_label_internal 恒定返回空字符串——这是"网页只显示包名、应用名
// 一直不显示"的确切原因，缓存不是没建，而是每一条都被填成了空标签。
//
// 现在改为：优先探测设备上是否有 aapt / aapt2 可执行文件（这是唯一
// 被证实真实存在 "application-label:" 输出格式的工具），如果有，就
// 用 `pm path` 拿到 apk 路径后对其运行 `aapt dump badging` 取真实
// 应用名；如果设备上没有 aapt（多数出厂 ROM 不预装构建工具，这种
// 情况并不少见），则诚实地退回显示包名，而不是再跑一个注定拿不到
// 数据的命令——这样至少行为是可预期、可解释的。
//
// 顺带修复：原来的实现会把标签里所有空格全部删除
// （remove_if c==' '），这对中文应用名没有影响，但会把类似
// "Google Play Store" 这样的英文应用名拆成
// "GooglePlayStore"，属于误伤，这次一并修正为只清理首尾空白和
// 换行符，保留标签内部的正常空格。
class AppLabelCache {
public:
    static AppLabelCache& instance() {
        static AppLabelCache inst;
        return inst;
    }

    void build() {
        std::lock_guard<std::mutex> lk(mutex_);
        cache_.clear();

        aapt_bin_ = detect_aapt_binary();
        if (aapt_bin_.empty()) {
            LOG_W("AppLabelCache",
                  "No aapt/aapt2 binary found on device, app names will fall back "
                  "to package names (this is a device/ROM limitation, not a crash)");
        } else {
            LOG_I("AppLabelCache", "Using " + aapt_bin_ + " for app label resolution");
        }

        auto append_from_pm = [this](const char* filter) {
            std::string pkg_cmd = "pm list packages -U " + std::string(filter) + " 2>/dev/null";
            FILE* pkg_pipe = popen(pkg_cmd.c_str(), "r");
            if (!pkg_pipe) return;

            char pkg_line[512];
            while (fgets(pkg_line, sizeof(pkg_line), pkg_pipe)) {
                std::string line(pkg_line);
                auto p = line.find("package:");
                if (p == std::string::npos) continue;
                auto u = line.find("uid:");
                std::string pkg = line.substr(p + 8, u - (p + 8) - 1);
                if (pkg.empty()) continue;

                std::string label = aapt_bin_.empty() ? "" : get_label_internal(pkg);
                if (!label.empty()) {
                    cache_[pkg] = label;
                }
            }
            pclose(pkg_pipe);
        };

        append_from_pm("-3");   // 用户应用
        append_from_pm("-s");   // 系统应用

        LOG_I("AppLabelCache", "Built cache with " + std::to_string(cache_.size()) + " labeled apps"
              + (aapt_bin_.empty() ? " (aapt unavailable, others fall back to package name)" : ""));
    }

    std::string get_label(const std::string& pkg) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = cache_.find(pkg);
        return (it != cache_.end()) ? it->second : pkg;
    }

private:
    // 常见的 aapt/aapt2 可执行文件位置。不同 ROM、不同 root 方案
    // （Magisk/KernelSU 自带的 busybox 环境、部分厂商保留的工具箱）
    // 放置位置不完全一致，逐个探测，找到第一个可执行的就用。
    std::string detect_aapt_binary() {
        static const char* candidates[] = {
            "/system/bin/aapt2",
            "/system/bin/aapt",
            "/vendor/bin/aapt2",
            "/vendor/bin/aapt",
            "/data/adb/ksu/bin/aapt2",
            "/data/adb/magisk/aapt2",
            nullptr
        };
        for (int i = 0; candidates[i] != nullptr; ++i) {
            struct stat st;
            if (stat(candidates[i], &st) == 0 && (st.st_mode & S_IXUSR)) {
                return candidates[i];
            }
        }
        // 最后尝试 PATH 里是否有（部分环境把 aapt2 放进了 PATH）
        FILE* which = popen("command -v aapt2 2>/dev/null || command -v aapt 2>/dev/null", "r");
        if (which) {
            char buf[256] = {};
            std::string found;
            if (fgets(buf, sizeof(buf), which)) {
                found = buf;
                while (!found.empty() && (found.back() == '\n' || found.back() == '\r')) found.pop_back();
            }
            pclose(which);
            if (!found.empty()) return found;
        }
        return "";
    }

    // 用 pm path 拿到 apk 路径，再用 aapt dump badging 提取真实的
    // application-label 字段（这是唯一被证实真实存在的字段名）
    std::string get_label_internal(const std::string& pkg) {
        std::string apk_path = get_apk_path(pkg);
        if (apk_path.empty()) return "";

        std::string cmd = aapt_bin_ + " dump badging " + shell_quote(apk_path) +
                           " 2>/dev/null | grep 'application-label:' | head -1";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";
        char buf[512] = {};
        std::string label;
        if (fgets(buf, sizeof(buf), pipe)) {
            std::string line(buf);
            auto pos = line.find("application-label:");
            if (pos != std::string::npos) {
                label = line.substr(pos + 19);
                // aapt 输出格式形如 application-label:'微信'（带单引号包裹），
                // 先去掉首尾包裹的引号，再只清理首尾空白/换行——不再删除
                // 标签内部的空格，避免把多词英文名字拆碎
                trim_quotes_and_whitespace(label);
            }
        }
        pclose(pipe);
        return label;
    }

    std::string get_apk_path(const std::string& pkg) {
        std::string cmd = "pm path " + shell_quote(pkg) + " 2>/dev/null | head -1";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";
        char buf[512] = {};
        std::string path;
        if (fgets(buf, sizeof(buf), pipe)) {
            path = buf;
            auto pos = path.find("package:");
            if (pos != std::string::npos) path = path.substr(pos + 8);
            while (!path.empty() && (path.back() == '\n' || path.back() == '\r')) path.pop_back();
        }
        pclose(pipe);
        return path;
    }

    static void trim_quotes_and_whitespace(std::string& s) {
        // 去掉首尾换行/回车
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        // 去掉 aapt 输出里包裹标签的单引号
        if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'') {
            s = s.substr(1, s.size() - 2);
        }
        // 再去掉真正意义上的首尾空白（不影响内部空格）
        size_t start = s.find_first_not_of(' ');
        size_t end   = s.find_last_not_of(' ');
        s = (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
    }

    static std::string shell_quote(const std::string& s) {
        std::string out = "'";
        for (char c : s) {
            if (c == '\'') out += "'\\''";
            else out += c;
        }
        out += "'";
        return out;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> cache_;
    std::string aapt_bin_;
};