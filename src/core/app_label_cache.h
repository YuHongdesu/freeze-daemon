#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdio>
#include <algorithm>
#include "util/logger.h"

class AppLabelCache {
public:
    static AppLabelCache& instance() {
        static AppLabelCache inst;
        return inst;
    }

    void build() {
        std::lock_guard<std::mutex> lk(mutex_);
        cache_.clear();

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

                std::string label = get_label_internal(pkg);
                if (!label.empty()) {
                    cache_[pkg] = label;
                }
            }
            pclose(pkg_pipe);
        };

        append_from_pm("-3");   // 用户应用
        append_from_pm("-s");   // 系统应用

        LOG_I("AppLabelCache", "Built cache with " + std::to_string(cache_.size()) + " apps");
    }

    std::string get_label(const std::string& pkg) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = cache_.find(pkg);
        return (it != cache_.end()) ? it->second : pkg;
    }

private:
    std::string get_label_internal(const std::string& pkg) {
        std::string cmd = "dumpsys package " + pkg + " 2>/dev/null | grep 'application-label:' | head -1";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "";
        char buf[512] = {};
        std::string label;
        if (fgets(buf, sizeof(buf), pipe)) {
            std::string line(buf);
            auto pos = line.find("application-label:");
            if (pos != std::string::npos) {
                label = line.substr(pos + 19);
                label.erase(std::remove_if(label.begin(), label.end(),
                    [](unsigned char c){ return c == '\n' || c == '\r' || c == ' '; }),
                    label.end());
            }
        }
        pclose(pipe);
        return label;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> cache_;
};