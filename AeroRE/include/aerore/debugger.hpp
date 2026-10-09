#pragma once

#include "aerore/iat.hpp"
#include "aerore/types.hpp"

#include <functional>
#include <optional>

namespace aerore {

enum class BpType { Software, HardwareExec, HardwareWrite, HardwareReadWrite, Memory };

struct Breakpoint {
    u64 id = 0;
    u64 va = 0;
    BpType type = BpType::Software;
    int size = 1;
    int hw_index = -1;
    u8 saved = 0;
    bool enabled = true;
    std::string condition;
};

struct RegState {
    u64 gpr[16]{};
    u64 rip = 0;
    u64 rflags = 0;
    bool valid = false;
};

struct DebugEvent {
    std::string kind;
    u64 va = 0;
    u32 pid = 0;
    u32 tid = 0;
    std::string message;
};

using BpCondition = std::function<bool(const RegState&)>;

// Windows debugger (create/attach, INT3, DR0-3, guard-page memory BPs,
// step in/over/out, run to cursor). On other hosts every call fails with
// last_error() == "debugger requires Windows".
class Debugger {
public:
    Debugger();
    ~Debugger();
    Debugger(const Debugger&) = delete;
    Debugger& operator=(const Debugger&) = delete;

    bool create(const std::string& path, const std::string& args);
    bool attach(u32 pid);
    void detach();

    bool pause();
    bool resume();
    bool step_into();
    bool step_over();
    bool step_out();
    bool run_to(u64 va);

    u64 add_bp(u64 va, BpType type, int size = 1, std::string condition = {});
    bool remove_bp(u64 id);
    void set_condition_fn(u64 id, BpCondition fn);
    std::vector<Breakpoint> breakpoints() const;

    RegState regs() const;
    bool write_reg(const std::string& name, u64 value);
    std::vector<u8> read_mem(u64 va, size_t n) const;
    bool write_mem(u64 va, const std::vector<u8>& data);

    std::vector<ModuleSpan> modules() const;
    std::optional<DebugEvent> poll();
    bool alive() const;
    const std::string& last_error() const { return error_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string error_;
};

}  // namespace aerore
