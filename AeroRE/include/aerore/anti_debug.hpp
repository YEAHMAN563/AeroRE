#pragma once

#include "aerore/types.hpp"

#include <memory>

namespace aerore {

// Each mitigation is independently configurable because concealment can alter
// target semantics. Conservative defaults keep irreversible thread hiding and
// hardware-breakpoint hygiene disabled until the operator opts in.
struct AntiAntiDebugOptions {
    bool enabled = true;
    bool patch_peb = true;
    bool patch_heap = true;
    bool hook_debug_apis = true;
    bool hook_nt_query_system = true;
    bool block_thread_hide_calls = true;
    bool hide_new_threads = false;
    bool sanitize_debug_registers = false;
    bool neutralize_output_debug_string = true;
    bool neutralize_invalid_handle = true;
    bool restore_on_detach = true;
};

// User-mode concealment companion for Debugger. It owns every remote patch and
// allocation it creates, restores reversible state on detach, and never needs a
// kernel driver. Native x86 and x64 builds are supported; an x64 build also
// recognizes and patches a WOW64 target's 32-bit PEB and IAT.
class AntiAntiDebug {
public:
    AntiAntiDebug();
    ~AntiAntiDebug();
    AntiAntiDebug(const AntiAntiDebug&) = delete;
    AntiAntiDebug& operator=(const AntiAntiDebug&) = delete;

    void set_options(const AntiAntiDebugOptions& options);
    const AntiAntiDebugOptions& options() const;
    bool load_ini(const std::string& path);
    bool save_ini(const std::string& path) const;

    bool attach(void* process_handle, u32 pid);
    void detach();
    void on_module(u64 module_base);
    void on_thread(u32 tid);
    void before_continue(u32 tid);
    void after_debug_event(u32 tid);

    // Returns true when the debugger should consume the exception instead of
    // forwarding it to the target's SEH chain.
    bool neutralize_exception(u32 exception_code) const;

    bool active() const;
    bool target_is_64_bit() const;
    std::vector<std::string> drain_log();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace aerore
