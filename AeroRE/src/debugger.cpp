#include "aerore/debugger.hpp"

#include <algorithm>
#include <cstring>
#include <functional>
#include <unordered_map>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace aerore {

#if !defined(_WIN32)

struct Debugger::Impl {};

Debugger::Debugger() : impl_(std::make_unique<Impl>()) { error_ = "debugger requires Windows"; }
Debugger::~Debugger() = default;
bool Debugger::create(const std::string&, const std::string&) { error_ = "debugger requires Windows"; return false; }
bool Debugger::attach(u32) { error_ = "debugger requires Windows"; return false; }
void Debugger::detach() {}
bool Debugger::pause() { return false; }
bool Debugger::resume() { return false; }
bool Debugger::step_into() { return false; }
bool Debugger::step_over() { return false; }
bool Debugger::step_out() { return false; }
bool Debugger::run_to(u64) { return false; }
u64 Debugger::add_bp(u64, BpType, int, std::string) { error_ = "debugger requires Windows"; return 0; }
bool Debugger::remove_bp(u64) { return false; }
void Debugger::set_condition_fn(u64, BpCondition) {}
std::vector<Breakpoint> Debugger::breakpoints() const { return {}; }
RegState Debugger::regs() const { return {}; }
bool Debugger::write_reg(const std::string&, u64) { return false; }
std::vector<u8> Debugger::read_mem(u64, size_t) const { return {}; }
bool Debugger::write_mem(u64, const std::vector<u8>&) { return false; }
std::vector<ModuleSpan> Debugger::modules() const { return {}; }
std::optional<DebugEvent> Debugger::poll() { return std::nullopt; }
bool Debugger::alive() const { return false; }

#else

struct Debugger::Impl {
    HANDLE process = nullptr;
    DWORD pid = 0;
    DWORD tid = 0;
    bool alive = false;
    bool paused = false;
    bool continue_pending = false;
    bool rearm_after_step = false;
    u64 rearm_va = 0;
    bool step_pause = false;
    u64 temp_bp = 0;
    std::vector<Breakpoint> bps;
    std::unordered_map<u64, BpCondition> conds;
    std::vector<DebugEvent> queue;
    u64 next_id = 1;

    Breakpoint* find_va(u64 va) {
        for (auto& b : bps)
            if (b.va == va && b.enabled) return &b;
        return nullptr;
    }
    Breakpoint* find_id(u64 id) {
        for (auto& b : bps)
            if (b.id == id) return &b;
        return nullptr;
    }

    bool read(u64 va, void* dst, size_t n) const {
        SIZE_T got = 0;
        return process && ReadProcessMemory(process, reinterpret_cast<LPCVOID>(va), dst, n, &got) && got == n;
    }
    bool write(u64 va, const void* src, size_t n) const {
        SIZE_T got = 0;
        DWORD old = 0;
        VirtualProtectEx(process, reinterpret_cast<LPVOID>(va), n, PAGE_EXECUTE_READWRITE, &old);
        BOOL ok = WriteProcessMemory(process, reinterpret_cast<LPVOID>(va), src, n, &got);
        VirtualProtectEx(process, reinterpret_cast<LPVOID>(va), n, old, &old);
        return ok && got == n;
    }

    HANDLE open_thread() const {
        return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    }

    RegState read_regs() const {
        RegState rs;
        HANDLE th = open_thread();
        if (!th) return rs;
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_ALL;
        if (GetThreadContext(th, &ctx)) {
            rs.valid = true;
            rs.rip = ctx.Rip;
            rs.rflags = ctx.EFlags;
            rs.gpr[0] = ctx.Rax; rs.gpr[1] = ctx.Rcx; rs.gpr[2] = ctx.Rdx; rs.gpr[3] = ctx.Rbx;
            rs.gpr[4] = ctx.Rsp; rs.gpr[5] = ctx.Rbp; rs.gpr[6] = ctx.Rsi; rs.gpr[7] = ctx.Rdi;
            rs.gpr[8] = ctx.R8; rs.gpr[9] = ctx.R9; rs.gpr[10] = ctx.R10; rs.gpr[11] = ctx.R11;
            rs.gpr[12] = ctx.R12; rs.gpr[13] = ctx.R13; rs.gpr[14] = ctx.R14; rs.gpr[15] = ctx.R15;
        }
        CloseHandle(th);
        return rs;
    }

    bool write_ctx(const std::function<void(CONTEXT&)>& fn) {
        HANDLE th = open_thread();
        if (!th) return false;
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_ALL;
        bool ok = false;
        if (GetThreadContext(th, &ctx)) {
            fn(ctx);
            ok = SetThreadContext(th, &ctx) == TRUE;
        }
        CloseHandle(th);
        return ok;
    }

    void arm_software(Breakpoint& bp) {
        u8 cur = 0;
        if (!read(bp.va, &cur, 1)) return;
        if (cur == 0xCC) return;
        bp.saved = cur;
        u8 cc = 0xCC;
        write(bp.va, &cc, 1);
    }

    void disarm_software(Breakpoint& bp) {
        write(bp.va, &bp.saved, 1);
    }

    int alloc_dr() {
        bool used[4] = {};
        for (const auto& b : bps)
            if (b.hw_index >= 0 && b.hw_index < 4) used[b.hw_index] = true;
        for (int i = 0; i < 4; ++i)
            if (!used[i]) return i;
        return -1;
    }

    void apply_dr() {
        write_ctx([&](CONTEXT& ctx) {
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
            ctx.Dr6 = 0;
            ctx.Dr7 = 0;
            DWORD64* drs[4] = {&ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3};
            for (const auto& b : bps) {
                if (b.hw_index < 0 || b.hw_index > 3 || !b.enabled) continue;
                *drs[b.hw_index] = b.va;
                ctx.Dr7 |= 1ull << (b.hw_index * 2);
                unsigned rw = 0;
                if (b.type == BpType::HardwareWrite) rw = 1;
                else if (b.type == BpType::HardwareReadWrite) rw = 3;
                ctx.Dr7 |= static_cast<DWORD64>(rw) << (16 + b.hw_index * 4);
            }
        });
    }

    void push_event(std::string kind, u64 va, std::string msg) {
        queue.push_back(DebugEvent{std::move(kind), va, pid, tid, std::move(msg)});
    }

    bool handle(const DEBUG_EVENT& ev) {
        tid = ev.dwThreadId;
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            push_event("create", reinterpret_cast<u64>(ev.u.CreateProcessInfo.lpBaseOfImage), "process created");
            return false;
        }
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            alive = false;
            paused = true;
            push_event("exit", ev.u.ExitProcess.dwExitCode, "process exited");
            return true;
        }
        if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            push_event("dll", reinterpret_cast<u64>(ev.u.LoadDll.lpBaseOfDll), "dll loaded");
            return false;
        }
        if (ev.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) return false;
        const auto& ex = ev.u.Exception.ExceptionRecord;
        DWORD code = ex.ExceptionCode;
        u64 addr = reinterpret_cast<u64>(ex.ExceptionAddress);
        if (code == EXCEPTION_BREAKPOINT) {
            RegState rs = read_regs();
            u64 rip = rs.valid ? rs.rip : addr;
            Breakpoint* bp = find_va(addr);
            if (!bp && rip) bp = find_va(rip > 0 ? rip - 1 : rip);
            if (!bp) return false;
            u64 at = bp->va;
            if (rs.valid && rs.rip == at + 1) write_ctx([&](CONTEXT& ctx) { ctx.Rip = at; });
            if (bp->type == BpType::Software) disarm_software(*bp);
            rearm_after_step = true;
            rearm_va = at;
            if (temp_bp && at == temp_bp) {
                remove_temp();
            }
            RegState now = read_regs();
            auto cit = conds.find(bp->id);
            if (cit != conds.end() && cit->second && !cit->second(now)) {
                write_ctx([&](CONTEXT& ctx) { ctx.EFlags |= 0x100; });
                return false;
            }
            paused = true;
            push_event("breakpoint", at, "int3");
            return true;
        }
        if (code == EXCEPTION_SINGLE_STEP) {
            if (rearm_after_step) {
                if (Breakpoint* bp = find_va(rearm_va))
                    if (bp->type == BpType::Software) arm_software(*bp);
                rearm_after_step = false;
            }
            if (step_pause) {
                step_pause = false;
                paused = true;
                RegState rs = read_regs();
                push_event("step", rs.rip, "single step");
                return true;
            }
            RegState rs = read_regs();
            for (const auto& b : bps) {
                if (b.hw_index < 0) continue;
                paused = true;
                push_event("breakpoint", b.va, "hardware");
                return true;
            }
            (void)rs;
            return false;
        }
        if (code == EXCEPTION_GUARD_PAGE || code == STATUS_GUARD_PAGE_VIOLATION) {
            paused = true;
            push_event("breakpoint", addr, "guard page");
            return true;
        }
        return false;
    }

    void remove_temp() {
        if (!temp_bp) return;
        for (auto it = bps.begin(); it != bps.end(); ++it) {
            if (it->va == temp_bp && it->id == 0) {
                if (it->type == BpType::Software) disarm_software(*it);
                bps.erase(it);
                break;
            }
        }
        temp_bp = 0;
    }

    bool pump() {
        while (alive && !paused) {
            DEBUG_EVENT ev{};
            if (!WaitForDebugEvent(&ev, 200)) continue;
            pid = ev.dwProcessId;
            bool stop = handle(ev);
            if (!stop) ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            else continue_pending = true;
            if (stop) return true;
        }
        return paused;
    }

    bool go(bool trap) {
        if (!alive) return false;
        if (trap) {
            step_pause = true;
            write_ctx([&](CONTEXT& ctx) { ctx.EFlags |= 0x100; });
        }
        if (continue_pending) {
            ContinueDebugEvent(pid, tid, DBG_CONTINUE);
            continue_pending = false;
        }
        paused = false;
        return pump();
    }
};

Debugger::Debugger() : impl_(std::make_unique<Impl>()) {}
Debugger::~Debugger() { detach(); }

bool Debugger::create(const std::string& path, const std::string& args) {
    std::string cmd = "\"" + path + "\"";
    if (!args.empty()) cmd += " " + args;
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                        nullptr, nullptr, &si, &pi)) {
        error_ = "CreateProcess failed";
        return false;
    }
    impl_->process = pi.hProcess;
    impl_->pid = pi.dwProcessId;
    impl_->tid = pi.dwThreadId;
    impl_->alive = true;
    CloseHandle(pi.hThread);
    impl_->paused = false;
    return impl_->pump();
}

bool Debugger::attach(u32 pid) {
    if (!DebugActiveProcess(pid)) {
        error_ = "DebugActiveProcess failed";
        return false;
    }
    DebugSetProcessKillOnExit(FALSE);
    impl_->pid = pid;
    impl_->process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    impl_->alive = true;
    impl_->paused = false;
    return impl_->pump();
}

void Debugger::detach() {
    if (!impl_->alive && !impl_->process) return;
    if (impl_->continue_pending) ContinueDebugEvent(impl_->pid, impl_->tid, DBG_CONTINUE);
    DebugActiveProcessStop(impl_->pid);
    if (impl_->process) CloseHandle(impl_->process);
    impl_->process = nullptr;
    impl_->alive = false;
    impl_->paused = false;
}

bool Debugger::pause() {
    if (!impl_->alive) return false;
    DebugBreakProcess(impl_->process);
    return impl_->pump();
}
bool Debugger::resume() { return impl_->go(false); }
bool Debugger::step_into() { return impl_->go(true); }

bool Debugger::step_over() {
    RegState rs = regs();
    if (!rs.valid) return step_into();
    u8 buf[15]{};
    if (!impl_->read(rs.rip, buf, sizeof(buf))) return step_into();
    Decoder dec(Arch::X64);
    auto in = dec.decode(rs.rip, buf, sizeof(buf));
    if (in && in->flow == Flow::Call) return run_to(rs.rip + in->len);
    return step_into();
}

bool Debugger::step_out() {
    RegState rs = regs();
    if (!rs.valid) return false;
    u64 ret = 0;
    if (!impl_->read(rs.gpr[4], &ret, 8)) return false;
    return run_to(ret);
}

bool Debugger::run_to(u64 va) {
    Breakpoint bp;
    bp.id = 0;
    bp.va = va;
    bp.type = BpType::Software;
    impl_->arm_software(bp);
    impl_->bps.push_back(bp);
    impl_->temp_bp = va;
    return impl_->go(false);
}

u64 Debugger::add_bp(u64 va, BpType type, int size, std::string condition) {
    if (!impl_->process) {
        error_ = "no process";
        return 0;
    }
    Breakpoint bp;
    bp.id = impl_->next_id++;
    bp.va = va;
    bp.type = type;
    bp.size = size;
    bp.condition = std::move(condition);
    if (type == BpType::Software) {
        impl_->arm_software(bp);
    } else if (type == BpType::Memory) {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        u64 page = va & ~(static_cast<u64>(si.dwPageSize) - 1);
        DWORD old = 0;
        if (!VirtualProtectEx(impl_->process, reinterpret_cast<LPVOID>(page), si.dwPageSize, PAGE_READWRITE | PAGE_GUARD,
                              &old)) {
            error_ = "VirtualProtectEx failed";
            return 0;
        }
    } else {
        bp.hw_index = impl_->alloc_dr();
        if (bp.hw_index < 0) {
            error_ = "no free debug register";
            return 0;
        }
        impl_->bps.push_back(bp);
        impl_->apply_dr();
        return bp.id;
    }
    impl_->bps.push_back(std::move(bp));
    return impl_->bps.back().id;
}

bool Debugger::remove_bp(u64 id) {
    auto it = std::find_if(impl_->bps.begin(), impl_->bps.end(), [&](const Breakpoint& b) { return b.id == id; });
    if (it == impl_->bps.end()) return false;
    if (it->type == BpType::Software) impl_->disarm_software(*it);
    bool hw = it->hw_index >= 0;
    impl_->bps.erase(it);
    if (hw) impl_->apply_dr();
    return true;
}

void Debugger::set_condition_fn(u64 id, BpCondition fn) { impl_->conds[id] = std::move(fn); }
std::vector<Breakpoint> Debugger::breakpoints() const { return impl_->bps; }
RegState Debugger::regs() const { return impl_->read_regs(); }

bool Debugger::write_reg(const std::string& name, u64 value) {
    int idx = -1;
    static const char* names[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                   "r8","r9","r10","r11","r12","r13","r14","r15"};
    for (int i = 0; i < 16; ++i)
        if (name == names[i]) idx = i;
    if (name == "rip") {
        return impl_->write_ctx([&](CONTEXT& ctx) { ctx.Rip = value; });
    }
    if (idx < 0) {
        error_ = "unknown register";
        return false;
    }
    return impl_->write_ctx([&](CONTEXT& ctx) {
        DWORD64* gprs[] = {&ctx.Rax,&ctx.Rcx,&ctx.Rdx,&ctx.Rbx,&ctx.Rsp,&ctx.Rbp,&ctx.Rsi,&ctx.Rdi,
                           &ctx.R8,&ctx.R9,&ctx.R10,&ctx.R11,&ctx.R12,&ctx.R13,&ctx.R14,&ctx.R15};
        *gprs[idx] = value;
    });
}

std::vector<u8> Debugger::read_mem(u64 va, size_t n) const {
    std::vector<u8> out(n);
    SIZE_T got = 0;
    if (!impl_->process || !ReadProcessMemory(impl_->process, reinterpret_cast<LPCVOID>(va), out.data(), n, &got))
        return {};
    out.resize(got);
    return out;
}

bool Debugger::write_mem(u64 va, const std::vector<u8>& data) {
    return impl_->write(va, data.data(), data.size());
}

std::vector<ModuleSpan> Debugger::modules() const {
    std::vector<ModuleSpan> mods;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, impl_->pid);
    if (snap == INVALID_HANDLE_VALUE) return mods;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            ModuleSpan m;
            char name[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, name, MAX_PATH, nullptr, nullptr);
            m.name = name;
            m.base = reinterpret_cast<u64>(me.modBaseAddr);
            m.size = me.modBaseSize;
            std::vector<u8> hdr = read_mem(m.base, 0x1000);
            if (hdr.size() >= 0x40 && hdr[0] == 'M' && hdr[1] == 'Z') {
                i32 lfanew = 0;
                std::memcpy(&lfanew, hdr.data() + 0x3C, 4);
                if (lfanew > 0 && static_cast<size_t>(lfanew) + 0x100 < hdr.size() &&
                    std::memcmp(hdr.data() + lfanew, "PE\0\0", 4) == 0) {
                    u16 magic = 0;
                    std::memcpy(&magic, hdr.data() + lfanew + 24, 2);
                    bool is64 = magic == 0x20B;
                    u32 dd_off = lfanew + 24 + (is64 ? 112 : 96);
                    u32 exp_rva = 0, exp_size = 0;
                    if (static_cast<size_t>(dd_off) + 8 <= hdr.size()) {
                        std::memcpy(&exp_rva, hdr.data() + dd_off, 4);
                        std::memcpy(&exp_size, hdr.data() + dd_off + 4, 4);
                    }
                    if (exp_rva && exp_size) {
                        auto dir = read_mem(m.base + exp_rva, 40);
                        if (dir.size() == 40) {
                            u32 base_ord = 0, nfun = 0, nnames = 0, aof = 0, aon = 0, aoo = 0;
                            std::memcpy(&base_ord, dir.data() + 16, 4);
                            std::memcpy(&nfun, dir.data() + 20, 4);
                            std::memcpy(&nnames, dir.data() + 24, 4);
                            std::memcpy(&aof, dir.data() + 28, 4);
                            std::memcpy(&aon, dir.data() + 32, 4);
                            std::memcpy(&aoo, dir.data() + 36, 4);
                            auto funcs = read_mem(m.base + aof, static_cast<size_t>(nfun) * 4);
                            auto names = read_mem(m.base + aon, static_cast<size_t>(nnames) * 4);
                            auto ords = read_mem(m.base + aoo, static_cast<size_t>(nnames) * 2);
                            std::vector<std::string> by_index(nfun);
                            for (u32 i = 0; i < nnames && (i + 1) * 4 <= names.size() && (i + 1) * 2 <= ords.size(); ++i) {
                                u32 nrva = 0;
                                u16 oi = 0;
                                std::memcpy(&nrva, names.data() + i * 4, 4);
                                std::memcpy(&oi, ords.data() + i * 2, 2);
                                auto nb = read_mem(m.base + nrva, 128);
                                std::string nm(nb.begin(), std::find(nb.begin(), nb.end(), 0));
                                if (oi < nfun) by_index[oi] = nm;
                            }
                            for (u32 i = 0; i < nfun && (i + 1) * 4 <= funcs.size(); ++i) {
                                u32 frva = 0;
                                std::memcpy(&frva, funcs.data() + i * 4, 4);
                                if (!frva) continue;
                                ModuleExport ex;
                                ex.name = by_index[i];
                                ex.ordinal = static_cast<u16>(base_ord + i);
                                ex.va = m.base + frva;
                                m.exports.push_back(std::move(ex));
                            }
                        }
                    }
                }
            }
            mods.push_back(std::move(m));
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return mods;
}

std::optional<DebugEvent> Debugger::poll() {
    if (impl_->queue.empty()) return std::nullopt;
    DebugEvent ev = impl_->queue.front();
    impl_->queue.erase(impl_->queue.begin());
    return ev;
}

bool Debugger::alive() const { return impl_->alive; }

#endif

}  // namespace aerore
