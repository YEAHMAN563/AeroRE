#include "aerore/anti_debug.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace aerore {

#if !defined(_WIN32)

struct AntiAntiDebug::Impl {
    AntiAntiDebugOptions options;
    std::vector<std::string> log;
};

AntiAntiDebug::AntiAntiDebug() : impl_(std::make_unique<Impl>()) {}
AntiAntiDebug::~AntiAntiDebug() = default;
void AntiAntiDebug::set_options(const AntiAntiDebugOptions& options) { impl_->options = options; }
const AntiAntiDebugOptions& AntiAntiDebug::options() const { return impl_->options; }
bool AntiAntiDebug::load_ini(const std::string&) { return false; }
bool AntiAntiDebug::save_ini(const std::string&) const { return false; }
bool AntiAntiDebug::attach(void*, u32) { impl_->log.push_back("anti-anti-debug requires Windows"); return false; }
void AntiAntiDebug::detach() {}
void AntiAntiDebug::on_module(u64) {}
void AntiAntiDebug::on_thread(u32) {}
void AntiAntiDebug::before_continue(u32) {}
void AntiAntiDebug::after_debug_event(u32) {}
bool AntiAntiDebug::neutralize_exception(u32) const { return false; }
bool AntiAntiDebug::active() const { return false; }
bool AntiAntiDebug::target_is_64_bit() const { return false; }
std::vector<std::string> AntiAntiDebug::drain_log() {
    std::vector<std::string> out;
    out.swap(impl_->log);
    return out;
}

#else

namespace {

constexpr ULONG kProcessBasicInformation = 0;
constexpr ULONG kProcessWow64Information = 26;
constexpr ULONG kThreadHideFromDebugger = 0x11;
constexpr u32 kStatusInvalidHandle = 0xC0000008u;
constexpr u32 kDebugPrintExceptionA = 0x40010006u;
constexpr u32 kDebugPrintExceptionW = 0x4001000Au;

using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);

struct ProcessBasicInformationLocal {
    PVOID reserved1 = nullptr;
    PVOID peb = nullptr;
    PVOID reserved2[2]{};
    ULONG_PTR process_id = 0;
    PVOID reserved3 = nullptr;
};

bool parse_bool(std::string value, bool fallback) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (value == "1" || value == "true" || value == "yes" || value == "on") return true;
    if (value == "0" || value == "false" || value == "no" || value == "off") return false;
    return fallback;
}

std::string trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

struct CodeBuilder {
    std::vector<u8> bytes;
    void byte(u8 value) { bytes.push_back(value); }
    void data(std::initializer_list<u8> values) { bytes.insert(bytes.end(), values); }
    void imm32(u32 value) {
        for (int i = 0; i < 4; ++i) byte(static_cast<u8>(value >> (i * 8)));
    }
    void imm64(u64 value) {
        for (int i = 0; i < 8; ++i) byte(static_cast<u8>(value >> (i * 8)));
    }
    size_t je8() {
        byte(0x74);
        byte(0);
        return bytes.size() - 1;
    }
    size_t jne8() {
        byte(0x75);
        byte(0);
        return bytes.size() - 1;
    }
    void branch(size_t displacement, size_t target) {
        const i64 delta = static_cast<i64>(target) - static_cast<i64>(displacement + 1);
        bytes[displacement] = static_cast<u8>(static_cast<std::int8_t>(delta));
    }
    void jump_original(bool target64, u64 original) {
        if (target64) {
            data({0x48, 0xB8});
            imm64(original);
        } else {
            byte(0xB8);
            imm32(static_cast<u32>(original));
        }
        data({0xFF, 0xE0});
    }
};

std::vector<u8> make_nt_query_process(bool target64, u64 original) {
    CodeBuilder code;
    std::vector<size_t> zero_branches;
    size_t flags_branch = 0;
    if (target64) {
        code.data({0x83, 0xFA, 0x07}); zero_branches.push_back(code.je8());
        code.data({0x83, 0xFA, 0x1E}); zero_branches.push_back(code.je8());
        code.data({0x83, 0xFA, 0x1F}); flags_branch = code.je8();
    } else {
        code.data({0x8B, 0x44, 0x24, 0x08});
        code.data({0x83, 0xF8, 0x07}); zero_branches.push_back(code.je8());
        code.data({0x83, 0xF8, 0x1E}); zero_branches.push_back(code.je8());
        code.data({0x83, 0xF8, 0x1F}); flags_branch = code.je8();
    }
    code.jump_original(target64, original);

    const size_t zero = code.bytes.size();
    if (target64) code.data({0x4D, 0x85, 0xC0});
    else code.data({0x8B, 0x44, 0x24, 0x0C, 0x85, 0xC0});
    size_t zero_null = code.je8();
    if (target64) code.data({0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00});
    else code.data({0xC7, 0x00, 0x00, 0x00, 0x00, 0x00});
    const size_t zero_success = code.bytes.size();
    code.data({0x31, 0xC0});
    if (target64) code.byte(0xC3); else code.data({0xC2, 0x14, 0x00});

    const size_t flags = code.bytes.size();
    if (target64) code.data({0x4D, 0x85, 0xC0});
    else code.data({0x8B, 0x44, 0x24, 0x0C, 0x85, 0xC0});
    size_t flags_null = code.je8();
    if (target64) code.data({0x41, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00});
    else code.data({0xC7, 0x00, 0x01, 0x00, 0x00, 0x00});
    const size_t flags_success = code.bytes.size();
    code.data({0x31, 0xC0});
    if (target64) code.byte(0xC3); else code.data({0xC2, 0x14, 0x00});

    for (size_t branch : zero_branches) code.branch(branch, zero);
    code.branch(flags_branch, flags);
    code.branch(zero_null, zero_success);
    code.branch(flags_null, flags_success);
    return code.bytes;
}

std::vector<u8> make_nt_query_system(bool target64, u64 original) {
    CodeBuilder code;
    if (target64) code.data({0x83, 0xF9, 0x23});
    else code.data({0x8B, 0x44, 0x24, 0x04, 0x83, 0xF8, 0x23});
    size_t fallback = code.jne8();
    if (target64) code.data({0x48, 0x85, 0xD2});
    else code.data({0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0});
    size_t no_output = code.je8();
    // SYSTEM_KERNEL_DEBUGGER_INFORMATION: Enabled=FALSE, NotPresent=TRUE.
    if (target64) code.data({0x66, 0xC7, 0x02, 0x00, 0x01});
    else code.data({0x66, 0xC7, 0x00, 0x00, 0x01});
    const size_t success = code.bytes.size();
    code.data({0x31, 0xC0});
    if (target64) code.byte(0xC3); else code.data({0xC2, 0x10, 0x00});
    const size_t original_path = code.bytes.size();
    code.jump_original(target64, original);
    code.branch(fallback, original_path);
    code.branch(no_output, success);
    return code.bytes;
}

std::vector<u8> make_nt_set_thread(bool target64, u64 original) {
    CodeBuilder code;
    if (target64) code.data({0x83, 0xFA, 0x11});
    else code.data({0x8B, 0x44, 0x24, 0x08, 0x83, 0xF8, 0x11});
    size_t fallback = code.jne8();
    code.data({0x31, 0xC0});
    if (target64) code.byte(0xC3); else code.data({0xC2, 0x10, 0x00});
    const size_t original_path = code.bytes.size();
    code.jump_original(target64, original);
    code.branch(fallback, original_path);
    return code.bytes;
}

std::vector<u8> make_stub(const std::string& name, bool target64, u64 original) {
    // Defeats the direct Win32 BeingDebugged wrapper without touching code in
    // kernel32/kernelbase: only the target module's IAT slot is redirected.
    if (name == "IsDebuggerPresent") return {0x31, 0xC0, 0xC3};
    // Defeats remote-debug-port checks while preserving the API's BOOL success
    // contract and writing FALSE to the caller-provided result.
    if (name == "CheckRemoteDebuggerPresent") {
        if (target64)
            return {0x48, 0x85, 0xD2, 0x74, 0x06, 0xC7, 0x02, 0, 0, 0, 0,
                    0xB8, 1, 0, 0, 0, 0xC3};
        return {0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0, 0x74, 0x06, 0xC7, 0x00, 0, 0, 0, 0,
                0xB8, 1, 0, 0, 0, 0xC2, 0x08, 0x00};
    }
    // Filters ProcessDebugPort, ProcessDebugObjectHandle, and
    // ProcessDebugFlags; every other information class tail-jumps to ntdll.
    if (name == "NtQueryInformationProcess") return make_nt_query_process(target64, original);
    // Hides SystemKernelDebuggerInformation while forwarding unrelated system
    // queries unchanged.
    if (name == "NtQuerySystemInformation") return make_nt_query_system(target64, original);
    // Prevents a target from using ThreadHideFromDebugger against AeroRE. The
    // explicit hide_new_threads option is a separate operator-controlled mode.
    if (name == "NtSetInformationThread") return make_nt_set_thread(target64, original);
    // Defeats OutputDebugString side-channel probes by turning imported calls
    // into a no-op; debugger exception events are also consumed when enabled.
    if (name == "OutputDebugStringA" || name == "OutputDebugStringW")
        return target64 ? std::vector<u8>{0xC3} : std::vector<u8>{0xC2, 0x04, 0x00};
    return {};
}

}  // namespace

struct AntiAntiDebug::Impl {
    struct Patch {
        u64 address = 0;
        std::vector<u8> original;
        std::string reason;
    };
    struct DebugRegisters {
        u64 dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr6 = 0, dr7 = 0;
    };

    AntiAntiDebugOptions options;
    HANDLE process = nullptr;
    u32 pid = 0;
    bool target64 = false;
    bool active = false;
    std::vector<Patch> patches;
    std::vector<u64> allocations;
    std::unordered_map<std::string, u64> stubs;
    std::unordered_set<u64> patched_addresses;
    std::unordered_map<u32, DebugRegisters> hidden_debug_registers;
    std::vector<std::string> log;

    template <typename T>
    bool read(u64 address, T& value) const {
        SIZE_T got = 0;
        return process && ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), &got) &&
               got == sizeof(T);
    }

    bool read_bytes(u64 address, void* data, size_t size) const {
        SIZE_T got = 0;
        return process && ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), data, size, &got) && got == size;
    }

    std::string read_string(u64 address, size_t cap = 256) const {
        std::string out;
        for (size_t i = 0; i < cap; ++i) {
            char c = 0;
            if (!read(address + i, c) || c == 0) break;
            out.push_back(c);
        }
        return out;
    }

    bool raw_write(u64 address, const void* data, size_t size) const {
        DWORD old = 0;
        SIZE_T wrote = 0;
        if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &old))
            return false;
        BOOL ok = WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), data, size, &wrote);
        FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), size);
        DWORD ignored = 0;
        VirtualProtectEx(process, reinterpret_cast<LPVOID>(address), size, old, &ignored);
        return ok && wrote == size;
    }

    bool patch(u64 address, const void* data, size_t size, const std::string& reason) {
        if (!address || !size) return false;
        if (patched_addresses.count(address)) return true;
        Patch record;
        record.address = address;
        record.reason = reason;
        record.original.resize(size);
        if (!read_bytes(address, record.original.data(), size) || !raw_write(address, data, size)) return false;
        patched_addresses.insert(address);
        patches.push_back(std::move(record));
        return true;
    }

    template <typename T>
    bool patch_value(u64 address, const T& value, const std::string& reason) {
        return patch(address, &value, sizeof(value), reason);
    }

    bool query_peb(u64& peb) const {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto query = reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!query) return false;
#if defined(_WIN64)
        BOOL wow64 = FALSE;
        IsWow64Process(process, &wow64);
        if (wow64) {
            ULONG_PTR wow_peb = 0;
            if (query(process, kProcessWow64Information, &wow_peb, sizeof(wow_peb), nullptr) < 0 || !wow_peb)
                return false;
            peb = wow_peb;
            return true;
        }
#endif
        ProcessBasicInformationLocal basic;
        if (query(process, kProcessBasicInformation, &basic, sizeof(basic), nullptr) < 0 || !basic.peb) return false;
        peb = reinterpret_cast<u64>(basic.peb);
        return true;
    }

    void patch_peb_and_heap() {
        u64 peb = 0;
        if (!query_peb(peb)) {
            log.push_back("PEB query failed");
            return;
        }
        if (options.patch_peb) {
            const u8 clear = 0;
            if (patch_value(peb + 2, clear, "PEB.BeingDebugged"))
                log.push_back("cleared PEB.BeingDebugged");
            const u64 nt_global_offset = target64 ? 0xBC : 0x68;
            u32 flags = 0;
            if (read(peb + nt_global_offset, flags)) {
                const u32 clean = flags & ~(0x10u | 0x20u | 0x40u);
                if (clean != flags && patch_value(peb + nt_global_offset, clean, "PEB.NtGlobalFlag"))
                    log.push_back("removed heap-debug bits from PEB.NtGlobalFlag");
            }
        }
        if (!options.patch_heap) return;
        const u64 heap_pointer_offset = target64 ? 0x30 : 0x18;
        u64 heap = 0;
        if (target64) {
            if (!read(peb + heap_pointer_offset, heap)) return;
        } else {
            u32 heap32 = 0;
            if (!read(peb + heap_pointer_offset, heap32)) return;
            heap = heap32;
        }
        const u64 flags_offset = target64 ? 0x70 : 0x40;
        const u64 force_offset = target64 ? 0x74 : 0x44;
        u32 heap_flags = 0;
        if (read(heap + flags_offset, heap_flags)) {
            const u32 clean = (heap_flags & ~(0x20u | 0x40u | 0x40000000u)) | 0x2u;
            patch_value(heap + flags_offset, clean, "ProcessHeap.Flags");
        }
        const u32 force_flags = 0;
        if (patch_value(heap + force_offset, force_flags, "ProcessHeap.ForceFlags"))
            log.push_back("normalized process heap Flags/ForceFlags");
    }

    u64 ensure_stub(const std::string& name, u64 original) {
        auto found = stubs.find(name);
        if (found != stubs.end()) return found->second;
        std::vector<u8> code = make_stub(name, target64, original);
        if (code.empty()) return 0;
        LPVOID remote = VirtualAllocEx(process, nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remote) return 0;
        SIZE_T wrote = 0;
        if (!WriteProcessMemory(process, remote, code.data(), code.size(), &wrote) || wrote != code.size()) {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            return 0;
        }
        FlushInstructionCache(process, remote, code.size());
        u64 address = reinterpret_cast<u64>(remote);
        allocations.push_back(address);
        stubs[name] = address;
        return address;
    }

    bool hook_enabled(const std::string& name) const {
        if (!options.hook_debug_apis) return false;
        if (name == "NtQuerySystemInformation" && !options.hook_nt_query_system) return false;
        if (name == "NtSetInformationThread" && !options.block_thread_hide_calls) return false;
        if ((name == "OutputDebugStringA" || name == "OutputDebugStringW") &&
            !options.neutralize_output_debug_string)
            return false;
        return name == "IsDebuggerPresent" || name == "CheckRemoteDebuggerPresent" ||
               name == "NtQueryInformationProcess" || name == "NtQuerySystemInformation" ||
               name == "NtSetInformationThread" || name == "OutputDebugStringA" ||
               name == "OutputDebugStringW";
    }

    void hook_module(u64 module) {
        if (!active || !options.hook_debug_apis || !module) return;
        std::array<u8, 0x1000> header{};
        if (!read_bytes(module, header.data(), header.size()) || header[0] != 'M' || header[1] != 'Z') return;
        const u32 lfanew = *reinterpret_cast<const u32*>(header.data() + 0x3C);
        if (lfanew > 0xE00 || lfanew + 0x100 >= header.size() ||
            std::memcmp(header.data() + lfanew, "PE\0\0", 4) != 0)
            return;
        const u16 magic = *reinterpret_cast<const u16*>(header.data() + lfanew + 24);
        const bool module64 = magic == 0x20B;
        if (module64 != target64) return;
        const u32 directory = lfanew + 24 + (module64 ? 112u : 96u);
        if (directory + 16 > header.size()) return;
        const u32 import_rva = *reinterpret_cast<const u32*>(header.data() + directory + 8);
        if (!import_rva) return;

        const size_t pointer_size = target64 ? 8 : 4;
        const u64 ordinal_flag = target64 ? 0x8000000000000000ull : 0x80000000ull;
        for (u32 descriptor_index = 0; descriptor_index < 1024; ++descriptor_index) {
            std::array<u8, 20> descriptor{};
            if (!read_bytes(module + import_rva + descriptor_index * descriptor.size(), descriptor.data(), descriptor.size()))
                break;
            const u32 original_first = *reinterpret_cast<const u32*>(descriptor.data());
            const u32 first_thunk = *reinterpret_cast<const u32*>(descriptor.data() + 16);
            if (!original_first && !first_thunk) break;
            if (!original_first || !first_thunk) continue;
            for (u32 index = 0; index < 65536; ++index) {
                u64 lookup = 0;
                if (target64) {
                    if (!read(module + original_first + static_cast<u64>(index) * pointer_size, lookup)) break;
                } else {
                    u32 lookup32 = 0;
                    if (!read(module + original_first + static_cast<u64>(index) * pointer_size, lookup32)) break;
                    lookup = lookup32;
                }
                if (!lookup) break;
                if (lookup & ordinal_flag) continue;
                std::string name = read_string(module + static_cast<u32>(lookup) + 2);
                if (!hook_enabled(name)) continue;
                const u64 slot = module + first_thunk + static_cast<u64>(index) * pointer_size;
                u64 original = 0;
                if (target64) {
                    if (!read(slot, original)) continue;
                } else {
                    u32 original32 = 0;
                    if (!read(slot, original32)) continue;
                    original = original32;
                }
                u64 replacement = ensure_stub(name, original);
                if (!replacement) continue;
                bool ok = target64 ? patch_value(slot, replacement, "IAT!" + name)
                                   : patch_value(slot, static_cast<u32>(replacement), "IAT!" + name);
                if (ok) log.push_back("hooked " + name + " in module " + hex(module));
            }
        }
    }

    void hook_all_modules() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE) return;
        MODULEENTRY32W module{};
        module.dwSize = sizeof(module);
        if (Module32FirstW(snapshot, &module)) {
            do {
                hook_module(reinterpret_cast<u64>(module.modBaseAddr));
            } while (Module32NextW(snapshot, &module));
        }
        CloseHandle(snapshot);
    }

    void restore() {
        if (options.restore_on_detach && process) {
            for (auto it = patches.rbegin(); it != patches.rend(); ++it)
                raw_write(it->address, it->original.data(), it->original.size());
        }
        if (process) {
            for (u64 allocation : allocations)
                VirtualFreeEx(process, reinterpret_cast<LPVOID>(allocation), 0, MEM_RELEASE);
        }
        patches.clear();
        allocations.clear();
        stubs.clear();
        patched_addresses.clear();
        hidden_debug_registers.clear();
    }
};

AntiAntiDebug::AntiAntiDebug() : impl_(std::make_unique<Impl>()) {}
AntiAntiDebug::~AntiAntiDebug() { detach(); }

void AntiAntiDebug::set_options(const AntiAntiDebugOptions& options) { impl_->options = options; }
const AntiAntiDebugOptions& AntiAntiDebug::options() const { return impl_->options; }

bool AntiAntiDebug::load_ini(const std::string& path) {
    std::ifstream input(path);
    if (!input) return false;
    std::unordered_map<std::string, bool*> keys = {
        {"enabled", &impl_->options.enabled},
        {"patch_peb", &impl_->options.patch_peb},
        {"patch_heap", &impl_->options.patch_heap},
        {"hook_debug_apis", &impl_->options.hook_debug_apis},
        {"hook_nt_query_system", &impl_->options.hook_nt_query_system},
        {"block_thread_hide_calls", &impl_->options.block_thread_hide_calls},
        {"hide_new_threads", &impl_->options.hide_new_threads},
        {"sanitize_debug_registers", &impl_->options.sanitize_debug_registers},
        {"neutralize_output_debug_string", &impl_->options.neutralize_output_debug_string},
        {"neutralize_invalid_handle", &impl_->options.neutralize_invalid_handle},
        {"restore_on_detach", &impl_->options.restore_on_detach},
    };
    std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#' || line[0] == '[') continue;
        size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        std::string key = trim(line.substr(0, equals));
        auto found = keys.find(key);
        if (found != keys.end()) *found->second = parse_bool(trim(line.substr(equals + 1)), *found->second);
    }
    return true;
}

bool AntiAntiDebug::save_ini(const std::string& path) const {
    std::ofstream output(path, std::ios::trunc);
    if (!output) return false;
    auto write = [&](const char* name, bool value) { output << name << '=' << (value ? "true" : "false") << '\n'; };
    output << "[anti_anti_debug]\n";
    write("enabled", impl_->options.enabled);
    write("patch_peb", impl_->options.patch_peb);
    write("patch_heap", impl_->options.patch_heap);
    write("hook_debug_apis", impl_->options.hook_debug_apis);
    write("hook_nt_query_system", impl_->options.hook_nt_query_system);
    write("block_thread_hide_calls", impl_->options.block_thread_hide_calls);
    write("hide_new_threads", impl_->options.hide_new_threads);
    write("sanitize_debug_registers", impl_->options.sanitize_debug_registers);
    write("neutralize_output_debug_string", impl_->options.neutralize_output_debug_string);
    write("neutralize_invalid_handle", impl_->options.neutralize_invalid_handle);
    write("restore_on_detach", impl_->options.restore_on_detach);
    return static_cast<bool>(output);
}

bool AntiAntiDebug::attach(void* process_handle, u32 pid) {
    detach();
    impl_->process = static_cast<HANDLE>(process_handle);
    impl_->pid = pid;
    if (!impl_->process || !impl_->options.enabled) return false;
#if defined(_WIN64)
    BOOL wow64 = FALSE;
    IsWow64Process(impl_->process, &wow64);
    impl_->target64 = wow64 == FALSE;
#else
    impl_->target64 = false;
#endif
    impl_->active = true;
    impl_->patch_peb_and_heap();
    impl_->hook_all_modules();
    impl_->log.push_back(std::string("anti-anti-debug active for ") + (impl_->target64 ? "x64" : "x86") + " target");
    return true;
}

void AntiAntiDebug::detach() {
    if (impl_->active) impl_->restore();
    impl_->process = nullptr;
    impl_->pid = 0;
    impl_->active = false;
}

void AntiAntiDebug::on_module(u64 module_base) { impl_->hook_module(module_base); }

void AntiAntiDebug::on_thread(u32 tid) {
    if (!impl_->active || !impl_->options.hide_new_threads) return;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto set_info = reinterpret_cast<NtSetInformationThreadFn>(GetProcAddress(ntdll, "NtSetInformationThread"));
    HANDLE thread = OpenThread(THREAD_SET_INFORMATION, FALSE, tid);
    if (!set_info || !thread) return;
    if (set_info(thread, kThreadHideFromDebugger, nullptr, 0) >= 0)
        impl_->log.push_back("hid thread " + std::to_string(tid) + " from debugger events");
    CloseHandle(thread);
}

void AntiAntiDebug::before_continue(u32 tid) {
    if (!impl_->active || !impl_->options.sanitize_debug_registers) return;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!thread) return;
#if defined(_WIN64)
    if (!impl_->target64) {
        WOW64_CONTEXT context{};
        context.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
        if (Wow64GetThreadContext(thread, &context)) {
            impl_->hidden_debug_registers[tid] = {context.Dr0, context.Dr1, context.Dr2,
                                                  context.Dr3, context.Dr6, context.Dr7};
            context.Dr0 = context.Dr1 = context.Dr2 = context.Dr3 = context.Dr6 = context.Dr7 = 0;
            Wow64SetThreadContext(thread, &context);
        }
        CloseHandle(thread);
        return;
    }
#endif
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &context)) {
        impl_->hidden_debug_registers[tid] = {context.Dr0, context.Dr1, context.Dr2,
                                              context.Dr3, context.Dr6, context.Dr7};
        context.Dr0 = context.Dr1 = context.Dr2 = context.Dr3 = context.Dr6 = context.Dr7 = 0;
        SetThreadContext(thread, &context);
    }
    CloseHandle(thread);
}

void AntiAntiDebug::after_debug_event(u32 tid) {
    if (!impl_->active || !impl_->options.sanitize_debug_registers) return;
    auto found = impl_->hidden_debug_registers.find(tid);
    if (found == impl_->hidden_debug_registers.end()) return;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!thread) return;
#if defined(_WIN64)
    if (!impl_->target64) {
        WOW64_CONTEXT context{};
        context.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
        if (Wow64GetThreadContext(thread, &context)) {
            context.Dr0 = static_cast<DWORD>(found->second.dr0);
            context.Dr1 = static_cast<DWORD>(found->second.dr1);
            context.Dr2 = static_cast<DWORD>(found->second.dr2);
            context.Dr3 = static_cast<DWORD>(found->second.dr3);
            context.Dr6 = static_cast<DWORD>(found->second.dr6);
            context.Dr7 = static_cast<DWORD>(found->second.dr7);
            Wow64SetThreadContext(thread, &context);
        }
        CloseHandle(thread);
        impl_->hidden_debug_registers.erase(found);
        return;
    }
#endif
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &context)) {
        context.Dr0 = found->second.dr0; context.Dr1 = found->second.dr1;
        context.Dr2 = found->second.dr2; context.Dr3 = found->second.dr3;
        context.Dr6 = found->second.dr6; context.Dr7 = found->second.dr7;
        SetThreadContext(thread, &context);
    }
    CloseHandle(thread);
    impl_->hidden_debug_registers.erase(found);
}

bool AntiAntiDebug::neutralize_exception(u32 exception_code) const {
    if (!impl_->active) return false;
    if (impl_->options.neutralize_invalid_handle && exception_code == kStatusInvalidHandle) return true;
    return impl_->options.neutralize_output_debug_string &&
           (exception_code == kDebugPrintExceptionA || exception_code == kDebugPrintExceptionW);
}

bool AntiAntiDebug::active() const { return impl_->active; }
bool AntiAntiDebug::target_is_64_bit() const { return impl_->target64; }

std::vector<std::string> AntiAntiDebug::drain_log() {
    std::vector<std::string> out;
    out.swap(impl_->log);
    return out;
}

#endif

}  // namespace aerore
