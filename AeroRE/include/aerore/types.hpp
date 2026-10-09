#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace aerore {

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

enum class Arch { X86, X64 };

inline std::string hex(u64 v) {
    std::ostringstream os;
    os << "0x" << std::hex << v;
    return os.str();
}

inline std::string to_lower_copy(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

struct ProgressEvent {
    std::string stage;
    std::string detail;
    int percent = 0;
};

// UI thread drains this. Workers only post. The UI never waits on analysis.
class ProgressQueue {
public:
    void post(std::string stage, std::string detail, int percent) {
        std::lock_guard lock(mu_);
        q_.push_back(ProgressEvent{std::move(stage), std::move(detail), percent});
    }
    std::vector<ProgressEvent> drain() {
        std::lock_guard lock(mu_);
        std::vector<ProgressEvent> out(q_.begin(), q_.end());
        q_.clear();
        return out;
    }

private:
    std::mutex mu_;
    std::deque<ProgressEvent> q_;
};

enum class Reg : u8 {
    Rax = 0, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
    None = 255
};

inline const char* reg_name(Reg r, int width) {
    static const char* n64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                 "r8","r9","r10","r11","r12","r13","r14","r15"};
    static const char* n32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                                 "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char* n16[] = {"ax","cx","dx","bx","sp","bp","si","di",
                                 "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char* n8[] = {"al","cl","dl","bl","spl","bpl","sil","dil",
                                "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    auto i = static_cast<unsigned>(r);
    if (i > 15) return "?";
    if (width <= 1) return n8[i];
    if (width == 2) return n16[i];
    if (width == 4) return n32[i];
    return n64[i];
}

enum class Flow : u8 { Next, Jmp, Jcc, Call, Ret, Stop };

struct MemOp {
    Reg base = Reg::None;
    Reg index = Reg::None;
    u8 scale = 1;
    i64 disp = 0;
    bool rip_relative = false;
    int width = 0;
};

struct Operand {
    enum Kind { None, Reg, Imm, Mem } kind = None;
    aerore::Reg reg = aerore::Reg::None;
    MemOp mem{};
    i64 imm = 0;
    int width = 0;
};

struct Insn {
    u64 va = 0;
    u8 len = 0;
    u8 raw[15]{};
    char mnemonic[32]{};
    char text[192]{};
    Operand ops[4]{};
    u8 op_count = 0;
    Flow flow = Flow::Next;
    bool target_valid = false;
    u64 target = 0;
    bool target_is_mem = false;
    bool has_mem_va = false;
    u64 mem_va = 0;
    bool has_disp32 = false;
    u8 disp_off = 0;
};

enum class XrefKind : u8 { Call, Jump, Data, String, TailCall };

inline const char* xref_name(XrefKind k) {
    switch (k) {
        case XrefKind::Call: return "call";
        case XrefKind::Jump: return "jump";
        case XrefKind::Data: return "data";
        case XrefKind::String: return "string";
        case XrefKind::TailCall: return "tail";
    }
    return "?";
}

struct Xref {
    u64 src = 0;
    u64 dst = 0;
    XrefKind kind = XrefKind::Data;
};

enum class EdgeKind : u8 { Fallthrough, Taken, TailCall, SwitchCase };

struct Edge {
    u64 target = 0;
    EdgeKind kind = EdgeKind::Fallthrough;
};

struct BasicBlock {
    u64 start = 0;
    u64 end = 0;
    std::vector<Edge> succs;
};

struct LoopInfo {
    u64 header = 0;
    u64 back_edge_from = 0;
};

struct Function {
    u64 start = 0;
    u64 end = 0;
    std::string name;
    std::vector<BasicBlock> blocks;
    std::vector<LoopInfo> loops;
};

struct StringHit {
    u64 va = 0;
    std::string text;
    bool utf16 = false;
};

struct TypeMember {
    std::string name;
    std::string type_name;
    int offset = 0;
    int size = 0;
};

struct StructType {
    std::string name;
    int size = 0;
    std::vector<TypeMember> members;
};

struct ImportSym {
    std::string dll;
    std::string name;
    u16 ordinal = 0;
    u64 iat_va = 0;
};

struct ExportSym {
    std::string name;
    u16 ordinal = 0;
    u64 va = 0;
    u64 rva = 0;
};

struct SectionInfo {
    std::string name;
    u64 va = 0;
    u64 rva = 0;
    u64 vsize = 0;
    u64 raw_size = 0;
    u32 raw_ptr = 0;
    u32 chars = 0;
    double entropy = 0;
    bool executable = false;
    bool readable = false;
    bool writable = false;
};

struct IatSlot {
    u64 slot_rva = 0;
    u64 slot_va = 0;
    u64 raw_value = 0;
    u64 resolved = 0;
    std::string module;
    std::string name;
    u16 ordinal = 0;
    bool trampoline = false;
    bool named = false;
    std::string note;
};

struct IatReport {
    std::vector<IatSlot> slots;
    bool patched = false;
    std::string message;
};

struct ExportFixReport {
    std::vector<ExportSym> entries;
    bool patched = false;
    bool skipped = false;
    std::string message;
};

struct ModuleExport {
    std::string name;
    u16 ordinal = 0;
    u64 va = 0;
};

struct ModuleSpan {
    std::string name;
    u64 base = 0;
    u64 size = 0;
    std::vector<ModuleExport> exports;
};

}  // namespace aerore
