#include "aerore/emu.hpp"

#include <cstring>
#include <sstream>
#include <unordered_map>

namespace aerore {
namespace {

struct Cpu {
    u64 r[16]{};
    u64 rip = 0;
    bool zf = false, sf = false, cf = false, of = false, flags = false;
    std::unordered_map<u64, u8> mem;
    const PeImage* image = nullptr;

    u8 read8(u64 va) const {
        auto it = mem.find(va);
        if (it != mem.end()) return it->second;
        if (image && image->contains_va(va)) {
            u8 b = 0;
            if (image->read_rva(image->va_to_rva(va), &b, 1)) return b;
        }
        return 0;
    }
    u64 readn(u64 va, int width) const {
        u64 v = 0;
        for (int i = 0; i < width; ++i) v |= static_cast<u64>(read8(va + i)) << (8 * i);
        return v;
    }
    void writen(u64 va, int width, u64 v) {
        for (int i = 0; i < width; ++i) mem[va + i] = static_cast<u8>((v >> (8 * i)) & 0xff);
    }
    static u64 mask_of(int width) {
        if (width >= 8) return ~0ull;
        if (width <= 0) return 0xff;
        return (1ull << (width * 8)) - 1;
    }
    u64 get(Reg reg, int width) const {
        if (reg == Reg::None) return 0;
        return r[static_cast<int>(reg)] & mask_of(width ? width : 8);
    }
    void set(Reg reg, int width, u64 v) {
        if (reg == Reg::None) return;
        int i = static_cast<int>(reg);
        if (width >= 8 || width == 0) r[i] = v;
        else if (width == 4) r[i] = v & 0xffffffffull;
        else {
            u64 m = mask_of(width);
            r[i] = (r[i] & ~m) | (v & m);
        }
    }
};

u64 effective(const Cpu& cpu, const Operand& op, u64 next) {
    if (op.mem.rip_relative) return next + static_cast<u64>(op.mem.disp);
    u64 a = 0;
    if (op.mem.base != Reg::None) a += cpu.r[static_cast<int>(op.mem.base)];
    if (op.mem.index != Reg::None) a += cpu.r[static_cast<int>(op.mem.index)] * op.mem.scale;
    a += static_cast<u64>(op.mem.disp);
    return a;
}

int width_of(const Operand& op, bool is64) {
    if (op.width) return op.width;
    return is64 ? 8 : 4;
}

bool cond(const Cpu& c, const std::string& m) {
    if (!c.flags) return false;
    if (m == "je" || m == "jz") return c.zf;
    if (m == "jne" || m == "jnz") return !c.zf;
    if (m == "jb" || m == "jnae" || m == "jc") return c.cf;
    if (m == "jae" || m == "jnb" || m == "jnc") return !c.cf;
    if (m == "jbe" || m == "jna") return c.cf || c.zf;
    if (m == "ja" || m == "jnbe") return !c.cf && !c.zf;
    if (m == "jl" || m == "jnge") return c.sf != c.of;
    if (m == "jge" || m == "jnl") return c.sf == c.of;
    if (m == "jle" || m == "jng") return c.zf || c.sf != c.of;
    if (m == "jg" || m == "jnle") return !c.zf && c.sf == c.of;
    if (m == "js") return c.sf;
    if (m == "jns") return !c.sf;
    if (m == "jo") return c.of;
    if (m == "jno") return !c.of;
    if (m == "jp" || m == "jpe") return false;
    if (m == "jnp" || m == "jpo") return true;
    return false;
}

void logic_flags(Cpu& c, u64 result, int width) {
    u64 m = Cpu::mask_of(width);
    result &= m;
    c.zf = result == 0;
    int bits = width * 8;
    c.sf = bits ? ((result >> (bits - 1)) & 1) : false;
    c.cf = false;
    c.of = false;
    c.flags = true;
}

std::string diff_snap(const u64* a, const u64* b) {
    std::ostringstream os;
    for (int i = 0; i < 16; ++i) {
        if (a[i] == b[i]) continue;
        const char* name = reg_name(static_cast<Reg>(i), 8);
        i64 delta = static_cast<i64>(b[i] - a[i]);
        if (i == static_cast<int>(Reg::Rsp)) continue;
        if (delta == 1) os << "inc " << name << "; ";
        else if (delta == -1) os << "dec " << name << "; ";
        else if (delta > -128 && delta < 128 && delta != 0) os << "add " << name << ", " << delta << "; ";
        else os << "mov " << name << ", " << hex(b[i]) << "; ";
    }
    return os.str();
}

}  // namespace

TraceResult trace_region(const PeImage& image, Decoder& decoder, u64 start_va, u64 vm_lo, u64 vm_hi, int step_cap) {
    TraceResult result;
    Cpu cpu;
    cpu.image = &image;
    cpu.rip = start_va;
    cpu.r[static_cast<int>(Reg::Rsp)] = 0x70000000;
    bool is64 = image.is64();
    int stack_w = is64 ? 8 : 4;
    std::unordered_map<u64, int> hits;
    u64 hot = 0;
    int hotc = 0;
    u64 snap[16]{};
    bool armed = false;
    std::ostringstream log;

    auto pushv = [&](u64 v) {
        cpu.r[static_cast<int>(Reg::Rsp)] -= stack_w;
        cpu.writen(cpu.r[static_cast<int>(Reg::Rsp)], stack_w, v);
    };
    auto popv = [&]() {
        u64 v = cpu.readn(cpu.r[static_cast<int>(Reg::Rsp)], stack_w);
        cpu.r[static_cast<int>(Reg::Rsp)] += stack_w;
        return v;
    };

    if (step_cap <= 0) step_cap = 200000;
    for (int step = 0; step < step_cap; ++step) {
        result.steps = step + 1;
        u64 rip = cpu.rip;
        hits[rip]++;
        if (hits[rip] > hotc) {
            hot = rip;
            hotc = hits[rip];
        }
        bool in_vm = (vm_hi > vm_lo) && rip >= vm_lo && rip < vm_hi;
        if (step > 0 && !in_vm && image.contains_va(rip) && image.executable_rva(image.va_to_rva(rip))) {
            result.found_oep = true;
            result.oep_va = rip;
            log << "oep " << hex(rip) << " after " << result.steps << " steps\n";
            break;
        }
        if (hotc >= 3 && rip == hot) {
            if (armed) {
                std::string d = diff_snap(snap, cpu.r);
                if (!d.empty()) result.lifted.push_back(hex(rip) + " " + d);
            }
            std::memcpy(snap, cpu.r, sizeof(snap));
            armed = true;
        }
        if (!image.contains_va(rip)) {
            log << "rip left image at " << hex(rip) << "\n";
            break;
        }
        u8 buf[15];
        size_t take = std::min<size_t>(image.avail_rva(image.va_to_rva(rip)), 15);
        if (!take || !image.read_rva(image.va_to_rva(rip), buf, take)) break;
        // Overlay wins over the original file bytes so stub writes are visible.
        for (size_t i = 0; i < take; ++i) {
            auto it = cpu.mem.find(rip + i);
            if (it != cpu.mem.end()) buf[i] = it->second;
        }
        auto insn = decoder.decode(rip, buf, take);
        if (!insn) {
            log << "undecoded at " << hex(rip) << "\n";
            break;
        }
        const Insn& in = *insn;
        u64 next = rip + in.len;
        std::string m = in.mnemonic;
        auto opw = [&](int i) { return i < in.op_count ? width_of(in.ops[i], is64) : (is64 ? 8 : 4); };

        bool ok = true;
        if (m == "nop" || m == "endbr64" || m == "endbr32") {
            cpu.rip = next;
        } else if (m == "push") {
            u64 v = 0;
            if (in.op_count && in.ops[0].kind == Operand::Reg) v = cpu.get(in.ops[0].reg, stack_w);
            else if (in.op_count && in.ops[0].kind == Operand::Imm) v = static_cast<u64>(in.ops[0].imm);
            else ok = false;
            if (ok) {
                pushv(v);
                cpu.rip = next;
            }
        } else if (m == "pop") {
            u64 v = popv();
            if (in.op_count && in.ops[0].kind == Operand::Reg) cpu.set(in.ops[0].reg, stack_w, v);
            else ok = false;
            if (ok) cpu.rip = next;
        } else if (m == "lea" && in.op_count >= 2 && in.ops[0].kind == Operand::Reg) {
            cpu.set(in.ops[0].reg, opw(0), effective(cpu, in.ops[1], next));
            cpu.rip = next;
        } else if (m == "mov" && in.op_count >= 2) {
            u64 v = 0;
            if (in.ops[1].kind == Operand::Reg) v = cpu.get(in.ops[1].reg, opw(1));
            else if (in.ops[1].kind == Operand::Imm) v = static_cast<u64>(in.ops[1].imm);
            else if (in.ops[1].kind == Operand::Mem) v = cpu.readn(effective(cpu, in.ops[1], next), opw(1));
            else ok = false;
            if (ok && in.ops[0].kind == Operand::Reg) cpu.set(in.ops[0].reg, opw(0), v);
            else if (ok && in.ops[0].kind == Operand::Mem) cpu.writen(effective(cpu, in.ops[0], next), opw(0), v);
            else ok = false;
            if (ok) cpu.rip = next;
        } else if (m == "movzx" && in.op_count >= 2 && in.ops[0].kind == Operand::Reg) {
            u64 v = 0;
            if (in.ops[1].kind == Operand::Reg) v = cpu.get(in.ops[1].reg, opw(1));
            else if (in.ops[1].kind == Operand::Mem) v = cpu.readn(effective(cpu, in.ops[1], next), opw(1));
            else ok = false;
            if (ok) {
                cpu.set(in.ops[0].reg, opw(0), v);
                cpu.rip = next;
            }
        } else if (m == "movsx" || m == "movsxd") {
            if (in.op_count >= 2 && in.ops[0].kind == Operand::Reg) {
                int sw = opw(1);
                u64 v = 0;
                if (in.ops[1].kind == Operand::Reg) v = cpu.get(in.ops[1].reg, sw);
                else if (in.ops[1].kind == Operand::Mem) v = cpu.readn(effective(cpu, in.ops[1], next), sw);
                else ok = false;
                if (ok) {
                    int bits = sw * 8;
                    if (bits && bits < 64 && (v & (1ull << (bits - 1)))) v |= ~Cpu::mask_of(sw);
                    cpu.set(in.ops[0].reg, opw(0), v);
                    cpu.rip = next;
                }
            } else ok = false;
        } else if ((m == "add" || m == "sub" || m == "xor" || m == "or" || m == "and" || m == "cmp" || m == "test") &&
                   in.op_count >= 2) {
            auto val = [&](const Operand& op) -> u64 {
                if (op.kind == Operand::Reg) return cpu.get(op.reg, width_of(op, is64));
                if (op.kind == Operand::Imm) return static_cast<u64>(op.imm);
                if (op.kind == Operand::Mem) return cpu.readn(effective(cpu, op, next), width_of(op, is64));
                return 0;
            };
            int w = opw(0);
            u64 a = val(in.ops[0]);
            u64 b = val(in.ops[1]);
            u64 mask = Cpu::mask_of(w);
            a &= mask;
            b &= mask;
            u64 res = 0;
            if (m == "add") res = (a + b) & mask;
            else if (m == "sub" || m == "cmp") res = (a - b) & mask;
            else if (m == "xor" || m == "test") res = (m == "test" ? (a & b) : (a ^ b)) & mask;
            else if (m == "or") res = (a | b) & mask;
            else res = (a & b) & mask;
            if (m == "add" || m == "sub" || m == "cmp") {
                if (m == "add") {
                    cpu.cf = (a + b) < a;
                    int bits = w * 8;
                    bool sa = bits && (a >> (bits - 1));
                    bool sb = bits && (b >> (bits - 1));
                    bool sr = bits && (res >> (bits - 1));
                    cpu.of = (sa == sb) && (sa != sr);
                } else {
                    cpu.cf = a < b;
                    int bits = w * 8;
                    bool sa = bits && (a >> (bits - 1));
                    bool sb = bits && (b >> (bits - 1));
                    bool sr = bits && (res >> (bits - 1));
                    cpu.of = (sa != sb) && (sa != sr);
                }
                cpu.zf = res == 0;
                int bits = w * 8;
                cpu.sf = bits && ((res >> (bits - 1)) & 1);
                cpu.flags = true;
            } else {
                logic_flags(cpu, res, w);
            }
            if (m != "cmp" && m != "test" && in.ops[0].kind == Operand::Reg) cpu.set(in.ops[0].reg, w, res);
            else if (m != "cmp" && m != "test" && in.ops[0].kind == Operand::Mem)
                cpu.writen(effective(cpu, in.ops[0], next), w, res);
            cpu.rip = next;
        } else if ((m == "inc" || m == "dec" || m == "not" || m == "neg") && in.op_count >= 1) {
            int w = opw(0);
            u64 a = 0;
            if (in.ops[0].kind == Operand::Reg) a = cpu.get(in.ops[0].reg, w);
            else if (in.ops[0].kind == Operand::Mem) a = cpu.readn(effective(cpu, in.ops[0], next), w);
            else ok = false;
            u64 res = a;
            if (m == "inc") res = a + 1;
            else if (m == "dec") res = a - 1;
            else if (m == "not") res = ~a;
            else res = static_cast<u64>(-static_cast<i64>(a));
            res &= Cpu::mask_of(w);
            if (ok && in.ops[0].kind == Operand::Reg) cpu.set(in.ops[0].reg, w, res);
            else if (ok) cpu.writen(effective(cpu, in.ops[0], next), w, res);
            if (m == "inc" || m == "dec") {
                cpu.zf = res == 0;
                int bits = w * 8;
                cpu.sf = bits && ((res >> (bits - 1)) & 1);
                cpu.flags = true;
            }
            if (ok) cpu.rip = next;
        } else if ((m == "shl" || m == "shr" || m == "sar") && in.op_count >= 1) {
            int w = opw(0);
            u64 a = in.ops[0].kind == Operand::Reg ? cpu.get(in.ops[0].reg, w) : 0;
            u64 sh = 0;
            if (in.op_count >= 2 && in.ops[1].kind == Operand::Imm) sh = static_cast<u64>(in.ops[1].imm);
            else if (in.op_count >= 2 && in.ops[1].kind == Operand::Reg) sh = cpu.get(in.ops[1].reg, 1);
            sh &= 63;
            u64 res = (m == "shl") ? (a << sh) : (a >> sh);
            if (in.ops[0].kind == Operand::Reg) cpu.set(in.ops[0].reg, w, res);
            cpu.rip = next;
        } else if (m == "xchg" && in.op_count >= 2 && in.ops[0].kind == Operand::Reg && in.ops[1].kind == Operand::Reg) {
            u64 a = cpu.get(in.ops[0].reg, opw(0));
            u64 b = cpu.get(in.ops[1].reg, opw(1));
            cpu.set(in.ops[0].reg, opw(0), b);
            cpu.set(in.ops[1].reg, opw(1), a);
            cpu.rip = next;
        } else if (m == "call") {
            pushv(next);
            if (in.target_valid) cpu.rip = in.target;
            else if (in.has_mem_va) cpu.rip = cpu.readn(in.mem_va, stack_w);
            else if (in.op_count && in.ops[0].kind == Operand::Reg) cpu.rip = cpu.get(in.ops[0].reg, stack_w);
            else if (in.op_count && in.ops[0].kind == Operand::Mem)
                cpu.rip = cpu.readn(effective(cpu, in.ops[0], next), stack_w);
            else ok = false;
            if (ok && !image.contains_va(cpu.rip)) {
                cpu.rip = next;
                cpu.r[static_cast<int>(Reg::Rsp)] += stack_w;
                log << "external call skipped at " << hex(rip) << "\n";
            }
        } else if (m == "jmp") {
            if (in.target_valid && !in.target_is_mem) cpu.rip = in.target;
            else if (in.has_mem_va) cpu.rip = cpu.readn(in.mem_va, stack_w);
            else if (in.op_count && in.ops[0].kind == Operand::Mem)
                cpu.rip = cpu.readn(effective(cpu, in.ops[0], next), stack_w);
            else if (in.op_count && in.ops[0].kind == Operand::Reg) cpu.rip = cpu.get(in.ops[0].reg, stack_w);
            else ok = false;
        } else if (in.flow == Flow::Jcc) {
            if (!cpu.flags) {
                log << "unknown flags at " << hex(rip) << "\n";
                break;
            }
            cpu.rip = cond(cpu, m) && in.target_valid ? in.target : next;
        } else if (m == "ret" || m == "retf") {
            cpu.rip = popv();
            if (in.op_count && in.ops[0].kind == Operand::Imm)
                cpu.r[static_cast<int>(Reg::Rsp)] += static_cast<u64>(in.ops[0].imm);
        } else if (m == "leave") {
            cpu.r[static_cast<int>(Reg::Rsp)] = cpu.r[static_cast<int>(Reg::Rbp)];
            cpu.r[static_cast<int>(Reg::Rbp)] = popv();
            cpu.rip = next;
        } else if (m == "int3" || m == "hlt" || m == "ud2") {
            log << m << " at " << hex(rip) << "\n";
            break;
        } else {
            log << "unsupported " << in.text << " at " << hex(rip) << "\n";
            break;
        }
        if (!ok) {
            log << "failed " << in.text << " at " << hex(rip) << "\n";
            break;
        }
    }
    result.log = log.str();
    return result;
}

}  // namespace aerore
