#include "aerore/decoder.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>

#if defined(AERORE_HAS_ZYDIS)
#include <Zydis/Zydis.h>
#endif

namespace aerore {
namespace {

struct Cur {
    const u8* p;
    const u8* begin;
    const u8* end;
    bool ok = true;
    u8 get() {
        if (p >= end) {
            ok = false;
            return 0;
        }
        return *p++;
    }
};

struct Mr {
    bool present = false;
    u8 mod = 0, reg = 0, rm = 0;
    Reg base = Reg::None;
    Reg index = Reg::None;
    u8 scale = 1;
    i64 disp = 0;
    int disp_size = 0;
    u8 disp_off = 0;
    bool rip = false;
    bool reg_only = false;
    Reg rm_reg = Reg::None;
};

const char* jcc_name(unsigned c) {
    static const char* n[] = {"jo","jno","jb","jae","je","jne","jbe","ja",
                               "js","jns","jp","jnp","jl","jge","jle","jg"};
    return n[c & 15];
}

i64 read_disp(Cur& c, int size) {
    i64 v = 0;
    if (size == 1) {
        v = static_cast<int8_t>(c.get());
    } else if (size == 2) {
        u8 b0 = c.get(), b1 = c.get();
        v = static_cast<i16>(b0 | (b1 << 8));
    } else if (size == 4) {
        u8 b[4] = {c.get(), c.get(), c.get(), c.get()};
        u32 u = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
        v = static_cast<i32>(u);
    }
    return v;
}

Mr parse_modrm(Cur& c, bool addr64, bool rex_b, bool rex_x, bool rex_r) {
    Mr m;
    u8 b = c.get();
    if (!c.ok) return m;
    m.present = true;
    m.mod = (b >> 6) & 3;
    m.reg = ((b >> 3) & 7) | (rex_r ? 8 : 0);
    m.rm = b & 7;
    if (m.mod == 3) {
        m.reg_only = true;
        m.rm_reg = static_cast<Reg>(m.rm | (rex_b ? 8 : 0));
        return m;
    }
    bool sib = (m.rm == 4);
    if (sib) {
        u8 s = c.get();
        if (!c.ok) return m;
        m.scale = 1u << ((s >> 6) & 3);
        unsigned idx = ((s >> 3) & 7) | (rex_x ? 8 : 0);
        unsigned base = (s & 7) | (rex_b ? 8 : 0);
        if (!(((s >> 3) & 7) == 4 && !rex_x)) m.index = static_cast<Reg>(idx);
        if ((s & 7) == 5 && m.mod == 0) {
            m.base = Reg::None;
            m.disp_size = 4;
        } else {
            m.base = static_cast<Reg>(base);
        }
    } else if (addr64 && m.mod == 0 && m.rm == 5) {
        m.rip = true;
        m.base = Reg::None;
        m.disp_size = 4;
    } else if (!addr64 && m.mod == 0 && m.rm == 5) {
        m.base = Reg::None;
        m.disp_size = 4;
    } else {
        m.base = static_cast<Reg>(m.rm | (rex_b ? 8 : 0));
    }
    if (m.mod == 1) m.disp_size = 1;
    else if (m.mod == 2) m.disp_size = 4;
    if (m.disp_size) {
        m.disp_off = static_cast<u8>(c.p - c.begin);
        m.disp = read_disp(c, m.disp_size);
    }
    return m;
}

void add_reg(Insn& in, Reg r, int width) {
    if (in.op_count >= 4) return;
    auto& o = in.ops[in.op_count++];
    o.kind = Operand::Reg;
    o.reg = r;
    o.width = width;
}
void add_imm(Insn& in, i64 imm, int width) {
    if (in.op_count >= 4) return;
    auto& o = in.ops[in.op_count++];
    o.kind = Operand::Imm;
    o.imm = imm;
    o.width = width;
}
void add_mem(Insn& in, const Mr& m, int width) {
    if (in.op_count >= 4) return;
    auto& o = in.ops[in.op_count++];
    if (m.reg_only) {
        o.kind = Operand::Reg;
        o.reg = m.rm_reg;
        o.width = width;
        return;
    }
    o.kind = Operand::Mem;
    o.width = width;
    o.mem.base = m.base;
    o.mem.index = m.index;
    o.mem.scale = m.scale ? m.scale : 1;
    o.mem.disp = m.disp;
    o.mem.rip_relative = m.rip;
    o.mem.width = width;
}

void finish_text(Insn& in, bool is64) {
    std::ostringstream os;
    os << in.mnemonic;
    for (u8 i = 0; i < in.op_count; ++i) {
        os << (i ? ", " : " ");
        const auto& o = in.ops[i];
        if (o.kind == Operand::Reg) os << reg_name(o.reg, o.width ? o.width : (is64 ? 8 : 4));
        else if (o.kind == Operand::Imm) {
            if (o.imm < 0) os << "-0x" << std::hex << static_cast<u64>(-o.imm);
            else os << "0x" << std::hex << static_cast<u64>(o.imm);
        } else if (o.kind == Operand::Mem) {
            const char* sz = "dword";
            if (o.width == 1) sz = "byte";
            else if (o.width == 2) sz = "word";
            else if (o.width == 8) sz = "qword";
            else if (o.width == 4) sz = "dword";
            os << sz << " ptr [";
            bool any = false;
            int aw = is64 ? 8 : 4;
            if (o.mem.rip_relative) {
                os << "rip";
                any = true;
            } else if (o.mem.base != Reg::None) {
                os << reg_name(o.mem.base, aw);
                any = true;
            }
            if (o.mem.index != Reg::None) {
                if (any) os << "+";
                os << reg_name(o.mem.index, aw);
                if (o.mem.scale != 1) os << "*" << static_cast<int>(o.mem.scale);
                any = true;
            }
            if (o.mem.disp || !any) {
                if (o.mem.disp < 0) os << "-0x" << std::hex << static_cast<u64>(-o.mem.disp);
                else {
                    if (any) os << "+";
                    os << "0x" << std::hex << static_cast<u64>(o.mem.disp);
                }
            }
            os << "]";
        }
    }
    std::snprintf(in.text, sizeof(in.text), "%s", os.str().c_str());
}

void set_m(Insn& in, const char* m) { std::snprintf(in.mnemonic, sizeof(in.mnemonic), "%s", m); }

std::optional<Insn> decode_builtin(Arch arch, u64 va, const u8* bytes, size_t n) {
    if (!bytes || n == 0) return std::nullopt;
    size_t cap = std::min<size_t>(n, 15);
    Cur c{bytes, bytes, bytes + cap, true};
    bool is64 = arch == Arch::X64;
    bool rex_w = false, rex_r = false, rex_x = false, rex_b = false;
    bool opsize16 = false, addr32 = false;
    for (int i = 0; i < 14 && c.ok; ++i) {
        if (c.p >= c.end) break;
        u8 b = *c.p;
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) {
            c.p++;
            continue;
        }
        if (b == 0x66) {
            c.p++;
            opsize16 = true;
            continue;
        }
        if (b == 0x67) {
            c.p++;
            addr32 = true;
            continue;
        }
        if (is64 && b >= 0x40 && b <= 0x4F) {
            c.p++;
            rex_w = (b & 8) != 0;
            rex_r = (b & 4) != 0;
            rex_x = (b & 2) != 0;
            rex_b = (b & 1) != 0;
            continue;
        }
        break;
    }
    if (c.p >= c.end) return std::nullopt;
    bool addr64 = is64 && !addr32;
    int def_w = rex_w ? 8 : (opsize16 ? 2 : 4);
    // push/pop default to 64-bit in long mode unless 66
    int stack_w = is64 ? (opsize16 ? 2 : 8) : def_w;

    u8 op = c.get();
    if (!c.ok) return std::nullopt;
    bool two = false;
    u8 op2 = 0;
    if (op == 0x0F) {
        two = true;
        op2 = c.get();
        if (!c.ok) return std::nullopt;
    }

    Insn in;
    in.va = va;
    auto fail = []() { return std::optional<Insn>{}; };

    auto finish = [&]() -> std::optional<Insn> {
        if (!c.ok) return fail();
        in.len = static_cast<u8>(c.p - c.begin);
        if (in.len == 0 || in.len > 15) return fail();
        std::memcpy(in.raw, bytes, in.len);
        for (u8 i = 0; i < in.op_count; ++i) {
            if (in.ops[i].kind == Operand::Mem && in.ops[i].mem.rip_relative) {
                in.has_mem_va = true;
                in.mem_va = va + in.len + static_cast<u64>(in.ops[i].mem.disp);
            }
        }
        // disp_off already absolute within insn if set by caller via has_disp32
        finish_text(in, is64);
        return in;
    };

    const char* alu[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};

    if (!two) {
        if (!is64 && op >= 0x40 && op <= 0x4F) {
            set_m(in, op < 0x48 ? "inc" : "dec");
            add_reg(in, static_cast<Reg>(op & 7), def_w);
            in.flow = Flow::Next;
            return finish();
        }
        if (is64 && (op == 0x06 || op == 0x07 || op == 0x0E || op == 0x16 || op == 0x17 || op == 0x1E ||
                     op == 0x1F || op == 0x27 || op == 0x2F || op == 0x37 || op == 0x3F || op == 0x60 ||
                     op == 0x61 || op == 0x62 || op == 0x82 || op == 0x9A || op == 0xC4 || op == 0xC5 ||
                     op == 0xD4 || op == 0xD5 || op == 0xEA))
            return fail();

        if (op <= 0x3F && (op & 7) <= 5 && op != 0x0F) {
            unsigned which = op >> 3;
            unsigned low = op & 7;
            set_m(in, alu[which]);
            if (low <= 3) {
                bool byte = (low & 1) == 0;
                int w = byte ? 1 : def_w;
                Mr m = parse_modrm(c, addr64, rex_b, rex_x, rex_r);
                if (!m.present || !c.ok) return fail();
                if (m.disp_size == 4) {
                    in.has_disp32 = true;
                    in.disp_off = m.disp_off;
                }
                bool reg_dest = (low & 2) != 0;
                if (reg_dest) {
                    add_reg(in, static_cast<Reg>(m.reg), w);
                    add_mem(in, m, w);
                } else {
                    add_mem(in, m, w);
                    add_reg(in, static_cast<Reg>(m.reg), w);
                }
            } else if (low == 4) {
                add_reg(in, Reg::Rax, 1);
                add_imm(in, static_cast<int8_t>(c.get()), 1);
            } else {
                int w = def_w;
                i64 imm = read_disp(c, w == 2 ? 2 : 4);
                add_reg(in, Reg::Rax, w == 8 ? 8 : w);
                add_imm(in, imm, w == 8 ? 4 : w);
            }
            return finish();
        }

        if (op >= 0x50 && op <= 0x57) {
            set_m(in, "push");
            add_reg(in, static_cast<Reg>((op & 7) | (rex_b ? 8 : 0)), stack_w);
            return finish();
        }
        if (op >= 0x58 && op <= 0x5F) {
            set_m(in, "pop");
            add_reg(in, static_cast<Reg>((op & 7) | (rex_b ? 8 : 0)), stack_w);
            return finish();
        }
        if (op == 0x68) {
            set_m(in, "push");
            add_imm(in, read_disp(c, opsize16 ? 2 : 4), stack_w);
            return finish();
        }
        if (op == 0x6A) {
            set_m(in, "push");
            add_imm(in, static_cast<int8_t>(c.get()), stack_w);
            return finish();
        }
        if (op == 0x70 || (op >= 0x71 && op <= 0x7F) || op == 0xEB || op == 0xE0 || op == 0xE1 || op == 0xE2 ||
            op == 0xE3) {
            i64 rel = static_cast<int8_t>(c.get());
            if (!c.ok) return fail();
            u8 len = static_cast<u8>(c.p - c.begin);
            if (op >= 0x70 && op <= 0x7F) {
                set_m(in, jcc_name(op - 0x70));
                in.flow = Flow::Jcc;
            } else if (op == 0xEB) {
                set_m(in, "jmp");
                in.flow = Flow::Jmp;
            } else if (op == 0xE3) {
                set_m(in, is64 ? "jrcxz" : "jecxz");
                in.flow = Flow::Jcc;
            } else if (op == 0xE2) {
                set_m(in, "loop");
                in.flow = Flow::Jcc;
            } else if (op == 0xE1) {
                set_m(in, "loope");
                in.flow = Flow::Jcc;
            } else {
                set_m(in, "loopne");
                in.flow = Flow::Jcc;
            }
            in.target_valid = true;
            in.target = va + len + static_cast<u64>(rel);
            add_imm(in, rel, 1);
            in.len = len;
            std::memcpy(in.raw, bytes, len);
            finish_text(in, is64);
            // rewrite text target as absolute for branches
            std::snprintf(in.text, sizeof(in.text), "%s %s", in.mnemonic, hex(in.target).c_str());
            return in;
        }
        if (op >= 0xB0 && op <= 0xB7) {
            set_m(in, "mov");
            Reg r = static_cast<Reg>((op & 7) | (rex_b ? 8 : 0));
            add_reg(in, r, 1);
            add_imm(in, c.get(), 1);
            return finish();
        }
        if (op >= 0xB8 && op <= 0xBF) {
            set_m(in, "mov");
            Reg r = static_cast<Reg>((op & 7) | (rex_b ? 8 : 0));
            int w = rex_w ? 8 : (opsize16 ? 2 : 4);
            add_reg(in, r, w == 2 ? 2 : (rex_w ? 8 : 4));
            if (w == 8) {
                u8 b[8];
                for (int i = 0; i < 8; ++i) b[i] = c.get();
                if (!c.ok) return fail();
                u64 v = 0;
                for (int i = 0; i < 8; ++i) v |= static_cast<u64>(b[i]) << (8 * i);
                add_imm(in, static_cast<i64>(v), 8);
            } else {
                add_imm(in, read_disp(c, w == 2 ? 2 : 4), w);
            }
            return finish();
        }
        if (op >= 0x90 && op <= 0x97) {
            unsigned reg = (op & 7) | (rex_b ? 8 : 0);
            if (op == 0x90 && !rex_b) set_m(in, "nop");
            else {
                set_m(in, "xchg");
                add_reg(in, rex_w ? Reg::Rax : Reg::Rax, def_w);
                add_reg(in, static_cast<Reg>(reg), def_w);
            }
            return finish();
        }
        if (op == 0xE8 || op == 0xE9) {
            int relsz = opsize16 && !is64 ? 2 : 4;
            i64 rel = read_disp(c, relsz);
            if (!c.ok) return fail();
            u8 len = static_cast<u8>(c.p - c.begin);
            set_m(in, op == 0xE8 ? "call" : "jmp");
            in.flow = op == 0xE8 ? Flow::Call : Flow::Jmp;
            in.target_valid = true;
            in.target = va + len + static_cast<u64>(rel);
            add_imm(in, rel, relsz);
            in.len = len;
            std::memcpy(in.raw, bytes, len);
            std::snprintf(in.text, sizeof(in.text), "%s %s", in.mnemonic, hex(in.target).c_str());
            return in;
        }
        if (op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA) {
            set_m(in, (op == 0xCB || op == 0xCA) ? "retf" : "ret");
            in.flow = Flow::Ret;
            if (op == 0xC2 || op == 0xCA) add_imm(in, read_disp(c, 2), 2);
            return finish();
        }
        if (op == 0xC9) {
            set_m(in, "leave");
            return finish();
        }
        if (op == 0xCC) {
            set_m(in, "int3");
            in.flow = Flow::Stop;
            return finish();
        }
        if (op == 0xCD) {
            set_m(in, "int");
            add_imm(in, c.get(), 1);
            in.flow = Flow::Stop;
            return finish();
        }
        if (op == 0xF4) {
            set_m(in, "hlt");
            in.flow = Flow::Stop;
            return finish();
        }
        if (op == 0x90) {
            set_m(in, "nop");
            return finish();
        }

        bool need_modrm = false;
        bool imm8 = false, immz = false, imm16 = false;
        const char* fixed = nullptr;
        int grp = 0;  // 1=80, 2=C0, 3=F6, 4=FE, 5=FF, 6=8F, 7=C6
        switch (op) {
            case 0x63: fixed = is64 ? "movsxd" : "arpl"; need_modrm = true; break;
            case 0x69: fixed = "imul"; need_modrm = true; immz = true; break;
            case 0x6B: fixed = "imul"; need_modrm = true; imm8 = true; break;
            case 0x80: case 0x82: grp = 1; need_modrm = true; imm8 = true; break;
            case 0x81: grp = 1; need_modrm = true; immz = true; break;
            case 0x83: grp = 1; need_modrm = true; imm8 = true; break;
            case 0x84: case 0x85: fixed = "test"; need_modrm = true; break;
            case 0x86: case 0x87: fixed = "xchg"; need_modrm = true; break;
            case 0x88: case 0x89: case 0x8A: case 0x8B: fixed = "mov"; need_modrm = true; break;
            case 0x8C: case 0x8E: fixed = "mov"; need_modrm = true; break;
            case 0x8D: fixed = "lea"; need_modrm = true; break;
            case 0x8F: grp = 6; need_modrm = true; break;
            case 0x98: fixed = rex_w ? "cdqe" : (opsize16 ? "cbw" : "cwde"); break;
            case 0x99: fixed = rex_w ? "cqo" : (opsize16 ? "cwd" : "cdq"); break;
            case 0x9B: fixed = "wait"; break;
            case 0x9C: fixed = "pushf"; break;
            case 0x9D: fixed = "popf"; break;
            case 0x9E: fixed = "sahf"; break;
            case 0x9F: fixed = "lahf"; break;
            case 0xA0: case 0xA1: case 0xA2: case 0xA3: fixed = "mov"; break;
            case 0xA4: case 0xA5: fixed = "movs"; break;
            case 0xA6: case 0xA7: fixed = "cmps"; break;
            case 0xA8: fixed = "test"; imm8 = true; break;
            case 0xA9: fixed = "test"; immz = true; break;
            case 0xAA: case 0xAB: fixed = "stos"; break;
            case 0xAC: case 0xAD: fixed = "lods"; break;
            case 0xAE: case 0xAF: fixed = "scas"; break;
            case 0xC0: case 0xC1: grp = 2; need_modrm = true; imm8 = true; break;
            case 0xC6: case 0xC7: grp = 7; need_modrm = true; break;
            case 0xC8: fixed = "enter"; imm16 = true; imm8 = true; break;
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: grp = 2; need_modrm = true; break;
            case 0xD7: fixed = "xlat"; break;
            case 0xD8: case 0xD9: case 0xDA: case 0xDB:
            case 0xDC: case 0xDD: case 0xDE: case 0xDF: fixed = "fpu"; need_modrm = true; break;
            case 0xE4: case 0xE5: case 0xE6: case 0xE7: fixed = (op & 2) ? "out" : "in"; imm8 = true; break;
            case 0xEC: case 0xED: fixed = "in"; break;
            case 0xEE: case 0xEF: fixed = "out"; break;
            case 0xF1: fixed = "int1"; in.flow = Flow::Stop; break;
            case 0xF5: fixed = "cmc"; break;
            case 0xF6: case 0xF7: grp = 3; need_modrm = true; break;
            case 0xF8: fixed = "clc"; break;
            case 0xF9: fixed = "stc"; break;
            case 0xFA: fixed = "cli"; break;
            case 0xFB: fixed = "sti"; break;
            case 0xFC: fixed = "cld"; break;
            case 0xFD: fixed = "std"; break;
            case 0xFE: grp = 4; need_modrm = true; break;
            case 0xFF: grp = 5; need_modrm = true; break;
            case 0x6C: case 0x6D: fixed = "ins"; break;
            case 0x6E: case 0x6F: fixed = "outs"; break;
            default: break;
        }

        if (!fixed && !grp && !need_modrm && op != 0xA0 && !(op >= 0xA0 && op <= 0xA3)) {
            // fallthrough to handling below if fixed set or grp
        }

        if (fixed || grp || (op >= 0xA0 && op <= 0xA3)) {
            Mr m{};
            if (need_modrm) {
                m = parse_modrm(c, addr64, rex_b, rex_x, rex_r);
                if (!m.present || !c.ok) return fail();
                if (m.disp_size == 4) {
                    in.has_disp32 = true;
                    in.disp_off = m.disp_off;
                }
            }
            bool byte = (op & 1) == 0;
            int w = byte ? 1 : def_w;
            if (op == 0x63 && is64) w = def_w;
            const char* g2[] = {"rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"};
            const char* g3[] = {"test", "test", "not", "neg", "mul", "imul", "div", "idiv"};
            if (grp == 1) {
                set_m(in, alu[m.reg & 7]);
                int gw = (op == 0x80 || op == 0x82) ? 1 : def_w;
                add_mem(in, m, gw);
            } else if (grp == 2) {
                set_m(in, g2[m.reg & 7]);
                int gw = (op == 0xC0 || op == 0xD0 || op == 0xD2) ? 1 : def_w;
                add_mem(in, m, gw);
                if (op == 0xD0 || op == 0xD1) add_imm(in, 1, 1);
                if (op == 0xD2 || op == 0xD3) add_reg(in, Reg::Rcx, 1);
            } else if (grp == 3) {
                set_m(in, g3[m.reg & 7]);
                int gw = (op == 0xF6) ? 1 : def_w;
                add_mem(in, m, gw);
                if ((m.reg & 7) == 0) {
                    if (op == 0xF6) imm8 = true;
                    else immz = true;
                }
            } else if (grp == 4) {
                set_m(in, (m.reg & 7) == 0 ? "inc" : "dec");
                add_mem(in, m, 1);
            } else if (grp == 5) {
                unsigned r = m.reg & 7;
                int gw = def_w == 2 ? 2 : (is64 ? 8 : def_w);
                if (r == 0) set_m(in, "inc");
                else if (r == 1) set_m(in, "dec");
                else if (r == 2) {
                    set_m(in, "call");
                    in.flow = Flow::Call;
                } else if (r == 4) {
                    set_m(in, "jmp");
                    in.flow = Flow::Jmp;
                } else if (r == 6) {
                    set_m(in, "push");
                    gw = stack_w;
                } else if (r == 3 || r == 5) {
                    set_m(in, r == 3 ? "callf" : "jmpf");
                    in.flow = r == 3 ? Flow::Call : Flow::Jmp;
                } else {
                    set_m(in, "ud");
                }
                add_mem(in, m, (r == 2 || r == 4 || r == 6) ? gw : w);
                if ((r == 2 || r == 4) && !m.reg_only) in.target_is_mem = true;
                if ((r == 2 || r == 4) && m.reg_only) in.target_is_mem = false;
            } else if (grp == 6) {
                set_m(in, "pop");
                add_mem(in, m, stack_w);
            } else if (grp == 7) {
                set_m(in, "mov");
                int gw = (op == 0xC6) ? 1 : def_w;
                add_mem(in, m, gw);
                if (op == 0xC6) imm8 = true;
                else immz = true;
            } else if (fixed) {
                set_m(in, fixed);
                if (op == 0x84 || op == 0x86 || op == 0x88 || op == 0x8A) {
                    int bw = 1;
                    if (op == 0x8A) {
                        add_reg(in, static_cast<Reg>(m.reg), bw);
                        add_mem(in, m, bw);
                    } else if (op == 0x88 || op == 0x84 || op == 0x86) {
                        add_mem(in, m, bw);
                        add_reg(in, static_cast<Reg>(m.reg), bw);
                    }
                } else if (op == 0x85 || op == 0x87 || op == 0x89 || op == 0x8B || op == 0x63) {
                    if (op == 0x8B || op == 0x63) {
                        int dw = op == 0x63 && is64 ? (rex_w ? 8 : 4) : def_w;
                        add_reg(in, static_cast<Reg>(m.reg), dw);
                        add_mem(in, m, op == 0x63 ? 4 : dw);
                    } else {
                        add_mem(in, m, def_w);
                        add_reg(in, static_cast<Reg>(m.reg), def_w);
                    }
                } else if (op == 0x8D) {
                    add_reg(in, static_cast<Reg>(m.reg), def_w);
                    add_mem(in, m, def_w);
                } else if (op == 0x69 || op == 0x6B) {
                    add_reg(in, static_cast<Reg>(m.reg), def_w);
                    add_mem(in, m, def_w);
                } else if (op == 0xA0) {
                    add_reg(in, Reg::Rax, 1);
                    i64 disp = read_disp(c, addr64 ? 8 : 4);
                    add_imm(in, disp, addr64 ? 8 : 4);
                } else if (op == 0xA1) {
                    add_reg(in, Reg::Rax, def_w);
                    i64 disp = read_disp(c, addr64 ? 8 : 4);
                    add_imm(in, disp, addr64 ? 8 : 4);
                } else if (op == 0xA2 || op == 0xA3) {
                    i64 disp = read_disp(c, addr64 ? 8 : 4);
                    add_imm(in, disp, addr64 ? 8 : 4);
                    add_reg(in, Reg::Rax, op == 0xA2 ? 1 : def_w);
                } else if (op == 0xA8) {
                    add_reg(in, Reg::Rax, 1);
                } else if (op == 0xA9) {
                    add_reg(in, Reg::Rax, rex_w ? 8 : def_w);
                } else if (need_modrm && std::strcmp(fixed, "fpu") != 0 && op != 0x8C && op != 0x8E) {
                    add_mem(in, m, w);
                }
            }
            if (imm8) add_imm(in, static_cast<int8_t>(c.get()), 1);
            if (immz) {
                int isz = opsize16 ? 2 : 4;
                add_imm(in, read_disp(c, isz), isz);
            }
            if (imm16) add_imm(in, read_disp(c, 2), 2);
            return finish();
        }
        return fail();
    }

    // 0F secondary map
    auto jcc_near = [&](unsigned which) -> std::optional<Insn> {
        i64 rel = read_disp(c, 4);
        if (!c.ok) return fail();
        u8 len = static_cast<u8>(c.p - c.begin);
        set_m(in, jcc_name(which));
        in.flow = Flow::Jcc;
        in.target_valid = true;
        in.target = va + len + static_cast<u64>(rel);
        in.len = len;
        std::memcpy(in.raw, bytes, len);
        std::snprintf(in.text, sizeof(in.text), "%s %s", in.mnemonic, hex(in.target).c_str());
        return in;
    };
    if (op2 >= 0x80 && op2 <= 0x8F) return jcc_near(op2 - 0x80);

    const char* simple = nullptr;
    bool modrm = true;
    bool imm8 = false;
    switch (op2) {
        case 0x05: simple = "syscall"; modrm = false; break;
        case 0x07: simple = "sysret"; modrm = false; break;
        case 0x0B: simple = "ud2"; modrm = false; in.flow = Flow::Stop; break;
        case 0x30: simple = "wrmsr"; modrm = false; break;
        case 0x31: simple = "rdtsc"; modrm = false; break;
        case 0x32: simple = "rdmsr"; modrm = false; break;
        case 0x33: simple = "rdpmc"; modrm = false; break;
        case 0x34: simple = "sysenter"; modrm = false; break;
        case 0x35: simple = "sysexit"; modrm = false; break;
        case 0x77: simple = "emms"; modrm = false; break;
        case 0xA0: simple = "push"; modrm = false; break;
        case 0xA1: simple = "pop"; modrm = false; break;
        case 0xA2: simple = "cpuid"; modrm = false; break;
        case 0xA8: simple = "push"; modrm = false; break;
        case 0xA9: simple = "pop"; modrm = false; break;
        case 0xAA: simple = "rsm"; modrm = false; break;
        case 0x1F: simple = "nop"; break;
        case 0xA3: simple = "bt"; break;
        case 0xAB: simple = "bts"; break;
        case 0xB3: simple = "btr"; break;
        case 0xBB: simple = "btc"; break;
        case 0xAF: simple = "imul"; break;
        case 0xB6: case 0xB7: simple = "movzx"; break;
        case 0xBE: case 0xBF: simple = "movsx"; break;
        case 0xA4: case 0xAC: simple = op2 == 0xA4 ? "shld" : "shrd"; imm8 = true; break;
        case 0xA5: case 0xAD: simple = op2 == 0xA5 ? "shld" : "shrd"; break;
        case 0xBA: simple = nullptr; imm8 = true; break;
        case 0xBC: simple = "bsf"; break;
        case 0xBD: simple = "bsr"; break;
        case 0xB0: case 0xB1: simple = "cmpxchg"; break;
        case 0xC0: case 0xC1: simple = "xadd"; break;
        default: break;
    }
    if (op2 >= 0xC8 && op2 <= 0xCF) {
        set_m(in, "bswap");
        add_reg(in, static_cast<Reg>((op2 & 7) | (rex_b ? 8 : 0)), def_w);
        return finish();
    }
    if (simple && !modrm) {
        set_m(in, simple);
        if (op2 == 0xA0 || op2 == 0xA8) add_reg(in, Reg::None, 0);
        return finish();
    }
    if (op2 >= 0x40 && op2 <= 0x4F) simple = "cmov";
    if (op2 >= 0x90 && op2 <= 0x9F) simple = "set";

    Mr m = parse_modrm(c, addr64, rex_b, rex_x, rex_r);
    if (!m.present || !c.ok) return fail();
    if (m.disp_size == 4) {
        in.has_disp32 = true;
        in.disp_off = m.disp_off;
    }
    if (op2 == 0xBA) {
        const char* bn[] = {"bt", "bts", "btr", "btc"};
        unsigned r = m.reg & 7;
        set_m(in, r >= 4 ? bn[r - 4] : "bt");
        add_mem(in, m, def_w);
        add_imm(in, c.get(), 1);
        return finish();
    }
    if (op2 >= 0x40 && op2 <= 0x4F) {
        std::snprintf(in.mnemonic, sizeof(in.mnemonic), "cmov%s", jcc_name(op2 - 0x40) + 1);
        add_reg(in, static_cast<Reg>(m.reg), def_w);
        add_mem(in, m, def_w);
        return finish();
    }
    if (op2 >= 0x90 && op2 <= 0x9F) {
        std::snprintf(in.mnemonic, sizeof(in.mnemonic), "set%s", jcc_name(op2 - 0x90) + 1);
        add_mem(in, m, 1);
        return finish();
    }
    if (!simple) {
        std::snprintf(in.mnemonic, sizeof(in.mnemonic), "ext_%02x", op2);
    } else {
        set_m(in, simple);
    }
    if (op2 == 0xB6 || op2 == 0xBE) {
        add_reg(in, static_cast<Reg>(m.reg), def_w);
        add_mem(in, m, 1);
    } else if (op2 == 0xB7 || op2 == 0xBF) {
        add_reg(in, static_cast<Reg>(m.reg), def_w);
        add_mem(in, m, 2);
    } else if (op2 == 0xAF || op2 == 0xBC || op2 == 0xBD) {
        add_reg(in, static_cast<Reg>(m.reg), def_w);
        add_mem(in, m, def_w);
    } else if (simple) {
        add_mem(in, m, def_w);
        add_reg(in, static_cast<Reg>(m.reg), def_w);
    } else {
        add_mem(in, m, def_w);
    }
    if (imm8) add_imm(in, c.get(), 1);
    return finish();
}

#if defined(AERORE_HAS_ZYDIS)
Flow flow_from_zydis(ZydisMnemonic m, ZydisInstructionCategory cat) {
    if (m == ZYDIS_MNEMONIC_RET || m == ZYDIS_MNEMONIC_IRET || m == ZYDIS_MNEMONIC_IRETD ||
        m == ZYDIS_MNEMONIC_IRETQ)
        return Flow::Ret;
    if (m == ZYDIS_MNEMONIC_CALL) return Flow::Call;
    if (m == ZYDIS_MNEMONIC_JMP) return Flow::Jmp;
    if (cat == ZYDIS_CATEGORY_COND_BR) return Flow::Jcc;
    if (m == ZYDIS_MNEMONIC_INT3 || m == ZYDIS_MNEMONIC_HLT || m == ZYDIS_MNEMONIC_UD2) return Flow::Stop;
    return Flow::Next;
}

Reg register_from_zydis(ZydisRegister r) {
    switch (r) {
        case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_RAX: return Reg::Rax;
        case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_ECX:
        case ZYDIS_REGISTER_RCX: return Reg::Rcx;
        case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_RDX: return Reg::Rdx;
        case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_RBX: return Reg::Rbx;
        case ZYDIS_REGISTER_SPL: case ZYDIS_REGISTER_SP: case ZYDIS_REGISTER_ESP:
        case ZYDIS_REGISTER_RSP: return Reg::Rsp;
        case ZYDIS_REGISTER_BPL: case ZYDIS_REGISTER_BP: case ZYDIS_REGISTER_EBP:
        case ZYDIS_REGISTER_RBP: return Reg::Rbp;
        case ZYDIS_REGISTER_SIL: case ZYDIS_REGISTER_SI: case ZYDIS_REGISTER_ESI:
        case ZYDIS_REGISTER_RSI: return Reg::Rsi;
        case ZYDIS_REGISTER_DIL: case ZYDIS_REGISTER_DI: case ZYDIS_REGISTER_EDI:
        case ZYDIS_REGISTER_RDI: return Reg::Rdi;
        case ZYDIS_REGISTER_R8B: case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8D:
        case ZYDIS_REGISTER_R8: return Reg::R8;
        case ZYDIS_REGISTER_R9B: case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9D:
        case ZYDIS_REGISTER_R9: return Reg::R9;
        case ZYDIS_REGISTER_R10B: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10D:
        case ZYDIS_REGISTER_R10: return Reg::R10;
        case ZYDIS_REGISTER_R11B: case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11D:
        case ZYDIS_REGISTER_R11: return Reg::R11;
        case ZYDIS_REGISTER_R12B: case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12D:
        case ZYDIS_REGISTER_R12: return Reg::R12;
        case ZYDIS_REGISTER_R13B: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13D:
        case ZYDIS_REGISTER_R13: return Reg::R13;
        case ZYDIS_REGISTER_R14B: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14D:
        case ZYDIS_REGISTER_R14: return Reg::R14;
        case ZYDIS_REGISTER_R15B: case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15D:
        case ZYDIS_REGISTER_R15: return Reg::R15;
        default: return Reg::None;
    }
}

std::optional<Insn> decode_zydis(const ZydisDecoder& dec, const ZydisFormatter& fmt, u64 va, const u8* bytes,
                                 size_t n) {
    ZydisDecodedInstruction zi;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, bytes, n, &zi, ops))) return std::nullopt;
    Insn in;
    in.va = va;
    in.len = static_cast<u8>(std::min<unsigned>(zi.length, 15));
    std::memcpy(in.raw, bytes, in.len);
    const char* mnem = ZydisMnemonicGetString(zi.mnemonic);
    std::snprintf(in.mnemonic, sizeof(in.mnemonic), "%s", mnem ? mnem : "db");
    for (char* p = in.mnemonic; *p; ++p)
        if (*p >= 'A' && *p <= 'Z') *p = static_cast<char>(*p - 'A' + 'a');
    char text[256];
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &zi, ops, zi.operand_count_visible, text, sizeof(text),
                                                     va, ZYAN_NULL))) {
        // formatter keeps mnemonic uppercase; lower the first token roughly by copying as-is
        std::snprintf(in.text, sizeof(in.text), "%s", text);
    }
    in.flow = flow_from_zydis(zi.mnemonic, zi.meta.category);
    for (ZyanU8 i = 0; i < zi.operand_count_visible && in.op_count < 4; ++i) {
        const auto& op = ops[i];
        auto& dst = in.ops[in.op_count];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            dst.kind = Operand::Reg;
            // Zydis register enum isn't our enum. Leave mnemonic text authoritative.
            // Map GPR only.
            if (op.reg.value >= ZYDIS_REGISTER_AL && op.reg.value <= ZYDIS_REGISTER_R15B)
                dst.width = 1;
            else if (op.reg.value >= ZYDIS_REGISTER_AX && op.reg.value <= ZYDIS_REGISTER_R15W)
                dst.width = 2;
            else if (op.reg.value >= ZYDIS_REGISTER_EAX && op.reg.value <= ZYDIS_REGISTER_R15D)
                dst.width = 4;
            else
                dst.width = 8;
            dst.reg = register_from_zydis(op.reg.value);
            if (dst.reg == Reg::None && op.reg.value != ZYDIS_REGISTER_NONE) {
                // keep slot only for GPRs the emulator understands
                continue;
            }
            dst.kind = Operand::Reg;
            in.op_count++;
        } else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            dst.kind = Operand::Imm;
            dst.imm = op.imm.is_signed ? op.imm.value.s : static_cast<i64>(op.imm.value.u);
            dst.width = op.size / 8;
            if (zi.meta.category == ZYDIS_CATEGORY_COND_BR || zi.mnemonic == ZYDIS_MNEMONIC_JMP ||
                zi.mnemonic == ZYDIS_MNEMONIC_CALL) {
                u64 abs = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&zi, &op, va, &abs))) {
                    in.target_valid = true;
                    in.target = abs;
                }
            }
            in.op_count++;
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            dst.kind = Operand::Mem;
            dst.width = std::max(1, static_cast<int>(op.size / 8));
            dst.mem.base = register_from_zydis(op.mem.base);
            dst.mem.index = register_from_zydis(op.mem.index);
            dst.mem.scale = op.mem.scale ? op.mem.scale : 1;
            dst.mem.rip_relative = op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP;
            dst.mem.disp = op.mem.disp.value;
            if (dst.mem.rip_relative) {
                in.has_mem_va = true;
                in.mem_va = va + in.len + static_cast<u64>(dst.mem.disp);
                u64 abs = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&zi, &op, va, &abs))) in.mem_va = abs;
            }
            if (in.flow == Flow::Call || in.flow == Flow::Jmp) in.target_is_mem = true;
            in.op_count++;
        }
    }
    if (zi.raw.disp.size == 32) {
        in.has_disp32 = true;
        in.disp_off = zi.raw.disp.offset;
    }
    if (in.text[0] == 0) std::snprintf(in.text, sizeof(in.text), "%s", in.mnemonic);
    return in;
}
#endif

}  // namespace

struct Decoder::Impl {
    Arch arch;
#if defined(AERORE_HAS_ZYDIS)
    ZydisDecoder zd{};
    ZydisFormatter zf{};
    bool zydis_ok = false;
#endif
};

Decoder::Decoder(Arch arch) : impl_(std::make_unique<Impl>()) {
    impl_->arch = arch;
#if defined(AERORE_HAS_ZYDIS)
    auto mode = arch == Arch::X64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    auto sw = arch == Arch::X64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    impl_->zydis_ok = ZYAN_SUCCESS(ZydisDecoderInit(&impl_->zd, mode, sw)) &&
                      ZYAN_SUCCESS(ZydisFormatterInit(&impl_->zf, ZYDIS_FORMATTER_STYLE_INTEL));
#endif
}
Decoder::~Decoder() = default;
Decoder::Decoder(Decoder&&) noexcept = default;
Decoder& Decoder::operator=(Decoder&&) noexcept = default;
Arch Decoder::arch() const { return impl_->arch; }

std::optional<Insn> Decoder::decode(u64 va, const u8* bytes, size_t n) const {
#if defined(AERORE_HAS_ZYDIS)
    if (impl_->zydis_ok) {
        if (auto z = decode_zydis(impl_->zd, impl_->zf, va, bytes, n)) return z;
    }
#endif
    return decode_builtin(impl_->arch, va, bytes, n);
}

}  // namespace aerore
