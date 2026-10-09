#include "aerore/iat.hpp"

#include "aerore/json.hpp"

#include <cstring>
#include <map>
#include <sstream>
#include <unordered_map>

namespace aerore {
namespace {

u64 read_u64_le(const u8* p, int n) {
    u64 v = 0;
    for (int i = 0; i < n; ++i) v |= static_cast<u64>(p[i]) << (8 * i);
    return v;
}

struct Resolved {
    const ModuleSpan* mod = nullptr;
    const ModuleExport* exp = nullptr;
};

Resolved lookup(u64 va, const std::vector<ModuleSpan>& mods) {
    Resolved r;
    for (const auto& m : mods) {
        if (m.size && (va < m.base || va >= m.base + m.size)) continue;
        if (!m.size && va < m.base) continue;
        r.mod = &m;
        for (const auto& e : m.exports) {
            if (e.va == va) {
                r.exp = &e;
                return r;
            }
        }
        return r;
    }
    return r;
}

u64 follow_trampoline(PeImage& image, Decoder& decoder, u64 va, int depth) {
    if (depth > 4 || !image.contains_va(va)) return va;
    u8 buf[15];
    size_t take = std::min<size_t>(image.avail_rva(image.va_to_rva(va)), 15);
    if (!take) return va;
    if (!image.read_rva(image.va_to_rva(va), buf, take)) return va;
    auto in = decoder.decode(va, buf, take);
    if (!in) return va;
    if (in->flow == Flow::Jmp && in->target_valid && !in->target_is_mem)
        return follow_trampoline(image, decoder, in->target, depth + 1);
    if ((in->flow == Flow::Jmp || in->flow == Flow::Call) && in->has_mem_va && image.contains_va(in->mem_va)) {
        auto p = image.read_ptr_rva(image.va_to_rva(in->mem_va));
        if (p) return follow_trampoline(image, decoder, *p, depth + 1);
    }
    if (std::strcmp(in->mnemonic, "mov") == 0 && in->op_count >= 2 && in->ops[0].kind == Operand::Reg &&
        in->ops[1].kind == Operand::Imm && in->ops[1].width >= 8) {
        u64 next = va + in->len;
        size_t t2 = std::min<size_t>(image.avail_rva(image.va_to_rva(next)), 15);
        u8 b2[15];
        if (t2 && image.read_rva(image.va_to_rva(next), b2, t2)) {
            auto n2 = decoder.decode(next, b2, t2);
            if (n2 && n2->flow == Flow::Jmp && n2->op_count >= 1 && n2->ops[0].kind == Operand::Reg &&
                n2->ops[0].reg == in->ops[0].reg)
                return static_cast<u64>(in->ops[1].imm);
        }
    }
    if (std::strcmp(in->mnemonic, "push") == 0 && in->op_count >= 1 && in->ops[0].kind == Operand::Imm) {
        u64 next = va + in->len;
        size_t t2 = std::min<size_t>(image.avail_rva(image.va_to_rva(next)), 15);
        u8 b2[15];
        if (t2 && image.read_rva(image.va_to_rva(next), b2, t2)) {
            auto n2 = decoder.decode(next, b2, t2);
            if (n2 && n2->flow == Flow::Ret) return static_cast<u64>(in->ops[0].imm);
        }
    }
    return va;
}

void patch_refs(PeImage& image, Decoder& decoder, const std::vector<IatSlot>& slots, u64 new_base_rva,
                const std::vector<u64>& new_slot_rvas) {
    std::unordered_map<u64, u64> old_to_new;
    for (size_t i = 0; i < slots.size() && i < new_slot_rvas.size(); ++i)
        old_to_new[slots[i].slot_va] = image.image_base() + new_slot_rvas[i];
    (void)new_base_rva;
    for (const auto& s : image.sections()) {
        if (!s.executable) continue;
        u64 va = s.va;
        u64 end = s.va + s.vsize;
        int guard = 0;
        while (va + 1 < end && guard++ < 2000000) {
            size_t take = std::min<size_t>(image.avail_rva(image.va_to_rva(va)), 15);
            u8 buf[15];
            if (!take || !image.read_rva(image.va_to_rva(va), buf, take)) break;
            auto in = decoder.decode(va, buf, take);
            if (!in || in->len == 0) {
                va++;
                continue;
            }
            if (in->has_mem_va && in->has_disp32) {
                auto it = old_to_new.find(in->mem_va);
                if (it != old_to_new.end()) {
                    i32 disp = static_cast<i32>(static_cast<i64>(it->second) - static_cast<i64>(va + in->len));
                    u8* p = image.ptr_rva(image.va_to_rva(va) + in->disp_off, 4);
                    if (p) std::memcpy(p, &disp, 4);
                }
            }
            for (const auto& kv : old_to_new) {
                u64 old = kv.first;
                u8 le[8];
                for (int i = 0; i < 8; ++i) le[i] = static_cast<u8>((old >> (8 * i)) & 0xff);
                if (in->len >= 8) {
                    for (u8 off = 0; off + 8 <= in->len; ++off) {
                        if (std::memcmp(in->raw + off, le, 8) == 0) {
                            u8* p = image.ptr_rva(image.va_to_rva(va) + off, 8);
                            if (p) std::memcpy(p, &kv.second, 8);
                        }
                    }
                }
            }
            va += in->len;
        }
    }
}

}  // namespace

std::vector<ModuleSpan> modules_from_json(const std::string& json_text) {
    Json root = Json::parse(json_text);
    if (root.type != Json::Type::Array) throw std::runtime_error("modules json must be an array");
    std::vector<ModuleSpan> mods;
    for (const auto& item : root.arr) {
        ModuleSpan m;
        m.name = item.get_str("name");
        m.base = item.get_u64("base");
        m.size = item.get_u64("size");
        if (const Json* ex = item.get("exports")) {
            if (ex->type == Json::Type::Array) {
                for (const auto& e : ex->arr) {
                    ModuleExport me;
                    me.name = e.get_str("name");
                    me.ordinal = static_cast<u16>(e.get_u64("ordinal"));
                    me.va = e.get_u64("va");
                    m.exports.push_back(std::move(me));
                }
            }
        }
        mods.push_back(std::move(m));
    }
    return mods;
}

IatReport fix_iat(PeImage& image, Decoder& decoder, const std::vector<ModuleSpan>& modules, bool patch) {
    IatReport report;
    if (modules.empty()) {
        report.message = "no module snapshots; pass exports from a live process or a JSON module list";
        return report;
    }
    const u64 step = image.is64() ? 8 : 4;
    for (const auto& sec : image.sections()) {
        if (sec.executable) continue;
        for (u64 off = 0; off + step <= sec.vsize; off += step) {
            auto raw = image.read_ptr_rva(sec.rva + off);
            if (!raw || *raw < 0x10000) continue;
            u64 slot_va = image.image_base() + sec.rva + off;
            bool tramp = false;
            u64 resolved = *raw;
            if (image.contains_va(resolved)) {
                u64 followed = follow_trampoline(image, decoder, resolved, 0);
                if (followed != resolved) {
                    tramp = true;
                    resolved = followed;
                }
            }
            if (image.contains_va(resolved)) continue;
            auto hit = lookup(resolved, modules);
            if (!hit.mod) continue;
            IatSlot slot;
            slot.slot_rva = sec.rva + off;
            slot.slot_va = slot_va;
            slot.raw_value = *raw;
            slot.resolved = resolved;
            slot.module = hit.mod->name;
            slot.trampoline = tramp;
            if (hit.exp) {
                slot.name = hit.exp->name;
                slot.ordinal = hit.exp->ordinal;
                slot.named = !hit.exp->name.empty();
                if (!slot.named) slot.note = "ordinal";
            } else {
                slot.note = "inside module but not an export";
            }
            report.slots.push_back(std::move(slot));
        }
    }

    std::vector<IatSlot> rebuildable;
    for (const auto& s : report.slots)
        if (s.named || s.ordinal) rebuildable.push_back(s);

    if (!patch) {
        report.message = "resolved " + std::to_string(report.slots.size()) + " slots (report only)";
        return report;
    }
    if (rebuildable.empty()) {
        report.message = "nothing to rebuild";
        return report;
    }

    std::map<std::string, std::vector<IatSlot>> by_dll;
    for (const auto& s : rebuildable) by_dll[s.module].push_back(s);

    const bool is64 = image.is64();
    const u32 ptr = is64 ? 8u : 4u;
    const u64 ord_flag = is64 ? 0x8000000000000000ull : 0x80000000ull;

    // Layout: descriptors, ILT blocks, IAT blocks, hint/names, dll strings.
    struct DllBuilt {
        std::string name;
        std::vector<IatSlot> slots;
        std::vector<u64> ilt;
        std::vector<u64> hint_off;  // offset of hint/name within section, or ordinal encoded later
        bool ordinal_only = false;
    };
    std::vector<DllBuilt> dlls;
    for (auto& kv : by_dll) {
        DllBuilt d;
        d.name = kv.first;
        d.slots = kv.second;
        dlls.push_back(std::move(d));
    }

    // First pass sizes with placeholder RVAs. We need the section RVA before we can
    // write hint/name RVAs into thunks, so build bytes in two steps: reserve descriptors
    // and thunks, then fill after the section RVA is known.
    size_t desc_bytes = (dlls.size() + 1) * 20;
    size_t thunk_bytes = 0;
    for (const auto& d : dlls) thunk_bytes += (d.slots.size() + 1) * ptr * 2;

    std::vector<u8> names;
    std::vector<u32> hint_at(0);
    struct HintLoc {
        size_t dll;
        size_t slot;
        u32 off;
        bool ordinal;
        u16 ord;
    };
    std::vector<HintLoc> hints;
    for (size_t di = 0; di < dlls.size(); ++di) {
        for (size_t si = 0; si < dlls[di].slots.size(); ++si) {
            const auto& sl = dlls[di].slots[si];
            HintLoc h;
            h.dll = di;
            h.slot = si;
            if (sl.name.empty()) {
                h.ordinal = true;
                h.ord = sl.ordinal ? sl.ordinal : 1;
            } else {
                h.ordinal = false;
                if (names.size() & 1) names.push_back(0);
                h.off = static_cast<u32>(names.size());
                names.push_back(0);
                names.push_back(0);
                names.insert(names.end(), sl.name.begin(), sl.name.end());
                names.push_back(0);
            }
            hints.push_back(h);
        }
    }
    std::vector<u32> dll_off;
    for (const auto& d : dlls) {
        dll_off.push_back(static_cast<u32>(names.size()));
        names.insert(names.end(), d.name.begin(), d.name.end());
        names.push_back(0);
    }

    std::vector<u8> sec(desc_bytes + thunk_bytes + names.size(), 0);
    // name blob sits after descriptors + thunks
    if (!names.empty()) std::memcpy(sec.data() + desc_bytes + thunk_bytes, names.data(), names.size());

    u64 sec_rva = 0;  // filled after add; thunks store RVAs so we patch them once RVA is known
    // We'll write thunks as offsets from section start, then add sec_rva after add_section... 
    // add_section returns RVA. Build relative then add.
    auto write_thunk = [&](size_t off, u64 value) {
        for (u32 i = 0; i < ptr; ++i) sec[off + i] = static_cast<u8>((value >> (8 * i)) & 0xff);
    };

    size_t thunk_cursor = desc_bytes;
    std::vector<u64> new_slot_rvas_rel;  // offset within section of IAT slot, parallel to rebuildable order
    std::vector<u64> new_slot_for_old;    // same order as rebuildable
    std::map<u64, u64> oldrva_to_rel;

    for (size_t di = 0; di < dlls.size(); ++di) {
        size_t ilt_off = thunk_cursor;
        thunk_cursor += (dlls[di].slots.size() + 1) * ptr;
        size_t iat_off = thunk_cursor;
        thunk_cursor += (dlls[di].slots.size() + 1) * ptr;
        for (size_t si = 0; si < dlls[di].slots.size(); ++si) {
            const HintLoc* h = nullptr;
            for (const auto& cand : hints)
                if (cand.dll == di && cand.slot == si) h = &cand;
            u64 thunk = 0;
            if (h && h->ordinal) thunk = ord_flag | h->ord;
            else if (h) thunk = /*rva later*/ (desc_bytes + thunk_bytes + h->off);
            write_thunk(ilt_off + si * ptr, thunk);
            write_thunk(iat_off + si * ptr, thunk);
            u64 rel = iat_off + si * ptr;
            oldrva_to_rel[dlls[di].slots[si].slot_rva] = rel;
        }
        // descriptor: OFT, time, forwarder, name, FT
        size_t dpos = di * 20;
        auto wu32 = [&](size_t o, u32 v) { std::memcpy(sec.data() + o, &v, 4); };
        wu32(dpos + 0, static_cast<u32>(ilt_off));
        wu32(dpos + 12, static_cast<u32>(desc_bytes + thunk_bytes + dll_off[di]));
        wu32(dpos + 16, static_cast<u32>(iat_off));
    }

    constexpr u32 kExec = 0x20000000;
    constexpr u32 kRead = 0x40000000;
    constexpr u32 kWrite = 0x80000000;
    constexpr u32 kInit = 0x00000040;
    u64 rva = image.add_section(".aeroiat", kInit | kRead | kWrite, sec);
    if (!rva) {
        report.message = "resolved " + std::to_string(report.slots.size()) +
                         " slots but the PE header has no room for a new section";
        return report;
    }
    // Patch RVAs: every stored section-relative thunk (not ordinals) and descriptors.
    u8* base = image.ptr_rva(rva, sec.size());
    if (!base) {
        report.message = "section added but not mapped";
        return report;
    }
    auto add_rva = [&](size_t off) {
        u64 v = read_u64_le(base + off, static_cast<int>(ptr));
        if (v & ord_flag) return;
        v += rva;
        for (u32 i = 0; i < ptr; ++i) base[off + i] = static_cast<u8>((v >> (8 * i)) & 0xff);
    };
    size_t cursor = desc_bytes;
    for (size_t di = 0; di < dlls.size(); ++di) {
        size_t count = dlls[di].slots.size();
        for (size_t si = 0; si < count; ++si) {
            add_rva(cursor + si * ptr);
            add_rva(cursor + (count + 1) * ptr + si * ptr);
        }
        u32 oft = 0, name = 0, ft = 0;
        std::memcpy(&oft, base + di * 20, 4);
        std::memcpy(&name, base + di * 20 + 12, 4);
        std::memcpy(&ft, base + di * 20 + 16, 4);
        oft += static_cast<u32>(rva);
        name += static_cast<u32>(rva);
        ft += static_cast<u32>(rva);
        std::memcpy(base + di * 20, &oft, 4);
        std::memcpy(base + di * 20 + 12, &name, 4);
        std::memcpy(base + di * 20 + 16, &ft, 4);
        cursor += (count + 1) * ptr * 2;
    }

    u32 idata_size = static_cast<u32>(sec.size());
    image.set_data_directory(1, static_cast<u32>(rva), idata_size);
    // IAT directory = first thunk array through the last. Use whole thunk region.
    image.set_data_directory(12, static_cast<u32>(rva + desc_bytes), static_cast<u32>(thunk_bytes));

    std::vector<u64> new_slot_rvas;
    new_slot_rvas.reserve(rebuildable.size());
    // rebuildable order is not by_dll order. Map by old slot rva.
    std::vector<IatSlot> ordered = rebuildable;
    for (auto& sl : ordered) {
        u64 rel = oldrva_to_rel[sl.slot_rva];
        new_slot_rvas.push_back(rva + rel);
    }
    patch_refs(image, decoder, ordered, rva, new_slot_rvas);

    report.patched = true;
    report.message = "rebuilt import directory for " + std::to_string(ordered.size()) + " slots into .aeroiat";
    return report;
}

}  // namespace aerore
