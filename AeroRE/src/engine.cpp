#include "aerore/engine.hpp"

#include "aerore/pool.hpp"

#include <atomic>
#include <cstring>
#include <set>
#include <unordered_set>

namespace aerore {
namespace {

bool is_gap_padding(u8 b) { return b == 0xCC || b == 0x90 || b == 0x00; }

struct SweepOut {
    std::vector<Insn> insns;
};

bool prologue_at(const Insn& in, const u8* raw, size_t n, bool is64) {
    if (n < 2) return false;
    if (is64) {
        if (n >= 4 && raw[0] == 0x48 && raw[1] == 0x89 && raw[2] == 0x5C && raw[3] == 0x24) return true;
        if (n >= 3 && raw[0] == 0x48 && raw[1] == 0x83 && raw[2] == 0xEC) return true;
        if (n >= 3 && raw[0] == 0x48 && raw[1] == 0x81 && raw[2] == 0xEC) return true;
        if (n >= 3 && raw[0] == 0x48 && raw[1] == 0x8B && raw[2] == 0xC4) return true;
        if (raw[0] == 0x55) return true;
        if (n >= 2 && raw[0] == 0x40 && raw[1] == 0x55) return true;
        if (std::strcmp(in.mnemonic, "push") == 0 && in.op_count && in.ops[0].reg == Reg::Rbp) return true;
        if (std::strcmp(in.mnemonic, "sub") == 0 && in.op_count && in.ops[0].reg == Reg::Rsp) return true;
    } else {
        if (n >= 3 && raw[0] == 0x55 && raw[1] == 0x8B && raw[2] == 0xEC) return true;
        if (n >= 2 && raw[0] == 0x83 && raw[1] == 0xEC) return true;
        if (raw[0] == 0x55) return true;
    }
    return false;
}

Function build_function(u64 start, const std::unordered_set<u64>& starts, const std::unordered_map<u64, Insn>& imap,
                         const PeImage& image, Decoder& decoder, std::vector<Xref>& local_xrefs) {
    Function fn;
    fn.start = start;
    std::unordered_map<u64, Insn> body;
    std::set<u64> leaders{start};
    std::vector<u64> work{start};
    std::unordered_set<u64> queued{start};

    auto enqueue = [&](u64 va) {
        if (!queued.insert(va).second) return;
        leaders.insert(va);
        work.push_back(va);
    };

    while (!work.empty()) {
        u64 va = work.back();
        work.pop_back();
        if (va != start && starts.count(va)) continue;
        while (body.size() < 100000) {
            if (va != start && starts.count(va)) break;
            Insn in;
            auto it = imap.find(va);
            if (it != imap.end()) {
                in = it->second;
            } else {
                if (!image.contains_va(va)) break;
                u64 rva = image.va_to_rva(va);
                size_t avail = image.avail_rva(rva);
                if (!avail) break;
                u8 buf[15];
                size_t take = std::min<size_t>(avail, 15);
                if (!image.read_rva(rva, buf, take)) break;
                auto d = decoder.decode(va, buf, take);
                if (!d) break;
                in = *d;
            }
            body[va] = in;
            u64 next = va + in.len;
            if (in.has_mem_va) local_xrefs.push_back({va, in.mem_va, XrefKind::Data});
            if (in.flow == Flow::Call) {
                if (in.target_valid) local_xrefs.push_back({va, in.target, XrefKind::Call});
                va = next;
                if (starts.count(va)) break;
                continue;
            }
            if (in.flow == Flow::Jcc) {
                enqueue(next);
                if (in.target_valid) {
                    if (starts.count(in.target) && in.target != start)
                        local_xrefs.push_back({va, in.target, XrefKind::TailCall});
                    else {
                        enqueue(in.target);
                        local_xrefs.push_back({va, in.target, XrefKind::Jump});
                    }
                }
                break;
            }
            if (in.flow == Flow::Jmp) {
                if (in.target_valid && !in.target_is_mem) {
                    if (starts.count(in.target) && in.target != start)
                        local_xrefs.push_back({va, in.target, XrefKind::TailCall});
                    else {
                        enqueue(in.target);
                        local_xrefs.push_back({va, in.target, XrefKind::Jump});
                    }
                }
                break;
            }
            if (in.flow == Flow::Ret || in.flow == Flow::Stop) break;
            va = next;
            if (leaders.count(va)) break;
        }
    }

    if (body.empty()) {
        fn.end = start;
        return fn;
    }

    std::vector<u64> leader_list;
    for (u64 l : leaders)
        if (body.count(l)) leader_list.push_back(l);
    std::sort(leader_list.begin(), leader_list.end());

    for (u64 L : leader_list) {
        BasicBlock bb;
        bb.start = L;
        u64 va = L;
        while (body.count(va)) {
            const Insn& in = body[va];
            u64 next = va + in.len;
            bool stop = false;
            if (in.flow == Flow::Jcc) {
                if (body.count(next)) bb.succs.push_back({next, EdgeKind::Fallthrough});
                if (in.target_valid && body.count(in.target)) bb.succs.push_back({in.target, EdgeKind::Taken});
                else if (in.target_valid) bb.succs.push_back({in.target, EdgeKind::TailCall});
                stop = true;
            } else if (in.flow == Flow::Jmp) {
                if (in.target_valid && body.count(in.target)) bb.succs.push_back({in.target, EdgeKind::Taken});
                else if (in.target_valid) bb.succs.push_back({in.target, EdgeKind::TailCall});
                stop = true;
            } else if (in.flow == Flow::Ret || in.flow == Flow::Stop) {
                stop = true;
            }
            va = next;
            if (stop) break;
            if (leaders.count(va) && va != bb.start) {
                bb.succs.push_back({va, EdgeKind::Fallthrough});
                break;
            }
            if (!body.count(va)) break;
        }
        bb.end = va;
        fn.blocks.push_back(std::move(bb));
    }
    for (const auto& [va, in] : body) fn.end = std::max(fn.end, va + in.len);

    std::unordered_set<u64> bstarts;
    for (const auto& b : fn.blocks) bstarts.insert(b.start);
    for (const auto& b : fn.blocks) {
        for (const auto& e : b.succs) {
            if (e.kind == EdgeKind::TailCall) continue;
            if (bstarts.count(e.target) && e.target <= b.start) fn.loops.push_back({e.target, b.start});
        }
    }

    // Switch tables: indirect jmp preceded by a scale-4/8 memory operand and a cmp bound.
    std::vector<u64> vas;
    for (const auto& kv : body) vas.push_back(kv.first);
    std::sort(vas.begin(), vas.end());
    for (size_t i = 0; i < vas.size(); ++i) {
        const Insn& jmp = body[vas[i]];
        if (jmp.flow != Flow::Jmp || jmp.target_valid) continue;
        u64 table = 0;
        int scale = 0;
        int count = 0;
        u64 base_reg_va = 0;
        for (int back = 1; back <= 8 && i >= static_cast<size_t>(back); ++back) {
            const Insn& prev = body[vas[i - back]];
            if (std::strcmp(prev.mnemonic, "cmp") == 0 && prev.op_count >= 2 && prev.ops[1].kind == Operand::Imm) {
                count = static_cast<int>(prev.ops[1].imm) + 1;
            }
            for (u8 oi = 0; oi < prev.op_count; ++oi) {
                if (prev.ops[oi].kind == Operand::Mem && prev.ops[oi].mem.index != Reg::None &&
                    (prev.ops[oi].mem.scale == 4 || prev.ops[oi].mem.scale == 8)) {
                    scale = prev.ops[oi].mem.scale;
                    if (prev.has_mem_va) table = prev.mem_va;
                    if (prev.ops[oi].mem.rip_relative) table = prev.va + prev.len + static_cast<u64>(prev.ops[oi].mem.disp);
                }
            }
            if (std::strcmp(prev.mnemonic, "lea") == 0 && prev.op_count >= 2 && prev.ops[1].kind == Operand::Mem &&
                prev.ops[1].mem.rip_relative) {
                base_reg_va = prev.va + prev.len + static_cast<u64>(prev.ops[1].mem.disp);
            }
        }
        if (!table && base_reg_va) table = base_reg_va;
        if (!table || (scale != 4 && scale != 8 && !base_reg_va)) continue;
        if (count <= 0 || count > 256) count = 64;
        bool rel32 = scale == 4 || base_reg_va;
        for (int c = 0; c < count; ++c) {
            u64 entry = table + static_cast<u64>(c) * (rel32 && scale != 8 ? 4 : scale ? scale : 4);
            if (!image.contains_va(entry)) break;
            u64 target = 0;
            if (scale == 8) {
                auto p = image.read_ptr_rva(image.va_to_rva(entry));
                if (!p) break;
                target = *p;
            } else {
                u8 b[4];
                if (!image.read_rva(image.va_to_rva(entry), b, 4)) break;
                i32 rel = static_cast<i32>(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24));
                target = (base_reg_va ? base_reg_va : table) + static_cast<u64>(static_cast<i64>(rel));
            }
            if (!image.contains_va(target) || !image.executable_rva(image.va_to_rva(target))) break;
            local_xrefs.push_back({jmp.va, target, XrefKind::Jump});
            for (auto& bb : fn.blocks) {
                if (jmp.va >= bb.start && jmp.va < bb.end) {
                    bb.succs.push_back({target, EdgeKind::SwitchCase});
                    break;
                }
            }
        }
    }
    return fn;
}

void scan_strings(const PeImage& image, ProgramModel& out) {
    auto consider = [&](u64 va, const std::string& text, bool utf16) {
        if (text.size() < 4) return;
        out.strings.push_back({va, text, utf16});
    };
    for (const auto& s : image.sections()) {
        if (s.executable || s.vsize == 0) continue;
        const u8* p = image.ptr_rva(s.rva, 1);
        if (!p) continue;
        size_t n = std::min(static_cast<size_t>(s.vsize), image.avail_rva(s.rva));
        size_t i = 0;
        while (i < n) {
            size_t j = i;
            while (j < n && p[j] >= 0x20 && p[j] < 0x7F) ++j;
            if (j - i >= 4 && (j == n || p[j] == 0)) consider(image.image_base() + s.rva + i, std::string(reinterpret_cast<const char*>(p + i), j - i), false);
            i = j + 1;
        }
        i = 0;
        while (i + 8 < n) {
            size_t j = i;
            std::string text;
            while (j + 1 < n) {
                u16 cu = static_cast<u16>(p[j] | (p[j + 1] << 8));
                if (cu < 0x20 || cu > 0x7E) break;
                text.push_back(static_cast<char>(cu));
                j += 2;
            }
            if (text.size() >= 4 && (j + 1 >= n || (p[j] == 0 && p[j + 1] == 0)))
                consider(image.image_base() + s.rva + i, text, true);
            i += 2;
        }
    }
}

}  // namespace

AnalysisStats analyze(const PeImage& image, Decoder& decoder, ProgramModel& out, ProgressQueue& progress) {
    AnalysisStats stats;
    Pool pool;
    stats.threads = pool.size();
    progress.post("sweep", "linear sweep", 10);

    struct Chunk {
        u64 va;
        u64 end;
    };
    std::vector<Chunk> chunks;
    for (const auto& s : image.sections()) {
        if (!s.executable || s.vsize == 0) continue;
        // Section starts are valid decode boundaries. Arbitrary byte offsets are
        // not: an instruction can straddle a fixed-size split and make the next
        // worker start in its middle. Function-level jobs provide the second
        // stage of parallelism once call targets are known.
        chunks.push_back({s.va, s.va + s.vsize});
    }
    std::vector<SweepOut> parts(chunks.size());
    std::atomic<int> done{0};
    for (size_t i = 0; i < chunks.size(); ++i) {
        pool.submit([&, i] {
            const auto& ch = chunks[i];
            u64 va = ch.va;
            int guard = 0;
            while (va < ch.end && guard++ < 5000000) {
                if (!image.contains_va(va)) break;
                u64 rva = image.va_to_rva(va);
                size_t avail = image.avail_rva(rva);
                if (!avail) break;
                u8 buf[15];
                size_t take = std::min<size_t>(avail, 15);
                if (!image.read_rva(rva, buf, take)) break;
                auto d = decoder.decode(va, buf, take);
                if (!d || d->len == 0) {
                    va += 1;
                    continue;
                }
                if (va + d->len > ch.end && va != ch.va) break;
                parts[i].insns.push_back(*d);
                va += d->len;
            }
            int n = done.fetch_add(1) + 1;
            if (chunks.size() && (n % 4) == 0)
                progress.post("sweep", "chunk " + std::to_string(n), 10 + (20 * n) / static_cast<int>(chunks.size()));
        });
    }
    pool.wait();
    progress.post("merge", "deterministic fixup", 35);

    std::vector<Insn> candidates;
    for (auto& p : parts) {
        candidates.insert(candidates.end(), p.insns.begin(), p.insns.end());
    }
    std::sort(candidates.begin(), candidates.end(), [](const Insn& a, const Insn& b) {
        if (a.va != b.va) return a.va < b.va;
        return a.len < b.len;
    });

    std::unordered_set<u64> branch_targets;
    branch_targets.insert(image.entry_va());
    for (const auto& ex : image.exports()) branch_targets.insert(ex.va);
    for (u64 t : image.tls_callbacks()) branch_targets.insert(t);
    for (const auto& in : candidates) {
        if ((in.flow == Flow::Call || in.flow == Flow::Jmp || in.flow == Flow::Jcc) && in.target_valid)
            branch_targets.insert(in.target);
    }

    std::unordered_map<u64, Insn> imap;
    u64 cursor = 0;
    bool have_cursor = false;
    for (const auto& in : candidates) {
        if (imap.count(in.va)) {
            stats.conflicts_dropped++;
            continue;
        }
        bool overlap = false;
        if (have_cursor && in.va < cursor) {
            overlap = true;
        }
        if (overlap) {
            stats.conflicts_dropped++;
            continue;
        }
        if (have_cursor && in.va > cursor) {
            bool leader = branch_targets.count(in.va) > 0;
            if (!leader) {
                // Accept a decode that begins after padding.
                bool pad = true;
                if (image.contains_va(cursor)) {
                    u64 rva = image.va_to_rva(cursor);
                    size_t gap = static_cast<size_t>(std::min<u64>(in.va - cursor, 16));
                    for (size_t k = 0; k < gap; ++k) {
                        u8 b = 0;
                        if (!image.read_rva(rva + k, &b, 1) || !is_gap_padding(b)) {
                            pad = false;
                            break;
                        }
                    }
                }
                if (!pad && (in.va - cursor) > 16) {
                    stats.conflicts_dropped++;
                    continue;
                }
            }
        }
        imap.emplace(in.va, in);
        cursor = in.va + in.len;
        have_cursor = true;
    }

    progress.post("seeds", "function boundaries", 45);
    std::unordered_set<u64> starts;
    auto consider = [&](u64 va) {
        if (!image.contains_va(va)) return;
        if (!image.executable_rva(image.va_to_rva(va))) return;
        if (!imap.count(va)) {
            u8 buf[15];
            size_t take = std::min<size_t>(image.avail_rva(image.va_to_rva(va)), 15);
            if (!take || !image.read_rva(image.va_to_rva(va), buf, take)) return;
            auto d = decoder.decode(va, buf, take);
            if (!d) return;
            imap.emplace(va, *d);
        }
        starts.insert(va);
    };
    consider(image.entry_va());
    for (const auto& ex : image.exports()) consider(ex.va);
    for (u64 t : image.tls_callbacks()) consider(t);
    std::vector<u64> call_targets;
    call_targets.reserve(imap.size() / 8);
    for (const auto& kv : imap) {
        const Insn& in = kv.second;
        if (in.flow == Flow::Call && in.target_valid) call_targets.push_back(in.target);
    }
    std::sort(call_targets.begin(), call_targets.end());
    call_targets.erase(std::unique(call_targets.begin(), call_targets.end()), call_targets.end());
    for (u64 target : call_targets) consider(target);
    // Prologue only when nothing falls through into it.
    std::unordered_set<u64> fall_into;
    for (const auto& kv : imap) fall_into.insert(kv.first + kv.second.len);
    for (const auto& kv : imap) {
        if (fall_into.count(kv.first)) continue;
        if (prologue_at(kv.second, kv.second.raw, kv.second.len, image.is64())) consider(kv.first);
    }

    // Data pointers into executable code (vtables, function tables).
    for (const auto& s : image.sections()) {
        if (s.executable) continue;
        u64 step = image.is64() ? 8 : 4;
        for (u64 off = 0; off + step <= s.vsize; off += step) {
            auto p = image.read_ptr_rva(s.rva + off);
            if (!p) break;
            if (!image.contains_va(*p)) continue;
            if (!image.executable_rva(image.va_to_rva(*p))) continue;
            if (imap.count(*p)) consider(*p);
        }
    }

    progress.post("cfg", "recursive descent", 55);
    std::vector<u64> seeds(starts.begin(), starts.end());
    std::sort(seeds.begin(), seeds.end());
    struct Job {
        Function fn;
        std::vector<Xref> xrefs;
    };
    std::vector<Job> jobs(seeds.size());
    std::atomic<int> fdone{0};
    for (size_t i = 0; i < seeds.size(); ++i) {
        pool.submit([&, i] {
            jobs[i].fn = build_function(seeds[i], starts, imap, image, decoder, jobs[i].xrefs);
            int n = fdone.fetch_add(1) + 1;
            if (!seeds.empty() && (n % 8) == 0) {
                progress.post("cfg", "function " + hex(seeds[i]),
                              55 + static_cast<int>(25.0 * n / seeds.size()));
            }
        });
    }
    pool.wait();

    progress.post("fixup", "merge functions", 82);
    std::vector<Function> funcs;
    std::vector<Xref> xrefs;
    for (size_t i = 0; i < jobs.size(); ++i) {
        if (jobs[i].fn.end <= jobs[i].fn.start && jobs[i].fn.blocks.empty()) continue;
        funcs.push_back(std::move(jobs[i].fn));
        xrefs.insert(xrefs.end(), jobs[i].xrefs.begin(), jobs[i].xrefs.end());
    }
    std::sort(funcs.begin(), funcs.end(), [](const Function& a, const Function& b) { return a.start < b.start; });
    // Clip overlapping ranges deterministically (lower address wins).
    for (size_t i = 0; i < funcs.size(); ++i) {
        u64 limit = (i + 1 < funcs.size()) ? funcs[i + 1].start : ~0ull;
        if (funcs[i].end > limit) funcs[i].end = limit;
        std::vector<BasicBlock> kept;
        for (auto& b : funcs[i].blocks) {
            if (b.start >= funcs[i].end) continue;
            if (b.end > funcs[i].end) b.end = funcs[i].end;
            std::vector<Edge> edges;
            for (auto& e : b.succs) {
                if (e.kind == EdgeKind::TailCall || e.kind == EdgeKind::SwitchCase || e.target < funcs[i].end ||
                    starts.count(e.target))
                    edges.push_back(e);
            }
            b.succs.swap(edges);
            kept.push_back(std::move(b));
        }
        funcs[i].blocks.swap(kept);
    }

    std::unordered_map<u64, std::string> export_names;
    for (const auto& ex : image.exports())
        if (!ex.name.empty()) export_names[ex.va] = ex.name;
    for (auto& f : funcs) {
        auto it = export_names.find(f.start);
        if (it != export_names.end()) f.name = it->second;
        else f.name = "sub_" + hex(f.start).substr(2);
    }

    out.functions = std::move(funcs);
    out.insns = std::move(imap);
    out.xrefs = std::move(xrefs);

    progress.post("xrefs", "strings and data", 90);
    scan_strings(image, out);
    std::unordered_set<u64> string_vas;
    for (const auto& s : out.strings) string_vas.insert(s.va);

    std::vector<Xref> extra;
    for (const auto& kv : out.insns) {
        const Insn& in = kv.second;
        if (!in.has_mem_va) continue;
        if (string_vas.count(in.mem_va)) extra.push_back({in.va, in.mem_va, XrefKind::String});
        if (!image.contains_va(in.mem_va)) continue;
        auto ptr = image.read_ptr_rva(image.va_to_rva(in.mem_va));
        if (!ptr) continue;
        if (image.contains_va(*ptr) && image.executable_rva(image.va_to_rva(*ptr)))
            extra.push_back({in.mem_va, *ptr, XrefKind::Data});
    }
    // Pointer-sized slots in non-exec sections.
    for (const auto& s : image.sections()) {
        if (s.executable) continue;
        u64 step = image.is64() ? 8 : 4;
        for (u64 off = 0; off + step <= s.vsize && off < 0x200000; off += step) {
            auto p = image.read_ptr_rva(s.rva + off);
            if (!p || !image.contains_va(*p)) continue;
            if (!image.executable_rva(image.va_to_rva(*p))) continue;
            extra.push_back({image.image_base() + s.rva + off, *p, XrefKind::Data});
        }
    }
    out.xrefs.insert(out.xrefs.end(), extra.begin(), extra.end());
    std::sort(out.xrefs.begin(), out.xrefs.end(), [](const Xref& a, const Xref& b) {
        if (a.src != b.src) return a.src < b.src;
        if (a.dst != b.dst) return a.dst < b.dst;
        return static_cast<int>(a.kind) < static_cast<int>(b.kind);
    });
    out.xrefs.erase(std::unique(out.xrefs.begin(), out.xrefs.end(),
                                [](const Xref& a, const Xref& b) {
                                    return a.src == b.src && a.dst == b.dst && a.kind == b.kind;
                                }),
                    out.xrefs.end());

    stats.insn_count = out.insns.size();
    stats.function_count = out.functions.size();
    stats.xref_count = out.xrefs.size();
    progress.post("done", "analysis complete", 100);
    return stats;
}

}  // namespace aerore
