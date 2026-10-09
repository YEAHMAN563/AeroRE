#include "aerore/database.hpp"
#include "aerore/decoder.hpp"
#include "aerore/engine.hpp"
#include "aerore/exports.hpp"
#include "aerore/iat.hpp"
#include "aerore/mcp.hpp"
#include "aerore/pseudocode.hpp"
#include "aerore/session.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

namespace {

int g_fails = 0;

void expect(bool cond, const char* expr, int line) {
    if (!cond) {
        std::cerr << "FAIL line " << line << " " << expr << "\n";
        ++g_fails;
    }
}
#define CHECK(c) expect((c), #c, __LINE__)

struct Buf {
    std::vector<aerore::u8> b;
    void ensure(size_t n) {
        if (b.size() < n) b.resize(n, 0);
    }
    void w16(size_t o, uint16_t v) {
        ensure(o + 2);
        b[o] = static_cast<aerore::u8>(v);
        b[o + 1] = static_cast<aerore::u8>(v >> 8);
    }
    void w32(size_t o, uint32_t v) {
        ensure(o + 4);
        for (int i = 0; i < 4; ++i) b[o + i] = static_cast<aerore::u8>(v >> (8 * i));
    }
    void w64(size_t o, uint64_t v) {
        ensure(o + 8);
        for (int i = 0; i < 8; ++i) b[o + i] = static_cast<aerore::u8>(v >> (8 * i));
    }
    void bytes_at(size_t o, const std::vector<aerore::u8>& d) {
        ensure(o + d.size());
        std::memcpy(b.data() + o, d.data(), d.size());
    }
    void section(size_t off, const char* name, uint32_t vsize, uint32_t va, uint32_t raw, uint32_t ptr, uint32_t chars) {
        ensure(off + 40);
        std::memset(b.data() + off, 0, 40);
        std::memcpy(b.data() + off, name, std::min<size_t>(8, std::strlen(name)));
        w32(off + 8, vsize);
        w32(off + 12, va);
        w32(off + 16, raw);
        w32(off + 20, ptr);
        w32(off + 36, chars);
    }
};

// Two-section PE32+. code_a lives at RVA 0x1000, code_b at RVA 0x2000.
std::vector<aerore::u8> build_pe(const char* sec_a, const std::vector<aerore::u8>& code_a, uint32_t chars_a,
                                 const char* sec_b, const std::vector<aerore::u8>& code_b, uint32_t chars_b,
                                 uint32_t entry_rva, const std::vector<std::pair<uint32_t, uint64_t>>& rdata_qwords) {
    Buf f;
    f.ensure(0x800);
    f.b[0] = 'M';
    f.b[1] = 'Z';
    f.w32(0x3C, 0x80);
    f.b[0x80] = 'P';
    f.b[0x81] = 'E';
    f.w16(0x84, 0x8664);
    f.w16(0x86, 2);
    f.w16(0x94, 0xF0);
    f.w16(0x96, 0x22);
    const size_t opt = 0x98;
    f.w16(opt, 0x20B);
    f.w32(opt + 16, entry_rva);
    f.w32(opt + 20, 0x1000);
    f.w64(opt + 24, 0x140000000ull);
    f.w32(opt + 32, 0x1000);
    f.w32(opt + 36, 0x200);
    f.w16(opt + 48, 6);
    f.w32(opt + 56, 0x3000);
    f.w32(opt + 60, 0x400);
    f.w16(opt + 68, 3);
    f.w16(opt + 70, 0x160);
    f.w64(opt + 72, 0x100000);
    f.w64(opt + 80, 0x1000);
    f.w64(opt + 88, 0x100000);
    f.w64(opt + 96, 0x1000);
    f.w32(opt + 108, 16);
    constexpr uint32_t kX = 0x60000020;
    f.section(0x188, sec_a, 0x200, 0x1000, 0x200, 0x400, chars_a ? chars_a : kX);
    f.section(0x188 + 40, sec_b, 0x200, 0x2000, 0x200, 0x600, chars_b ? chars_b : 0x40000040);
    f.bytes_at(0x400, code_a);
    f.bytes_at(0x600, code_b);
    for (const auto& q : rdata_qwords) f.w64(0x600 + (q.first - 0x2000), q.second);
    f.ensure(0x800);
    return f.b;
}

void test_decode() {
    aerore::Decoder d(aerore::Arch::X64);
    auto one = [&](std::vector<aerore::u8> bytes, const char* mnem, aerore::u64 va = 0x140001000) {
        auto in = d.decode(va, bytes.data(), bytes.size());
        if (!in) {
            std::cerr << "decode failed for " << mnem << "\n";
            ++g_fails;
            return aerore::Insn{};
        }
        if (std::strcmp(in->mnemonic, mnem) != 0) {
            std::cerr << "mnemonic " << in->mnemonic << " text " << in->text << " expected " << mnem << "\n";
            ++g_fails;
        }
        return *in;
    };
    one({0x48, 0x31, 0xC0}, "xor");
    one({0x48, 0x83, 0xEC, 0x28}, "sub");
    auto call = one({0xE8, 0x00, 0x00, 0x00, 0x00}, "call");
    CHECK(call.target_valid && call.target == 0x140001005);
    one({0xC3}, "ret");
    auto movzx = one({0x41, 0x0F, 0xB6, 0x08}, "movzx");
    CHECK(movzx.op_count >= 2 && movzx.ops[1].kind == aerore::Operand::Mem && movzx.ops[1].mem.base == aerore::Reg::R8);
    one({0x49, 0xFF, 0xC0}, "inc");
    auto jmpmem = one({0xFF, 0x24, 0xCA}, "jmp");
    CHECK(jmpmem.flow == aerore::Flow::Jmp);
    CHECK(jmpmem.op_count >= 1 && jmpmem.ops[0].kind == aerore::Operand::Mem);
    CHECK(jmpmem.ops[0].mem.base == aerore::Reg::Rdx);
    CHECK(jmpmem.ops[0].mem.index == aerore::Reg::Rcx);
    CHECK(jmpmem.ops[0].mem.scale == 8);
    auto lea = one({0x48, 0x8D, 0x0D, 0x10, 0x00, 0x00, 0x00}, "lea");
    CHECK(lea.has_mem_va);
    CHECK(lea.mem_va == 0x140001000 + 7 + 0x10);
}

void test_analysis_and_db() {
    using u8 = aerore::u8;
    // func @ 0x1000: sub rsp,28; call 0x1020; add rsp,28; ret
    // func @ 0x1020: xor rax,rax; lea rcx, [rip -> 0x2000]; ret
    std::vector<u8> text = {
        0x48, 0x83, 0xEC, 0x28, 0xE8, 0x17, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xC3,
    };
    text.resize(0x20, 0xCC);
    text.insert(text.end(), {0x48, 0x31, 0xC0, 0x48, 0x8D, 0x0D, 0xD6, 0x0F, 0x00, 0x00, 0xC3});
    std::vector<u8> rdata = {'H', 'e', 'l', 'l', 'o', 0};
    auto file = build_pe(".text", text, 0x60000020, ".rdata", rdata, 0x40000040, 0x1000,
                         {{0x2100, 0x00007FFE00001000ull}});
    const char* dbpath = "aerore-test.idb";
    std::remove(dbpath);
    {
    aerore::Session session;
    session.load_bytes(file, "sample.exe", false);
    auto m = session.model();
    CHECK(m->image_base == 0x140000000ull);
    CHECK(m->functions.size() >= 2);
    bool saw_call = false;
    bool saw_string = false;
    for (const auto& x : m->xrefs) {
        if (x.kind == aerore::XrefKind::Call && x.dst == 0x140001020ull) saw_call = true;
        if (x.kind == aerore::XrefKind::String && x.dst == 0x140002000ull) saw_string = true;
    }
    CHECK(saw_call);
    CHECK(saw_string);
    const aerore::Function* f = m->function_by_start(0x140001000ull);
    CHECK(f != nullptr);
    if (f) {
        CHECK(!f->blocks.empty());
        CHECK(f->name.rfind("sub_", 0) == 0);
        auto pseudo = aerore::build_pseudocode(*m, *f);
        CHECK(!pseudo.empty());
        bool saw_call_preview = false;
        for (const auto& line : pseudo)
            if (line.text.find("sub_") != std::string::npos && line.text.find("();") != std::string::npos)
                saw_call_preview = true;
        CHECK(saw_call_preview);
    }

    session.save_db(dbpath);
    aerore::Session again;
    again.open_db(dbpath);
    auto m2 = again.model();
    CHECK(m2->functions.size() == m->functions.size());
    CHECK(m2->insns.size() == m->insns.size());
    again.set_comment(0x140001000ull, "entry");
    aerore::StructType st;
    st.name = "POINT";
    st.members.push_back({"x", "i32", 0, 4});
    st.members.push_back({"y", "i32", 4, 4});
    st.size = 8;
    again.define_struct(st);
    std::string q = again.query("SELECT name FROM functions ORDER BY start LIMIT 1");
    CHECK(q.find("sub_") != std::string::npos || q.find("name") != std::string::npos);
    std::string bad;
    bool threw = false;
    try {
        bad = again.query("DELETE FROM functions");
    } catch (...) {
        threw = true;
    }
    CHECK(threw);
    }
    std::remove(dbpath);
    std::remove("aerore-test.idb-shm");
    std::remove("aerore-test.idb-wal");
}

void test_iat() {
    std::vector<aerore::u8> text = {0x48, 0x31, 0xC0, 0xC3};
    std::vector<aerore::u8> data(0x20, 0);
    auto file = build_pe(".text", text, 0x60000020, ".data", data, 0xC0000040, 0x1000,
                         {{0x2000, 0x00007FFE00001000ull}});
    // also a trampoline: slot points at a jmp [rip] inside the image? keep the direct case.
    aerore::PeImage image = aerore::PeImage::parse(file);
    aerore::Decoder dec(aerore::Arch::X64);
    std::string mods = R"([{"name":"kernel32.dll","base":"0x7ffe00000000","size":"0x200000",
        "exports":[{"name":"GetProcAddress","ordinal":10,"va":"0x7ffe00001000"}]}])";
    auto parsed = aerore::modules_from_json(mods);
    auto report = aerore::fix_iat(image, dec, parsed, true);
    CHECK(!report.slots.empty());
    CHECK(report.slots[0].name == "GetProcAddress");
    CHECK(report.patched);
    auto rebuilt = image.rebuild(false);
    aerore::PeImage again = aerore::PeImage::parse(rebuilt);
    bool found = false;
    for (const auto& im : again.imports())
        if (im.name == "GetProcAddress") found = true;
    CHECK(found);
}

void test_unpack() {
    std::vector<aerore::u8> stub = {0xE9, 0xFB, 0x0F, 0x00, 0x00};
    std::vector<aerore::u8> real = {0x48, 0x31, 0xC0, 0xC3};
    auto file = build_pe(".vmp0", stub, 0x60000020, ".text", real, 0x60000020, 0x1000, {});
    aerore::Session session;
    session.load_bytes(file, "packed.exe", false);
    auto dets = session.unpackers().detect_all(*session.image());
    int vmp = 0;
    for (auto& d : dets)
        if (d.first == "vmprotect") vmp = d.second;
    CHECK(vmp >= 60);
    auto r = session.unpack_best();
    CHECK(r.ok);
    CHECK(r.oep_rva == 0x2000);
    auto m = session.model();
    CHECK(m->entry == 0x140002000ull);
    CHECK(session.last_post_unpack().ran);
    CHECK(session.last_post_unpack().eligible);
    CHECK(!session.last_post_unpack().assessment.virtualized);
}

#ifdef AERORE_HAS_LZMA
void test_static_vmprotect_lzma() {
    std::vector<aerore::u8> stub = {0xE9, 0xFB, 0xEF, 0xFF, 0xFF};
    auto file = build_pe(".text", {}, 0x60000020, ".vmp0", stub, 0x60000020, 0x2000, {});
    auto w32 = [&](size_t offset, uint32_t value) {
        for (int i = 0; i < 4; ++i) file[offset + i] = static_cast<aerore::u8>(value >> (8 * i));
    };
    // The original .text is virtual-only. The VM section holds stock LZMA
    // properties, one raw block, and a legacy {Src,Dst} PACKER_INFO entry.
    w32(0x188 + 16, 0);
    w32(0x188 + 20, 0);
    const aerore::u8 properties[] = {0x5d, 0x00, 0x00, 0x00, 0x04};
    std::memcpy(file.data() + 0x620, properties, sizeof(properties));
    const aerore::u8 compressed[] = {0x00, 0x24, 0x0c, 0x54, 0x0c, 0x38, 0x7d,
                                     0xff, 0xff, 0xff, 0xfc, 0x20, 0x00, 0x00};
    std::memcpy(file.data() + 0x640, compressed, sizeof(compressed));
    w32(0x678, 0x2020);
    w32(0x680, 0x2040);
    w32(0x684, 0x1000);

    aerore::Session session;
    session.load_bytes(file, "static-vmp.exe", false);
    auto result = session.unpack_best();
    CHECK(result.ok);
    CHECK(result.static_unpack);
    CHECK(result.decompressed_blocks == 1);
    CHECK(result.oep_rva == 0x1000);
    const auto bytes = session.read_va(0x140001000ull, 4);
    CHECK(bytes == std::vector<aerore::u8>({0x48, 0x31, 0xC0, 0xC3}));
}
#endif

void test_export_rebuild_and_json() {
    std::vector<aerore::u8> text = {0x48, 0x31, 0xC0, 0xC3};
    auto file = build_pe(".text", text, 0x60000020, ".rdata", {'A', 0}, 0x40000040, 0x1000, {});
    aerore::PeImage image = aerore::PeImage::parse(file);
    aerore::ExportSym symbol;
    symbol.name = "AeroEntry";
    symbol.ordinal = 7;
    symbol.rva = 0x1000;
    symbol.va = image.image_base() + symbol.rva;
    auto report = aerore::fix_exports(image, {symbol}, "sample.dll", true);
    CHECK(report.patched);
    auto rebuilt = image.rebuild(false);
    aerore::PeImage parsed = aerore::PeImage::parse(rebuilt);
    CHECK(parsed.exports().size() == 1);
    if (!parsed.exports().empty()) {
        CHECK(parsed.exports()[0].name == "AeroEntry");
        CHECK(parsed.exports()[0].ordinal == 7);
        CHECK(parsed.exports()[0].rva == 0x1000);
    }

    aerore::Session session;
    session.load_bytes(file, "sample.dll", false);
    auto session_report = session.fix_exports({symbol}, true);
    CHECK(session_report.patched);
    std::string json = session.symbols_json();
    CHECK(json.find("aerore.symbols.v1") != std::string::npos);
    CHECK(json.find("AeroEntry") != std::string::npos);
    CHECK(json.find("\"imports\"") != std::string::npos);
    CHECK(json.find("\"exports\"") != std::string::npos);
}

void test_repair_gate_blocks_virtualized_dump() {
    auto file = build_pe(".vmp0", {0xC3}, 0xE0000060, ".rdata", {0}, 0x40000040, 0x1000, {});
    aerore::PeImage image = aerore::PeImage::parse(file);
    aerore::Decoder decoder(image.arch());
    auto assessment = aerore::assess_dump(image, decoder);
    CHECK(assessment.virtualized);

    std::vector<aerore::u8> jump = {0xE9, 0xFB, 0x0F, 0x00, 0x00};
    auto still_virtualized = build_pe(".vmp0", jump, 0x60000020, ".vmp1", {0xC3}, 0x60000020, 0x1000, {});
    aerore::Session session;
    session.load_bytes(still_virtualized, "still-vm.exe", false);
    auto unpacked = session.unpack_best();
    CHECK(unpacked.ok);
    CHECK(session.last_post_unpack().ran);
    CHECK(!session.last_post_unpack().eligible);
    CHECK(session.last_post_unpack().assessment.virtualized);
    CHECK(session.last_post_unpack().iat.message.find("skipped") != std::string::npos);
    CHECK(session.last_post_unpack().exports.skipped);
}

void test_mcp() {
    aerore::Session session;
    aerore::McpServer mcp(session);
    std::string init = mcp.handle(R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})");
    CHECK(init.find("aerore") != std::string::npos);
    CHECK(init.find("2025-11-25") != std::string::npos);
    CHECK(init.find("\"id\":1") != std::string::npos);
    std::string tools = mcp.handle(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
    CHECK(tools.find("fix_iat") != std::string::npos);
    CHECK(tools.find("disassemble") != std::string::npos);
    std::vector<aerore::u8> text = {0xC3};
    auto file = build_pe(".text", text, 0x60000020, ".rdata", {'A', 'B', 'C', 'D', 0}, 0x40000040, 0x1000, {});
    const char* path = "aerore-mcp.exe";
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    out.close();
    std::string call = mcp.handle(
        std::string(R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"load_file","arguments":{"path":")") +
        path + R"(","auto_unpack":false}}})");
    CHECK(call.find("functions") != std::string::npos);
    std::string fns = mcp.handle(R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_functions","arguments":{}}})");
    CHECK(fns.find("sub_") != std::string::npos || fns.find("140001000") != std::string::npos);
    std::remove(path);
}

void test_themida_detect() {
    auto file = build_pe(".themida", {0xC3}, 0x60000020, ".text", {0xC3}, 0x60000020, 0x1000, {});
    aerore::PeImage image = aerore::PeImage::parse(file);
    aerore::UnpackerRegistry reg;
    int score = 0;
    for (auto& d : reg.detect_all(image))
        if (d.first == "themida") score = d.second;
    CHECK(score >= 70);
}

void test_anti_debug_defaults() {
    aerore::AntiAntiDebug guard;
    const auto& options = guard.options();
    CHECK(options.enabled);
    CHECK(options.patch_peb);
    CHECK(options.patch_heap);
    CHECK(options.hook_debug_apis);
    CHECK(options.block_thread_hide_calls);
    CHECK(!options.hide_new_threads);
    CHECK(!options.sanitize_debug_registers);
}

}  // namespace

int main() {
    test_decode();
    test_analysis_and_db();
    test_iat();
    test_unpack();
#ifdef AERORE_HAS_LZMA
    test_static_vmprotect_lzma();
#endif
    test_export_rebuild_and_json();
    test_repair_gate_blocks_virtualized_dump();
    test_mcp();
    test_themida_detect();
    test_anti_debug_defaults();
    if (g_fails) {
        std::cerr << g_fails << " checks failed\n";
        return 1;
    }
    std::cout << "all tests passed\n";
    return 0;
}
