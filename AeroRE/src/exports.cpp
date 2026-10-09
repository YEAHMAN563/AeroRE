#include "aerore/exports.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>

namespace aerore {
namespace {

void put_u16(std::vector<u8>& out, size_t off, u16 value) {
    if (off + 2 <= out.size()) std::memcpy(out.data() + off, &value, 2);
}

void put_u32(std::vector<u8>& out, size_t off, u32 value) {
    if (off + 4 <= out.size()) std::memcpy(out.data() + off, &value, 4);
}

void put_u32(u8* out, size_t off, u32 value) { std::memcpy(out + off, &value, 4); }

std::string image_name(const std::string& path) {
    if (path.empty()) return "image.dll";
    std::filesystem::path p(path);
    std::string name = p.filename().string();
    return name.empty() ? "image.dll" : name;
}

bool same_exports(const std::vector<ExportSym>& current, const std::vector<ExportSym>& wanted) {
    if (current.size() != wanted.size()) return false;
    for (const auto& w : wanted) {
        bool found = false;
        for (const auto& c : current) {
            if (c.ordinal == w.ordinal && c.name == w.name && c.rva == w.rva) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

}  // namespace

ExportFixReport fix_exports(PeImage& image, const std::vector<ExportSym>& candidates,
                            const std::string& module_name, bool patch) {
    ExportFixReport report;
    std::map<u16, ExportSym> by_ordinal;
    for (auto ex : candidates) {
        if (!ex.rva && ex.va >= image.image_base()) ex.rva = ex.va - image.image_base();
        if (!ex.va && ex.rva) ex.va = image.image_base() + ex.rva;
        if (!ex.rva || !image.contains_rva(ex.rva)) continue;
        by_ordinal.emplace(ex.ordinal, std::move(ex));
    }
    for (const auto& kv : by_ordinal) report.entries.push_back(kv.second);

    if (report.entries.empty()) {
        report.message = "no recoverable exports were preserved";
        return report;
    }
    if (same_exports(image.exports(), report.entries)) {
        report.message = "existing export directory is already valid";
        return report;
    }
    if (!patch) {
        report.message = "validated " + std::to_string(report.entries.size()) + " recoverable exports (report only)";
        return report;
    }

    const u32 ordinal_base = report.entries.front().ordinal;
    const u32 ordinal_last = report.entries.back().ordinal;
    const u64 function_count64 = static_cast<u64>(ordinal_last) - ordinal_base + 1;
    if (function_count64 > 65536) {
        report.skipped = true;
        report.message = "export ordinal span is too large to rebuild safely";
        return report;
    }
    const u32 function_count = static_cast<u32>(function_count64);

    std::vector<const ExportSym*> named;
    for (const auto& ex : report.entries)
        if (!ex.name.empty()) named.push_back(&ex);
    std::sort(named.begin(), named.end(), [](const ExportSym* a, const ExportSym* b) {
        if (a->name != b->name) return a->name < b->name;
        return a->ordinal < b->ordinal;
    });

    constexpr size_t kDirectorySize = 40;
    const size_t eat_off = kDirectorySize;
    const size_t names_off = eat_off + static_cast<size_t>(function_count) * 4;
    const size_t ordinals_off = names_off + named.size() * 4;
    size_t strings_off = ordinals_off + named.size() * 2;
    std::vector<u8> section(strings_off, 0);

    std::string dll = image_name(module_name);
    const u32 dll_rel = static_cast<u32>(section.size());
    section.insert(section.end(), dll.begin(), dll.end());
    section.push_back(0);

    std::vector<u32> name_rel;
    for (const ExportSym* ex : named) {
        name_rel.push_back(static_cast<u32>(section.size()));
        section.insert(section.end(), ex->name.begin(), ex->name.end());
        section.push_back(0);
    }

    for (const auto& ex : report.entries)
        put_u32(section, eat_off + static_cast<size_t>(ex.ordinal - ordinal_base) * 4,
                static_cast<u32>(ex.rva));
    for (size_t i = 0; i < named.size(); ++i)
        put_u16(section, ordinals_off + i * 2, static_cast<u16>(named[i]->ordinal - ordinal_base));

    constexpr u32 kInitialized = 0x00000040;
    constexpr u32 kRead = 0x40000000;
    u64 section_rva = image.add_section(".aeroexp", kInitialized | kRead, section);
    if (!section_rva) {
        report.skipped = true;
        report.message = "exports validated but the PE header has no room for a new section";
        return report;
    }
    u8* base = image.ptr_rva(section_rva, section.size());
    if (!base) {
        report.skipped = true;
        report.message = "export section was added but is not mapped";
        return report;
    }

    put_u32(base, 12, static_cast<u32>(section_rva + dll_rel));
    put_u32(base, 16, ordinal_base);
    put_u32(base, 20, function_count);
    put_u32(base, 24, static_cast<u32>(named.size()));
    put_u32(base, 28, static_cast<u32>(section_rva + eat_off));
    put_u32(base, 32, static_cast<u32>(section_rva + names_off));
    put_u32(base, 36, static_cast<u32>(section_rva + ordinals_off));
    for (size_t i = 0; i < name_rel.size(); ++i)
        put_u32(base, names_off + i * 4, static_cast<u32>(section_rva + name_rel[i]));

    image.set_data_directory(0, static_cast<u32>(section_rva), static_cast<u32>(section.size()));
    report.patched = true;
    report.message = "rebuilt export directory for " + std::to_string(report.entries.size()) +
                     " symbols into .aeroexp";
    return report;
}

}  // namespace aerore
