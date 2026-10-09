#pragma once

#include "aerore/types.hpp"

#include <optional>
#include <utility>

namespace aerore {

struct ResourceNode {
    std::string name;
    u32 id = 0;
    bool named = false;
    bool leaf = false;
    u64 data_rva = 0;
    u32 data_size = 0;
    std::vector<ResourceNode> children;
};

struct RelocEntry {
    u64 rva = 0;
    u8 type = 0;
};

struct RichEntry {
    u16 prod_id = 0;
    u16 build = 0;
    u32 count = 0;
};

class PeImage {
public:
    static PeImage parse(std::vector<u8> file);

    bool is64() const { return is64_; }
    Arch arch() const { return is64_ ? Arch::X64 : Arch::X86; }
    u64 image_base() const { return image_base_; }
    u64 entry_rva() const { return entry_rva_; }
    u64 entry_va() const { return image_base_ + entry_rva_; }
    u32 size_of_image() const { return size_of_image_; }
    u32 section_align() const { return section_align_; }
    u32 file_align() const { return file_align_; }
    u32 size_of_headers() const { return size_of_headers_; }
    u16 subsystem() const { return subsystem_; }
    u16 machine() const { return machine_; }
    const std::string& path_hint() const { return path_hint_; }
    void set_path_hint(std::string p) { path_hint_ = std::move(p); }

    const std::vector<SectionInfo>& sections() const { return sections_; }
    const std::vector<ImportSym>& imports() const { return imports_; }
    const std::vector<ExportSym>& exports() const { return exports_; }
    const std::vector<u64>& tls_callbacks() const { return tls_; }
    const std::vector<RelocEntry>& relocs() const { return relocs_; }
    const std::vector<RichEntry>& rich() const { return rich_; }
    const std::vector<ResourceNode>& resources() const { return resources_; }
    std::vector<u8> overlay() const { return overlay_; }
    const std::vector<u8>& mapped() const { return mapped_; }
    const std::vector<u8>& file_bytes() const { return file_; }

    std::pair<u32, u32> data_directory(int index) const;

    bool executable_rva(u64 rva) const;
    bool contains_rva(u64 rva) const { return rva < mapped_.size(); }
    bool contains_va(u64 va) const;
    u64 va_to_rva(u64 va) const { return va - image_base_; }

    size_t avail_rva(u64 rva) const;
    bool read_rva(u64 rva, void* dst, size_t n) const;
    std::optional<u64> read_ptr_rva(u64 rva) const;
    std::string read_cstr(u64 rva, size_t cap = 512) const;
    u8* ptr_rva(u64 rva, size_t n);
    const u8* ptr_rva(u64 rva, size_t n) const;

    void set_entry_rva(u64 rva);
    void set_data_directory(int index, u32 rva, u32 size);
    // Append a section. Returns its RVA, or 0 on failure (no header slack).
    u64 add_section(const std::string& name, u32 chars, const std::vector<u8>& data);
    std::vector<u8> rebuild(bool virtual_dump) const;

    std::string describe() const;

private:
    void parse_directories();
    void parse_imports();
    void parse_exports();
    void parse_relocs();
    void parse_tls();
    void parse_resources();
    void parse_rich();
    u32 dd_offset() const;
    u32 opt_offset() const;

    std::vector<u8> file_;
    std::vector<u8> mapped_;
    std::vector<u8> overlay_;
    std::vector<SectionInfo> sections_;
    std::vector<ImportSym> imports_;
    std::vector<ExportSym> exports_;
    std::vector<u64> tls_;
    std::vector<RelocEntry> relocs_;
    std::vector<RichEntry> rich_;
    std::vector<ResourceNode> resources_;
    std::string path_hint_;

    bool is64_ = true;
    u16 machine_ = 0;
    u64 image_base_ = 0;
    u64 entry_rva_ = 0;
    u32 size_of_image_ = 0;
    u32 size_of_headers_ = 0;
    u32 section_align_ = 0x1000;
    u32 file_align_ = 0x200;
    u16 subsystem_ = 0;
    u16 number_of_sections_ = 0;
    u16 size_of_optional_ = 0;
    u32 e_lfanew_ = 0;
    int num_dd_ = 16;
};

double entropy_bytes(const u8* p, size_t n);

}  // namespace aerore
