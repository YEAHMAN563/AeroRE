#pragma once

#include "aerore/types.hpp"

#include <unordered_map>

namespace aerore {

// Published snapshot. Analysis builds one privately, then Session swaps it in.
// Readers (UI, MCP) hold a shared_ptr and never block the worker threads.
class ProgramModel {
public:
    std::vector<Function> functions;
    std::unordered_map<u64, Insn> insns;
    std::vector<u64> insn_vas;
    std::vector<Xref> xrefs;
    std::unordered_map<u64, std::vector<size_t>> xref_to;
    std::unordered_map<u64, std::vector<size_t>> xref_from;
    std::unordered_map<u64, std::string> names;
    std::unordered_map<u64, std::string> comments;
    std::unordered_map<u64, std::string> type_at;
    std::vector<StringHit> strings;
    std::unordered_map<u64, size_t> string_at;
    std::vector<StructType> structs;
    std::vector<ImportSym> imports;
    std::vector<ExportSym> exports;
    std::vector<SectionInfo> sections;
    std::vector<u64> tls_callbacks;
    std::string rich;
    std::string unpack_log;
    std::string image_path;
    u64 image_base = 0;
    u64 entry = 0;
    u64 overlay_size = 0;
    Arch arch = Arch::X64;
    bool is64 = true;

    void reindex();
    const Function* function_containing(u64 va) const;
    const Function* function_by_start(u64 va) const;
    std::string name_of(u64 va) const;
    std::vector<Xref> xrefs_to(u64 va) const;
    std::vector<Xref> xrefs_from(u64 va) const;
};

}  // namespace aerore
