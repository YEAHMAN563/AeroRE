#include "aerore/model.hpp"

#include <algorithm>

namespace aerore {

void ProgramModel::reindex() {
    insn_vas.clear();
    insn_vas.reserve(insns.size());
    for (auto& kv : insns) insn_vas.push_back(kv.first);
    std::sort(insn_vas.begin(), insn_vas.end());

    xref_to.clear();
    xref_from.clear();
    for (size_t i = 0; i < xrefs.size(); ++i) {
        xref_to[xrefs[i].dst].push_back(i);
        xref_from[xrefs[i].src].push_back(i);
    }
    std::sort(functions.begin(), functions.end(),
              [](const Function& a, const Function& b) { return a.start < b.start; });
    for (const auto& f : functions)
        if (!f.name.empty()) names[f.start] = f.name;

    string_at.clear();
    for (size_t i = 0; i < strings.size(); ++i) string_at[strings[i].va] = i;
}

const Function* ProgramModel::function_containing(u64 va) const {
    auto it = std::upper_bound(functions.begin(), functions.end(), va,
                               [](u64 v, const Function& f) { return v < f.start; });
    if (it == functions.begin()) return nullptr;
    --it;
    if (va >= it->start && va < it->end) return &(*it);
    return nullptr;
}

const Function* ProgramModel::function_by_start(u64 va) const {
    auto it = std::lower_bound(functions.begin(), functions.end(), va,
                               [](const Function& f, u64 v) { return f.start < v; });
    if (it != functions.end() && it->start == va) return &(*it);
    return nullptr;
}

std::string ProgramModel::name_of(u64 va) const {
    auto it = names.find(va);
    if (it != names.end()) return it->second;
    return hex(va);
}

std::vector<Xref> ProgramModel::xrefs_to(u64 va) const {
    std::vector<Xref> out;
    auto it = xref_to.find(va);
    if (it == xref_to.end()) return out;
    for (size_t i : it->second) out.push_back(xrefs[i]);
    return out;
}

std::vector<Xref> ProgramModel::xrefs_from(u64 va) const {
    std::vector<Xref> out;
    auto it = xref_from.find(va);
    if (it == xref_from.end()) return out;
    for (size_t i : it->second) out.push_back(xrefs[i]);
    return out;
}

}  // namespace aerore
