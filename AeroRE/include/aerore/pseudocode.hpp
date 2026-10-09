#pragma once

#include "aerore/model.hpp"

namespace aerore {

struct PseudoLine {
    u64 va = 0;
    int indent = 0;
    bool label = false;
    std::string text;
};

// A deterministic, intentionally conservative high-level preview. It renders
// recovered CFG structure and calls without inventing data-flow semantics; a
// future micro-IR decompiler can replace this API without changing the UI.
std::vector<PseudoLine> build_pseudocode(const ProgramModel& model, const Function& function);

}  // namespace aerore
