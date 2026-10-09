#include "aerore/pseudocode.hpp"

#include <cstring>
#include <set>

namespace aerore {
namespace {

std::string location(u64 va) { return "loc_" + hex(va).substr(2); }

std::string condition_name(const Insn& instruction) {
    std::string mnemonic = instruction.mnemonic;
    if (mnemonic.size() > 1 && mnemonic[0] == 'j') return mnemonic.substr(1);
    return "condition";
}

}  // namespace

std::vector<PseudoLine> build_pseudocode(const ProgramModel& model, const Function& function) {
    std::vector<PseudoLine> output;
    output.push_back({function.start, 0, false, "void " + function.name + "() {"});

    std::set<u64> labels;
    for (const auto& block : function.blocks) {
        labels.insert(block.start);
        for (const auto& edge : block.succs) labels.insert(edge.target);
    }

    for (u64 va : model.insn_vas) {
        if (va < function.start || va >= function.end) continue;
        auto found = model.insns.find(va);
        if (found == model.insns.end()) continue;
        const Insn& instruction = found->second;
        if (labels.count(va)) output.push_back({va, 1, true, location(va) + ":"});

        std::string line;
        if (instruction.flow == Flow::Call) {
            line = instruction.target_valid ? model.name_of(instruction.target) + "();"
                                            : "call_indirect();";
        } else if (instruction.flow == Flow::Jcc && instruction.target_valid) {
            line = "if (" + condition_name(instruction) + ") goto " + location(instruction.target) + ";";
        } else if (instruction.flow == Flow::Jmp) {
            line = instruction.target_valid ? "goto " + location(instruction.target) + ";"
                                            : "goto dispatch_target;";
        } else if (instruction.flow == Flow::Ret) {
            line = "return;";
        } else if (std::strcmp(instruction.mnemonic, "nop") != 0 &&
                   std::strcmp(instruction.mnemonic, "int3") != 0) {
            line = std::string("/* ") + instruction.text + " */";
        }
        if (!line.empty()) output.push_back({va, 2, false, std::move(line)});
    }
    output.push_back({function.end, 0, false, "}"});
    return output;
}

}  // namespace aerore
