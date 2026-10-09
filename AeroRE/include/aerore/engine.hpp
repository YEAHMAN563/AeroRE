#pragma once

#include "aerore/decoder.hpp"
#include "aerore/model.hpp"
#include "aerore/pe.hpp"

namespace aerore {

struct AnalysisStats {
    unsigned threads = 1;
    size_t insn_count = 0;
    size_t function_count = 0;
    size_t xref_count = 0;
    size_t conflicts_dropped = 0;
};

// Hybrid pipeline:
//   1. parallel linear sweep, one or more chunks per executable section
//   2. single-threaded deterministic merge (overlap fixup)
//   3. function seeds: entry, exports, TLS, call targets, prologue-after-gap
//   4. parallel recursive descent, one job per function (read-only insn map)
//   5. single-threaded range clip + sorted xref merge
//   6. string scan and data/code cross references
AnalysisStats analyze(const PeImage& image, Decoder& decoder, ProgramModel& out, ProgressQueue& progress);

}  // namespace aerore
