#pragma once

#include "aerore/decoder.hpp"
#include "aerore/pe.hpp"

namespace aerore {

struct TraceResult {
    u64 oep_va = 0;
    bool found_oep = false;
    int steps = 0;
    std::string log;
    std::vector<std::string> lifted;
};

// Concrete interpreter for straight-line packer stubs and a bounded VMProtect
// handler trace. `vm_lo`/`vm_hi` are the VA range of the protector section.
// Execution that lands in a different executable section is reported as OEP.
TraceResult trace_region(const PeImage& image, Decoder& decoder, u64 start_va, u64 vm_lo, u64 vm_hi, int step_cap);

}  // namespace aerore
