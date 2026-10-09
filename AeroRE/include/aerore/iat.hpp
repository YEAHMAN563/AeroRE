#pragma once

#include "aerore/decoder.hpp"
#include "aerore/pe.hpp"

namespace aerore {

std::vector<ModuleSpan> modules_from_json(const std::string& json_text);

// Scan pointer-sized slots, follow short trampolines (jmp/call/mov+jmp/push+ret),
// resolve against module export snapshots, then optionally rebuild a PE import
// directory and retarget rip-relative slots at the new IAT.
IatReport fix_iat(PeImage& image, Decoder& decoder, const std::vector<ModuleSpan>& modules, bool patch);

}  // namespace aerore
