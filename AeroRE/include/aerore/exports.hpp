#pragma once

#include "aerore/pe.hpp"

namespace aerore {

// Validate or rebuild IMAGE_EXPORT_DIRECTORY from symbols preserved before
// unpacking. Existing valid directories are left untouched.
ExportFixReport fix_exports(PeImage& image, const std::vector<ExportSym>& candidates,
                            const std::string& module_name, bool patch);

}  // namespace aerore
