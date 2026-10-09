#pragma once

#include "aerore/session.hpp"

namespace aerore {

// Dear ImGui front-end (Win32 + DX11). Returns 0 on normal close.
// Non-Windows builds return 1 and print a one-line reason.
int run_gui(Session& session, const std::string& initial_path);

}  // namespace aerore
