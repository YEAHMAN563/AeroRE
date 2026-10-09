#include "aerore/ui.hpp"

#include "aerore/mcp.hpp"
#include "aerore/pseudocode.hpp"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <sstream>
#include <stdexcept>

#if defined(_WIN32) && defined(AERORE_HAS_IMGUI)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <tchar.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace {

ID3D11Device* g_dev = nullptr;
ID3D11DeviceContext* g_ctx = nullptr;
IDXGISwapChain* g_swap = nullptr;
ID3D11RenderTargetView* g_rtv = nullptr;
HWND g_hwnd = nullptr;

struct UiState {
    aerore::u64 cursor = 0;
    std::string status = "Ready";
    std::deque<std::string> console;
    char function_filter[128]{};
    int attach_pid = 0;
    bool attach_popup = false;
    bool show_functions = true;
    bool show_disassembly = true;
    bool show_pseudocode = true;
    bool show_hex = true;
    bool show_graph = true;
    bool show_xrefs = true;
    bool show_symbols = true;
    bool show_strings = true;
    bool show_registers = true;
    bool show_stack = true;
    bool show_console = true;
};

void log_line(UiState& ui, std::string line) {
    if (line.empty()) return;
    ui.console.push_back(std::move(line));
    while (ui.console.size() > 1500) ui.console.pop_front();
}

void create_rtv() {
    ID3D11Texture2D* back = nullptr;
    g_swap->GetBuffer(0, IID_PPV_ARGS(&back));
    g_dev->CreateRenderTargetView(back, nullptr, &g_rtv);
    back->Release();
}

void cleanup_rtv() {
    if (g_rtv) {
        g_rtv->Release();
        g_rtv = nullptr;
    }
}

LRESULT CALLBACK wnd_proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (ImGui_ImplWin32_WndProcHandler(h, msg, w, l)) return true;
    if (msg == WM_SIZE && g_dev && w != SIZE_MINIMIZED) {
        cleanup_rtv();
        g_swap->ResizeBuffers(0, LOWORD(l), HIWORD(l), DXGI_FORMAT_UNKNOWN, 0);
        create_rtv();
        return 0;
    }
    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

std::string open_file_dialog(const char* title, const char* filter) {
    char path[MAX_PATH]{};
    OPENFILENAMEA dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = g_hwnd;
    dialog.lpstrTitle = title;
    dialog.lpstrFilter = filter;
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    return GetOpenFileNameA(&dialog) ? path : std::string{};
}

std::string save_file_dialog(const char* title, const char* filter, const char* initial, const char* extension) {
    char path[MAX_PATH]{};
    std::snprintf(path, sizeof(path), "%s", initial);
    OPENFILENAMEA dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = g_hwnd;
    dialog.lpstrTitle = title;
    dialog.lpstrFilter = filter;
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrDefExt = extension;
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    return GetSaveFileNameA(&dialog) ? path : std::string{};
}

template <typename Fn>
void guarded(UiState& ui, const char* action, Fn&& fn) {
    try {
        fn();
        log_line(ui, std::string(action) + ": " + ui.status);
    } catch (const std::exception& ex) {
        ui.status = ex.what();
        log_line(ui, std::string(action) + " failed: " + ex.what());
    }
}

std::string instruction_bytes(const aerore::Insn& instruction) {
    std::string out;
    char byte[4]{};
    for (aerore::u8 i = 0; i < instruction.len; ++i) {
        std::snprintf(byte, sizeof(byte), "%02X", instruction.raw[i]);
        if (!out.empty()) out.push_back(' ');
        out += byte;
    }
    return out;
}

void open_image(aerore::Session& session, UiState& ui) {
    std::string path = open_file_dialog("Open PE image", "PE files\0*.exe;*.dll;*.sys;*.scr\0All files\0*.*\0");
    if (path.empty()) return;
    guarded(ui, "load", [&] {
        session.load_file(path, true);
        ui.cursor = session.model()->entry;
        ui.status = "Loaded and analyzed " + path;
    });
}

void save_project(aerore::Session& session, UiState& ui) {
    std::string path = save_file_dialog("Save AeroRE project", "AeroRE databases\0*.idb\0All files\0*.*\0",
                                        "aerore.idb", "idb");
    if (path.empty()) return;
    guarded(ui, "save", [&] {
        session.save_db(path);
        ui.status = "Saved " + path;
    });
}

void draw_menu(aerore::Session& session, aerore::McpTcpServer& mcp, UiState& ui, bool& open) {
    if (!ImGui::BeginMainMenuBar()) return;
    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open PE...", "Ctrl+O")) {
            open_image(session, ui);
        }
        if (ImGui::MenuItem("Save project database...", "Ctrl+S", false, session.image() != nullptr)) {
            save_project(session, ui);
        }
        if (ImGui::MenuItem("Export imports + exports JSON...", nullptr, false, session.image() != nullptr)) {
            std::string path = save_file_dialog("Export symbols", "JSON files\0*.json\0All files\0*.*\0",
                                                "aerore-symbols.json", "json");
            if (!path.empty()) guarded(ui, "export", [&] {
                session.export_symbols_json(path);
                ui.status = "Exported symbols to " + path;
            });
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4")) open = false;
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Analysis")) {
        if (ImGui::MenuItem("Run unpacker", nullptr, false, session.image() != nullptr)) {
            guarded(ui, "unpack", [&] {
                auto result = session.unpack_best();
                ui.status = result.ok ? "Unpack completed" : result.log;
            });
        }
        if (ImGui::MenuItem("Fix IAT from attached process", nullptr, false, session.image() != nullptr)) {
            guarded(ui, "IAT", [&] { ui.status = session.fix_iat({}, true).message; });
        }
        if (ImGui::MenuItem("Validate / fix exports", nullptr, false, session.image() != nullptr)) {
            guarded(ui, "exports", [&] { ui.status = session.fix_exports({}, true).message; });
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Debug")) {
        const bool debugging = session.debugger().alive();
        const bool paused = session.debugger().paused();
        if (ImGui::MenuItem("Start process...")) {
            std::string path = open_file_dialog("Start process under AeroRE", "Executables\0*.exe\0All files\0*.*\0");
            if (!path.empty()) guarded(ui, "debug create", [&] {
                if (!session.debugger().create(path, "")) throw std::runtime_error(session.debugger().last_error());
                ui.status = "Process created and paused at system breakpoint";
            });
        }
        if (ImGui::MenuItem("Attach to PID...")) ui.attach_popup = true;
        ImGui::Separator();
        if (ImGui::MenuItem("Pause", "F12", false, debugging && !paused)) session.debugger().pause();
        if (ImGui::MenuItem("Resume", "F9", false, paused)) session.debugger().resume();
        if (ImGui::MenuItem("Step into", "F7", false, paused)) session.debugger().step_into();
        if (ImGui::MenuItem("Step over", "F8", false, paused)) session.debugger().step_over();
        if (ImGui::MenuItem("Step out", "Ctrl+F9", false, paused)) session.debugger().step_out();
        if (ImGui::MenuItem("Run to cursor", "F4", false, paused))
            session.debugger().run_to(ui.cursor);
        if (ImGui::MenuItem("Software breakpoint", "F2", false, paused))
            session.debugger().add_bp(ui.cursor, aerore::BpType::Software);

        if (ImGui::BeginMenu("Anti-anti-debug settings")) {
            aerore::AntiAntiDebugOptions options = session.debugger().anti_debug_options();
            bool changed = false;
            changed |= ImGui::MenuItem("Enable concealment", nullptr, &options.enabled);
            changed |= ImGui::MenuItem("Patch PEB flags", nullptr, &options.patch_peb);
            changed |= ImGui::MenuItem("Normalize process heap", nullptr, &options.patch_heap);
            changed |= ImGui::MenuItem("Hook debugger APIs", nullptr, &options.hook_debug_apis);
            changed |= ImGui::MenuItem("Hide kernel-debug query", nullptr, &options.hook_nt_query_system);
            changed |= ImGui::MenuItem("Block target thread-hide calls", nullptr, &options.block_thread_hide_calls);
            ImGui::Separator();
            changed |= ImGui::MenuItem("Hide new threads (advanced)", nullptr, &options.hide_new_threads);
            changed |= ImGui::MenuItem("Clear DR0-DR7 while running (disables HW BP hits)", nullptr,
                                       &options.sanitize_debug_registers);
            changed |= ImGui::MenuItem("Neutralize OutputDebugString", nullptr,
                                       &options.neutralize_output_debug_string);
            changed |= ImGui::MenuItem("Neutralize invalid CloseHandle", nullptr,
                                       &options.neutralize_invalid_handle);
            changed |= ImGui::MenuItem("Restore patches on detach", nullptr, &options.restore_on_detach);
            if (changed) session.debugger().set_anti_debug_options(options);
            ImGui::Separator();
            if (ImGui::MenuItem("Save as aerore-hide.ini")) {
                session.debugger().save_anti_debug_config("aerore-hide.ini");
                ui.status = "Saved aerore-hide.ini";
            }
            ImGui::EndMenu();
        }
        if (ImGui::MenuItem("Detach", nullptr, false, debugging)) session.debugger().detach();
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("Functions", nullptr, &ui.show_functions);
        ImGui::MenuItem("Disassembly", nullptr, &ui.show_disassembly);
        ImGui::MenuItem("Pseudocode preview", nullptr, &ui.show_pseudocode);
        ImGui::MenuItem("Hex", nullptr, &ui.show_hex);
        ImGui::MenuItem("Graph", nullptr, &ui.show_graph);
        ImGui::MenuItem("Xrefs", nullptr, &ui.show_xrefs);
        ImGui::MenuItem("Imports / exports", nullptr, &ui.show_symbols);
        ImGui::MenuItem("Strings", nullptr, &ui.show_strings);
        ImGui::MenuItem("Registers", nullptr, &ui.show_registers);
        ImGui::MenuItem("Stack", nullptr, &ui.show_stack);
        ImGui::MenuItem("Console / MCP", nullptr, &ui.show_console);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Tools")) {
        if (ImGui::MenuItem("Copy MCP endpoint", nullptr, false, mcp.running())) {
            std::string endpoint = "127.0.0.1:" + std::to_string(mcp.port());
            ImGui::SetClipboardText(endpoint.c_str());
            ui.status = "Copied " + endpoint;
        }
        ImGui::EndMenu();
    }
    ImGui::SameLine(ImGui::GetWindowWidth() - 290.0f);
    const char* mode = !session.debugger().alive() ? "STATIC" : (session.debugger().paused() ? "DEBUG PAUSED" : "DEBUG RUNNING");
    ImGui::TextDisabled("%s | %s", mode,
                        mcp.status().c_str());
    ImGui::EndMainMenuBar();
}

void handle_shortcuts(aerore::Session& session, UiState& ui) {
    ImGuiIO& io = ImGui::GetIO();
    if (io.WantTextInput) return;
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O)) open_image(session, ui);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S) && session.image()) save_project(session, ui);
    if (!session.debugger().alive()) return;
    const bool paused = session.debugger().paused();
    if (ImGui::IsKeyPressed(ImGuiKey_F12) && !paused) session.debugger().pause();
    if (ImGui::IsKeyPressed(ImGuiKey_F9) && !io.KeyCtrl && paused) session.debugger().resume();
    if (ImGui::IsKeyPressed(ImGuiKey_F7) && paused) session.debugger().step_into();
    if (ImGui::IsKeyPressed(ImGuiKey_F8) && paused) session.debugger().step_over();
    if (ImGui::IsKeyPressed(ImGuiKey_F9) && io.KeyCtrl && paused) session.debugger().step_out();
    if (ImGui::IsKeyPressed(ImGuiKey_F4) && paused) session.debugger().run_to(ui.cursor);
    if (ImGui::IsKeyPressed(ImGuiKey_F2) && paused)
        session.debugger().add_bp(ui.cursor, aerore::BpType::Software);
}

void draw_attach_popup(aerore::Session& session, UiState& ui) {
    if (ui.attach_popup) {
        ImGui::OpenPopup("Attach to process");
        ui.attach_popup = false;
    }
    if (ImGui::BeginPopupModal("Attach to process", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Enter the decimal process ID.");
        ImGui::InputInt("PID", &ui.attach_pid);
        if (ImGui::Button("Attach", ImVec2(110, 0))) {
            if (ui.attach_pid > 0) guarded(ui, "attach", [&] {
                if (!session.debugger().attach(static_cast<aerore::u32>(ui.attach_pid)))
                    throw std::runtime_error(session.debugger().last_error());
                ui.status = "Attached and paused at system breakpoint";
            });
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(110, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void draw_functions(const std::shared_ptr<const aerore::ProgramModel>& model, UiState& ui) {
    if (!ui.show_functions) return;
    ImGui::SetNextWindowPos(ImVec2(0, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(280, 560), ImGuiCond_FirstUseEver);
    ImGui::Begin("Functions", &ui.show_functions);
    ImGui::InputTextWithHint("##function-filter", "Filter sub_...", ui.function_filter, sizeof(ui.function_filter));
    ImGui::Separator();
    if (model) {
        const std::string filter = aerore::to_lower_copy(ui.function_filter);
        for (const auto& function : model->functions) {
            if (!filter.empty() && aerore::to_lower_copy(function.name).find(filter) == std::string::npos) continue;
            std::string label = function.name + "  " + aerore::hex(function.start);
            if (ImGui::Selectable(label.c_str(), ui.cursor == function.start)) ui.cursor = function.start;
        }
    }
    ImGui::End();
}

void draw_disassembly(const std::shared_ptr<const aerore::ProgramModel>& model, UiState& ui) {
    if (!ui.show_disassembly) return;
    ImGui::SetNextWindowPos(ImVec2(285, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(720, 430), ImGuiCond_FirstUseEver);
    ImGui::Begin("Disassembly", &ui.show_disassembly);
    ImGui::TextDisabled("IDA-style listing  |  Space: graph  |  F2: breakpoint");
    if (model && ImGui::BeginTable("disassembly", 4,
                                   ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                       ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 115);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Comment", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        auto begin = std::lower_bound(model->insn_vas.begin(), model->insn_vas.end(), ui.cursor);
        if (begin == model->insn_vas.end() && !model->insn_vas.empty()) begin = model->insn_vas.begin();
        for (int row = 0; begin != model->insn_vas.end() && row < 500; ++begin, ++row) {
            auto found = model->insns.find(*begin);
            if (found == model->insns.end()) continue;
            const aerore::Insn& instruction = found->second;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            const bool selected = ui.cursor == instruction.va;
            if (ImGui::Selectable(aerore::hex(instruction.va).c_str(), selected,
                                  ImGuiSelectableFlags_SpanAllColumns))
                ui.cursor = instruction.va;
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%s", instruction_bytes(instruction).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(instruction.text);
            ImGui::TableSetColumnIndex(3);
            auto comment = model->comments.find(instruction.va);
            if (comment != model->comments.end()) ImGui::TextColored(ImVec4(0.55f, 0.78f, 0.62f, 1), "%s", comment->second.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

void draw_pseudocode(const std::shared_ptr<const aerore::ProgramModel>& model, UiState& ui) {
    if (!ui.show_pseudocode) return;
    ImGui::SetNextWindowPos(ImVec2(1010, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(520, 430), ImGuiCond_FirstUseEver);
    ImGui::Begin("Pseudocode Preview", &ui.show_pseudocode);
    ImGui::TextDisabled("Conservative CFG lifting; comments preserve unresolved assembly.");
    if (model) {
        const aerore::Function* function = model->function_containing(ui.cursor);
        if (!function) function = model->function_by_start(ui.cursor);
        if (function) {
            for (const auto& line : aerore::build_pseudocode(*model, *function)) {
                ImGui::Indent(line.indent * 14.0f);
                ImVec4 color = line.label ? ImVec4(0.50f, 0.72f, 0.95f, 1) : ImVec4(0.86f, 0.88f, 0.91f, 1);
                ImGui::PushStyleColor(ImGuiCol_Text, color);
                if (ImGui::Selectable(line.text.c_str(), ui.cursor == line.va && line.va != 0)) ui.cursor = line.va;
                ImGui::PopStyleColor();
                ImGui::Unindent(line.indent * 14.0f);
            }
        } else {
            ImGui::TextUnformatted("Select a recovered function.");
        }
    }
    ImGui::End();
}

void draw_hex(aerore::Session& session, UiState& ui) {
    if (!ui.show_hex) return;
    ImGui::SetNextWindowPos(ImVec2(285, 455), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(720, 235), ImGuiCond_FirstUseEver);
    ImGui::Begin("Hex View", &ui.show_hex);
    const aerore::u64 base = ui.cursor & ~0xFull;
    auto bytes = session.read_va(base, 512);
    for (size_t row = 0; row < bytes.size(); row += 16) {
        std::ostringstream line;
        line << aerore::hex(base + row) << "  ";
        std::string ascii;
        for (size_t column = 0; column < 16; ++column) {
            if (row + column < bytes.size()) {
                char value[4]{};
                std::snprintf(value, sizeof(value), "%02X ", bytes[row + column]);
                line << value;
                unsigned char c = bytes[row + column];
                ascii.push_back(c >= 32 && c < 127 ? static_cast<char>(c) : '.');
            } else {
                line << "   ";
                ascii.push_back(' ');
            }
        }
        line << " " << ascii;
        ImGui::TextUnformatted(line.str().c_str());
    }
    ImGui::End();
}

void draw_graph(const std::shared_ptr<const aerore::ProgramModel>& model, UiState& ui) {
    if (!ui.show_graph) return;
    ImGui::SetNextWindowPos(ImVec2(1010, 455), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(520, 300), ImGuiCond_FirstUseEver);
    ImGui::Begin("Control Flow Graph", &ui.show_graph);
    if (model) {
        const aerore::Function* function = model->function_containing(ui.cursor);
        if (function) {
            ImDrawList* draw = ImGui::GetWindowDrawList();
            ImVec2 origin = ImGui::GetCursorScreenPos();
            size_t index = 0;
            for (const auto& block : function->blocks) {
                const float column = static_cast<float>(index % 2);
                const float row = static_cast<float>(index / 2);
                ImVec2 p0(origin.x + column * 235.0f, origin.y + row * 64.0f);
                ImVec2 p1(p0.x + 215.0f, p0.y + 45.0f);
                draw->AddRectFilled(p0, p1, IM_COL32(31, 39, 52, 255), 4.0f);
                draw->AddRect(p0, p1, IM_COL32(86, 145, 205, 255), 4.0f);
                std::string label = aerore::hex(block.start) + "  -> " + std::to_string(block.succs.size());
                draw->AddText(ImVec2(p0.x + 8, p0.y + 12), IM_COL32(225, 230, 238, 255), label.c_str());
                ++index;
                if (index >= 20) break;
            }
            ImGui::Dummy(ImVec2(480, static_cast<float>((index + 1) / 2) * 64.0f));
        }
    }
    ImGui::End();
}

void draw_xrefs(const std::shared_ptr<const aerore::ProgramModel>& model, UiState& ui) {
    if (!ui.show_xrefs) return;
    ImGui::SetNextWindowSize(ImVec2(390, 230), ImGuiCond_FirstUseEver);
    ImGui::Begin("Cross references", &ui.show_xrefs);
    if (model) {
        ImGui::Text("References to %s", aerore::hex(ui.cursor).c_str());
        for (const auto& xref : model->xrefs_to(ui.cursor)) {
            std::string label = aerore::hex(xref.src) + "  " + aerore::xref_name(xref.kind);
            if (ImGui::Selectable(label.c_str())) ui.cursor = xref.src;
        }
        ImGui::Separator();
        ImGui::TextUnformatted("References from cursor");
        for (const auto& xref : model->xrefs_from(ui.cursor)) {
            std::string label = aerore::hex(xref.dst) + "  " + aerore::xref_name(xref.kind);
            if (ImGui::Selectable(label.c_str())) ui.cursor = xref.dst;
        }
    }
    ImGui::End();
}

void draw_symbols(aerore::Session& session, const std::shared_ptr<const aerore::ProgramModel>& model, UiState& ui) {
    if (!ui.show_symbols) return;
    ImGui::SetNextWindowSize(ImVec2(560, 300), ImGuiCond_FirstUseEver);
    ImGui::Begin("Imports / Exports", &ui.show_symbols);
    if (ImGui::Button("Export imports + exports JSON...")) {
        std::string path = save_file_dialog("Export symbols", "JSON files\0*.json\0All files\0*.*\0",
                                            "aerore-symbols.json", "json");
        if (!path.empty()) guarded(ui, "export", [&] {
            session.export_symbols_json(path);
            ui.status = "Exported symbols to " + path;
        });
    }
    if (model && ImGui::BeginTabBar("symbols-tabs")) {
        if (ImGui::BeginTabItem("Imports")) {
            for (const auto& symbol : model->imports)
                ImGui::Text("%s!%s  %s", symbol.dll.c_str(),
                            symbol.name.empty() ? ("#" + std::to_string(symbol.ordinal)).c_str() : symbol.name.c_str(),
                            aerore::hex(symbol.iat_va).c_str());
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Exports")) {
            for (const auto& symbol : model->exports) {
                std::string label = (symbol.name.empty() ? "#" + std::to_string(symbol.ordinal) : symbol.name) +
                                    "  " + aerore::hex(symbol.va);
                if (ImGui::Selectable(label.c_str())) ui.cursor = symbol.va;
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

void draw_strings(const std::shared_ptr<const aerore::ProgramModel>& model, UiState& ui) {
    if (!ui.show_strings) return;
    ImGui::SetNextWindowSize(ImVec2(520, 260), ImGuiCond_FirstUseEver);
    ImGui::Begin("Strings", &ui.show_strings);
    if (model) {
        for (const auto& string : model->strings) {
            std::string label = aerore::hex(string.va) + "  " + string.text;
            if (ImGui::Selectable(label.c_str())) ui.cursor = string.va;
        }
    }
    ImGui::End();
}

void draw_debug_state(aerore::Session& session, UiState& ui) {
    if (ui.show_registers) {
        ImGui::SetNextWindowSize(ImVec2(330, 320), ImGuiCond_FirstUseEver);
        ImGui::Begin("Registers", &ui.show_registers);
        aerore::RegState registers = session.debugger().regs();
        if (registers.valid) {
            static const char* names[] = {"RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
                                          "R8","R9","R10","R11","R12","R13","R14","R15"};
            for (int i = 0; i < 16; ++i) ImGui::Text("%-4s %s", names[i], aerore::hex(registers.gpr[i]).c_str());
            ImGui::Separator();
            ImGui::Text("RIP  %s", aerore::hex(registers.rip).c_str());
            ImGui::Text("RFLAGS %s", aerore::hex(registers.rflags).c_str());
        } else {
            ImGui::TextDisabled("No paused debuggee");
        }
        ImGui::End();
    }
    if (ui.show_stack) {
        ImGui::SetNextWindowSize(ImVec2(380, 280), ImGuiCond_FirstUseEver);
        ImGui::Begin("Stack", &ui.show_stack);
        aerore::RegState registers = session.debugger().regs();
        if (registers.valid) {
            auto stack = session.debugger().read_mem(registers.gpr[4], 256);
            const size_t width = sizeof(void*);
            for (size_t offset = 0; offset + width <= stack.size(); offset += width) {
                aerore::u64 value = 0;
                std::memcpy(&value, stack.data() + offset, width);
                ImGui::Text("%s  %s", aerore::hex(registers.gpr[4] + offset).c_str(), aerore::hex(value).c_str());
            }
        } else {
            ImGui::TextDisabled("No paused debuggee");
        }
        ImGui::End();
    }
}

void drain_runtime_events(aerore::Session& session, UiState& ui) {
    for (const auto& event : session.progress().drain()) {
        ui.status = event.stage + ": " + event.detail + " (" + std::to_string(event.percent) + "%)";
        log_line(ui, ui.status);
    }
    while (auto event = session.debugger().poll()) {
        std::string line = "debug/" + event->kind + " tid=" + std::to_string(event->tid) +
                           " at " + aerore::hex(event->va) + " " + event->message;
        log_line(ui, line);
        ui.status = line;
    }
    for (auto& line : session.debugger().anti_debug_log()) log_line(ui, "hide: " + line);
}

void draw_console(aerore::Session& session, aerore::McpTcpServer& mcp, UiState& ui) {
    if (!ui.show_console) return;
    ImGui::SetNextWindowSize(ImVec2(850, 250), ImGuiCond_FirstUseEver);
    ImGui::Begin("Console / MCP", &ui.show_console);
    ImGui::Text("MCP: %s", mcp.status().c_str());
    ImGui::SameLine();
    if (mcp.running() && ImGui::SmallButton("Copy endpoint")) {
        std::string endpoint = "127.0.0.1:" + std::to_string(mcp.port());
        ImGui::SetClipboardText(endpoint.c_str());
    }
    ImGui::SameLine();
    ImGui::TextDisabled("stdio remains available with: aerore mcp");
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear")) ui.console.clear();
    ImGui::Separator();
    ImGui::BeginChild("console-scroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto& line : ui.console) ImGui::TextUnformatted(line.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.0f) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
    ImGui::End();
    (void)session;
}

void draw_workspace(aerore::Session& session, aerore::McpTcpServer& mcp, UiState& ui, bool& open) {
    mcp.pump();
    drain_runtime_events(session, ui);
    handle_shortcuts(session, ui);
    ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport(), ImGuiDockNodeFlags_PassthruCentralNode);
    draw_menu(session, mcp, ui, open);
    draw_attach_popup(session, ui);
    auto model = session.model();
    draw_functions(model, ui);
    draw_disassembly(model, ui);
    draw_pseudocode(model, ui);
    draw_hex(session, ui);
    draw_graph(model, ui);
    draw_xrefs(model, ui);
    draw_symbols(session, model, ui);
    draw_strings(model, ui);
    draw_debug_state(session, ui);
    draw_console(session, mcp, ui);
}

void apply_theme() {
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 3.0f;
    style.FrameRounding = 3.0f;
    style.TabRounding = 3.0f;
    style.WindowPadding = ImVec2(7, 7);
    style.FramePadding = ImVec2(6, 4);
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.055f, 0.067f, 0.086f, 1.0f);
    style.Colors[ImGuiCol_TitleBg] = ImVec4(0.075f, 0.094f, 0.125f, 1.0f);
    style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.10f, 0.14f, 0.19f, 1.0f);
    style.Colors[ImGuiCol_Header] = ImVec4(0.12f, 0.28f, 0.43f, 0.75f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.17f, 0.39f, 0.59f, 0.90f);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.90f, 0.48f, 0.16f, 0.85f);
    style.Colors[ImGuiCol_TabActive] = ImVec4(0.14f, 0.31f, 0.47f, 1.0f);
    style.Colors[ImGuiCol_CheckMark] = ImVec4(0.96f, 0.55f, 0.20f, 1.0f);
}

}  // namespace

namespace aerore {

int run_gui(Session& session, const std::string& initial_path) {
    UiState ui;
    if (!initial_path.empty()) {
        try {
            session.load_file(initial_path, true);
            ui.cursor = session.model()->entry;
            log_line(ui, "Loaded " + initial_path);
        } catch (const std::exception& ex) {
            log_line(ui, ex.what());
        }
    }

    WNDCLASSEXW window_class{sizeof(window_class), CS_CLASSDC, wnd_proc, 0, 0, GetModuleHandleW(nullptr),
                             nullptr, nullptr, nullptr, nullptr, L"AeroRE", nullptr};
    RegisterClassExW(&window_class);
    g_hwnd = CreateWindowW(window_class.lpszClassName, L"AeroRE Workbench", WS_OVERLAPPEDWINDOW,
                           40, 40, 1560, 940, nullptr, nullptr, window_class.hInstance, nullptr);
    DXGI_SWAP_CHAIN_DESC swap_desc{};
    swap_desc.BufferCount = 2;
    swap_desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swap_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_desc.OutputWindow = g_hwnd;
    swap_desc.SampleDesc.Count = 1;
    swap_desc.Windowed = TRUE;
    swap_desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL feature_level;
    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
                                      D3D11_SDK_VERSION, &swap_desc, &g_swap, &g_dev,
                                      &feature_level, &g_ctx) != S_OK) {
        DestroyWindow(g_hwnd);
        UnregisterClassW(window_class.lpszClassName, window_class.hInstance);
        return 1;
    }
    create_rtv();
    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    ImGui::GetIO().ConfigWindowsMoveFromTitleBarOnly = true;
    apply_theme();
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_dev, g_ctx);

    u16 mcp_port = 37091;
    if (const char* configured = std::getenv("AERORE_MCP_PORT")) {
        int parsed = std::atoi(configured);
        if (parsed > 0 && parsed <= 65535) mcp_port = static_cast<u16>(parsed);
    }
    McpTcpServer mcp(session);
    mcp.start(mcp_port);
    log_line(ui, "MCP " + mcp.status());
    log_line(ui, "Anti-anti-debug settings: aerore-hide.ini");

    bool open = true;
    while (open) {
        MSG message;
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            if (message.message == WM_QUIT) open = false;
        }
        if (!open) break;
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        draw_workspace(session, mcp, ui, open);
        ImGui::Render();
        const float clear[4] = {0.045f, 0.052f, 0.066f, 1.0f};
        g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_ctx->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swap->Present(1, 0);
    }

    mcp.stop();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_rtv();
    if (g_swap) g_swap->Release();
    if (g_ctx) g_ctx->Release();
    if (g_dev) g_dev->Release();
    DestroyWindow(g_hwnd);
    UnregisterClassW(window_class.lpszClassName, window_class.hInstance);
    g_hwnd = nullptr;
    return 0;
}

}  // namespace aerore

#else

namespace aerore {
int run_gui(Session&, const std::string&) {
    std::cerr << "The Dear ImGui UI is built on Windows (cmake -DAERORE_BUILD_GUI=ON).\n";
    return 1;
}
}  // namespace aerore

#endif
