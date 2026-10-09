#include "aerore/ui.hpp"

#include <cstdio>
#include <iostream>

#if defined(_WIN32) && defined(AERORE_HAS_IMGUI)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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

void draw(aerore::Session& session, aerore::u64& cursor, std::string& status) {
    auto model = session.model();
    for (const auto& ev : session.progress().drain()) status = ev.stage + " " + ev.detail + " " + std::to_string(ev.percent) + "%";

    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Save IDB") && model) session.save_db("aerore.idb");
            if (ImGui::MenuItem("Unpack")) session.unpack_best();
            if (ImGui::MenuItem("Fix IAT (report)")) session.fix_iat({}, false);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Debug")) {
            if (ImGui::MenuItem("Step into")) session.debugger().step_into();
            if (ImGui::MenuItem("Step over")) session.debugger().step_over();
            if (ImGui::MenuItem("Step out")) session.debugger().step_out();
            if (ImGui::MenuItem("Resume")) session.debugger().resume();
            if (ImGui::MenuItem("Software BP at cursor")) session.debugger().add_bp(cursor, aerore::BpType::Software);
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    ImGui::SetNextWindowPos(ImVec2(0, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(280, 500), ImGuiCond_FirstUseEver);
    ImGui::Begin("Functions");
    if (model) {
        for (const auto& f : model->functions) {
            if (ImGui::Selectable(f.name.c_str(), cursor == f.start)) cursor = f.start;
        }
    }
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(290, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(640, 360), ImGuiCond_FirstUseEver);
    ImGui::Begin("Disassembly");
    if (model && ImGui::BeginTable("dis", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableSetupColumn("Comment");
        ImGui::TableHeadersRow();
        aerore::u64 va = cursor;
        for (int i = 0; i < 200; ++i) {
            auto it = model->insns.find(va);
            if (it == model->insns.end()) break;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(aerore::hex(va).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) cursor = va;
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(it->second.text);
            ImGui::TableSetColumnIndex(2);
            auto c = model->comments.find(va);
            if (c != model->comments.end()) ImGui::TextUnformatted(c->second.c_str());
            va += it->second.len ? it->second.len : 1;
        }
        ImGui::EndTable();
    }
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(290, 390), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(640, 180), ImGuiCond_FirstUseEver);
    ImGui::Begin("Hex");
    auto bytes = session.read_va(cursor & ~0xfull, 256);
    for (size_t row = 0; row < bytes.size(); row += 16) {
        std::string line = aerore::hex((cursor & ~0xfull) + row) + "  ";
        for (size_t c = 0; c < 16 && row + c < bytes.size(); ++c) {
            char b[4];
            std::snprintf(b, sizeof(b), "%02x ", bytes[row + c]);
            line += b;
        }
        ImGui::TextUnformatted(line.c_str());
    }
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(940, 20), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(320, 220), ImGuiCond_FirstUseEver);
    ImGui::Begin("Xrefs");
    if (model) {
        for (const auto& x : model->xrefs_to(cursor))
            ImGui::Text("from %s %s", aerore::hex(x.src).c_str(), aerore::xref_name(x.kind));
        for (const auto& x : model->xrefs_from(cursor))
            ImGui::Text("to %s %s", aerore::hex(x.dst).c_str(), aerore::xref_name(x.kind));
    }
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(940, 250), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(320, 240), ImGuiCond_FirstUseEver);
    ImGui::Begin("Graph");
    if (model) {
        if (const aerore::Function* f = model->function_containing(cursor)) {
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 origin = ImGui::GetCursorScreenPos();
            int i = 0;
            for (const auto& b : f->blocks) {
                ImVec2 p0(origin.x + 10, origin.y + i * 36);
                ImVec2 p1(p0.x + 220, p0.y + 28);
                dl->AddRectFilled(p0, p1, IM_COL32(28, 36, 48, 255));
                dl->AddRect(p0, p1, IM_COL32(120, 170, 220, 255));
                std::string label = aerore::hex(b.start);
                dl->AddText(ImVec2(p0.x + 6, p0.y + 6), IM_COL32(230, 236, 240, 255), label.c_str());
                ++i;
                if (i > 12) break;
            }
            ImGui::Dummy(ImVec2(240, i * 36.f));
        }
    }
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(940, 500), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(320, 160), ImGuiCond_FirstUseEver);
    ImGui::Begin("Registers");
    aerore::RegState rs = session.debugger().regs();
    if (rs.valid) {
        static const char* nm[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
        for (int i = 0; i < 8; ++i) ImGui::Text("%s %s", nm[i], aerore::hex(rs.gpr[i]).c_str());
        ImGui::Text("rip %s", aerore::hex(rs.rip).c_str());
    } else {
        ImGui::TextUnformatted(session.debugger().last_error().c_str());
    }
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(0, 530), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(280, 140), ImGuiCond_FirstUseEver);
    ImGui::Begin("Status");
    ImGui::TextUnformatted(status.c_str());
    if (model) ImGui::Text("insns %zu  funcs %zu", model->insns.size(), model->functions.size());
    ImGui::End();
}

}  // namespace

namespace aerore {

int run_gui(Session& session, const std::string& initial_path) {
    if (!initial_path.empty()) {
        try {
            session.load_file(initial_path, true);
        } catch (const std::exception& ex) {
            std::cerr << ex.what() << "\n";
        }
    }
    WNDCLASSEXW wc{sizeof(wc), CS_CLASSDC, wnd_proc, 0, 0, GetModuleHandleW(nullptr), nullptr, nullptr, nullptr, nullptr,
                   L"AeroRE", nullptr};
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"AeroRE", WS_OVERLAPPEDWINDOW, 80, 80, 1280, 800, nullptr, nullptr,
                              wc.hInstance, nullptr);
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL fl;
    D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &sd, &g_swap,
                                  &g_dev, &fl, &g_ctx);
    create_rtv();
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_dev, g_ctx);
    u64 cursor = session.model() ? session.model()->entry : 0;
    std::string status = "ready";
    bool open = true;
    while (open) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) open = false;
        }
        if (!open) break;
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        draw(session, cursor, status);
        ImGui::Render();
        const float clear[4] = {0.08f, 0.09f, 0.11f, 1.f};
        g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_ctx->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swap->Present(1, 0);
    }
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_rtv();
    if (g_swap) g_swap->Release();
    if (g_ctx) g_ctx->Release();
    if (g_dev) g_dev->Release();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
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
