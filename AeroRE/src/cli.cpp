#include "aerore/mcp.hpp"
#include "aerore/session.hpp"
#include "aerore/ui.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>

namespace {

const char* arg(int argc, char** argv, const char* key, const char* def = nullptr) {
    for (int i = 0; i < argc - 1; ++i)
        if (std::string(argv[i]) == key) return argv[i + 1];
    return def;
}
bool flag(int argc, char** argv, const char* key) {
    for (int i = 0; i < argc; ++i)
        if (std::string(argv[i]) == key) return true;
    return false;
}

void usage() {
    std::cerr
        << "aerore analyze <file> [-o idb] [--unpack]\n"
        << "aerore info <file>\n"
        << "aerore disasm <file> --va 0x140001000 [--count 40]\n"
        << "aerore fix-iat <file> --modules mods.json [--patch] [-o out.exe]\n"
        << "aerore unpack <file> [-o out.exe]\n"
        << "aerore mcp\n"
        << "aerore gui [file]\n"
        << "aerore query <idb> <sql>\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 1;
    }
    std::string cmd = argv[1];
    try {
        aerore::Session session;
        if (cmd == "mcp") {
            aerore::McpServer server(session);
            server.serve_stdio();
            return 0;
        }
        if (cmd == "gui") {
            std::string path = argc >= 3 ? argv[2] : "";
            return aerore::run_gui(session, path);
        }
        if (cmd == "query") {
            if (argc < 4) {
                usage();
                return 1;
            }
            session.open_db(argv[2]);
            std::cout << session.query(argv[3]) << "\n";
            return 0;
        }
        if (argc < 3) {
            usage();
            return 1;
        }
        std::string file = argv[2];
        if (cmd == "info") {
            session.load_file(file, false);
            if (session.image()) std::cout << session.image()->describe();
            auto dets = session.unpackers().detect_all(*session.image());
            std::cout << "unpackers:\n";
            for (auto& d : dets) std::cout << "  " << d.first << " score " << d.second << "\n";
            return 0;
        }
        if (cmd == "analyze") {
            bool unpack = flag(argc, argv, "--unpack");
            session.load_file(file, unpack);
            auto m = session.model();
            auto st = session.last_stats();
            std::cout << "threads " << st.threads << " insns " << st.insn_count << " functions " << st.function_count
                      << " xrefs " << st.xref_count << " dropped " << st.conflicts_dropped << "\n";
            for (const auto& f : m->functions)
                std::cout << f.name << " " << aerore::hex(f.start) << "-" << aerore::hex(f.end) << " blocks "
                          << f.blocks.size() << " loops " << f.loops.size() << "\n";
            if (const char* out = arg(argc, argv, "-o")) session.save_db(out);
            if (!session.last_error().empty()) std::cout << session.last_error();
            return 0;
        }
        if (cmd == "disasm") {
            session.load_file(file, false);
            const char* vas = arg(argc, argv, "--va");
            if (!vas) {
                usage();
                return 1;
            }
            aerore::u64 va = std::stoull(vas, nullptr, 0);
            int count = arg(argc, argv, "--count") ? std::atoi(arg(argc, argv, "--count")) : 32;
            auto m = session.model();
            for (int i = 0; i < count; ++i) {
                auto it = m->insns.find(va);
                if (it == m->insns.end()) break;
                std::cout << aerore::hex(it->second.va) << "  " << it->second.text << "\n";
                va += it->second.len ? it->second.len : 1;
            }
            return 0;
        }
        if (cmd == "unpack") {
            session.load_file(file, false);
            auto r = session.unpack_best();
            std::cout << r.log;
            if (const char* out = arg(argc, argv, "-o")) {
                if (r.rebuilt.empty()) {
                    std::cerr << "nothing to write\n";
                    return 1;
                }
                std::ofstream f(out, std::ios::binary);
                f.write(reinterpret_cast<const char*>(r.rebuilt.data()), static_cast<std::streamsize>(r.rebuilt.size()));
            }
            return r.ok ? 0 : 2;
        }
        if (cmd == "fix-iat") {
            const char* mods_path = arg(argc, argv, "--modules");
            if (!mods_path) {
                usage();
                return 1;
            }
            std::ifstream in(mods_path);
            std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            session.load_file(file, false);
            auto mods = aerore::modules_from_json(json);
            bool patch = flag(argc, argv, "--patch");
            auto report = session.fix_iat(mods, patch);
            std::cout << report.message << "\n";
            for (const auto& s : report.slots) {
                std::cout << aerore::hex(s.slot_va) << " -> " << s.module << "!"
                          << (s.name.empty() ? ("#" + std::to_string(s.ordinal)) : s.name);
                if (s.trampoline) std::cout << " (trampoline)";
                if (!s.note.empty()) std::cout << " [" << s.note << "]";
                std::cout << "\n";
            }
            if (patch && session.image()) {
                auto bytes = session.image()->rebuild(false);
                const char* out = arg(argc, argv, "-o");
                if (out) {
                    std::ofstream f(out, std::ios::binary);
                    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
                }
            }
            return 0;
        }
        usage();
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }
}
