#include "aerore/mcp.hpp"

#include <cctype>
#include <cstdlib>
#include <iostream>
#include <sstream>

namespace aerore {
namespace {

Json rpc_ok(const Json& id, Json result) {
    Json msg = Json::object();
    msg.set("jsonrpc", Json::string("2.0"));
    msg.set("id", id);
    msg.set("result", std::move(result));
    return msg;
}

Json rpc_err(const Json& id, int code, const std::string& message) {
    Json msg = Json::object();
    msg.set("jsonrpc", Json::string("2.0"));
    msg.set("id", id);
    Json err = Json::object();
    err.set("code", Json::number(code));
    err.set("message", Json::string(message));
    msg.set("error", std::move(err));
    return msg;
}

Json tool(const std::string& name, const std::string& desc, Json schema) {
    Json t = Json::object();
    t.set("name", Json::string(name));
    t.set("description", Json::string(desc));
    t.set("inputSchema", std::move(schema));
    return t;
}

Json obj_schema(std::vector<std::pair<std::string, Json>> props, std::vector<std::string> required) {
    Json s = Json::object();
    s.set("type", Json::string("object"));
    Json p = Json::object();
    for (auto& kv : props) p.set(kv.first, std::move(kv.second));
    s.set("properties", std::move(p));
    Json req = Json::array();
    for (auto& r : required) req.arr.push_back(Json::string(r));
    s.set("required", std::move(req));
    return s;
}

Json str_prop() {
    Json j = Json::object();
    j.set("type", Json::string("string"));
    return j;
}
Json num_prop() {
    Json j = Json::object();
    j.set("type", Json::string("number"));
    return j;
}
Json bool_prop() {
    Json j = Json::object();
    j.set("type", Json::string("boolean"));
    return j;
}

Json array_prop() {
    Json j = Json::object();
    j.set("type", Json::string("array"));
    return j;
}

}  // namespace

McpServer::McpServer(Session& session) : session_(session) {}

Json McpServer::tools_list() const {
    Json tools = Json::array();
    tools.arr.push_back(tool("load_file", "Load a PE and run analysis. auto_unpack runs the packer plugins first.",
                             obj_schema({{"path", str_prop()}, {"auto_unpack", bool_prop()}}, {"path"})));
    tools.arr.push_back(tool("save_db", "Write the SQLite IDB.", obj_schema({{"path", str_prop()}}, {"path"})));
    tools.arr.push_back(tool("open_db", "Open a saved IDB.", obj_schema({{"path", str_prop()}}, {"path"})));
    tools.arr.push_back(tool("list_functions", "List recovered functions.", obj_schema({}, {})));
    tools.arr.push_back(tool("disassemble", "Disassemble count instructions at va.",
                             obj_schema({{"va", str_prop()}, {"count", num_prop()}}, {"va"})));
    tools.arr.push_back(tool("xrefs_to", "Cross-references to an address.", obj_schema({{"va", str_prop()}}, {"va"})));
    tools.arr.push_back(tool("xrefs_from", "Cross-references from an address.", obj_schema({{"va", str_prop()}}, {"va"})));
    tools.arr.push_back(tool("cfg", "Basic blocks of the function containing va.", obj_schema({{"va", str_prop()}}, {"va"})));
    tools.arr.push_back(tool("list_imports", "Import table.", obj_schema({}, {})));
    tools.arr.push_back(tool("list_exports", "Export table.", obj_schema({}, {})));
    tools.arr.push_back(tool("list_strings", "Recovered strings.", obj_schema({}, {})));
    tools.arr.push_back(tool("list_sections", "PE sections.", obj_schema({}, {})));
    tools.arr.push_back(tool("get_bytes", "Read bytes at va.", obj_schema({{"va", str_prop()}, {"size", num_prop()}}, {"va"})));
    tools.arr.push_back(tool("set_name", "Rename an address.", obj_schema({{"va", str_prop()}, {"name", str_prop()}}, {"va", "name"})));
    tools.arr.push_back(tool("set_comment", "Comment an address.",
                             obj_schema({{"va", str_prop()}, {"comment", str_prop()}}, {"va", "comment"})));
    tools.arr.push_back(tool("define_struct", "Declare a struct type.",
                             obj_schema({{"name", str_prop()}, {"members", array_prop()}}, {"name"})));
    tools.arr.push_back(tool("detect_packers", "Score unpacker plugins.", obj_schema({}, {})));
    tools.arr.push_back(tool("unpack", "Run the highest-scoring unpacker.", obj_schema({}, {})));
    tools.arr.push_back(tool("fix_iat", "Resolve and optionally rebuild the import table.",
                             obj_schema({{"patch", bool_prop()}, {"modules", array_prop()}}, {})));
    tools.arr.push_back(tool("query", "Read-only SQL against the IDB.", obj_schema({{"sql", str_prop()}}, {"sql"})));
    Json result = Json::object();
    result.set("tools", std::move(tools));
    return result;
}

Json McpServer::call_tool(const std::string& name, const Json& args) {
    auto va_of = [&](const char* key) { return args.get_u64(key, 0); };
    auto snap = session_.model();
    auto require = [&]() {
        if (!snap) throw std::runtime_error("nothing loaded");
    };

    if (name == "load_file") {
        session_.load_file(args.get_str("path"), args.get_bool("auto_unpack", true));
        snap = session_.model();
        Json j = Json::object();
        j.set("image_base", Json::string(hex(snap->image_base)));
        j.set("entry", Json::string(hex(snap->entry)));
        j.set("functions", Json::number(static_cast<double>(snap->functions.size())));
        j.set("insns", Json::number(static_cast<double>(snap->insns.size())));
        return Json::string(j.dump());
    }
    if (name == "save_db") {
        session_.save_db(args.get_str("path"));
        return Json::string("saved");
    }
    if (name == "open_db") {
        session_.open_db(args.get_str("path"));
        return Json::string("opened");
    }
    if (name == "list_functions") {
        require();
        Json arr = Json::array();
        for (const auto& f : snap->functions) {
            Json o = Json::object();
            o.set("start", Json::string(hex(f.start)));
            o.set("end", Json::string(hex(f.end)));
            o.set("name", Json::string(f.name));
            o.set("blocks", Json::number(static_cast<double>(f.blocks.size())));
            o.set("loops", Json::number(static_cast<double>(f.loops.size())));
            arr.arr.push_back(std::move(o));
        }
        return Json::string(arr.dump());
    }
    if (name == "disassemble") {
        require();
        u64 va = va_of("va");
        int count = static_cast<int>(args.get_u64("count", 32));
        if (count <= 0) count = 32;
        if (count > 500) count = 500;
        Json arr = Json::array();
        const PeImage* image = session_.image();
        Decoder* dec = image ? &session_.decoder() : nullptr;
        for (int i = 0; i < count; ++i) {
            const Insn* in = nullptr;
            Insn tmp;
            auto it = snap->insns.find(va);
            if (it != snap->insns.end()) in = &it->second;
            else if (image && dec && image->contains_va(va)) {
                u8 buf[15];
                size_t take = std::min<size_t>(image->avail_rva(image->va_to_rva(va)), 15);
                if (take && image->read_rva(image->va_to_rva(va), buf, take)) {
                    if (auto d = dec->decode(va, buf, take)) {
                        tmp = *d;
                        in = &tmp;
                    }
                }
            }
            if (!in) break;
            Json o = Json::object();
            o.set("va", Json::string(hex(in->va)));
            o.set("text", Json::string(in->text));
            auto c = snap->comments.find(in->va);
            if (c != snap->comments.end()) o.set("comment", Json::string(c->second));
            arr.arr.push_back(std::move(o));
            va += in->len ? in->len : 1;
        }
        return Json::string(arr.dump());
    }
    if (name == "xrefs_to" || name == "xrefs_from") {
        require();
        auto xs = name == "xrefs_to" ? snap->xrefs_to(va_of("va")) : snap->xrefs_from(va_of("va"));
        Json arr = Json::array();
        for (const auto& x : xs) {
            Json o = Json::object();
            o.set("src", Json::string(hex(x.src)));
            o.set("dst", Json::string(hex(x.dst)));
            o.set("kind", Json::string(xref_name(x.kind)));
            arr.arr.push_back(std::move(o));
        }
        return Json::string(arr.dump());
    }
    if (name == "cfg") {
        require();
        const Function* f = snap->function_containing(va_of("va"));
        if (!f) f = snap->function_by_start(va_of("va"));
        if (!f) return Json::string("{\"error\":\"no function\"}");
        Json o = Json::object();
        o.set("name", Json::string(f->name));
        o.set("start", Json::string(hex(f->start)));
        o.set("end", Json::string(hex(f->end)));
        Json blocks = Json::array();
        for (const auto& b : f->blocks) {
            Json bb = Json::object();
            bb.set("start", Json::string(hex(b.start)));
            bb.set("end", Json::string(hex(b.end)));
            Json suc = Json::array();
            for (const auto& e : b.succs) suc.arr.push_back(Json::string(hex(e.target)));
            bb.set("succs", std::move(suc));
            blocks.arr.push_back(std::move(bb));
        }
        o.set("blocks", std::move(blocks));
        Json loops = Json::array();
        for (const auto& l : f->loops) loops.arr.push_back(Json::string(hex(l.header)));
        o.set("loops", std::move(loops));
        return Json::string(o.dump());
    }
    if (name == "list_imports") {
        require();
        Json arr = Json::array();
        for (const auto& im : snap->imports) {
            Json o = Json::object();
            o.set("dll", Json::string(im.dll));
            o.set("name", Json::string(im.name));
            o.set("ordinal", Json::number(im.ordinal));
            o.set("iat", Json::string(hex(im.iat_va)));
            arr.arr.push_back(std::move(o));
        }
        return Json::string(arr.dump());
    }
    if (name == "list_exports") {
        require();
        Json arr = Json::array();
        for (const auto& ex : snap->exports) {
            Json o = Json::object();
            o.set("name", Json::string(ex.name));
            o.set("va", Json::string(hex(ex.va)));
            o.set("ordinal", Json::number(ex.ordinal));
            arr.arr.push_back(std::move(o));
        }
        return Json::string(arr.dump());
    }
    if (name == "list_strings") {
        require();
        Json arr = Json::array();
        size_t n = 0;
        for (const auto& s : snap->strings) {
            if (n++ > 2000) break;
            Json o = Json::object();
            o.set("va", Json::string(hex(s.va)));
            o.set("text", Json::string(s.text));
            o.set("utf16", Json::boolean(s.utf16));
            arr.arr.push_back(std::move(o));
        }
        return Json::string(arr.dump());
    }
    if (name == "list_sections") {
        require();
        Json arr = Json::array();
        for (const auto& s : snap->sections) {
            Json o = Json::object();
            o.set("name", Json::string(s.name));
            o.set("va", Json::string(hex(s.va)));
            o.set("vsize", Json::string(hex(s.vsize)));
            o.set("entropy", Json::number(s.entropy));
            o.set("executable", Json::boolean(s.executable));
            arr.arr.push_back(std::move(o));
        }
        return Json::string(arr.dump());
    }
    if (name == "get_bytes") {
        auto bytes = session_.read_va(va_of("va"), static_cast<size_t>(args.get_u64("size", 16)));
        std::ostringstream os;
        os << std::hex;
        for (u8 b : bytes) os.width(2), os << std::setfill('0') << static_cast<int>(b);
        return Json::string(os.str());
    }
    if (name == "set_name") {
        session_.set_name(va_of("va"), args.get_str("name"));
        return Json::string("ok");
    }
    if (name == "set_comment") {
        session_.set_comment(va_of("va"), args.get_str("comment"));
        return Json::string("ok");
    }
    if (name == "define_struct") {
        StructType t;
        t.name = args.get_str("name");
        if (const Json* members = args.get("members")) {
            if (members->type == Json::Type::Array) {
                int next = 0;
                for (const auto& m : members->arr) {
                    TypeMember mem;
                    mem.name = m.get_str("name");
                    mem.type_name = m.get_str("type", "byte");
                    mem.offset = static_cast<int>(m.get_u64("offset", static_cast<unsigned long long>(next)));
                    mem.size = static_cast<int>(m.get_u64("size", 8));
                    next = mem.offset + mem.size;
                    t.members.push_back(mem);
                }
                t.size = next;
            }
        }
        session_.define_struct(t);
        return Json::string("ok");
    }
    if (name == "detect_packers") {
        if (!session_.image()) return Json::string("[]");
        Json arr = Json::array();
        for (const auto& d : session_.unpackers().detect_all(*session_.image())) {
            Json o = Json::object();
            o.set("id", Json::string(d.first));
            o.set("score", Json::number(d.second));
            arr.arr.push_back(std::move(o));
        }
        return Json::string(arr.dump());
    }
    if (name == "unpack") {
        UnpackResult r = session_.unpack_best();
        Json o = Json::object();
        o.set("ok", Json::boolean(r.ok));
        o.set("packer", Json::string(r.packer));
        o.set("oep", Json::string(hex(r.oep_rva)));
        o.set("log", Json::string(r.log));
        return Json::string(o.dump());
    }
    if (name == "fix_iat") {
        std::vector<ModuleSpan> mods;
        if (const Json* m = args.get("modules")) {
            if (m->type == Json::Type::Array) mods = modules_from_json(m->dump());
        }
        bool patch = args.get_bool("patch", false);
        IatReport r = session_.fix_iat(mods, patch);
        Json o = Json::object();
        o.set("patched", Json::boolean(r.patched));
        o.set("message", Json::string(r.message));
        o.set("slots", Json::number(static_cast<double>(r.slots.size())));
        Json arr = Json::array();
        for (const auto& s : r.slots) {
            Json sl = Json::object();
            sl.set("slot", Json::string(hex(s.slot_va)));
            sl.set("module", Json::string(s.module));
            sl.set("name", Json::string(s.name.empty() ? ("#" + std::to_string(s.ordinal)) : s.name));
            sl.set("resolved", Json::string(hex(s.resolved)));
            sl.set("trampoline", Json::boolean(s.trampoline));
            sl.set("note", Json::string(s.note));
            arr.arr.push_back(std::move(sl));
        }
        o.set("entries", std::move(arr));
        return Json::string(o.dump());
    }
    if (name == "query") {
        if (!session_.db()) session_.save_db(args.get_str("db", "aerore.idb"));
        return Json::string(session_.query(args.get_str("sql")));
    }
    throw std::runtime_error("unknown tool " + name);
}

std::string McpServer::handle(const std::string& message) {
    Json id = Json::nul();
    try {
        Json req = Json::parse(message);
        if (const Json* i = req.get("id")) id = *i;
        std::string method = req.get_str("method");
        const Json* params = req.get("params");
        Json empty = Json::object();
        const Json& p = params ? *params : empty;
        if (method == "initialize") {
            Json result = Json::object();
            result.set("protocolVersion", Json::string("2025-11-25"));
            Json caps = Json::object();
            caps.set("tools", Json::object());
            result.set("capabilities", std::move(caps));
            Json info = Json::object();
            info.set("name", Json::string("aerore"));
            info.set("version", Json::string("0.2.0"));
            result.set("serverInfo", std::move(info));
            return rpc_ok(id, std::move(result)).dump();
        }
        if (method == "notifications/initialized" || method == "initialized") {
            return {};
        }
        if (method == "tools/list") return rpc_ok(id, tools_list()).dump();
        if (method == "tools/call") {
            std::string name = p.get_str("name");
            const Json* a = p.get("arguments");
            Json args = a ? *a : Json::object();
            try {
                Json payload = call_tool(name, args);
                Json result = Json::object();
                Json content = Json::array();
                Json item = Json::object();
                item.set("type", Json::string("text"));
                item.set("text", payload.type == Json::Type::String ? std::move(payload) : Json::string(payload.dump()));
                content.arr.push_back(std::move(item));
                result.set("content", std::move(content));
                return rpc_ok(id, std::move(result)).dump();
            } catch (const std::exception& ex) {
                Json result = Json::object();
                Json content = Json::array();
                Json item = Json::object();
                item.set("type", Json::string("text"));
                item.set("text", Json::string(ex.what()));
                content.arr.push_back(std::move(item));
                result.set("content", std::move(content));
                result.set("isError", Json::boolean(true));
                return rpc_ok(id, std::move(result)).dump();
            }
        }
        if (method == "ping") return rpc_ok(id, Json::object()).dump();
        return rpc_err(id, -32601, "method not found").dump();
    } catch (const std::exception& ex) {
        return rpc_err(id, -32700, ex.what()).dump();
    }
}

void McpServer::serve_stdio() {
    std::ios::sync_with_stdio(false);
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        if (line.rfind("Content-Length:", 0) == 0) {
            size_t length = static_cast<size_t>(std::strtoull(line.c_str() + 15, nullptr, 10));
            while (std::getline(std::cin, line)) {
                if (line == "\r" || line.empty()) break;
            }
            std::string body(length, '\0');
            std::cin.read(body.data(), static_cast<std::streamsize>(length));
            if (static_cast<size_t>(std::cin.gcount()) != length) break;
            std::string response = handle(body);
            if (!response.empty())
                std::cout << "Content-Length: " << response.size() << "\r\n\r\n" << response << std::flush;
            continue;
        }

        std::string response = handle(line);
        if (!response.empty()) std::cout << response << '\n' << std::flush;
    }
}

}  // namespace aerore
