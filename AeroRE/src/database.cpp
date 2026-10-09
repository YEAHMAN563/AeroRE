#include "aerore/database.hpp"

#include "aerore/json.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace aerore {
namespace {

void check(int rc, sqlite3* db, const char* what) {
    if (rc == SQLITE_OK || rc == SQLITE_DONE || rc == SQLITE_ROW) return;
    std::string msg = what;
    msg += ": ";
    msg += sqlite3_errmsg(db);
    throw std::runtime_error(msg);
}

struct Stmt {
    sqlite3_stmt* s = nullptr;
    sqlite3* db = nullptr;
    Stmt(sqlite3* db, const char* sql) : db(db) { check(sqlite3_prepare_v2(db, sql, -1, &s, nullptr), db, "prepare"); }
    ~Stmt() { sqlite3_finalize(s); }
    void bind_i64(int i, i64 v) { check(sqlite3_bind_int64(s, i, v), db, "bind"); }
    void bind_int(int i, int v) { check(sqlite3_bind_int(s, i, v), db, "bind"); }
    void bind_text(int i, const std::string& v) {
        check(sqlite3_bind_text(s, i, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT), db, "bind");
    }
    void bind_blob(int i, const void* p, int n) {
        check(sqlite3_bind_blob(s, i, p, n, SQLITE_TRANSIENT), db, "bind");
    }
    bool step() {
        int rc = sqlite3_step(s);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        check(rc, db, "step");
        return false;
    }
    void reset() {
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
    }
};

bool is_readonly_sql(std::string sql) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    sql.erase(sql.begin(), std::find_if(sql.begin(), sql.end(), not_space));
    while (!sql.empty() && std::isspace(static_cast<unsigned char>(sql.back()))) sql.pop_back();
    if (!sql.empty() && sql.back() == ';') sql.pop_back();
    if (sql.find(';') != std::string::npos) return false;
    for (char& c : sql)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return sql.rfind("select", 0) == 0 || sql.rfind("with", 0) == 0 || sql.rfind("pragma", 0) == 0 ||
           sql.rfind("explain", 0) == 0;
}

}  // namespace

Database::Database(const std::string& path) : path_(path) {
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "open failed";
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error(msg);
    }
    exec("PRAGMA journal_mode=WAL;");
    exec("PRAGMA foreign_keys=ON;");
    migrate();
}

Database::~Database() {
    if (db_) sqlite3_close(db_);
}

void Database::exec(const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "exec";
        sqlite3_free(err);
        throw std::runtime_error(msg);
    }
}

void Database::migrate() {
    exec(R"SQL(
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS segments(
  start INTEGER PRIMARY KEY, end INTEGER, name TEXT, flags INTEGER, data BLOB);
CREATE TABLE IF NOT EXISTS functions(start INTEGER PRIMARY KEY, end INTEGER, name TEXT);
CREATE TABLE IF NOT EXISTS blocks(func INTEGER, start INTEGER, end INTEGER, PRIMARY KEY(func, start));
CREATE TABLE IF NOT EXISTS edges(func INTEGER, src INTEGER, dst INTEGER, kind INTEGER);
CREATE TABLE IF NOT EXISTS loops(func INTEGER, header INTEGER, back_from INTEGER);
CREATE TABLE IF NOT EXISTS insns(
  va INTEGER PRIMARY KEY, len INTEGER, bytes BLOB, mnem TEXT, text TEXT, flow INTEGER);
CREATE TABLE IF NOT EXISTS xrefs(src INTEGER, dst INTEGER, kind INTEGER);
CREATE INDEX IF NOT EXISTS ix_xref_dst ON xrefs(dst);
CREATE INDEX IF NOT EXISTS ix_xref_src ON xrefs(src);
CREATE TABLE IF NOT EXISTS names(va INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS comments(va INTEGER PRIMARY KEY, text TEXT);
CREATE TABLE IF NOT EXISTS imports(
  id INTEGER PRIMARY KEY AUTOINCREMENT, dll TEXT, name TEXT, ordinal INTEGER, iat_va INTEGER);
CREATE TABLE IF NOT EXISTS exports(va INTEGER, name TEXT, ordinal INTEGER, rva INTEGER);
CREATE TABLE IF NOT EXISTS strings(va INTEGER PRIMARY KEY, text TEXT, utf16 INTEGER);
CREATE TABLE IF NOT EXISTS structs(name TEXT PRIMARY KEY, size INTEGER);
CREATE TABLE IF NOT EXISTS members(
  struct TEXT, name TEXT, type_name TEXT, offset INTEGER, size INTEGER);
CREATE TABLE IF NOT EXISTS type_uses(va INTEGER PRIMARY KEY, type_name TEXT);
CREATE TABLE IF NOT EXISTS netnodes(
  node TEXT, alt INTEGER, tag TEXT, data BLOB, PRIMARY KEY(node, alt, tag));
CREATE TABLE IF NOT EXISTS iat_slots(
  slot_rva INTEGER PRIMARY KEY, raw_value INTEGER, resolved INTEGER, module TEXT,
  name TEXT, ordinal INTEGER, trampoline INTEGER, note TEXT);
)SQL");
}

void Database::set_meta(const std::string& key, const std::string& value) {
    Stmt st(db_, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
    st.bind_text(1, key);
    st.bind_text(2, value);
    st.step();
}

std::string Database::meta(const std::string& key) const {
    Stmt st(db_, "SELECT value FROM meta WHERE key=?");
    st.bind_text(1, key);
    if (!st.step()) return {};
    const char* t = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
    return t ? t : "";
}

void Database::save_model(const ProgramModel& model) {
    exec("BEGIN");
    try {
        exec("DELETE FROM segments; DELETE FROM functions; DELETE FROM blocks; DELETE FROM edges; DELETE FROM loops;");
        exec("DELETE FROM insns; DELETE FROM xrefs; DELETE FROM names; DELETE FROM comments; DELETE FROM imports;");
        exec("DELETE FROM exports; DELETE FROM strings; DELETE FROM structs; DELETE FROM members; DELETE FROM type_uses;");
        set_meta("image_base", std::to_string(model.image_base));
        set_meta("entry", std::to_string(model.entry));
        set_meta("arch", model.is64 ? "x64" : "x86");
        set_meta("path", model.image_path);
        set_meta("unpack_log", model.unpack_log);
        set_meta("rich", model.rich);
        set_meta("overlay", std::to_string(model.overlay_size));

        {
            Stmt st(db_, "INSERT INTO segments(start,end,name,flags,data) VALUES(?,?,?,?,?)");
            for (const auto& s : model.sections) {
                st.bind_i64(1, static_cast<i64>(s.va));
                st.bind_i64(2, static_cast<i64>(s.va + s.vsize));
                st.bind_text(3, s.name);
                st.bind_i64(4, s.chars);
                st.bind_blob(5, "", 0);
                st.step();
                st.reset();
            }
        }
        {
            Stmt st(db_, "INSERT INTO functions(start,end,name) VALUES(?,?,?)");
            Stmt blk(db_, "INSERT INTO blocks(func,start,end) VALUES(?,?,?)");
            Stmt ed(db_, "INSERT INTO edges(func,src,dst,kind) VALUES(?,?,?,?)");
            Stmt lp(db_, "INSERT INTO loops(func,header,back_from) VALUES(?,?,?)");
            for (const auto& f : model.functions) {
                st.bind_i64(1, static_cast<i64>(f.start));
                st.bind_i64(2, static_cast<i64>(f.end));
                st.bind_text(3, f.name);
                st.step();
                st.reset();
                for (const auto& b : f.blocks) {
                    blk.bind_i64(1, static_cast<i64>(f.start));
                    blk.bind_i64(2, static_cast<i64>(b.start));
                    blk.bind_i64(3, static_cast<i64>(b.end));
                    blk.step();
                    blk.reset();
                    for (const auto& e : b.succs) {
                        ed.bind_i64(1, static_cast<i64>(f.start));
                        ed.bind_i64(2, static_cast<i64>(b.start));
                        ed.bind_i64(3, static_cast<i64>(e.target));
                        ed.bind_int(4, static_cast<int>(e.kind));
                        ed.step();
                        ed.reset();
                    }
                }
                for (const auto& l : f.loops) {
                    lp.bind_i64(1, static_cast<i64>(f.start));
                    lp.bind_i64(2, static_cast<i64>(l.header));
                    lp.bind_i64(3, static_cast<i64>(l.back_edge_from));
                    lp.step();
                    lp.reset();
                }
            }
        }
        {
            Stmt st(db_, "INSERT INTO insns(va,len,bytes,mnem,text,flow) VALUES(?,?,?,?,?,?)");
            for (const auto& kv : model.insns) {
                const Insn& in = kv.second;
                st.bind_i64(1, static_cast<i64>(in.va));
                st.bind_int(2, in.len);
                st.bind_blob(3, in.raw, in.len);
                st.bind_text(4, in.mnemonic);
                st.bind_text(5, in.text);
                st.bind_int(6, static_cast<int>(in.flow));
                st.step();
                st.reset();
            }
        }
        {
            Stmt st(db_, "INSERT INTO xrefs(src,dst,kind) VALUES(?,?,?)");
            for (const auto& x : model.xrefs) {
                st.bind_i64(1, static_cast<i64>(x.src));
                st.bind_i64(2, static_cast<i64>(x.dst));
                st.bind_int(3, static_cast<int>(x.kind));
                st.step();
                st.reset();
            }
        }
        {
            Stmt st(db_, "INSERT INTO names(va,name) VALUES(?,?)");
            for (const auto& kv : model.names) {
                st.bind_i64(1, static_cast<i64>(kv.first));
                st.bind_text(2, kv.second);
                st.step();
                st.reset();
            }
        }
        {
            Stmt st(db_, "INSERT INTO comments(va,text) VALUES(?,?)");
            for (const auto& kv : model.comments) {
                st.bind_i64(1, static_cast<i64>(kv.first));
                st.bind_text(2, kv.second);
                st.step();
                st.reset();
            }
        }
        {
            Stmt st(db_, "INSERT INTO imports(dll,name,ordinal,iat_va) VALUES(?,?,?,?)");
            for (const auto& im : model.imports) {
                st.bind_text(1, im.dll);
                st.bind_text(2, im.name);
                st.bind_int(3, im.ordinal);
                st.bind_i64(4, static_cast<i64>(im.iat_va));
                st.step();
                st.reset();
            }
        }
        {
            Stmt st(db_, "INSERT INTO exports(va,name,ordinal,rva) VALUES(?,?,?,?)");
            for (const auto& ex : model.exports) {
                st.bind_i64(1, static_cast<i64>(ex.va));
                st.bind_text(2, ex.name);
                st.bind_int(3, ex.ordinal);
                st.bind_i64(4, static_cast<i64>(ex.rva));
                st.step();
                st.reset();
            }
        }
        {
            Stmt st(db_, "INSERT INTO strings(va,text,utf16) VALUES(?,?,?)");
            for (const auto& s : model.strings) {
                st.bind_i64(1, static_cast<i64>(s.va));
                st.bind_text(2, s.text);
                st.bind_int(3, s.utf16 ? 1 : 0);
                st.step();
                st.reset();
            }
        }
        for (const auto& t : model.structs) define_struct(t);
        {
            Stmt st(db_, "INSERT INTO type_uses(va,type_name) VALUES(?,?)");
            for (const auto& kv : model.type_at) {
                st.bind_i64(1, static_cast<i64>(kv.first));
                st.bind_text(2, kv.second);
                st.step();
                st.reset();
            }
        }
        exec("COMMIT");
    } catch (...) {
        exec("ROLLBACK");
        throw;
    }
}

void Database::load_model(ProgramModel& model) {
    model = ProgramModel{};
    model.image_base = std::stoull(meta("image_base").empty() ? "0" : meta("image_base"));
    model.entry = std::stoull(meta("entry").empty() ? "0" : meta("entry"));
    model.is64 = meta("arch") != "x86";
    model.arch = model.is64 ? Arch::X64 : Arch::X86;
    model.image_path = meta("path");
    model.unpack_log = meta("unpack_log");
    model.rich = meta("rich");
    if (!meta("overlay").empty()) model.overlay_size = std::stoull(meta("overlay"));

    {
        Stmt st(db_, "SELECT start,end,name,flags FROM segments ORDER BY start");
        while (st.step()) {
            SectionInfo s;
            s.va = static_cast<u64>(sqlite3_column_int64(st.s, 0));
            u64 end = static_cast<u64>(sqlite3_column_int64(st.s, 1));
            s.vsize = end - s.va;
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 2));
            s.name = n ? n : "";
            s.chars = static_cast<u32>(sqlite3_column_int64(st.s, 3));
            s.rva = model.image_base ? s.va - model.image_base : s.va;
            model.sections.push_back(s);
        }
    }
    {
        Stmt st(db_, "SELECT start,end,name FROM functions ORDER BY start");
        while (st.step()) {
            Function f;
            f.start = static_cast<u64>(sqlite3_column_int64(st.s, 0));
            f.end = static_cast<u64>(sqlite3_column_int64(st.s, 1));
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 2));
            f.name = n ? n : "";
            model.functions.push_back(std::move(f));
        }
        Stmt blk(db_, "SELECT func,start,end FROM blocks ORDER BY func,start");
        while (blk.step()) {
            u64 func = static_cast<u64>(sqlite3_column_int64(blk.s, 0));
            BasicBlock b;
            b.start = static_cast<u64>(sqlite3_column_int64(blk.s, 1));
            b.end = static_cast<u64>(sqlite3_column_int64(blk.s, 2));
            for (auto& f : model.functions)
                if (f.start == func) f.blocks.push_back(b);
        }
        Stmt ed(db_, "SELECT func,src,dst,kind FROM edges");
        while (ed.step()) {
            u64 func = static_cast<u64>(sqlite3_column_int64(ed.s, 0));
            u64 src = static_cast<u64>(sqlite3_column_int64(ed.s, 1));
            Edge e;
            e.target = static_cast<u64>(sqlite3_column_int64(ed.s, 2));
            e.kind = static_cast<EdgeKind>(sqlite3_column_int(ed.s, 3));
            for (auto& f : model.functions) {
                if (f.start != func) continue;
                for (auto& b : f.blocks)
                    if (b.start == src) b.succs.push_back(e);
            }
        }
        Stmt lp(db_, "SELECT func,header,back_from FROM loops");
        while (lp.step()) {
            u64 func = static_cast<u64>(sqlite3_column_int64(lp.s, 0));
            LoopInfo l;
            l.header = static_cast<u64>(sqlite3_column_int64(lp.s, 1));
            l.back_edge_from = static_cast<u64>(sqlite3_column_int64(lp.s, 2));
            for (auto& f : model.functions)
                if (f.start == func) f.loops.push_back(l);
        }
    }
    {
        Stmt st(db_, "SELECT va,len,bytes,mnem,text,flow FROM insns");
        while (st.step()) {
            Insn in;
            in.va = static_cast<u64>(sqlite3_column_int64(st.s, 0));
            in.len = static_cast<u8>(sqlite3_column_int(st.s, 1));
            const void* blob = sqlite3_column_blob(st.s, 2);
            int bn = sqlite3_column_bytes(st.s, 2);
            if (blob && bn > 0) std::memcpy(in.raw, blob, std::min(bn, 15));
            const char* m = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 3));
            const char* t = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 4));
            if (m) std::snprintf(in.mnemonic, sizeof(in.mnemonic), "%s", m);
            if (t) std::snprintf(in.text, sizeof(in.text), "%s", t);
            in.flow = static_cast<Flow>(sqlite3_column_int(st.s, 5));
            model.insns.emplace(in.va, in);
        }
    }
    {
        Stmt st(db_, "SELECT src,dst,kind FROM xrefs");
        while (st.step()) {
            Xref x;
            x.src = static_cast<u64>(sqlite3_column_int64(st.s, 0));
            x.dst = static_cast<u64>(sqlite3_column_int64(st.s, 1));
            x.kind = static_cast<XrefKind>(sqlite3_column_int(st.s, 2));
            model.xrefs.push_back(x);
        }
    }
    {
        Stmt st(db_, "SELECT va,name FROM names");
        while (st.step()) {
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            model.names[static_cast<u64>(sqlite3_column_int64(st.s, 0))] = n ? n : "";
        }
    }
    {
        Stmt st(db_, "SELECT va,text FROM comments");
        while (st.step()) {
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            model.comments[static_cast<u64>(sqlite3_column_int64(st.s, 0))] = n ? n : "";
        }
    }
    {
        Stmt st(db_, "SELECT dll,name,ordinal,iat_va FROM imports");
        while (st.step()) {
            ImportSym im;
            const char* d = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            im.dll = d ? d : "";
            im.name = n ? n : "";
            im.ordinal = static_cast<u16>(sqlite3_column_int(st.s, 2));
            im.iat_va = static_cast<u64>(sqlite3_column_int64(st.s, 3));
            model.imports.push_back(std::move(im));
        }
    }
    {
        Stmt st(db_, "SELECT va,name,ordinal,rva FROM exports");
        while (st.step()) {
            ExportSym ex;
            ex.va = static_cast<u64>(sqlite3_column_int64(st.s, 0));
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            ex.name = n ? n : "";
            ex.ordinal = static_cast<u16>(sqlite3_column_int(st.s, 2));
            ex.rva = static_cast<u64>(sqlite3_column_int64(st.s, 3));
            model.exports.push_back(std::move(ex));
        }
    }
    {
        Stmt st(db_, "SELECT va,text,utf16 FROM strings");
        while (st.step()) {
            StringHit s;
            s.va = static_cast<u64>(sqlite3_column_int64(st.s, 0));
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            s.text = n ? n : "";
            s.utf16 = sqlite3_column_int(st.s, 2) != 0;
            model.strings.push_back(std::move(s));
        }
    }
    {
        Stmt st(db_, "SELECT name,size FROM structs");
        while (st.step()) {
            StructType t;
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
            t.name = n ? n : "";
            t.size = sqlite3_column_int(st.s, 1);
            model.structs.push_back(std::move(t));
        }
        Stmt mem(db_, "SELECT struct,name,type_name,offset,size FROM members");
        while (mem.step()) {
            const char* sn = reinterpret_cast<const char*>(sqlite3_column_text(mem.s, 0));
            std::string sname = sn ? sn : "";
            TypeMember m;
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(mem.s, 1));
            const char* ty = reinterpret_cast<const char*>(sqlite3_column_text(mem.s, 2));
            m.name = n ? n : "";
            m.type_name = ty ? ty : "";
            m.offset = sqlite3_column_int(mem.s, 3);
            m.size = sqlite3_column_int(mem.s, 4);
            for (auto& t : model.structs)
                if (t.name == sname) t.members.push_back(m);
        }
    }
    {
        Stmt st(db_, "SELECT va,type_name FROM type_uses");
        while (st.step()) {
            const char* n = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            model.type_at[static_cast<u64>(sqlite3_column_int64(st.s, 0))] = n ? n : "";
        }
    }
    model.reindex();
}

void Database::save_iat(const std::vector<IatSlot>& slots) {
    exec("DELETE FROM iat_slots");
    Stmt st(db_, "INSERT INTO iat_slots(slot_rva,raw_value,resolved,module,name,ordinal,trampoline,note) VALUES(?,?,?,?,?,?,?,?)");
    for (const auto& s : slots) {
        st.bind_i64(1, static_cast<i64>(s.slot_rva));
        st.bind_i64(2, static_cast<i64>(s.raw_value));
        st.bind_i64(3, static_cast<i64>(s.resolved));
        st.bind_text(4, s.module);
        st.bind_text(5, s.name);
        st.bind_int(6, s.ordinal);
        st.bind_int(7, s.trampoline ? 1 : 0);
        st.bind_text(8, s.note);
        st.step();
        st.reset();
    }
}

void Database::set_name(u64 va, const std::string& name) {
    Stmt st(db_, "INSERT INTO names(va,name) VALUES(?,?) ON CONFLICT(va) DO UPDATE SET name=excluded.name");
    st.bind_i64(1, static_cast<i64>(va));
    st.bind_text(2, name);
    st.step();
}

void Database::set_comment(u64 va, const std::string& text) {
    Stmt st(db_, "INSERT INTO comments(va,text) VALUES(?,?) ON CONFLICT(va) DO UPDATE SET text=excluded.text");
    st.bind_i64(1, static_cast<i64>(va));
    st.bind_text(2, text);
    st.step();
}

void Database::define_struct(const StructType& type) {
    Stmt delm(db_, "DELETE FROM members WHERE struct=?");
    delm.bind_text(1, type.name);
    delm.step();
    Stmt st(db_, "INSERT INTO structs(name,size) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET size=excluded.size");
    st.bind_text(1, type.name);
    st.bind_int(2, type.size);
    st.step();
    Stmt mem(db_, "INSERT INTO members(struct,name,type_name,offset,size) VALUES(?,?,?,?,?)");
    for (const auto& m : type.members) {
        mem.bind_text(1, type.name);
        mem.bind_text(2, m.name);
        mem.bind_text(3, m.type_name);
        mem.bind_int(4, m.offset);
        mem.bind_int(5, m.size);
        mem.step();
        mem.reset();
    }
}

void Database::apply_type(u64 va, const std::string& type_name) {
    Stmt st(db_, "INSERT INTO type_uses(va,type_name) VALUES(?,?) ON CONFLICT(va) DO UPDATE SET type_name=excluded.type_name");
    st.bind_i64(1, static_cast<i64>(va));
    st.bind_text(2, type_name);
    st.step();
}

std::string Database::query_json(const std::string& sql) const {
    if (!is_readonly_sql(sql)) throw std::runtime_error("only a single SELECT, WITH, PRAGMA, or EXPLAIN is allowed");
    Stmt st(db_, sql.c_str());
    int cols = sqlite3_column_count(st.s);
    Json arr = Json::array();
    while (st.step()) {
        Json row = Json::object();
        for (int c = 0; c < cols; ++c) {
            const char* name = sqlite3_column_name(st.s, c);
            std::string key = name ? name : ("c" + std::to_string(c));
            int type = sqlite3_column_type(st.s, c);
            if (type == SQLITE_NULL) row.set(key, Json::nul());
            else if (type == SQLITE_INTEGER) row.set(key, Json::number_u64(static_cast<unsigned long long>(sqlite3_column_int64(st.s, c))));
            else if (type == SQLITE_FLOAT) row.set(key, Json::number(sqlite3_column_double(st.s, c)));
            else {
                const char* t = reinterpret_cast<const char*>(sqlite3_column_text(st.s, c));
                row.set(key, Json::string(t ? t : ""));
            }
        }
        arr.arr.push_back(std::move(row));
    }
    return arr.dump();
}

void Database::netnode_set(const std::string& node, i64 alt, const std::string& tag, const std::vector<u8>& data) {
    Stmt st(db_, "INSERT INTO netnodes(node,alt,tag,data) VALUES(?,?,?,?) "
                 "ON CONFLICT(node,alt,tag) DO UPDATE SET data=excluded.data");
    st.bind_text(1, node);
    st.bind_i64(2, alt);
    st.bind_text(3, tag);
    st.bind_blob(4, data.data(), static_cast<int>(data.size()));
    st.step();
}

std::vector<u8> Database::netnode_get(const std::string& node, i64 alt, const std::string& tag) const {
    Stmt st(db_, "SELECT data FROM netnodes WHERE node=? AND alt=? AND tag=?");
    st.bind_text(1, node);
    st.bind_i64(2, alt);
    st.bind_text(3, tag);
    if (!st.step()) return {};
    const u8* p = reinterpret_cast<const u8*>(sqlite3_column_blob(st.s, 0));
    int n = sqlite3_column_bytes(st.s, 0);
    if (!p || n <= 0) return {};
    return std::vector<u8>(p, p + n);
}

}  // namespace aerore
