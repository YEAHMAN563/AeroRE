#pragma once

#include "aerore/model.hpp"

#include <string>

struct sqlite3;

namespace aerore {

// IDA-style IDB. One SQLite file holds the program database: functions, blocks,
// edges, insns, xrefs, names, comments, types, imports/exports, segments, and
// a netnode blob table for plugins.
class Database {
public:
    explicit Database(const std::string& path);
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    const std::string& path() const { return path_; }

    void save_model(const ProgramModel& model);
    void load_model(ProgramModel& model);
    void save_iat(const std::vector<IatSlot>& slots);
    void set_meta(const std::string& key, const std::string& value);
    std::string meta(const std::string& key) const;

    void set_name(u64 va, const std::string& name);
    void set_comment(u64 va, const std::string& text);
    void define_struct(const StructType& type);
    void apply_type(u64 va, const std::string& type_name);

    // Read-only. Rejects anything that is not a single SELECT/WITH/PRAGMA/EXPLAIN.
    std::string query_json(const std::string& sql) const;

    void netnode_set(const std::string& node, i64 alt, const std::string& tag, const std::vector<u8>& data);
    std::vector<u8> netnode_get(const std::string& node, i64 alt, const std::string& tag) const;

private:
    void exec(const char* sql);
    void migrate();

    sqlite3* db_ = nullptr;
    std::string path_;
};

}  // namespace aerore
