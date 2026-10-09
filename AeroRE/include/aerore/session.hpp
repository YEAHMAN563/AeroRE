#pragma once

#include "aerore/database.hpp"
#include "aerore/debugger.hpp"
#include "aerore/decoder.hpp"
#include "aerore/engine.hpp"
#include "aerore/exports.hpp"
#include "aerore/pe.hpp"
#include "aerore/unpack.hpp"

#include <mutex>

namespace aerore {

struct PostUnpackRepair {
    bool ran = false;
    bool eligible = false;
    DumpAssessment assessment;
    IatReport iat;
    ExportFixReport exports;
    std::string summary;
};

class Session {
public:
    Session();
    ~Session();

    void load_file(const std::string& path, bool auto_unpack);
    void load_bytes(std::vector<u8> bytes, const std::string& label, bool auto_unpack);
    void open_db(const std::string& path);
    void save_db(const std::string& path);

    std::shared_ptr<const ProgramModel> model() const;
    PeImage* image();
    const PeImage* image() const;
    Database* db();
    Debugger& debugger();
    ProgressQueue& progress();
    UnpackerRegistry& unpackers();
    Decoder& decoder();

    IatReport fix_iat(const std::vector<ModuleSpan>& modules, bool patch);
    ExportFixReport fix_exports(const std::vector<ExportSym>& candidates, bool patch);
    UnpackResult unpack_best();
    std::string symbols_json() const;
    void export_symbols_json(const std::string& path) const;
    std::string query(const std::string& sql);

    bool set_name(u64 va, const std::string& name);
    bool set_comment(u64 va, const std::string& text);
    void define_struct(const StructType& type);
    std::vector<u8> read_va(u64 va, size_t n) const;

    const std::string& last_error() const { return error_; }
    const AnalysisStats& last_stats() const { return stats_; }
    const PostUnpackRepair& last_post_unpack() const { return post_unpack_; }

private:
    void publish_from_image(bool run_analysis);
    void run_post_unpack_repairs(const std::vector<ExportSym>& preserved_exports, UnpackResult& result);
    void ensure_db(const std::string& path);

    mutable std::mutex mu_;
    std::shared_ptr<ProgramModel> model_;
    std::unique_ptr<PeImage> image_;
    std::unique_ptr<Database> db_;
    std::unique_ptr<Debugger> debugger_;
    std::unique_ptr<Decoder> decoder_;
    ProgressQueue progress_;
    UnpackerRegistry unpackers_;
    AnalysisStats stats_{};
    PostUnpackRepair post_unpack_{};
    std::vector<ExportSym> preserved_exports_;
    std::string error_;
};

}  // namespace aerore
