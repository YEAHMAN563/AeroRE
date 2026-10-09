#pragma once

#include "aerore/database.hpp"
#include "aerore/debugger.hpp"
#include "aerore/decoder.hpp"
#include "aerore/engine.hpp"
#include "aerore/pe.hpp"
#include "aerore/unpack.hpp"

#include <mutex>

namespace aerore {

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
    UnpackResult unpack_best();
    std::string query(const std::string& sql);

    bool set_name(u64 va, const std::string& name);
    bool set_comment(u64 va, const std::string& text);
    void define_struct(const StructType& type);
    std::vector<u8> read_va(u64 va, size_t n) const;

    const std::string& last_error() const { return error_; }
    const AnalysisStats& last_stats() const { return stats_; }

private:
    void publish_from_image(bool run_analysis);
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
    std::string error_;
};

}  // namespace aerore
