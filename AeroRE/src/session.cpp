#include "aerore/session.hpp"

#include "aerore/json.hpp"

#include <fstream>
#include <sstream>

namespace aerore {
namespace {

std::vector<u8> read_all(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path);
    return std::vector<u8>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

Session::Session() : model_(std::make_shared<ProgramModel>()), debugger_(std::make_unique<Debugger>()),
                     decoder_(std::make_unique<Decoder>(Arch::X64)) {}

Session::~Session() = default;

Decoder& Session::decoder() { return *decoder_; }
Debugger& Session::debugger() { return *debugger_; }
ProgressQueue& Session::progress() { return progress_; }
UnpackerRegistry& Session::unpackers() { return unpackers_; }

std::shared_ptr<const ProgramModel> Session::model() const {
    std::lock_guard lock(mu_);
    return model_;
}
PeImage* Session::image() { return image_.get(); }
const PeImage* Session::image() const { return image_.get(); }
Database* Session::db() { return db_.get(); }

void Session::ensure_db(const std::string& path) {
    if (!db_ || db_->path() != path) db_ = std::make_unique<Database>(path);
}

void Session::publish_from_image(bool run_analysis) {
    auto model = std::make_shared<ProgramModel>();
    model->image_base = image_->image_base();
    model->entry = image_->entry_va();
    model->is64 = image_->is64();
    model->arch = image_->arch();
    model->image_path = image_->path_hint();
    model->sections = image_->sections();
    model->imports = image_->imports();
    model->exports = image_->exports();
    model->tls_callbacks = image_->tls_callbacks();
    model->overlay_size = image_->overlay().size();
    model->unpack_log = error_;
    std::ostringstream rich;
    for (const auto& r : image_->rich())
        rich << "prod=" << r.prod_id << " build=" << r.build << " count=" << r.count << "; ";
    model->rich = rich.str();
    decoder_ = std::make_unique<Decoder>(image_->arch());
    if (run_analysis) stats_ = analyze(*image_, *decoder_, *model, progress_);
    model->reindex();
    if (db_) db_->save_model(*model);
    std::lock_guard lock(mu_);
    model_ = std::move(model);
}

void Session::load_bytes(std::vector<u8> bytes, const std::string& label, bool auto_unpack) {
    error_.clear();
    post_unpack_ = {};
    progress_.post("load", label, 2);
    image_ = std::make_unique<PeImage>(PeImage::parse(std::move(bytes)));
    image_->set_path_hint(label);
    preserved_exports_ = image_->exports();
    if (auto_unpack) {
        if (IUnpacker* u = unpackers_.best(*image_)) {
            if (u->detect(*image_) >= 60) {
                progress_.post("unpack", u->name(), 4);
                UnpackResult r = u->unpack(*image_, progress_);
                error_ = r.log;
                if (r.ok && !r.rebuilt.empty()) {
                    image_ = std::make_unique<PeImage>(PeImage::parse(std::move(r.rebuilt)));
                    image_->set_path_hint(label);
                    run_post_unpack_repairs(preserved_exports_, r);
                } else {
                    error_ = r.log;
                }
            }
        }
    }
    publish_from_image(true);
}

void Session::load_file(const std::string& path, bool auto_unpack) {
    load_bytes(read_all(path), path, auto_unpack);
}

void Session::open_db(const std::string& path) {
    ensure_db(path);
    auto model = std::make_shared<ProgramModel>();
    db_->load_model(*model);
    std::lock_guard lock(mu_);
    model_ = std::move(model);
}

void Session::save_db(const std::string& path) {
    ensure_db(path);
    auto snap = model();
    if (snap) db_->save_model(*snap);
}

IatReport Session::fix_iat(const std::vector<ModuleSpan>& modules, bool patch) {
    IatReport report;
    if (!image_) {
        report.message = "no image loaded";
        return report;
    }
    std::vector<ModuleSpan> available = modules.empty() ? debugger_->modules() : modules;
    report = aerore::fix_iat(*image_, *decoder_, available, patch);
    if (db_) db_->save_iat(report.slots);
    if (patch && report.patched) {
        std::string label = image_->path_hint();
        image_ = std::make_unique<PeImage>(PeImage::parse(image_->rebuild(false)));
        image_->set_path_hint(label);
        publish_from_image(true);
    }
    return report;
}

ExportFixReport Session::fix_exports(const std::vector<ExportSym>& candidates, bool patch) {
    ExportFixReport report;
    if (!image_) {
        report.message = "no image loaded";
        return report;
    }
    const auto& source = candidates.empty() ? preserved_exports_ : candidates;
    report = aerore::fix_exports(*image_, source, image_->path_hint(), patch);
    if (patch && report.patched) {
        std::string label = image_->path_hint();
        image_ = std::make_unique<PeImage>(PeImage::parse(image_->rebuild(false)));
        image_->set_path_hint(label);
        publish_from_image(true);
    }
    return report;
}

void Session::run_post_unpack_repairs(const std::vector<ExportSym>& preserved_exports, UnpackResult& result) {
    post_unpack_ = {};
    post_unpack_.ran = true;
    decoder_ = std::make_unique<Decoder>(image_->arch());
    post_unpack_.assessment = assess_dump(*image_, *decoder_);
    result.assessment = post_unpack_.assessment;

    std::ostringstream summary;
    summary << "post-unpack gate: virtualization=" << post_unpack_.assessment.virtualization_score
            << " obfuscation=" << post_unpack_.assessment.obfuscation_score << "\n";
    for (const auto& reason : post_unpack_.assessment.reasons) summary << "  " << reason << "\n";

    if (post_unpack_.assessment.virtualized || post_unpack_.assessment.obfuscated) {
        post_unpack_.iat.message = "automatic IAT repair skipped: dump remains virtualized or obfuscated";
        post_unpack_.exports.skipped = true;
        post_unpack_.exports.message = "automatic export repair skipped: dump remains virtualized or obfuscated";
        summary << post_unpack_.iat.message << "\n" << post_unpack_.exports.message << "\n";
    } else {
        post_unpack_.eligible = true;
        progress_.post("repair", "automatic IAT reconstruction", 96);
        post_unpack_.iat = aerore::fix_iat(*image_, *decoder_, debugger_->modules(), true);
        if (db_) db_->save_iat(post_unpack_.iat.slots);
        progress_.post("repair", "automatic export reconstruction", 98);
        post_unpack_.exports = aerore::fix_exports(*image_, preserved_exports, image_->path_hint(), true);
        summary << "IAT: " << post_unpack_.iat.message << "\n";
        summary << "exports: " << post_unpack_.exports.message << "\n";

        if (post_unpack_.iat.patched || post_unpack_.exports.patched) {
            std::string label = image_->path_hint();
            image_ = std::make_unique<PeImage>(PeImage::parse(image_->rebuild(false)));
            image_->set_path_hint(label);
            decoder_ = std::make_unique<Decoder>(image_->arch());
        }
    }
    post_unpack_.summary = summary.str();
    result.log += post_unpack_.summary;
    result.rebuilt = image_->rebuild(false);
    error_ = result.log;
}

UnpackResult Session::unpack_best() {
    UnpackResult result;
    if (!image_) {
        result.log = "no image loaded";
        return result;
    }
    IUnpacker* u = unpackers_.best(*image_);
    if (!u) {
        result.log = "no unpacker scored high enough";
        return result;
    }
    const std::vector<ExportSym> preserved = image_->exports();
    preserved_exports_ = preserved;
    result = u->unpack(*image_, progress_);
    error_ = result.log;
    if (result.ok && !result.rebuilt.empty()) {
        std::string label = image_->path_hint();
        image_ = std::make_unique<PeImage>(PeImage::parse(result.rebuilt));
        image_->set_path_hint(label);
        run_post_unpack_repairs(preserved, result);
        publish_from_image(true);
    }
    return result;
}

std::string Session::symbols_json() const {
    auto snap = model();
    if (!snap) throw std::runtime_error("no image loaded");
    Json root = Json::object();
    root.set("schema", Json::string("aerore.symbols.v1"));
    root.set("image", Json::string(snap->image_path));
    root.set("imageBase", Json::string(hex(snap->image_base)));
    root.set("architecture", Json::string(snap->is64 ? "x64" : "x86"));

    Json imports = Json::array();
    for (const auto& symbol : snap->imports) {
        Json item = Json::object();
        item.set("dll", Json::string(symbol.dll));
        item.set("name", Json::string(symbol.name));
        item.set("ordinal", Json::number_u64(symbol.ordinal));
        item.set("iatVa", Json::string(hex(symbol.iat_va)));
        imports.arr.push_back(std::move(item));
    }
    root.set("imports", std::move(imports));

    Json exports = Json::array();
    for (const auto& symbol : snap->exports) {
        Json item = Json::object();
        item.set("name", Json::string(symbol.name));
        item.set("ordinal", Json::number_u64(symbol.ordinal));
        item.set("rva", Json::string(hex(symbol.rva)));
        item.set("va", Json::string(hex(symbol.va)));
        exports.arr.push_back(std::move(item));
    }
    root.set("exports", std::move(exports));
    return root.dump();
}

void Session::export_symbols_json(const std::string& path) const {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot create " + path);
    const std::string json = symbols_json();
    out.write(json.data(), static_cast<std::streamsize>(json.size()));
    out.put('\n');
    if (!out) throw std::runtime_error("failed to write " + path);
}

std::string Session::query(const std::string& sql) {
    if (!db_) throw std::runtime_error("no database open");
    return db_->query_json(sql);
}

bool Session::set_name(u64 va, const std::string& name) {
    std::lock_guard lock(mu_);
    if (!model_) return false;
    auto next = std::make_shared<ProgramModel>(*model_);
    next->names[va] = name;
    for (auto& f : next->functions)
        if (f.start == va) f.name = name;
    model_ = std::move(next);
    if (db_) db_->set_name(va, name);
    return true;
}

bool Session::set_comment(u64 va, const std::string& text) {
    std::lock_guard lock(mu_);
    if (!model_) return false;
    auto next = std::make_shared<ProgramModel>(*model_);
    next->comments[va] = text;
    model_ = std::move(next);
    if (db_) db_->set_comment(va, text);
    return true;
}

void Session::define_struct(const StructType& type) {
    std::lock_guard lock(mu_);
    if (!model_) model_ = std::make_shared<ProgramModel>();
    auto next = std::make_shared<ProgramModel>(*model_);
    bool replaced = false;
    for (auto& s : next->structs)
        if (s.name == type.name) {
            s = type;
            replaced = true;
        }
    if (!replaced) next->structs.push_back(type);
    model_ = std::move(next);
    if (db_) db_->define_struct(type);
}

std::vector<u8> Session::read_va(u64 va, size_t n) const {
    std::vector<u8> out;
    if (!image_ || n == 0 || !image_->contains_va(va)) return out;
    u64 rva = image_->va_to_rva(va);
    size_t take = std::min(n, image_->avail_rva(rva));
    out.resize(take);
    if (!image_->read_rva(rva, out.data(), take)) out.clear();
    return out;
}

}  // namespace aerore
