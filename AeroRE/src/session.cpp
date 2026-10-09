#include "aerore/session.hpp"

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
    progress_.post("load", label, 2);
    image_ = std::make_unique<PeImage>(PeImage::parse(std::move(bytes)));
    image_->set_path_hint(label);
    if (auto_unpack) {
        if (IUnpacker* u = unpackers_.best(*image_)) {
            if (u->detect(*image_) >= 60) {
                progress_.post("unpack", u->name(), 4);
                UnpackResult r = u->unpack(*image_, progress_);
                error_ = r.log;
                if (r.ok && !r.rebuilt.empty()) {
                    image_ = std::make_unique<PeImage>(PeImage::parse(std::move(r.rebuilt)));
                    image_->set_path_hint(label);
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
    report = aerore::fix_iat(*image_, *decoder_, modules, patch);
    if (db_) db_->save_iat(report.slots);
    if (patch && report.patched) publish_from_image(true);
    return report;
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
    result = u->unpack(*image_, progress_);
    error_ = result.log;
    if (result.ok && !result.rebuilt.empty()) {
        std::string label = image_->path_hint();
        image_ = std::make_unique<PeImage>(PeImage::parse(result.rebuilt));
        image_->set_path_hint(label);
        publish_from_image(true);
    }
    return result;
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
