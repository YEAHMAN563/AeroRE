#include "aerore/unpack.hpp"

#include "aerore/emu.hpp"

#include <algorithm>
#include <sstream>

namespace aerore {
namespace {

std::string lower_name(std::string s) { return to_lower_copy(std::move(s)); }

const SectionInfo* section_containing_rva(const PeImage& image, u64 rva) {
    for (const auto& s : image.sections()) {
        if (rva >= s.rva && rva < s.rva + std::max<u64>(s.vsize, 1)) return &s;
    }
    return nullptr;
}

UnpackResult trace_and_dump(PeImage& image, const std::string& packer, ProgressQueue& progress) {
    progress.post("unpack", packer, 8);
    UnpackResult result;
    result.packer = packer;
    const SectionInfo* sec = section_containing_rva(image, image.entry_rva());
    u64 lo = 0, hi = 0;
    if (sec) {
        lo = sec->va;
        hi = sec->va + std::max<u64>(sec->vsize, 1);
    }
    Decoder decoder(image.arch());
    TraceResult tr = trace_region(image, decoder, image.entry_va(), lo, hi, 250000);
    result.lifted = tr.lifted;
    std::ostringstream log;
    log << packer << " trace\n" << tr.log;
    for (const auto& line : tr.lifted) log << "lift " << line << "\n";
    if (tr.found_oep) {
        result.oep_rva = tr.oep_va - image.image_base();
        image.set_entry_rva(result.oep_rva);
        result.rebuilt = image.rebuild(true);
        result.ok = !result.rebuilt.empty();
        log << "dumped image, entry rva " << hex(result.oep_rva) << "\n";
        progress.post("unpack", "original entry located", 100);
    } else {
        log << "no clean handoff out of the protector section\n";
        progress.post("unpack", "no oep", 100);
    }
    result.log = log.str();
    return result;
}

class VmProtectUnpacker final : public IUnpacker {
public:
    std::string id() const override { return "vmprotect"; }
    std::string name() const override { return "VMProtect"; }
    int detect(const PeImage& image) const override {
        int score = 0;
        for (const auto& s : image.sections()) {
            std::string n = lower_name(s.name);
            bool vmp = n.find("vmp") != std::string::npos;
            if (vmp) score += 50;
            if (image.entry_rva() >= s.rva && image.entry_rva() < s.rva + std::max<u64>(s.vsize, 1)) {
                if (vmp) score += 25;
                if (s.entropy > 7.0 && s.executable) score += 10;
            }
        }
        return std::min(score, 100);
    }
    UnpackResult unpack(PeImage& image, ProgressQueue& progress) override {
        auto r = trace_and_dump(image, name(), progress);
        r.confidence = detect(image);
        if (!r.lifted.empty())
            r.log += "handler effects recovered: " + std::to_string(r.lifted.size()) +
                     " (bounded semantic diff, not a complete devirtualizer)\n";
        return r;
    }
};

class ThemidaUnpacker final : public IUnpacker {
public:
    std::string id() const override { return "themida"; }
    std::string name() const override { return "Themida"; }
    int detect(const PeImage& image) const override {
        int score = 0;
        for (const auto& s : image.sections()) {
            std::string n = lower_name(s.name);
            if (n.find("themida") != std::string::npos || n.find("winlice") != std::string::npos) score += 70;
        }
        return std::min(score, 100);
    }
    UnpackResult unpack(PeImage& image, ProgressQueue& progress) override {
        auto r = trace_and_dump(image, name(), progress);
        r.confidence = detect(image);
        r.log += "Themida plugin uses the shared stub tracer. A dedicated mutation engine is not shipped.\n";
        return r;
    }
};

class EnigmaUnpacker final : public IUnpacker {
public:
    std::string id() const override { return "enigma"; }
    std::string name() const override { return "Enigma"; }
    int detect(const PeImage& image) const override {
        int score = 0;
        for (const auto& s : image.sections()) {
            if (lower_name(s.name).find("enigma") != std::string::npos) score += 70;
        }
        return std::min(score, 100);
    }
    UnpackResult unpack(PeImage& image, ProgressQueue& progress) override {
        auto r = trace_and_dump(image, name(), progress);
        r.confidence = detect(image);
        r.log += "Enigma plugin uses the shared stub tracer.\n";
        return r;
    }
};

class GenericStubUnpacker final : public IUnpacker {
public:
    std::string id() const override { return "stub"; }
    std::string name() const override { return "Generic stub"; }
    int detect(const PeImage& image) const override {
        const SectionInfo* s = section_containing_rva(image, image.entry_rva());
        if (!s) return 0;
        std::string n = lower_name(s->name);
        if (n.find("upx") != std::string::npos || n == ".pack") return 58;
        if (n != ".text" && s->executable && s->entropy > 6.8) return 48;
        return 0;
    }
    UnpackResult unpack(PeImage& image, ProgressQueue& progress) override {
        auto r = trace_and_dump(image, name(), progress);
        r.confidence = detect(image);
        return r;
    }
};

}  // namespace

UnpackerRegistry::UnpackerRegistry() {
    add(std::make_unique<VmProtectUnpacker>());
    add(std::make_unique<ThemidaUnpacker>());
    add(std::make_unique<EnigmaUnpacker>());
    add(std::make_unique<GenericStubUnpacker>());
}

void UnpackerRegistry::add(std::unique_ptr<IUnpacker> unpacker) { items_.push_back(std::move(unpacker)); }

IUnpacker* UnpackerRegistry::best(const PeImage& image) const {
    IUnpacker* winner = nullptr;
    int best_score = 39;
    for (const auto& item : items_) {
        int s = item->detect(image);
        if (s > best_score) {
            best_score = s;
            winner = item.get();
        }
    }
    return winner;
}

std::vector<std::pair<std::string, int>> UnpackerRegistry::detect_all(const PeImage& image) const {
    std::vector<std::pair<std::string, int>> out;
    for (const auto& item : items_) out.emplace_back(item->id(), item->detect(image));
    return out;
}

}  // namespace aerore
