#pragma once

#include "aerore/decoder.hpp"
#include "aerore/pe.hpp"

#include <memory>
#include <string>
#include <vector>

namespace aerore {

struct DumpAssessment {
    bool virtualized = false;
    bool obfuscated = false;
    int virtualization_score = 0;
    int obfuscation_score = 0;
    std::vector<std::string> reasons;
};

struct UnpackResult {
    bool ok = false;
    int confidence = 0;
    std::string packer;
    std::string log;
    u64 oep_rva = 0;
    std::vector<u8> rebuilt;
    std::vector<std::string> lifted;
    bool static_unpack = false;
    size_t decompressed_blocks = 0;
    DumpAssessment assessment;
};

// Conservative post-unpack classifier used to gate automatic PE rewrites.
// A positive result means that table fixers must stay report-only.
DumpAssessment assess_dump(const PeImage& image, Decoder& decoder);

class IUnpacker {
public:
    virtual ~IUnpacker() = default;
    virtual std::string id() const = 0;
    virtual std::string name() const = 0;
    virtual int detect(const PeImage& image) const = 0;
    virtual UnpackResult unpack(PeImage& image, ProgressQueue& progress) = 0;
};

class UnpackerRegistry {
public:
    UnpackerRegistry();
    void add(std::unique_ptr<IUnpacker> unpacker);
    IUnpacker* best(const PeImage& image) const;
    std::vector<std::pair<std::string, int>> detect_all(const PeImage& image) const;
    const std::vector<std::unique_ptr<IUnpacker>>& all() const { return items_; }

private:
    std::vector<std::unique_ptr<IUnpacker>> items_;
};

}  // namespace aerore
