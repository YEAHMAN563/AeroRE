#include "aerore/unpack.hpp"

#include "aerore/emu.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <sstream>

#ifdef AERORE_HAS_LZMA
#include <lzma.h>
#endif

namespace aerore {
namespace {

constexpr u32 kScnUninitialized = 0x00000080;
constexpr u32 kScnExecute = 0x20000000;
constexpr u32 kScnRead = 0x40000000;
constexpr size_t kLzmaProbe = 512;
constexpr std::array<u8, 5> kDefaultLzmaProperties{{0x5d, 0x00, 0x00, 0x00, 0x04}};

u16 get_u16(const u8* p) {
    u16 value = 0;
    std::memcpy(&value, p, 2);
    return value;
}

u32 get_u32(const u8* p) {
    u32 value = 0;
    std::memcpy(&value, p, 4);
    return value;
}

void put_u32(u8* p, u32 value) { std::memcpy(p, &value, 4); }

u32 rotate_left(u32 value, unsigned count) {
    count &= 31;
    return count ? (value << count) | (value >> (32 - count)) : value;
}

std::string lower_name(std::string s) { return to_lower_copy(std::move(s)); }

const SectionInfo* section_containing_rva(const PeImage& image, u64 rva) {
    for (const auto& s : image.sections()) {
        if (rva >= s.rva && rva < s.rva + std::max<u64>(s.vsize, 1)) return &s;
    }
    return nullptr;
}

std::optional<size_t> raw_offset(const PeImage& image, u32 rva) {
    const auto& file = image.file_bytes();
    if (rva < image.size_of_headers()) return rva < file.size() ? std::optional<size_t>(rva) : std::nullopt;
    for (const auto& s : image.sections()) {
        if (rva < s.rva || rva >= s.rva + s.vsize) continue;
        u64 delta = rva - s.rva;
        if (!s.raw_ptr || delta >= s.raw_size) return std::nullopt;
        u64 off = static_cast<u64>(s.raw_ptr) + delta;
        if (off >= file.size()) return std::nullopt;
        return static_cast<size_t>(off);
    }
    return std::nullopt;
}

std::vector<const SectionInfo*> packed_sections(const PeImage& image) {
    std::vector<const SectionInfo*> out;
    for (const auto& s : image.sections()) {
        if (s.raw_size == 0 && s.raw_ptr == 0 && (s.chars & kScnUninitialized) == 0) out.push_back(&s);
    }
    return out;
}

struct PackerEntry {
    u32 source_rva = 0;
    u32 destination_rva = 0;
};

struct PackerTable {
    bool found = false;
    bool encrypted = false;
    size_t file_offset = 0;
    std::array<u8, 5> properties = kDefaultLzmaProperties;
    std::vector<PackerEntry> entries;
};

bool lzma_decode(const std::array<u8, 5>& properties, const u8* compressed, size_t compressed_size,
                 size_t output_limit, std::vector<u8>& output, std::string& error) {
#ifdef AERORE_HAS_LZMA
    if (!compressed || compressed_size == 0 || output_limit == 0) {
        error = "empty LZMA block";
        return false;
    }
    lzma_filter filters[2] = {{LZMA_FILTER_LZMA1, nullptr}, {LZMA_VLI_UNKNOWN, nullptr}};
    lzma_ret rc = lzma_properties_decode(&filters[0], nullptr, properties.data(), properties.size());
    if (rc != LZMA_OK) {
        error = "invalid LZMA properties";
        return false;
    }
    lzma_stream stream = LZMA_STREAM_INIT;
    rc = lzma_raw_decoder(&stream, filters);
    lzma_filters_free(filters, nullptr);
    if (rc != LZMA_OK) {
        error = "cannot initialize raw LZMA decoder";
        return false;
    }

    output.assign(output_limit, 0);
    stream.next_in = compressed;
    stream.avail_in = compressed_size;
    stream.next_out = output.data();
    stream.avail_out = output.size();
    bool ok = false;
    for (;;) {
        rc = lzma_code(&stream, LZMA_FINISH);
        if (rc == LZMA_STREAM_END || stream.avail_out == 0) {
            ok = true;
            break;
        }
        if (rc != LZMA_OK || stream.avail_in == 0) break;
    }
    const size_t produced = output.size() - stream.avail_out;
    lzma_end(&stream);
    output.resize(produced);
    if (!ok || output.empty()) {
        error = "raw LZMA stream did not terminate inside its destination bound";
        return false;
    }
    return true;
#else
    (void)properties;
    (void)compressed;
    (void)compressed_size;
    (void)output_limit;
    (void)output;
    error = "AeroRE was built without liblzma";
    return false;
#endif
}

#ifdef AERORE_HAS_LZMA
bool probe_lzma(const std::array<u8, 5>& properties, const u8* compressed, size_t size) {
    std::vector<u8> probe;
    std::string error;
    return lzma_decode(properties, compressed, size, kLzmaProbe, probe, error);
}
#endif

PackerTable find_legacy_table(const PeImage& image, const std::vector<const SectionInfo*>& destinations) {
    PackerTable result;
    const auto& file = image.file_bytes();
    if (destinations.empty()) return result;
    const size_t bytes = destinations.size() * 8;
    for (size_t off = 8; off + bytes <= file.size(); ++off) {
        bool match = true;
        for (size_t i = 0; i < destinations.size(); ++i) {
            if (get_u32(file.data() + off + i * 8 + 4) != destinations[i]->rva) {
                match = false;
                break;
            }
        }
        if (!match) continue;
        u32 props_rva = get_u32(file.data() + off - 8);
        auto props_off = raw_offset(image, props_rva);
        if (!props_off || *props_off + result.properties.size() > file.size()) continue;
        std::memcpy(result.properties.data(), file.data() + *props_off, result.properties.size());
        if (result.properties[0] >= 225) continue;
        result.found = true;
        result.file_offset = off;
        bool sources_valid = true;
        for (size_t i = 0; i < destinations.size(); ++i) {
            PackerEntry entry{get_u32(file.data() + off + i * 8),
                              get_u32(file.data() + off + i * 8 + 4)};
            auto source = raw_offset(image, entry.source_rva);
            if (!source || file[*source] != 0) {
                sources_valid = false;
                break;
            }
#ifdef AERORE_HAS_LZMA
            if (!probe_lzma(result.properties, file.data() + *source, file.size() - *source)) {
                sources_valid = false;
                break;
            }
#endif
            result.entries.push_back(entry);
        }
        if (!sources_valid) {
            result = {};
            continue;
        }
        return result;
    }
    return result;
}

PackerTable find_encrypted_table(const PeImage& image, const std::vector<const SectionInfo*>& destinations) {
    PackerTable result;
    const auto& file = image.file_bytes();
    const size_t count = destinations.size();
    if (count < 2) return result;
    std::set<u32> destination_rvas;
    for (const SectionInfo* s : destinations) destination_rvas.insert(static_cast<u32>(s->rva));

    for (size_t off = 0; off + count * 8 <= file.size(); ++off) {
        bool sources_plausible = true;
        std::vector<size_t> source_offsets;
        for (size_t i = 0; i < count; ++i) {
            auto raw = raw_offset(image, get_u32(file.data() + off + i * 8));
            if (!raw || *raw >= file.size() || file[*raw] != 0) {
                sources_plausible = false;
                break;
            }
            source_offsets.push_back(*raw);
        }
        if (!sources_plausible) continue;

        const u32 first_stored = get_u32(file.data() + off + 4);
        for (const SectionInfo* seed : destinations) {
            const u32 key = first_stored ^ static_cast<u32>(seed->rva);
            std::set<u32> seen;
            std::vector<PackerEntry> entries;
            for (size_t i = 0; i < count; ++i) {
                const u32 stored = get_u32(file.data() + off + i * 8 + 4);
                const u32 destination = stored ^ rotate_left(key, static_cast<unsigned>(7 * i));
                if (!destination_rvas.count(destination) || !seen.insert(destination).second) break;
                entries.push_back({get_u32(file.data() + off + i * 8), destination});
            }
            if (entries.size() != count) continue;
#ifdef AERORE_HAS_LZMA
            bool decodes = true;
            for (size_t i = 0; i < count; ++i) {
                decodes = probe_lzma(kDefaultLzmaProperties, file.data() + source_offsets[i],
                                     file.size() - source_offsets[i]);
                if (!decodes) break;
            }
            if (!decodes) continue;
#endif
            result.found = true;
            result.encrypted = true;
            result.file_offset = off;
            result.entries = std::move(entries);
            return result;
        }
    }
    return result;
}

PackerTable locate_packer_table(const PeImage& image, const std::vector<const SectionInfo*>& destinations) {
    PackerTable table = find_legacy_table(image, destinations);
    return table.found ? table : find_encrypted_table(image, destinations);
}

struct StaticUnpackResult {
    bool ok = false;
    size_t blocks = 0;
    std::vector<u8> rebuilt;
    std::string log;
};

StaticUnpackResult static_unpack_vmprotect(const PeImage& image, ProgressQueue& progress) {
    StaticUnpackResult result;
    const auto destinations = packed_sections(image);
    if (destinations.empty()) {
        result.log = "no virtual-only VMProtect sections found; using stub tracing\n";
        return result;
    }
    progress.post("unpack", "locating VMProtect PACKER_INFO", 16);
    PackerTable table = locate_packer_table(image, destinations);
    if (!table.found) {
        result.log = "could not locate plaintext or encrypted VMProtect PACKER_INFO; using stub tracing\n";
        return result;
    }

    const auto& file = image.file_bytes();
    if (image.size_of_image() == 0 || image.size_of_headers() > file.size() ||
        image.size_of_headers() > image.size_of_image()) {
        result.log = "invalid image/header size for static VMProtect reconstruction\n";
        return result;
    }
    result.rebuilt.assign(image.size_of_image(), 0);
    std::memcpy(result.rebuilt.data(), file.data(), image.size_of_headers());
    for (const auto& s : image.sections()) {
        if (!s.raw_ptr || !s.raw_size || s.raw_ptr >= file.size() || s.rva >= result.rebuilt.size()) continue;
        size_t take = static_cast<size_t>(std::min<u64>(s.raw_size, file.size() - s.raw_ptr));
        take = std::min(take, result.rebuilt.size() - static_cast<size_t>(s.rva));
        if (take) std::memcpy(result.rebuilt.data() + s.rva, file.data() + s.raw_ptr, take);
    }

    if (result.rebuilt.size() < 0x40) {
        result.log = "rebuilt VMProtect image is too small\n";
        return result;
    }
    const u32 lfanew = get_u32(result.rebuilt.data() + 0x3c);
    if (static_cast<u64>(lfanew) + 24 > result.rebuilt.size()) {
        result.log = "rebuilt VMProtect NT headers are out of bounds\n";
        return result;
    }
    const u16 optional_size = get_u16(result.rebuilt.data() + lfanew + 20);
    const size_t section_headers = static_cast<size_t>(lfanew) + 24 + optional_size;
    if (section_headers + image.sections().size() * 40 > result.rebuilt.size()) {
        result.log = "rebuilt VMProtect section table is out of bounds\n";
        return result;
    }
    for (size_t i = 0; i < image.sections().size(); ++i) {
        u8* header = result.rebuilt.data() + section_headers + i * 40;
        put_u32(header + 20, static_cast<u32>(image.sections()[i].rva));
        if (image.sections()[i].vsize)
            put_u32(header + 16, static_cast<u32>(image.sections()[i].vsize));
    }

    std::ostringstream log;
    log << "VMProtect static reconstruction: PACKER_INFO at file offset " << hex(table.file_offset)
        << (table.encrypted ? " (Dst^rotl(key,7*n))" : " (plaintext)") << "\n";
    for (size_t i = 0; i < table.entries.size(); ++i) {
        const auto& entry = table.entries[i];
        auto source = raw_offset(image, entry.source_rva);
        const SectionInfo* destination = section_containing_rva(image, entry.destination_rva);
        if (!source || !destination || entry.destination_rva >= result.rebuilt.size()) {
            log << "block " << i << " has an invalid source or destination\n";
            result.log = log.str();
            result.rebuilt.clear();
            return result;
        }
        size_t destination_limit = result.rebuilt.size() - entry.destination_rva;
        const u64 inside = entry.destination_rva - destination->rva;
        if (inside < destination->vsize)
            destination_limit = std::min(destination_limit, static_cast<size_t>(destination->vsize - inside));
        std::vector<u8> decoded;
        std::string error;
        if (!lzma_decode(table.properties, file.data() + *source, file.size() - *source,
                         destination_limit, decoded, error)) {
            log << "block " << i << " LZMA decode failed: " << error << "\n";
            result.log = log.str();
            result.rebuilt.clear();
            return result;
        }
        std::memcpy(result.rebuilt.data() + entry.destination_rva, decoded.data(), decoded.size());
        ++result.blocks;
        log << "block " << i << " " << destination->name << " src=" << hex(entry.source_rva)
            << " dst=" << hex(entry.destination_rva) << " bytes=" << decoded.size() << "\n";
        progress.post("unpack", "decompressing " + destination->name,
                      20 + static_cast<int>((55 * (i + 1)) / table.entries.size()));
    }
    result.ok = result.blocks == table.entries.size();
    result.log = log.str();
    return result;
}

UnpackResult trace_and_dump(PeImage& image, const std::string& packer, ProgressQueue& progress) {
    progress.post("unpack", packer + " OEP trace", 78);
    UnpackResult result;
    result.packer = packer;
    const SectionInfo* sec = section_containing_rva(image, image.entry_rva());
    u64 lo = 0, hi = 0;
    if (sec) {
        lo = sec->va;
        hi = sec->va + std::max<u64>(sec->vsize, 1);
    }
    Decoder decoder(image.arch());
    TraceResult trace = trace_region(image, decoder, image.entry_va(), lo, hi, 250000);
    result.lifted = trace.lifted;
    std::ostringstream log;
    log << packer << " trace\n" << trace.log;
    for (const auto& line : trace.lifted) log << "lift " << line << "\n";
    if (trace.found_oep) {
        result.oep_rva = trace.oep_va - image.image_base();
        image.set_entry_rva(result.oep_rva);
        result.rebuilt = image.rebuild(true);
        result.ok = !result.rebuilt.empty();
        log << "dumped image, entry rva " << hex(result.oep_rva) << "\n";
        progress.post("unpack", "original entry located", 94);
    } else {
        log << "no clean handoff out of the protector section\n";
    }
    result.log = log.str();
    return result;
}

bool entry_matches(const PeImage& image, std::initializer_list<int> pattern) {
    const u8* p = image.ptr_rva(image.entry_rva(), pattern.size());
    if (!p) return false;
    size_t i = 0;
    for (int byte : pattern) {
        if (byte >= 0 && p[i] != static_cast<u8>(byte)) return false;
        ++i;
    }
    return true;
}

class VmProtectUnpacker final : public IUnpacker {
public:
    std::string id() const override { return "vmprotect"; }
    std::string name() const override { return "VMProtect"; }

    int detect(const PeImage& image) const override {
        const auto clr = image.data_directory(14);
        if (clr.first && clr.second) return 0;
        int score = 0;
        int virtual_only_before_entry = 0;
        const SectionInfo* entry = section_containing_rva(image, image.entry_rva());
        for (const auto& s : image.sections()) {
            std::string n = lower_name(s.name);
            const bool named = n.find("vmp") != std::string::npos;
            if (named) score += 45;
            if (&s == entry) {
                if (named) score += 25;
                if (s.entropy > 7.0 && s.executable) score += 12;
                if (s.chars == 0xE0000060 || s.chars == 0xE0000040 || s.chars == 0x60000060) score += 18;
            }
            if (s.rva < image.entry_rva() && s.raw_size == 0 && s.raw_ptr == 0 &&
                (s.chars & kScnUninitialized) == 0)
                ++virtual_only_before_entry;
        }
        if (entry && virtual_only_before_entry >= 3 && entry->raw_size &&
            (entry->chars & (kScnExecute | kScnRead)) == (kScnExecute | kScnRead) && entry->entropy > 7.0)
            score += 70;
        if (entry_matches(image, {0x9c, 0xe9}) || entry_matches(image, {0x9c, 0xff}) ||
            entry_matches(image, {0x68, -1, -1, -1, -1, 0xe9}) ||
            entry_matches(image, {0x68, -1, -1, -1, -1, 0xe8}))
            score += 50;
        return std::min(score, 100);
    }

    UnpackResult unpack(PeImage& image, ProgressQueue& progress) override {
        const int confidence = detect(image);
        StaticUnpackResult static_result = static_unpack_vmprotect(image, progress);
        UnpackResult result;
        if (static_result.ok) {
            PeImage expanded = PeImage::parse(static_result.rebuilt);
            expanded.set_path_hint(image.path_hint());
            result = trace_and_dump(expanded, name(), progress);
            result.static_unpack = true;
            result.decompressed_blocks = static_result.blocks;
            result.log = static_result.log + result.log;
            if (!result.ok) {
                result.ok = true;
                result.oep_rva = expanded.entry_rva();
                result.rebuilt = expanded.rebuild(true);
                result.log += "static section reconstruction succeeded; keeping current entry for manual OEP review\n";
            }
        } else {
            result = trace_and_dump(image, name(), progress);
            result.log = static_result.log + result.log;
        }
        result.confidence = confidence;
        if (!result.lifted.empty())
            result.log += "handler effects recovered: " + std::to_string(result.lifted.size()) +
                          " (bounded semantic lifting)\n";
        if (!result.rebuilt.empty()) {
            PeImage rebuilt = PeImage::parse(result.rebuilt);
            Decoder decoder(rebuilt.arch());
            result.assessment = assess_dump(rebuilt, decoder);
        }
        progress.post("unpack", "post-unpack classification complete", 100);
        return result;
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
        auto result = trace_and_dump(image, name(), progress);
        result.confidence = detect(image);
        result.log += "Themida plugin uses the shared stub tracer. A dedicated mutation engine is not shipped.\n";
        if (!result.rebuilt.empty()) {
            PeImage rebuilt = PeImage::parse(result.rebuilt);
            Decoder decoder(rebuilt.arch());
            result.assessment = assess_dump(rebuilt, decoder);
        }
        return result;
    }
};

class EnigmaUnpacker final : public IUnpacker {
public:
    std::string id() const override { return "enigma"; }
    std::string name() const override { return "Enigma"; }
    int detect(const PeImage& image) const override {
        int score = 0;
        for (const auto& s : image.sections())
            if (lower_name(s.name).find("enigma") != std::string::npos) score += 70;
        return std::min(score, 100);
    }
    UnpackResult unpack(PeImage& image, ProgressQueue& progress) override {
        auto result = trace_and_dump(image, name(), progress);
        result.confidence = detect(image);
        result.log += "Enigma plugin uses the shared stub tracer.\n";
        if (!result.rebuilt.empty()) {
            PeImage rebuilt = PeImage::parse(result.rebuilt);
            Decoder decoder(rebuilt.arch());
            result.assessment = assess_dump(rebuilt, decoder);
        }
        return result;
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
        auto result = trace_and_dump(image, name(), progress);
        result.confidence = detect(image);
        if (!result.rebuilt.empty()) {
            PeImage rebuilt = PeImage::parse(result.rebuilt);
            Decoder decoder(rebuilt.arch());
            result.assessment = assess_dump(rebuilt, decoder);
        }
        return result;
    }
};

}  // namespace

DumpAssessment assess_dump(const PeImage& image, Decoder& decoder) {
    DumpAssessment result;
    const SectionInfo* entry = section_containing_rva(image, image.entry_rva());
    if (!entry) {
        result.obfuscation_score = 100;
        result.obfuscated = true;
        result.reasons.push_back("entry point is outside every section");
        return result;
    }

    const std::string entry_name = lower_name(entry->name);
    if (entry_name.find("vmp") != std::string::npos || entry_name.find("themida") != std::string::npos ||
        entry_name.find("enigma") != std::string::npos) {
        result.virtualization_score += 65;
        result.obfuscation_score += 30;
        result.reasons.push_back("entry point remains in a protector-named section");
    }
    if (entry->entropy > 7.15) {
        result.virtualization_score += 20;
        result.obfuscation_score += 25;
        result.reasons.push_back("entry section remains high entropy");
    }
    if (entry->executable && entry->writable) {
        result.obfuscation_score += 12;
        result.reasons.push_back("entry section is writable and executable");
    }

    size_t virtual_only = 0;
    for (const auto& s : image.sections())
        if (s.rva < image.entry_rva() && s.raw_size == 0 && s.raw_ptr == 0 &&
            (s.chars & kScnUninitialized) == 0)
            ++virtual_only;
    if (virtual_only >= 3) {
        result.virtualization_score += 40;
        result.obfuscation_score += 20;
        result.reasons.push_back("multiple original sections are still virtual-only");
    }

    u64 va = image.entry_va();
    const u64 end = std::min<u64>(entry->va + entry->vsize, va + 8192);
    size_t decoded = 0, invalid = 0, indirect = 0, vm_ops = 0;
    while (va < end && decoded + invalid < 512) {
        const u64 rva = image.va_to_rva(va);
        const size_t take = std::min<size_t>(image.avail_rva(rva), 15);
        u8 bytes[15]{};
        if (!take || !image.read_rva(rva, bytes, take)) break;
        auto instruction = decoder.decode(va, bytes, take);
        if (!instruction || instruction->len == 0) {
            ++invalid;
            ++va;
            continue;
        }
        ++decoded;
        if ((instruction->flow == Flow::Jmp || instruction->flow == Flow::Call) &&
            (!instruction->target_valid || instruction->target_is_mem))
            ++indirect;
        const u8 op = instruction->raw[0];
        if (op == 0x9c || op == 0x9d || op == 0xf5 || op == 0xf8 || op == 0xf9 ||
            (op >= 0xd0 && op <= 0xd3) || (op >= 0x30 && op <= 0x33) ||
            (op == 0x0f && instruction->len > 1 && instruction->raw[1] == 0x31))
            ++vm_ops;
        va += instruction->len;
    }
    const size_t total = decoded + invalid;
    if (total >= 32 && invalid * 4 > total) {
        result.obfuscation_score += 40;
        result.reasons.push_back("entry decoding has a high invalid-instruction ratio");
    }
    if (decoded >= 40 && vm_ops >= 12 && vm_ops * 5 > decoded) {
        result.virtualization_score += 45;
        result.obfuscation_score += 30;
        result.reasons.push_back("entry code has VM-dispatch arithmetic density");
    }
    if (decoded >= 24 && indirect >= 6 && indirect * 8 > decoded) {
        result.virtualization_score += 35;
        result.obfuscation_score += 25;
        result.reasons.push_back("entry code has dense indirect control flow");
    }

    result.virtualization_score = std::min(result.virtualization_score, 100);
    result.obfuscation_score = std::min(result.obfuscation_score, 100);
    result.virtualized = result.virtualization_score >= 60;
    result.obfuscated = result.obfuscation_score >= 55;
    if (!result.virtualized && !result.obfuscated) result.reasons.push_back("dump passed conservative repair gate");
    return result;
}

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
        int score = item->detect(image);
        if (score > best_score) {
            best_score = score;
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
