#include "aerore/pe.hpp"

#include <cmath>
#include <cstring>
#include <functional>
#include <sstream>

namespace aerore {
namespace {

constexpr u32 kDirExport = 0;
constexpr u32 kDirImport = 1;
constexpr u32 kDirResource = 2;
constexpr u32 kDirException = 3;
constexpr u32 kDirBaseReloc = 5;
constexpr u32 kDirDebug = 6;
constexpr u32 kDirTls = 9;
constexpr u32 kDirDelay = 13;

constexpr u32 kScnMemExecute = 0x20000000;
constexpr u32 kScnMemRead = 0x40000000;
constexpr u32 kScnMemWrite = 0x80000000;
constexpr u32 kScnCntCode = 0x00000020;

u16 ru16(const u8* p) {
    u16 v;
    std::memcpy(&v, p, 2);
    return v;
}
u32 ru32(const u8* p) {
    u32 v;
    std::memcpy(&v, p, 4);
    return v;
}
u64 ru64(const u8* p) {
    u64 v;
    std::memcpy(&v, p, 8);
    return v;
}
void wu16(u8* p, u16 v) { std::memcpy(p, &v, 2); }
void wu32(u8* p, u32 v) { std::memcpy(p, &v, 4); }

u64 align_up(u64 v, u64 a) {
    if (a == 0) return v;
    return (v + a - 1) & ~(a - 1);
}

std::string name8(const char* n) {
    size_t len = 0;
    while (len < 8 && n[len]) ++len;
    return std::string(n, len);
}

}  // namespace

double entropy_bytes(const u8* p, size_t n) {
    if (!p || n == 0) return 0;
    unsigned counts[256] = {};
    for (size_t i = 0; i < n; ++i) counts[p[i]]++;
    double h = 0;
    for (unsigned c : counts) {
        if (!c) continue;
        double prob = static_cast<double>(c) / static_cast<double>(n);
        h -= prob * std::log2(prob);
    }
    return h;
}

u32 PeImage::opt_offset() const { return e_lfanew_ + 4 + 20; }

u32 PeImage::dd_offset() const { return opt_offset() + (is64_ ? 112u : 96u); }

PeImage PeImage::parse(std::vector<u8> file) {
    if (file.size() < 0x40) throw std::runtime_error("file too small for DOS header");
    if (file[0] != 'M' || file[1] != 'Z') throw std::runtime_error("missing MZ signature");
    PeImage img;
    img.file_ = std::move(file);
    const u8* f = img.file_.data();
    const size_t n = img.file_.size();
    i32 lfanew = 0;
    std::memcpy(&lfanew, f + 0x3C, 4);
    if (lfanew <= 0 || static_cast<size_t>(lfanew) + 4 + 20 > n)
        throw std::runtime_error("bad e_lfanew");
    img.e_lfanew_ = static_cast<u32>(lfanew);
    if (std::memcmp(f + img.e_lfanew_, "PE\0\0", 4) != 0) throw std::runtime_error("missing PE signature");

    const u8* coff = f + img.e_lfanew_ + 4;
    img.machine_ = ru16(coff + 0);
    img.number_of_sections_ = ru16(coff + 2);
    img.size_of_optional_ = ru16(coff + 16);
    if (img.opt_offset() + img.size_of_optional_ > n) throw std::runtime_error("optional header truncated");
    const u8* opt = f + img.opt_offset();
    u16 magic = ru16(opt);
    if (magic == 0x20B) img.is64_ = true;
    else if (magic == 0x10B) img.is64_ = false;
    else throw std::runtime_error("unknown optional header magic");

    u32 min_opt = img.is64_ ? 112u : 96u;
    if (img.size_of_optional_ < min_opt) throw std::runtime_error("optional header too small");
    img.entry_rva_ = ru32(opt + 16);
    if (img.is64_) {
        img.image_base_ = ru64(opt + 24);
        img.section_align_ = ru32(opt + 32);
        img.file_align_ = ru32(opt + 36);
        img.size_of_image_ = ru32(opt + 56);
        img.size_of_headers_ = ru32(opt + 60);
        img.subsystem_ = ru16(opt + 68);
        img.num_dd_ = static_cast<int>(ru32(opt + 108));
    } else {
        img.image_base_ = ru32(opt + 28);
        img.section_align_ = ru32(opt + 32);
        img.file_align_ = ru32(opt + 36);
        img.size_of_image_ = ru32(opt + 56);
        img.size_of_headers_ = ru32(opt + 60);
        img.subsystem_ = ru16(opt + 68);
        img.num_dd_ = static_cast<int>(ru32(opt + 92));
    }
    if (img.num_dd_ < 0) img.num_dd_ = 0;
    if (img.num_dd_ > 16) img.num_dd_ = 16;
    if (img.section_align_ == 0) img.section_align_ = 0x1000;
    if (img.file_align_ == 0) img.file_align_ = 0x200;

    u32 sec_off = img.opt_offset() + img.size_of_optional_;
    if (static_cast<u64>(sec_off) + static_cast<u64>(img.number_of_sections_) * 40 > n)
        throw std::runtime_error("section table truncated");

    u64 map_size = img.size_of_image_;
    struct Tmp {
        SectionInfo info;
        u32 vsize_hdr;
    };
    std::vector<Tmp> tmps;
    u64 max_raw_end = img.size_of_headers_;
    for (u16 i = 0; i < img.number_of_sections_; ++i) {
        const u8* sh = f + sec_off + i * 40;
        SectionInfo s;
        s.name = name8(reinterpret_cast<const char*>(sh));
        u32 vsize = ru32(sh + 8);
        s.rva = ru32(sh + 12);
        s.va = img.image_base_ + s.rva;
        s.raw_size = ru32(sh + 16);
        s.raw_ptr = ru32(sh + 20);
        s.chars = ru32(sh + 36);
        s.executable = (s.chars & kScnMemExecute) || (s.chars & kScnCntCode);
        s.readable = (s.chars & kScnMemRead) || s.executable;
        s.writable = (s.chars & kScnMemWrite) != 0;
        u32 span = std::max(vsize, static_cast<u32>(std::min<u64>(s.raw_size, 0xffffffffu)));
        map_size = std::max(map_size, s.rva + span);
        if (s.raw_ptr && s.raw_size)
            max_raw_end = std::max(max_raw_end, static_cast<u64>(s.raw_ptr) + s.raw_size);
        tmps.push_back({s, vsize});
    }
    if (map_size > 1024ull * 1024ull * 1024ull) throw std::runtime_error("image too large");
    img.mapped_.assign(static_cast<size_t>(map_size), 0);
    size_t hdr_copy = std::min(static_cast<size_t>(img.size_of_headers_), n);
    hdr_copy = std::min(hdr_copy, img.mapped_.size());
    std::memcpy(img.mapped_.data(), f, hdr_copy);

    for (auto& t : tmps) {
        u32 vsize = t.vsize_hdr ? t.vsize_hdr : static_cast<u32>(t.info.raw_size);
        t.info.vsize = vsize;
        size_t copy = static_cast<size_t>(std::min<u64>(t.info.raw_size, vsize));
        if (t.info.raw_ptr < n) copy = std::min(copy, n - t.info.raw_ptr);
        else copy = 0;
        if (t.info.rva < img.mapped_.size())
            copy = std::min(copy, img.mapped_.size() - static_cast<size_t>(t.info.rva));
        if (copy && t.info.raw_ptr + copy <= n)
            std::memcpy(img.mapped_.data() + t.info.rva, f + t.info.raw_ptr, copy);
        const u8* ent = img.mapped_.data() + t.info.rva;
        size_t ent_n = std::min(static_cast<size_t>(vsize), img.mapped_.size() - static_cast<size_t>(t.info.rva));
        t.info.entropy = entropy_bytes(ent, ent_n);
        img.sections_.push_back(t.info);
    }
    if (max_raw_end < n) img.overlay_.assign(f + max_raw_end, f + n);

    img.parse_rich();
    img.parse_directories();
    return img;
}

void PeImage::parse_directories() {
    parse_imports();
    parse_exports();
    parse_relocs();
    parse_tls();
    parse_resources();
    // Delay-load imports share the ImportSym list.
    if (num_dd_ > static_cast<int>(kDirDelay)) {
        u32 rva = 0, size = 0;
        const u8* dd = file_.data() + dd_offset() + kDirDelay * 8;
        if (dd_offset() + (kDirDelay + 1) * 8 <= file_.size()) {
            rva = ru32(dd);
            size = ru32(dd + 4);
        }
        if (rva && size) {
            for (u32 off = 0; off + 32 <= size; off += 32) {
                u8 raw[32];
                if (!read_rva(rva + off, raw, 32)) break;
                if (ru32(raw) == 0 && ru32(raw + 4) == 0) break;
                u32 name_rva = ru32(raw + 4);
                u32 int_rva = ru32(raw + 16);
                u32 iat_rva = ru32(raw + 12);
                std::string dll = read_cstr(name_rva);
                u32 thunk_rva = int_rva ? int_rva : iat_rva;
                u32 slot = iat_rva;
                for (int guard = 0; guard < 100000; ++guard) {
                    u64 thunk = 0;
                    if (!read_ptr_rva(thunk_rva).has_value()) break;
                    thunk = *read_ptr_rva(thunk_rva);
                    if (thunk == 0) break;
                    ImportSym im;
                    im.dll = dll;
                    im.iat_va = image_base_ + slot;
                    u64 ord_flag = is64_ ? 0x8000000000000000ull : 0x80000000ull;
                    if (thunk & ord_flag) {
                        im.ordinal = static_cast<u16>(thunk & 0xffff);
                    } else {
                        u8 hint[2];
                        if (read_rva(static_cast<u64>(thunk), hint, 2)) {
                            im.ordinal = ru16(hint);
                            im.name = read_cstr(static_cast<u64>(thunk) + 2);
                        }
                    }
                    imports_.push_back(std::move(im));
                    thunk_rva += is64_ ? 8u : 4u;
                    slot += is64_ ? 8u : 4u;
                }
            }
        }
    }
}

void PeImage::parse_imports() {
    if (num_dd_ <= static_cast<int>(kDirImport)) return;
    if (dd_offset() + 16 > file_.size()) return;
    u32 rva = ru32(file_.data() + dd_offset() + kDirImport * 8);
    u32 size = ru32(file_.data() + dd_offset() + kDirImport * 8 + 4);
    if (!rva || !size) return;
    for (u32 off = 0; off + 20 <= size + 20; off += 20) {
        u8 desc[20];
        if (!read_rva(rva + off, desc, 20)) break;
        u32 oft = ru32(desc + 0);
        u32 name = ru32(desc + 12);
        u32 ft = ru32(desc + 16);
        if (oft == 0 && name == 0 && ft == 0) break;
        std::string dll = read_cstr(name);
        u32 thunk_rva = oft ? oft : ft;
        u32 slot = ft;
        bool any = false;
        for (int guard = 0; guard < 200000; ++guard) {
            auto th = read_ptr_rva(thunk_rva);
            if (!th) break;
            if (*th == 0) break;
            any = true;
            ImportSym im;
            im.dll = dll;
            im.iat_va = image_base_ + slot;
            u64 ord_flag = is64_ ? 0x8000000000000000ull : 0x80000000ull;
            if (*th & ord_flag) {
                im.ordinal = static_cast<u16>(*th & 0xffff);
            } else {
                u8 hint[2];
                u64 nr = static_cast<u64>(*th);
                if (read_rva(nr, hint, 2)) {
                    im.ordinal = ru16(hint);
                    im.name = read_cstr(nr + 2);
                }
            }
            imports_.push_back(std::move(im));
            thunk_rva += is64_ ? 8u : 4u;
            slot += is64_ ? 8u : 4u;
        }
        (void)any;
    }
}

void PeImage::parse_exports() {
    if (num_dd_ <= static_cast<int>(kDirExport)) return;
    if (dd_offset() + 8 > file_.size()) return;
    u32 rva = ru32(file_.data() + dd_offset());
    u32 size = ru32(file_.data() + dd_offset() + 4);
    if (!rva || size < 40) return;
    u8 dir[40];
    if (!read_rva(rva, dir, 40)) return;
    u32 base = ru32(dir + 16);
    u32 nfun = ru32(dir + 20);
    u32 nnames = ru32(dir + 24);
    u32 aof = ru32(dir + 28);
    u32 aon = ru32(dir + 32);
    u32 aoo = ru32(dir + 36);
    std::vector<u32> funcs(nfun);
    for (u32 i = 0; i < nfun; ++i) {
        u8 b[4];
        if (!read_rva(aof + i * 4, b, 4)) break;
        funcs[i] = ru32(b);
    }
    std::vector<std::string> names(nfun);
    for (u32 i = 0; i < nnames; ++i) {
        u8 nb[4], ob[2];
        if (!read_rva(aon + i * 4, nb, 4)) break;
        if (!read_rva(aoo + i * 2, ob, 2)) break;
        u16 ord_index = ru16(ob);
        if (ord_index < nfun) names[ord_index] = read_cstr(ru32(nb));
    }
    for (u32 i = 0; i < nfun; ++i) {
        if (!funcs[i]) continue;
        ExportSym ex;
        ex.rva = funcs[i];
        ex.va = image_base_ + funcs[i];
        ex.ordinal = static_cast<u16>(base + i);
        ex.name = names[i];
        exports_.push_back(std::move(ex));
    }
}

void PeImage::parse_relocs() {
    if (num_dd_ <= static_cast<int>(kDirBaseReloc)) return;
    u32 rva = ru32(file_.data() + dd_offset() + kDirBaseReloc * 8);
    u32 size = ru32(file_.data() + dd_offset() + kDirBaseReloc * 8 + 4);
    if (!rva || !size) return;
    u32 off = 0;
    while (off + 8 <= size) {
        u8 hdr[8];
        if (!read_rva(rva + off, hdr, 8)) break;
        u32 page = ru32(hdr);
        u32 block = ru32(hdr + 4);
        if (block < 8) break;
        u32 count = (block - 8) / 2;
        for (u32 i = 0; i < count; ++i) {
            u8 ent[2];
            if (!read_rva(rva + off + 8 + i * 2, ent, 2)) break;
            u16 e = ru16(ent);
            u8 type = static_cast<u8>(e >> 12);
            u16 delta = static_cast<u16>(e & 0x0fff);
            if (type == 0) continue;
            RelocEntry re;
            re.rva = static_cast<u64>(page) + delta;
            re.type = type;
            relocs_.push_back(re);
        }
        off += block;
    }
}

void PeImage::parse_tls() {
    if (num_dd_ <= static_cast<int>(kDirTls)) return;
    u32 rva = ru32(file_.data() + dd_offset() + kDirTls * 8);
    u32 size = ru32(file_.data() + dd_offset() + kDirTls * 8 + 4);
    if (!rva || !size) return;
    u64 callbacks_va = 0;
    if (is64_) {
        u8 dir[40];
        if (!read_rva(rva, dir, 40)) return;
        callbacks_va = ru64(dir + 24);
    } else {
        u8 dir[24];
        if (!read_rva(rva, dir, 24)) return;
        callbacks_va = ru32(dir + 12);
    }
    if (!callbacks_va) return;
    if (callbacks_va < image_base_) return;
    u64 crva = callbacks_va - image_base_;
    for (int i = 0; i < 4096; ++i) {
        auto p = read_ptr_rva(crva);
        if (!p || *p == 0) break;
        tls_.push_back(*p);
        crva += is64_ ? 8u : 4u;
    }
}

void PeImage::parse_resources() {
    if (num_dd_ <= static_cast<int>(kDirResource)) return;
    u32 root = ru32(file_.data() + dd_offset() + kDirResource * 8);
    u32 size = ru32(file_.data() + dd_offset() + kDirResource * 8 + 4);
    if (!root || !size) return;

    struct Walker {
        const PeImage* img;
        u32 root;
        int budget;
        ResourceNode walk(u32 rel, int depth) {
            ResourceNode node;
            if (depth > 5 || budget-- <= 0) return node;
            u8 hdr[16];
            if (!img->read_rva(root + rel, hdr, 16)) return node;
            u16 named = ru16(hdr + 12);
            u16 ids = ru16(hdr + 14);
            u32 count = static_cast<u32>(named) + ids;
            for (u32 i = 0; i < count && i < 4096; ++i) {
                u8 ent[8];
                if (!img->read_rva(root + rel + 16 + i * 8ull, ent, 8)) break;
                u32 name_or_id = ru32(ent);
                u32 offset = ru32(ent + 4);
                ResourceNode child;
                if (name_or_id & 0x80000000u) {
                    child.named = true;
                    u32 noff = name_or_id & 0x7fffffffu;
                    u8 lenb[2];
                    if (img->read_rva(root + noff, lenb, 2)) {
                        u16 len = ru16(lenb);
                        std::string nm;
                        for (u16 c = 0; c < len && c < 260; ++c) {
                            u8 wb[2];
                            if (!img->read_rva(root + noff + 2 + c * 2, wb, 2)) break;
                            u16 cu = ru16(wb);
                            nm.push_back(cu < 128 ? static_cast<char>(cu) : '?');
                        }
                        child.name = std::move(nm);
                    }
                } else {
                    child.id = name_or_id;
                    child.name = std::to_string(name_or_id);
                }
                if (offset & 0x80000000u) {
                    auto sub = walk(offset & 0x7fffffffu, depth + 1);
                    child.children = std::move(sub.children);
                    if (child.children.empty()) child.children = std::move(sub.children);
                    // walk returns the directory node; steal its children
                    ResourceNode dir = walk(offset & 0x7fffffffu, depth + 1);
                    child.children = std::move(dir.children);
                } else {
                    u8 data[16];
                    if (img->read_rva(root + offset, data, 16)) {
                        child.leaf = true;
                        child.data_rva = ru32(data);
                        child.data_size = ru32(data + 4);
                    }
                }
                node.children.push_back(std::move(child));
            }
            return node;
        }
    };
    // The walker above double-walks subdirectories. Use a cleaner local lambda instead.
    resources_.clear();
    const PeImage* self = this;
    int budget = 8192;
    std::function<ResourceNode(u32, int)> walk = [&](u32 rel, int depth) -> ResourceNode {
        ResourceNode node;
        if (depth > 5 || budget-- <= 0) return node;
        u8 hdr[16];
        if (!self->read_rva(root + rel, hdr, 16)) return node;
        u16 named = ru16(hdr + 12);
        u16 ids = ru16(hdr + 14);
        u32 count = static_cast<u32>(named) + ids;
        for (u32 i = 0; i < count && i < 4096; ++i) {
            u8 ent[8];
            if (!self->read_rva(root + rel + 16ull + i * 8ull, ent, 8)) break;
            u32 name_or_id = ru32(ent);
            u32 offset = ru32(ent + 4);
            ResourceNode child;
            if (name_or_id & 0x80000000u) {
                child.named = true;
                u32 noff = name_or_id & 0x7fffffffu;
                u8 lenb[2];
                if (self->read_rva(root + noff, lenb, 2)) {
                    u16 len = ru16(lenb);
                    for (u16 c = 0; c < len && c < 260; ++c) {
                        u8 wb[2];
                        if (!self->read_rva(root + noff + 2 + c * 2ull, wb, 2)) break;
                        u16 cu = ru16(wb);
                        child.name.push_back(cu < 128 ? static_cast<char>(cu) : '?');
                    }
                }
            } else {
                child.id = name_or_id;
                child.name = std::to_string(name_or_id);
            }
            if (offset & 0x80000000u) {
                ResourceNode dir = walk(offset & 0x7fffffffu, depth + 1);
                child.children = std::move(dir.children);
            } else {
                u8 data[16];
                if (self->read_rva(root + offset, data, 16)) {
                    child.leaf = true;
                    child.data_rva = ru32(data);
                    child.data_size = ru32(data + 4);
                }
            }
            node.children.push_back(std::move(child));
        }
        return node;
    };
    resources_ = walk(0, 0).children;
    (void)sizeof(Walker);
}

void PeImage::parse_rich() {
    if (e_lfanew_ <= 0x80) return;
    const u8* f = file_.data();
    for (u32 i = 0x40; i + 8 < e_lfanew_; i += 4) {
        if (std::memcmp(f + i, "Rich", 4) != 0) continue;
        u32 key = ru32(f + i + 4);
        if (i < 4) break;
        for (u32 j = i; j >= 4;) {
            j -= 4;
            if ((ru32(f + j) ^ key) == 0x536E6144u) {
                for (u32 e = j + 16; e + 8 <= i; e += 8) {
                    u32 comp = ru32(f + e) ^ key;
                    u32 count = ru32(f + e + 4) ^ key;
                    RichEntry re;
                    re.prod_id = static_cast<u16>((comp >> 16) & 0xffff);
                    re.build = static_cast<u16>(comp & 0xffff);
                    re.count = count;
                    rich_.push_back(re);
                }
                return;
            }
            if (j < 4) break;
        }
        return;
    }
}

bool PeImage::executable_rva(u64 rva) const {
    for (const auto& s : sections_) {
        if (rva >= s.rva && rva < s.rva + s.vsize) return s.executable;
    }
    return false;
}

bool PeImage::contains_va(u64 va) const {
    if (va < image_base_) return false;
    return contains_rva(va - image_base_);
}

size_t PeImage::avail_rva(u64 rva) const {
    if (rva >= mapped_.size()) return 0;
    return mapped_.size() - static_cast<size_t>(rva);
}

bool PeImage::read_rva(u64 rva, void* dst, size_t n) const {
    if (!dst || n == 0) return false;
    if (rva >= mapped_.size() || n > mapped_.size() - static_cast<size_t>(rva)) return false;
    std::memcpy(dst, mapped_.data() + rva, n);
    return true;
}

std::optional<u64> PeImage::read_ptr_rva(u64 rva) const {
    if (is64_) {
        u8 b[8];
        if (!read_rva(rva, b, 8)) return std::nullopt;
        return ru64(b);
    }
    u8 b[4];
    if (!read_rva(rva, b, 4)) return std::nullopt;
    return ru32(b);
}

std::string PeImage::read_cstr(u64 rva, size_t cap) const {
    std::string s;
    for (size_t i = 0; i < cap; ++i) {
        if (rva + i >= mapped_.size()) break;
        char c = static_cast<char>(mapped_[static_cast<size_t>(rva + i)]);
        if (c == '\0') break;
        s.push_back(c);
    }
    return s;
}

u8* PeImage::ptr_rva(u64 rva, size_t n) {
    if (rva >= mapped_.size() || n > mapped_.size() - static_cast<size_t>(rva)) return nullptr;
    return mapped_.data() + rva;
}
const u8* PeImage::ptr_rva(u64 rva, size_t n) const {
    if (rva >= mapped_.size() || n > mapped_.size() - static_cast<size_t>(rva)) return nullptr;
    return mapped_.data() + rva;
}

void PeImage::set_entry_rva(u64 rva) {
    entry_rva_ = rva;
    if (opt_offset() + 20 <= file_.size()) wu32(file_.data() + opt_offset() + 16, static_cast<u32>(rva));
    if (16 + 4 <= mapped_.size() && opt_offset() + 20 <= mapped_.size())
        wu32(mapped_.data() + opt_offset() + 16, static_cast<u32>(rva));
}

void PeImage::set_data_directory(int index, u32 rva, u32 size) {
    if (index < 0 || index >= num_dd_) return;
    u32 off = dd_offset() + static_cast<u32>(index) * 8;
    if (off + 8 <= file_.size()) {
        wu32(file_.data() + off, rva);
        wu32(file_.data() + off + 4, size);
    }
    if (off + 8 <= mapped_.size()) {
        wu32(mapped_.data() + off, rva);
        wu32(mapped_.data() + off + 4, size);
    }
}

u64 PeImage::add_section(const std::string& name, u32 chars, const std::vector<u8>& data) {
    u32 sec_off = opt_offset() + size_of_optional_;
    u32 need = sec_off + (static_cast<u32>(number_of_sections_) + 1) * 40;
    u32 first_raw = 0;
    for (const auto& s : sections_) {
        if (s.raw_ptr && (first_raw == 0 || s.raw_ptr < first_raw)) first_raw = s.raw_ptr;
    }
    if (first_raw == 0) first_raw = size_of_headers_;
    if (need > size_of_headers_) {
        if (need > first_raw || need > file_.size()) return 0;
        size_of_headers_ = static_cast<u32>(align_up(need, file_align_));
        if (size_of_headers_ > first_raw) size_of_headers_ = first_raw;
        if (is64_) wu32(file_.data() + opt_offset() + 60, size_of_headers_);
        else wu32(file_.data() + opt_offset() + 60, size_of_headers_);
    }
    if (need > file_.size()) return 0;

    u64 rva = align_up(std::max<u64>(size_of_image_, mapped_.size()), section_align_);
    u64 vsize = std::max<u64>(data.size(), 1);
    u32 raw_size = static_cast<u32>(align_up(data.size(), file_align_));
    u32 new_soi = static_cast<u32>(align_up(rva + vsize, section_align_));

    u8* sh = file_.data() + sec_off + number_of_sections_ * 40;
    std::memset(sh, 0, 40);
    std::memset(sh, 0, 8);
    std::memcpy(sh, name.c_str(), std::min<size_t>(8, name.size()));
    wu32(sh + 8, static_cast<u32>(vsize));
    wu32(sh + 12, static_cast<u32>(rva));
    wu32(sh + 16, raw_size);
    // raw pointer filled in rebuild(); keep 0 until then and remember via SectionInfo
    wu32(sh + 36, chars);

    if (mapped_.size() < new_soi) mapped_.resize(static_cast<size_t>(new_soi), 0);
    if (!data.empty()) std::memcpy(mapped_.data() + rva, data.data(), data.size());

    wu16(file_.data() + e_lfanew_ + 4 + 2, static_cast<u16>(number_of_sections_ + 1));
    wu32(file_.data() + opt_offset() + 56, new_soi);

    SectionInfo s;
    s.name = name.substr(0, std::min<size_t>(8, name.size()));
    s.rva = rva;
    s.va = image_base_ + rva;
    s.vsize = vsize;
    s.raw_size = raw_size;
    s.raw_ptr = 0;
    s.chars = chars;
    s.executable = (chars & kScnMemExecute) || (chars & kScnCntCode);
    s.readable = (chars & kScnMemRead) || s.executable;
    s.writable = (chars & kScnMemWrite) != 0;
    s.entropy = entropy_bytes(data.data(), data.size());
    sections_.push_back(s);
    number_of_sections_++;
    size_of_image_ = new_soi;
    return rva;
}

std::vector<u8> PeImage::rebuild(bool virtual_dump) const {
    std::vector<SectionInfo> secs = sections_;
    u32 cursor = size_of_headers_;
    cursor = static_cast<u32>(align_up(cursor, file_align_));
    for (auto& s : secs) {
        u32 raw = virtual_dump ? static_cast<u32>(align_up(std::max<u64>(s.vsize, 1), file_align_))
                               : static_cast<u32>(align_up(s.raw_size ? s.raw_size : s.vsize, file_align_));
        if (raw == 0) raw = static_cast<u32>(file_align_);
        s.raw_size = raw;
        s.raw_ptr = cursor;
        cursor += raw;
    }
    std::vector<u8> out(cursor, 0);
    size_t hdr = std::min(static_cast<size_t>(size_of_headers_), file_.size());
    hdr = std::min(hdr, out.size());
    std::memcpy(out.data(), file_.data(), hdr);
    // refresh section headers inside out
    u32 sec_off = opt_offset() + size_of_optional_;
    for (size_t i = 0; i < secs.size(); ++i) {
        u8* sh = out.data() + sec_off + i * 40;
        if (sec_off + (i + 1) * 40 > out.size()) break;
        wu32(sh + 8, static_cast<u32>(secs[i].vsize));
        wu32(sh + 12, static_cast<u32>(secs[i].rva));
        wu32(sh + 16, static_cast<u32>(secs[i].raw_size));
        wu32(sh + 20, secs[i].raw_ptr);
        wu32(sh + 36, secs[i].chars);
        size_t copy = std::min(static_cast<size_t>(secs[i].raw_size), static_cast<size_t>(secs[i].vsize));
        if (secs[i].rva + copy <= mapped_.size() && secs[i].raw_ptr + copy <= out.size())
            std::memcpy(out.data() + secs[i].raw_ptr, mapped_.data() + secs[i].rva, copy);
    }
    if (opt_offset() + 64 <= out.size()) {
        wu32(out.data() + opt_offset() + 56, size_of_image_);
        wu32(out.data() + opt_offset() + 64, 0);  // checksum left for the loader
    }
    return out;
}

std::string PeImage::describe() const {
    std::ostringstream os;
    os << (is64_ ? "PE32+" : "PE32") << " machine=0x" << std::hex << machine_
       << " base=" << hex(image_base_) << " entry=" << hex(entry_va())
       << " subsystem=" << std::dec << subsystem_ << "\n";
    os << "sections:\n";
    for (const auto& s : sections_) {
        os << "  " << s.name << " rva=" << hex(s.rva) << " vsize=" << hex(s.vsize)
           << " entropy=" << s.entropy << (s.executable ? " X" : "") << (s.writable ? " W" : "")
           << "\n";
    }
    os << "imports: " << imports_.size() << "\n";
    for (const auto& im : imports_) {
        os << "  " << im.dll << "!" << (im.name.empty() ? ("#" + std::to_string(im.ordinal)) : im.name)
           << " iat=" << hex(im.iat_va) << "\n";
    }
    os << "exports: " << exports_.size() << "\n";
    for (const auto& ex : exports_)
        os << "  " << (ex.name.empty() ? ("#" + std::to_string(ex.ordinal)) : ex.name) << " " << hex(ex.va) << "\n";
    os << "relocs: " << relocs_.size() << " tls callbacks: " << tls_.size()
       << " rich entries: " << rich_.size() << " overlay: " << overlay_.size() << " bytes\n";
    if (!resources_.empty()) os << "resources: " << resources_.size() << " top-level entries\n";
    return os.str();
}

}  // namespace aerore
