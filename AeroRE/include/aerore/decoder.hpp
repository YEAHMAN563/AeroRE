#pragma once

#include "aerore/types.hpp"

#include <memory>
#include <optional>

namespace aerore {

class Decoder {
public:
    explicit Decoder(Arch arch);
    ~Decoder();
    Decoder(Decoder&&) noexcept;
    Decoder& operator=(Decoder&&) noexcept;
    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;

    std::optional<Insn> decode(u64 va, const u8* bytes, size_t n) const;
    Arch arch() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace aerore
