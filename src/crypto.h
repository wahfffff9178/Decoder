// ===================== src/crypto.h =====================
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace dec {
    using Bytes  = std::vector<uint8_t>;
    using Key32  = std::array<uint8_t, 32>;
    using Nonce12 = std::array<uint8_t, 12>;

    class Sha256 {
    public:
        Sha256();
        void update(const void* data, size_t len);
        void update(const Bytes& d)      { update(d.data(), d.size()); }
        void update(const std::string& s){ update(s.data(), s.size()); }
        Key32 digest();
        static Key32 hash(const void* data, size_t len);
        static Key32 hash(const std::string& s) { return hash(s.data(), s.size()); }
    private:
        void transform(const uint8_t* p);
        uint32_t h_[8];
        uint64_t total_;
        uint8_t  buf_[64];
        size_t   bufLen_;
    };

    class ChaCha20 {
    public:
        ChaCha20(const Key32& key, const Nonce12& nonce, uint32_t counter = 1);
        void xorData(uint8_t* data, size_t len);
    private:
        void refill();
        uint32_t state_[16];
        uint8_t  ks_[64];
        size_t   pos_;
    };

    std::string base64Encode(const uint8_t* p, size_t n);
    std::string base64Encode(const Bytes& b);
    bool        base64Decode(const std::string& in, Bytes& out);

    Key32 deriveKey(const std::string& password, const Bytes& salt, uint32_t iterations);
    Bytes randomBytes(size_t n);
    Nonce12 randomNonce();

} // namespace dec
