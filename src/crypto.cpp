// ===================== src/crypto.cpp =====================
#include "crypto.h"
#include <cstring>
#include <cstdio>
#include <random>
#include <stdexcept>

namespace dec {

    // ---------------- SHA-256 ----------------
    static const uint32_t K256[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

        static inline uint32_t rotr32(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }

        Sha256::Sha256() {
            h_[0]=0x6a09e667; h_[1]=0xbb67ae85; h_[2]=0x3c6ef372; h_[3]=0xa54ff53a;
            h_[4]=0x510e527f; h_[5]=0x9b05688c; h_[6]=0x1f83d9ab; h_[7]=0x5be0cd19;
            total_ = 0; bufLen_ = 0;
        }

        void Sha256::transform(const uint8_t* p) {
            uint32_t w[64];
            for (int i=0;i<16;i++)
                w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|(uint32_t)p[i*4+3];
            for (int i=16;i<64;i++) {
                uint32_t s0 = rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3);
                uint32_t s1 = rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10);
                w[i] = w[i-16]+s0+w[i-7]+s1;
            }
            uint32_t a=h_[0],b=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],h=h_[7];
            for (int i=0;i<64;i++) {
                uint32_t S1 = rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
                uint32_t ch = (e&f)^(~e&g);
                uint32_t t1 = h+S1+ch+K256[i]+w[i];
                uint32_t S0 = rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
                uint32_t maj = (a&b)^(a&c)^(b&c);
                uint32_t t2 = S0+maj;
                h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
            }
            h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d;
            h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=h;
        }

        void Sha256::update(const void* data, size_t len) {
            const uint8_t* p = (const uint8_t*)data;
            total_ += len;
            while (len > 0) {
                size_t take = 64 - bufLen_;
                if (take > len) take = len;
                std::memcpy(buf_ + bufLen_, p, take);
                bufLen_ += take; p += take; len -= take;
                if (bufLen_ == 64) { transform(buf_); bufLen_ = 0; }
            }
        }

        Key32 Sha256::digest() {
            uint64_t bits = total_ * 8;
            uint8_t pad = 0x80; update(&pad, 1);
            uint8_t zero = 0;
            while (bufLen_ != 56) update(&zero, 1);
            uint8_t lenb[8];
            for (int i=0;i<8;i++) lenb[i] = (uint8_t)(bits >> (56 - i*8));
            update(lenb, 8);
            Key32 out;
            for (int i=0;i<8;i++) {
                out[i*4]   = (uint8_t)(h_[i]>>24);
                out[i*4+1] = (uint8_t)(h_[i]>>16);
                out[i*4+2] = (uint8_t)(h_[i]>>8);
                out[i*4+3] = (uint8_t)(h_[i]);
            }
            return out;
        }

        Key32 Sha256::hash(const void* data, size_t len) {
            Sha256 s; s.update(data, len); return s.digest();
        }

        // ---------------- ChaCha20 ----------------
        static inline uint32_t rotl32(uint32_t x, int n){ return (x<<n)|(x>>(32-n)); }

        static void chachaInit(uint32_t st[16], const Key32& key, const Nonce12& nonce, uint32_t counter) {
            st[0]=0x61707865; st[1]=0x3320646e; st[2]=0x79622d32; st[3]=0x6b206574;
            for (int i=0;i<8;i++)
                st[4+i] = (uint32_t)key[i*4] | ((uint32_t)key[i*4+1]<<8) |
                ((uint32_t)key[i*4+2]<<16) | ((uint32_t)key[i*4+3]<<24);
            st[12] = counter;
            for (int i=0;i<3;i++)
                st[13+i] = (uint32_t)nonce[i*4] | ((uint32_t)nonce[i*4+1]<<8) |
                ((uint32_t)nonce[i*4+2]<<16) | ((uint32_t)nonce[i*4+3]<<24);
        }

        #define QR(a,b,c,d) a+=b; d^=a; d=rotl32(d,16); c+=d; b^=c; b=rotl32(b,12); \
        a+=b; d^=a; d=rotl32(d,8);  c+=d; b^=c; b=rotl32(b,7);

        static void chachaBlock(uint32_t out[16], const uint32_t in[16]) {
            uint32_t x[16];
            std::memcpy(x, in, sizeof(x));
            for (int i=0;i<10;i++) {
                QR(x[0],x[4],x[8], x[12]); QR(x[1],x[5],x[9], x[13]);
                QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
                QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
                QR(x[2],x[7],x[8], x[13]); QR(x[3],x[4],x[9], x[14]);
            }
            for (int i=0;i<16;i++) out[i] = x[i] + in[i];
        }

        ChaCha20::ChaCha20(const Key32& key, const Nonce12& nonce, uint32_t counter) {
            chachaInit(state_, key, nonce, counter);
            pos_ = 64;
        }

        void ChaCha20::refill() {
            uint32_t out[16];
            chachaBlock(out, state_);
            for (int i=0;i<16;i++) {
                ks_[i*4]   = (uint8_t)(out[i]);
                ks_[i*4+1] = (uint8_t)(out[i]>>8);
                ks_[i*4+2] = (uint8_t)(out[i]>>16);
                ks_[i*4+3] = (uint8_t)(out[i]>>24);
            }
            state_[12]++;   // 64 位计数器高位溢出在 <256GB 内不会发生
            pos_ = 0;
        }

        void ChaCha20::xorData(uint8_t* data, size_t len) {
            for (size_t i=0;i<len;i++) {
                if (pos_ == 64) refill();
                data[i] ^= ks_[pos_++];
            }
        }

        // ---------------- Base64 ----------------
        static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string base64Encode(const uint8_t* p, size_t n) {
            std::string out;
            out.reserve(((n + 2) / 3) * 4);
            size_t i = 0;
            while (i + 2 < n) {
                uint32_t v = (p[i]<<16)|(p[i+1]<<8)|p[i+2];
                out += B64[(v>>18)&63]; out += B64[(v>>12)&63];
                out += B64[(v>>6)&63];  out += B64[v&63];
                i += 3;
            }
            if (i + 1 == n) {
                uint32_t v = (p[i]<<16);
                out += B64[(v>>18)&63]; out += B64[(v>>12)&63]; out += "==";
            } else if (i + 2 == n) {
                uint32_t v = (p[i]<<16)|(p[i+1]<<8);
                out += B64[(v>>18)&63]; out += B64[(v>>12)&63];
                out += B64[(v>>6)&63];  out += '=';
            }
            return out;
        }
        std::string base64Encode(const Bytes& b) { return base64Encode(b.data(), b.size()); }

        bool base64Decode(const std::string& in, Bytes& out) {
            static int rev[256];
            static bool init = false;
            if (!init) {
                for (int i=0;i<256;i++) rev[i] = -1;
                for (int i=0;i<64;i++) rev[(unsigned char)B64[i]] = i;
                init = true;
            }
            out.clear();
            int buf = 0, bits = 0;
            for (char ch : in) {
                if (ch == '=' || ch == '\n' || ch == '\r' || ch == ' ') continue;
                int v = rev[(unsigned char)ch];
                if (v < 0) return false;
                buf = (buf << 6) | v;
                bits += 6;
                if (bits >= 8) { bits -= 8; out.push_back((uint8_t)((buf >> bits) & 0xFF)); }
            }
            return true;
        }

        // ---------------- KDF / 随机数 ----------------
        Key32 deriveKey(const std::string& password, const Bytes& salt, uint32_t iterations) {
            std::vector<uint8_t> b;
            b.reserve(32 + salt.size() + 4);
            b.insert(b.end(), password.begin(), password.end());
            b.insert(b.end(), salt.begin(), salt.end());
            Key32 k = Sha256::hash(b.data(), b.size());

            std::vector<uint8_t> b2;
            b2.reserve(32 + salt.size() + 4);
            for (uint32_t i = 1; i < iterations; i++) {
                b2.clear();
                b2.insert(b2.end(), k.begin(), k.end());
                b2.insert(b2.end(), salt.begin(), salt.end());
                b2.push_back((uint8_t)(i));
                b2.push_back((uint8_t)(i>>8));
                b2.push_back((uint8_t)(i>>16));
                b2.push_back((uint8_t)(i>>24));
                k = Sha256::hash(b2.data(), b2.size());
            }
            return k;
        }

        Bytes randomBytes(size_t n) {
            static std::mt19937_64 rng{std::random_device{}()};
            Bytes b(n);
            for (size_t i=0;i<n;i++) b[i] = (uint8_t)(rng() & 0xFF);
            return b;
        }

        Nonce12 randomNonce() {
            Bytes b = randomBytes(12);
            Nonce12 n;
            std::memcpy(n.data(), b.data(), 12);
            return n;
        }

} // namespace dec
