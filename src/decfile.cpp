#include "decfile.h"
#include "util.h"
#include <fstream>
#include <cstring>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

namespace dec {

    static constexpr uint32_t kDefaultIterations = 100000;
    static constexpr size_t   kSaltLen = 16;

    const char* decErrorText(DecError e) {
        switch (e) {
            case DecError::Ok:            return "成功";
            case DecError::NotDecFile:    return "这不是一个DEC加密文件";
            case DecError::VersionTooNew: return "dec版本大于当前decoder版本：此版本不支持这个Dec文件";
            case DecError::NeedPassword:  return "此文件需要密码";
            case DecError::WrongPassword: return "密码错误";
            case DecError::BadHeader:     return "DEC 文件头已损坏";
            case DecError::IoError:       return "文件读写错误";
            case DecError::IntegrityFailed:return "文件已被篡改或损坏 (MAC 校验失败)";
        }
        return "未知错误";
    }

    static Key32 bodyKey(const Key32& hkey) {
        static const char tag[] = "DECF-BODY-KEY";
        Bytes b(tag, tag + sizeof(tag) - 1);
        b.insert(b.end(), hkey.begin(), hkey.end());
        return Sha256::hash(b.data(), b.size());
    }

    static std::string checkOf(const Key32& key) {
        Key32 k = Sha256::hash(key.data(), key.size());
        return base64Encode(k.data(), 8);
    }

    // 构造 16 字节文件头
    static void buildPre(uint8_t pre[16], uint8_t flags, uint32_t headerLen) {
        std::memset(pre, 0, 16);
        std::memcpy(pre, "DECF", 4);
        pre[4] = kFormatVersion & 0xFF;
        pre[5] = (kFormatVersion >> 8) & 0xFF;
        pre[6] = flags;
        pre[8] = headerLen & 0xFF;
        pre[9] = (headerLen >> 8) & 0xFF;
        pre[10] = (headerLen >> 16) & 0xFF;
        pre[11] = (headerLen >> 24) & 0xFF;
    }

    DecError readHeader(const fs::path& p, const std::string& password, HeaderInfo& out) {
        std::ifstream f(p, std::ios::binary);
        if (!f) return DecError::IoError;

        uint8_t pre[16];
        f.read((char*)pre, 16);
        if (f.gcount() != 16) return DecError::NotDecFile;
        if (std::memcmp(pre, "DECF", 4) != 0) return DecError::NotDecFile;

        uint16_t ver = (uint16_t)(pre[4] | (pre[5] << 8));
        if (ver > kFormatVersion) return DecError::VersionTooNew;
        out.version = ver;

        uint8_t flags = pre[6];
        uint32_t headerLen = (uint32_t)pre[8] | ((uint32_t)pre[9] << 8) |
        ((uint32_t)pre[10] << 16) | ((uint32_t)pre[11] << 24);
        if (headerLen < 32 || headerLen > (64u << 20)) return DecError::NotDecFile;

        Bytes hb(headerLen);
        f.read((char*)hb.data(), (std::streamsize)headerLen);
        if ((size_t)f.gcount() != headerLen) return DecError::NotDecFile;

        bool hasPwd = (flags & kFlagHasPassword) != 0;
        if (hasPwd && password.empty()) return DecError::NeedPassword;
        std::string pwd = hasPwd ? password : std::string();

        out.salt.assign(hb.begin(), hb.begin() + kSaltLen);
        std::memcpy(out.headerNonce.data(), hb.data() + kSaltLen, 12);
        out.iterations = (uint32_t)hb[28] | ((uint32_t)hb[29] << 8) |
        ((uint32_t)hb[30] << 16) | ((uint32_t)hb[31] << 24);
        if (out.iterations == 0 || out.iterations > 5000000) out.iterations = kDefaultIterations;

        out.key = deriveKey(pwd, out.salt, out.iterations);
        out.hasPassword = hasPwd;
        out.headerLen = headerLen;
        out.bodyOffset = 16 + (uint64_t)headerLen;

        Bytes plain(hb.begin() + 32, hb.end());
        ChaCha20 cc(out.key, out.headerNonce, 1);
        cc.xorData(plain.data(), plain.size());

        std::string js((const char*)plain.data(), plain.size());
        try {
            out.json = Json::parse(js);
        } catch (...) {
            return DecError::WrongPassword;
        }
        std::string chk = out.json.getString("check");
        if (chk != checkOf(out.key)) return DecError::WrongPassword;

        return DecError::Ok;
    }

    bool encryptFile(const fs::path& src, const fs::path& dst,
                     const std::string& password, const std::string& remarks,
                     std::string& err) {
        std::error_code ec;
        uintmax_t size = fs::file_size(src, ec);
        if (ec) { err = "无法读取源文件大小: " + ec.message(); return false; }

        Bytes  salt = randomBytes(kSaltLen);
        Nonce12 hNonce = randomNonce();
        Bytes  bNonce = randomBytes(12);
        Key32  key  = deriveKey(password, salt, kDefaultIterations);

        Json h = Json::object();
        h.set("format",        (long long)kFormatVersion);
        h.set("remarks",       remarks);
        h.set("source_ip",     localIp());
        h.set("original_name", src.filename().string());
        h.set("original_size", (long long)size);
        h.set("original_mtime", fileTimeIso(src));
        h.set("encrypted_at",  nowIso());
        h.set("modified_at",   nowIso());
        h.set("cipher",        "chacha20");
        h.set("kdf",           "sha256-iter");
        h.set("body_nonce",    base64Encode(bNonce));
        h.set("check",         checkOf(key));

        std::string js = h.dump(2);
        Bytes plain(js.begin(), js.end());
        ChaCha20 hc(key, hNonce, 1);
        hc.xorData(plain.data(), plain.size());

        Bytes hblock;
        hblock.reserve(32 + plain.size());
        hblock.insert(hblock.end(), salt.begin(), salt.end());
        hblock.insert(hblock.end(), hNonce.begin(), hNonce.end());
        uint32_t it = kDefaultIterations;
        hblock.push_back((uint8_t)it);
        hblock.push_back((uint8_t)(it >> 8));
        hblock.push_back((uint8_t)(it >> 16));
        hblock.push_back((uint8_t)(it >> 24));
        hblock.insert(hblock.end(), plain.begin(), plain.end());

        fs::path tmp = dst;
        tmp += ".part";
        std::ofstream out(tmp, std::ios::binary);
        if (!out) { err = "无法创建输出文件"; return false; }

        uint8_t flags = kFlagHeaderEncrypted;
        if (!password.empty()) flags |= kFlagHasPassword;
        uint8_t pre[16];
        buildPre(pre, flags, (uint32_t)hblock.size());

        out.write((const char*)pre, 16);
        out.write((const char*)hblock.data(), (std::streamsize)hblock.size());

        // 初始化 HMAC
        Key32 macKey = hmacKeyFromMaster(key);
        HmacSha256 hmac(macKey);
        hmac.update(pre, 16);
        hmac.update(hblock);

        Nonce12 bn;
        std::memcpy(bn.data(), bNonce.data(), 12);
        ChaCha20 bc(bodyKey(key), bn, 1);

        std::ifstream in(src, std::ios::binary);
        if (!in) { out.close(); fs::remove(tmp); err = "无法打开源文件"; return false; }

        std::vector<char> buf(64 * 1024);
        while (in) {
            in.read(buf.data(), (std::streamsize)buf.size());
            std::streamsize n = in.gcount();
            if (n <= 0) break;
            bc.xorData((uint8_t*)buf.data(), (size_t)n);
            out.write(buf.data(), n);
            hmac.update(buf.data(), (size_t)n);
        }

        // 写入 MAC
        Key32 mac = hmac.digest();
        out.write((const char*)mac.data(), kMacLen);

        out.flush();
        if (!out) { out.close(); fs::remove(tmp); err = "写入失败"; return false; }
        out.close();

        fs::rename(tmp, dst, ec);
        if (ec) {
            fs::remove(dst, ec);
            fs::rename(tmp, dst, ec);
            if (ec) { fs::remove(tmp); err = "无法写入目标文件: " + ec.message(); return false; }
        }
        return true;
                     }

                     DecError decryptBody(const fs::path& src, const HeaderInfo& h, const fs::path& dst) {
                         std::string bnStr = h.json.getString("body_nonce");
                         Bytes bNonce;
                         if (!base64Decode(bnStr, bNonce) || bNonce.size() != 12) return DecError::BadHeader;

                         std::ifstream in(src, std::ios::binary);
                         if (!in) return DecError::IoError;

                         in.seekg(0, std::ios::end);
                         uint64_t fileSize = in.tellg();

                         // v2 及以上有 MAC 校验，v1 无
                         bool hasMac = (h.version >= 2 && fileSize >= h.bodyOffset + kMacLen);
                         uint64_t cipherLen = fileSize - h.bodyOffset - (hasMac ? kMacLen : 0);

                         if (hasMac) {
                             in.seekg(0, std::ios::beg);
                             Key32 macKey = hmacKeyFromMaster(h.key);
                             HmacSha256 hmac(macKey);

                             uint8_t pre[16];
                             in.read((char*)pre, 16);
                             hmac.update(pre, 16);

                             Bytes hb(h.headerLen);
                             in.read((char*)hb.data(), h.headerLen);
                             hmac.update(hb);

                             std::vector<char> buf(64 * 1024);
                             uint64_t remain = cipherLen;
                             while (remain > 0) {
                                 size_t toRead = (size_t)std::min<uint64_t>(remain, buf.size());
                                 in.read(buf.data(), toRead);
                                 hmac.update(buf.data(), toRead);
                                 remain -= toRead;
                             }

                             uint8_t expectedMac[32];
                             in.read((char*)expectedMac, kMacLen);
                             Key32 actualMac = hmac.digest();

                             if (std::memcmp(expectedMac, actualMac.data(), kMacLen) != 0) {
                                 return DecError::IntegrityFailed;
                             }
                         }

                         Nonce12 bn;
                         std::memcpy(bn.data(), bNonce.data(), 12);
                         ChaCha20 cc(bodyKey(h.key), bn, 1);

                         in.clear();
                         in.seekg((std::streamoff)h.bodyOffset, std::ios::beg);

                         fs::path tmp = dst;
                         tmp += ".part";
                         std::ofstream out(tmp, std::ios::binary);
                         if (!out) return DecError::IoError;

                         std::vector<char> buf(64 * 1024);
                         uint64_t remain = cipherLen;
                         while (remain > 0) {
                             size_t toRead = (size_t)std::min<uint64_t>(remain, buf.size());
                             in.read(buf.data(), toRead);
                             if (in.gcount() <= 0) break;
                             cc.xorData((uint8_t*)buf.data(), toRead);
                             out.write(buf.data(), toRead);
                             remain -= toRead;
                         }

                         out.flush();
                         if (!out) { out.close(); fs::remove(tmp); return DecError::IoError; }
                         out.close();

                         std::error_code ec;
                         fs::rename(tmp, dst, ec);
                         if (ec) {
                             fs::remove(dst, ec);
                             fs::rename(tmp, dst, ec);
                             if (ec) { fs::remove(tmp); return DecError::IoError; }
                         }
                         return DecError::Ok;
                     }

                     bool rewriteHeader(const fs::path& p, const HeaderInfo& h,
                                        const Json& newHeader, std::string& err) {
                         std::string js = newHeader.dump(2);
                         Bytes plain(js.begin(), js.end());

                         Nonce12 nonce = randomNonce();
                         ChaCha20 cc(h.key, nonce, 1);
                         cc.xorData(plain.data(), plain.size());

                         Bytes hblock;
                         hblock.reserve(32 + plain.size());
                         hblock.insert(hblock.end(), h.salt.begin(), h.salt.end());
                         hblock.insert(hblock.end(), nonce.begin(), nonce.end());
                         uint32_t it = h.iterations;
                         hblock.push_back((uint8_t)it);
                         hblock.push_back((uint8_t)(it >> 8));
                         hblock.push_back((uint8_t)(it >> 16));
                         hblock.push_back((uint8_t)(it >> 24));
                         hblock.insert(hblock.end(), plain.begin(), plain.end());

                         std::ifstream in(p, std::ios::binary);
                         if (!in) { err = "无法打开文件"; return false; }

                         in.seekg(0, std::ios::end);
                         uint64_t oldFileSize = in.tellg();
                         uint64_t cipherLen = oldFileSize - h.bodyOffset - (h.version >= 2 ? kMacLen : 0);
                         in.seekg((std::streamoff)h.bodyOffset, std::ios::beg);

                         fs::path tmp = p;
                         tmp += ".tmp";
                         std::ofstream out(tmp, std::ios::binary);
                         if (!out) { err = "无法创建临时文件"; return false; }

                         uint8_t flags = kFlagHeaderEncrypted;
                         if (h.hasPassword) flags |= kFlagHasPassword;
                         uint8_t pre[16];
                         buildPre(pre, flags, (uint32_t)hblock.size());

                         out.write((const char*)pre, 16);
                         out.write((const char*)hblock.data(), (std::streamsize)hblock.size());

                         // 构造新的 HMAC
                         Key32 macKey = hmacKeyFromMaster(h.key);
                         HmacSha256 hmac(macKey);
                         hmac.update(pre, 16);
                         hmac.update(hblock);

                         std::vector<char> buf(64 * 1024);
                         uint64_t remain = cipherLen;
                         while (remain > 0) {
                             size_t toRead = (size_t)std::min<uint64_t>(remain, buf.size());
                             in.read(buf.data(), toRead);
                             if (in.gcount() <= 0) break;
                             out.write(buf.data(), toRead);
                             hmac.update(buf.data(), toRead);
                             remain -= toRead;
                         }

                         Key32 mac = hmac.digest();
                         out.write((const char*)mac.data(), kMacLen);

                         out.flush();
                         bool ok = (bool)out;
                         out.close();
                         in.close();

                         if (!ok) { fs::remove(tmp); err = "写入失败"; return false; }

                         std::error_code ec;
                         fs::rename(tmp, p, ec);
                         if (ec) {
                             fs::remove(p, ec);
                             fs::rename(tmp, p, ec);
                             if (ec) { fs::remove(tmp); err = "无法替换原文件"; return false; }
                         }
                         return true;
                                        }

} // namespace dec
