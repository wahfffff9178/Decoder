// ===================== src/decfile.h =====================
#pragma once
#include "crypto.h"
#include "json.h"
#include <filesystem>
#include <string>

namespace dec {

    inline constexpr uint32_t kFormatVersion = 1;
    inline constexpr uint8_t  kFlagHeaderEncrypted = 0x01;
    inline constexpr uint8_t  kFlagHasPassword     = 0x02;

    enum class DecError {
        Ok = 0,
        NotDecFile,
        VersionTooNew,
        NeedPassword,
        WrongPassword,
        BadHeader,
        IoError
    };

    const char* decErrorText(DecError e);

    struct HeaderInfo {
        Json        json;
        Bytes       salt;
        Nonce12     headerNonce{};
        uint32_t    iterations = 0;
        Key32       key{};
        bool        hasPassword = false;
        uint64_t    headerLen = 0;
        uint64_t    bodyOffset = 0;
    };

    // 读取并解密头部（password 可为空）
    DecError readHeader(const std::filesystem::path& p, const std::string& password, HeaderInfo& out);

    // 加密单个文件到 dst
    bool encryptFile(const std::filesystem::path& src,
                     const std::filesystem::path& dst,
                     const std::string& password,
                     const std::string& remarks,
                     std::string& err);

    // 依据已经解析好的头部解密正文
    DecError decryptBody(const std::filesystem::path& src,
                         const HeaderInfo& h,
                         const std::filesystem::path& dst);

    // 只重写文件头，正文密文原样保留
    bool rewriteHeader(const std::filesystem::path& p, const HeaderInfo& h,
                       const Json& newHeader, std::string& err);

} // namespace dec
