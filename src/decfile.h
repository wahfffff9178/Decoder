#pragma once
#include "crypto.h"
#include "json.h"
#include <filesystem>
#include <string>

namespace dec {

    inline constexpr uint32_t kFormatVersion = 2; // 升级到 v2
    inline constexpr size_t   kMacLen = 32;

    inline constexpr uint8_t kFlagHeaderEncrypted = 0x01;
    inline constexpr uint8_t kFlagHasPassword     = 0x02;

    enum class DecError {
        Ok = 0,
        NotDecFile,
        VersionTooNew,
        NeedPassword,
        WrongPassword,
        BadHeader,
        IoError,
        IntegrityFailed // 新增：完整性校验失败
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
        uint32_t    version = 1; // 新增：记录文件版本
    };

    DecError readHeader(const std::filesystem::path& p, const std::string& password, HeaderInfo& out);

    bool encryptFile(const std::filesystem::path& src,
                     const std::filesystem::path& dst,
                     const std::string& password,
                     const std::string& remarks,
                     std::string& err);

    DecError decryptBody(const std::filesystem::path& src,
                         const HeaderInfo& h,
                         const std::filesystem::path& dst);

    bool rewriteHeader(const std::filesystem::path& p, const HeaderInfo& h,
                       const Json& newHeader, std::string& err);

} // namespace dec
