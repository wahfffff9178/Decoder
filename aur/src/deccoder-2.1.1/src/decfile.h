#pragma once
#include "crypto.h"
#include "json.h"
#include <filesystem>
#include <string>

namespace dec {

inline constexpr uint32_t kFormatVersion = 2;
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
    IntegrityFailed
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
    uint32_t    version = 1;
};

DecError readHeader(const std::filesystem::path& p, const std::string& password, HeaderInfo& out);

// 增加 is_archive 参数
bool encryptFile(const std::filesystem::path& src,
                 const std::filesystem::path& dst,
                 const std::string& password,
                 const std::string& remarks,
                 bool is_archive,
                 std::string& err);

DecError decryptBody(const std::filesystem::path& src,
                     const HeaderInfo& h,
                     const std::filesystem::path& dst);

bool rewriteHeader(const std::filesystem::path& p, const HeaderInfo& h,
                   const Json& newHeader, std::string& err);

// 新增：打包和解包目录
bool packDirectory(const std::filesystem::path& srcDir, const std::filesystem::path& outArchive, std::string& err);
bool unpackArchive(const std::filesystem::path& archiveFile, const std::filesystem::path& outDir, std::string& err);

} // namespace dec