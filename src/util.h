// ===================== src/util.h =====================
#pragma once
#include <string>
#include <filesystem>
#include <chrono>

namespace dec {
    std::string nowIso();
    std::string fileTimeIso(const std::filesystem::path& p);
    std::string publicIp(); // 注意这里的结尾分号
} // namespace dec
