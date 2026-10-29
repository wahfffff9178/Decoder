// ===================== src/util.h =====================
#pragma once
#include <string>
#include <filesystem>
#include <chrono>

namespace dec {

    std::string nowIso();
    std::string fileTimeIso(const std::filesystem::path& p);
    std::string localIp();

} // namespace dec
