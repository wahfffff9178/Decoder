// ===================== src/util.cpp =====================
#include "util.h"
#include <ctime>
#include <cstdio>
#include <array>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define popen _popen
#define pclose _pclose
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <cstring>
#endif

namespace fs = std::filesystem;

namespace dec {

    static std::string fmtTime(std::time_t t) {
        std::tm tm{};
        #ifdef _WIN32
        gmtime_s(&tm, &t);
        #else
        gmtime_r(&t, &tm);
        #endif
        char b[32];
        std::strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%SZ", &tm);
        return b;
    }

    std::string nowIso() { return fmtTime(std::time(nullptr)); }

    std::string fileTimeIso(const fs::path& p) {
        std::error_code ec;
        auto ft = fs::last_write_time(p, ec);
        if (ec) return nowIso();
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ft - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
        return fmtTime(std::chrono::system_clock::to_time_t(sctp));
    }

    // 本地 IP 作为降级备用
    static std::string localIp() {
        #ifdef _WIN32
        return "127.0.0.1";
        #else
        struct ifaddrs* ifa = nullptr;
        if (getifaddrs(&ifa) != 0) return "127.0.0.1";
        std::string best = "127.0.0.1";
        for (auto* p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
            char buf[INET_ADDRSTRLEN] = {0};
            auto* sin = (struct sockaddr_in*)p->ifa_addr;
            if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf)) { best = buf; break; }
        }
        freeifaddrs(ifa);
        return best;
        #endif
    }

    // 公网 IP
    std::string publicIp() {
        std::string cmd = "curl -s --max-time 2 https://api.ipify.org";
        std::string result;
        FILE* pipe = popen(cmd.c_str(), "r");

        if (pipe) {
            char buffer[128];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                result += buffer;
            }
            pclose(pipe);
        }

        while (!result.empty() && (result.back() == '\n' || result.back() == '\r' || result.back() == ' ')) {
            result.pop_back();
        }

        if (result.length() >= 7 && result.length() <= 15) {
            return result;
        }

        return localIp();
    }

} // namespace dec
