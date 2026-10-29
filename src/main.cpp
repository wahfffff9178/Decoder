// ===================== src/main.cpp =====================
#include "crypto.h"
#include "json.h"
#include "decfile.h"
#include "util.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <filesystem>

namespace fs = std::filesystem;
using namespace dec;

static const char* kVersion = "1.0.0";

// ---------------- 帮助 ----------------
static void printUsage(std::ostream& os) {
    os <<
    "用法:  decoder <操作> [...]\n"
    "操作:\n"
    "    decoder {-h --help}\n"
    "    decoder {-V --version}\n"
    "    decoder {-E --encryption} [文件/文件夹路径] <密码> <备注>\n"
    "    decoder {-U --decryption} [dec文件路径] <密码>\n"
    "    decoder {-R --readinghead} [dec文件路径] <密码>\n"
    "    decoder {-M --modifyhead} [dec文件路径] <密码>\n"
    "\n"
    "使用 'decoder {-h --help}' 及某个操作以查看可用选项\n";
}

static void printOpHelp(char op) {
    switch (op) {
        case 'E':
            std::cout <<
            "-E, --encryption  加密文件或整个文件夹（递归处理，自动跳过 .dec 文件）\n"
            "可用选项:\n"
            "    -f, --force          覆盖已存在的 .dec 文件\n"
            "位置参数:\n"
            "    <路径>   要加密的文件或文件夹\n"
            "    <密码>   加密密码，传 \"\" 表示无密码\n"
            "    <备注>   写入加密头的备注文本\n";
            break;
        case 'U':
            std::cout <<
            "-U, --decryption  解密 .dec 文件，按头部记录的原始文件名还原\n"
            "可用选项:\n"
            "    -f, --force          覆盖已存在的目标文件\n"
            "    -o, --output <路径>  指定输出文件或目录\n"
            "位置参数:\n"
            "    <dec文件路径>  <密码>\n";
            break;
        case 'R':
            std::cout <<
            "-R, --readinghead  只解密头部并输出摘要，不还原正文\n"
            "可用选项:\n"
            "    --json               输出完整 JSON 结构\n"
            "位置参数:\n"
            "    <dec文件路径>  <密码>\n";
            break;
        case 'M':
            std::cout <<
            "-M, --modifyhead  只重写加密头，正文密文原样保留\n"
            "可用选项:\n"
            "    --remarks <文本>     直接设置备注\n"
            "    -i, --ip <地址>      设置源 IP\n"
            "    -e, --edit           调用系统编辑器编辑头部 JSON\n"
            "不带以上任何选项时进入交互式修改备注。\n"
            "位置参数:\n"
            "    <dec文件路径>  <密码>\n";
            break;
        default: printUsage(std::cout);
    }
}

static std::string readAll(const fs::path& p, bool& ok) {
    std::ifstream f(p, std::ios::binary);
    if (!f) { ok = false; return {}; }
    std::ostringstream ss;
    ss << f.rdbuf();
    ok = true;
    return ss.str();
}

// ---------------- 操作：加密 ----------------
static int doEncrypt(const std::vector<std::string>& pos, bool force) {
    if (pos.size() < 3) {
        std::cerr << "错误: 参数不足，需要 <路径> <密码> <备注> (使用 -E -h 获取帮助)\n";
        return 1;
    }
    fs::path path = pos[0];
    std::string password = pos[1];
    std::string remarks  = pos[2];

    std::error_code ec;
    if (!fs::exists(path, ec)) {
        std::cerr << "错误: 路径不存在: " << path.string() << "\n";
        return 1;
    }

    std::vector<fs::path> files;
    if (fs::is_directory(path, ec)) {
        for (auto& e : fs::recursive_directory_iterator(
            path, fs::directory_options::skip_permission_denied, ec)) {
            if (e.is_regular_file()) files.push_back(e.path());
            }
    } else {
        files.push_back(path);
    }

    int ok = 0, skip = 0, fail = 0;
    for (auto& f : files) {
        std::string name = f.filename().string();
        if (name.size() >= 4 && name.compare(name.size() - 4, 4, ".dec") == 0) {
            std::cout << "[跳过] " << f.string() << " (已是 DEC 文件)\n";
            skip++;
            continue;
        }
        fs::path dst = f;
        dst += ".dec";
        if (fs::exists(dst, ec) && !force) {
            std::cout << "[跳过] " << dst.string() << " (目标已存在，使用 -f 覆盖)\n";
            skip++;
            continue;
        }
        std::string err;
        if (encryptFile(f, dst, password, remarks, err)) {
            std::cout << "[完成] " << f.string() << " -> " << dst.string() << "\n";
            ok++;
        } else {
            std::cerr << "[失败] " << f.string() << ": " << err << "\n";
            fail++;
        }
    }
    std::cout << "共 " << files.size() << " 个文件，成功 " << ok
    << "，跳过 " << skip << "，失败 " << fail << "\n";
    return fail ? 1 : 0;
}

// ---------------- 操作：解密 ----------------
static int doDecrypt(const std::vector<std::string>& pos, bool force, const std::string& outPath) {
    if (pos.empty()) {
        std::cerr << "错误: 缺少 <dec文件路径> (使用 -U -h 获取帮助)\n";
        return 1;
    }
    fs::path src = pos[0];
    std::string password = pos.size() > 1 ? pos[1] : "";

    HeaderInfo h;
    DecError e = readHeader(src, password, h);
    if (e != DecError::Ok) {
        std::cerr << "错误: " << decErrorText(e) << "\n";
        return 1;
    }

    std::string origName = h.json.getString("original_name");
    if (origName.empty()) origName = src.stem().string();

    fs::path dst;
    if (!outPath.empty()) {
        fs::path o = outPath;
        std::error_code ec;
        if (fs::is_directory(o, ec)) dst = o / origName;
        else dst = o;
    } else {
        dst = src.parent_path() / origName;
    }

    std::error_code ec;
    if (fs::exists(dst, ec) && !force) {
        std::cerr << "错误: 目标文件已存在: " << dst.string() << " (使用 -f 覆盖)\n";
        return 1;
    }
    if (fs::equivalent(src, dst, ec)) {
        std::cerr << "错误: 目标文件与源文件相同: " << dst.string() << "\n";
        return 1;
    }

    e = decryptBody(src, h, dst);
    if (e != DecError::Ok) {
        std::cerr << "错误: " << decErrorText(e) << "\n";
        return 1;
    }

    std::cout << "---------------Decryption complete---------------\n\n";
    std::cout << "Decryption file: " << src.string()
    << " decrypted to target file " << dst.string() << "\n";
    std::cout << "Encryption Header   : \"" << h.json.getString("remarks") << "\"\n";
    std::cout << "Encryption Source IP: \"" << h.json.getString("source_ip") << "\"\n";
    std::cout << "\n------------------------------------------------------\n";
    return 0;
}

// ---------------- 操作：读头 ----------------
static int doReadHead(const std::vector<std::string>& pos, bool jsonOut) {
    if (pos.empty()) {
        std::cerr << "错误: 缺少 <dec文件路径> (使用 -R -h 获取帮助)\n";
        return 1;
    }
    fs::path src = pos[0];
    std::string password = pos.size() > 1 ? pos[1] : "";

    HeaderInfo h;
    DecError e = readHeader(src, password, h);
    if (e != DecError::Ok) {
        std::cerr << "错误: " << decErrorText(e) << "\n";
        return 1;
    }

    if (jsonOut) {
        Json out = Json::object();
        out.set("file", src.string());
        out.set("format_version", (long long)kFormatVersion);
        out.set("has_password", h.hasPassword);
        out.set("kdf_salt", base64Encode(h.salt));
        out.set("kdf_iterations", (long long)h.iterations);
        out.set("body_offset", (long long)h.bodyOffset);
        out.set("header", h.json);
        std::cout << out.dump(2) << "\n";
        return 0;
    }

    std::cout << "---------------Header Analysis complete---------------\n\n";
    std::cout << "DEC Encrypted File " << src.string() << ":\n";
    std::cout << "Encryption Header   : \"" << h.json.getString("remarks") << "\"\n";
    std::cout << "Encryption Source IP: \"" << h.json.getString("source_ip") << "\"\n";
    std::cout << "\n------------------------------------------------------\n";
    return 0;
}

// ---------------- 操作：改头 ----------------
static int doModifyHead(const std::vector<std::string>& pos,
                        bool hasRemarks, const std::string& remarks,
                        bool hasIp, const std::string& ip,
                        bool edit) {
    if (pos.empty()) {
        std::cerr << "错误: 缺少 <dec文件路径> (使用 -M -h 获取帮助)\n";
        return 1;
    }
    fs::path src = pos[0];
    std::string password = pos.size() > 1 ? pos[1] : "";

    HeaderInfo h;
    DecError e = readHeader(src, password, h);
    if (e != DecError::Ok) {
        std::cerr << "错误: " << decErrorText(e) << "\n";
        return 1;
    }

    Json j = h.json;
    std::string origName  = h.json.getString("original_name");
    long long   origSize  = h.json.getInt("original_size");
    std::string bodyNonce = h.json.getString("body_nonce");

    if (hasRemarks) {
        j.set("remarks", remarks);
    } else if (hasIp) {
        j.set("source_ip", ip);
    } else if (edit) {
        fs::path tmp = fs::temp_directory_path() / "decoder_header.json";
        {
            std::ofstream f(tmp, std::ios::binary);
            if (!f) { std::cerr << "错误: 无法创建临时文件\n"; return 1; }
            f << j.dump(2);
        }
        const char* ed = std::getenv("VISUAL");
        if (!ed) ed = std::getenv("EDITOR");
        if (!ed) ed = "vi";
        std::string cmd = std::string(ed) + " \"" + tmp.string() + "\"";
        int rc = std::system(cmd.c_str());
        if (rc != 0) { std::cerr << "错误: 编辑器返回非零状态\n"; fs::remove(tmp); return 1; }

        bool ok = false;
        std::string content = readAll(tmp, ok);
        fs::remove(tmp);
        if (!ok) { std::cerr << "错误: 无法读取临时文件\n"; return 1; }
        try {
            j = Json::parse(content);
        } catch (const std::exception& ex) {
            std::cerr << "错误: 编辑后的内容不是合法 JSON: " << ex.what() << "\n";
            return 1;
        }
    } else {
        std::cout << "当前备注: " << j.getString("remarks") << "\n";
        std::cout << "请输入新备注: ";
        std::string line;
        std::getline(std::cin, line);
        j.set("remarks", line);
    }

    // 保护关键字段，避免误改导致正文无法解密
    j.set("format",        (long long)kFormatVersion);
    j.set("original_name", origName);
    j.set("original_size", origSize);
    j.set("body_nonce",    bodyNonce);
    j.set("modified_at",   nowIso());

    std::string err;
    if (!rewriteHeader(src, h, j, err)) {
        std::cerr << "错误: " << err << "\n";
        return 1;
    }
    std::cout << "[完成] 已更新加密头: " << src.string() << "\n";
    std::cout << "Encryption Header   : \"" << j.getString("remarks") << "\"\n";
    std::cout << "Encryption Source IP: \"" << j.getString("source_ip") << "\"\n";
    return 0;
                        }

                        // ---------------- 入口 ----------------
                        int main(int argc, char** argv) {
                            char op = 0;
                            bool help = false, version = false;
                            bool force = false, jsonOut = false, edit = false;
                            bool hasRemarks = false, hasIp = false, hasOut = false;
                            std::string remarks, ip, outPath;
                            std::vector<std::string> pos;

                            for (int i = 1; i < argc; i++) {
                                std::string a = argv[i];
                                if (a == "-h" || a == "--help") { help = true; }
                                else if (a == "-V" || a == "--version") { version = true; }
                                else if (a == "-E" || a == "--encryption") { op = 'E'; }
                                else if (a == "-U" || a == "--decryption") { op = 'U'; }
                                else if (a == "-R" || a == "--readinghead") { op = 'R'; }
                                else if (a == "-M" || a == "--modifyhead") { op = 'M'; }
                                else if (a == "-f" || a == "--force") { force = true; }
                                else if (a == "--json") { jsonOut = true; }
                                else if (a == "-e" || a == "--edit") { edit = true; }
                                else if (a == "--remarks") {
                                    if (i + 1 >= argc) { std::cerr << "错误: --remarks 缺少参数\n"; return 1; }
                                    remarks = argv[++i]; hasRemarks = true;
                                }
                                else if (a == "-i" || a == "--ip") {
                                    if (i + 1 >= argc) { std::cerr << "错误: -i 缺少参数\n"; return 1; }
                                    ip = argv[++i]; hasIp = true;
                                }
                                else if (a == "-o" || a == "--output") {
                                    if (i + 1 >= argc) { std::cerr << "错误: -o 缺少参数\n"; return 1; }
                                    outPath = argv[++i]; hasOut = true;
                                }
                                else if (!a.empty() && a[0] == '-' && a != "-") {
                                    std::cerr << "错误: 未知选项 " << a << " (使用 -h 获取帮助)\n";
                                    return 1;
                                }
                                else { pos.push_back(a); }
                            }

                            if (version && !op) { std::cout << "decoder " << kVersion << "\n"; return 0; }
                            if (op && help)     { printOpHelp(op); return 0; }
                            if (help)           { printUsage(std::cout); return 0; }
                            if (!op) {
                                std::cerr << "没有指定操作 (使用 -h 获取帮助)\n";
                                return 1;
                            }

                            switch (op) {
                                case 'E': return doEncrypt(pos, force);
                                case 'U': return doDecrypt(pos, force, outPath);
                                case 'R': return doReadHead(pos, jsonOut);
                                case 'M': return doModifyHead(pos, hasRemarks, remarks, hasIp, ip, edit);
                            }
                            return 1;
                        }
