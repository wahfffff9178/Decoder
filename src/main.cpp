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
#include <locale>
#include <clocale>
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#include <csignal>
#endif

namespace fs = std::filesystem;
using namespace dec;

// =====================================================================
// 国际化 (i18n) 支持
// =====================================================================
static bool use_zh = false;

static std::string T(const std::string &zh, const std::string &en)
{
    return use_zh ? zh : en;
}

static void detect_language()
{
    const char *lang = std::getenv("LANG");
    if (!lang)
        lang = std::getenv("LC_ALL");
    if (!lang)
        lang = std::getenv("LC_MESSAGES");
    if (lang)
    {
        std::string l(lang);
        if (l.find("zh") != std::string::npos)
        {
            use_zh = true;
        }
    }
#ifdef _WIN32
    if (GetACP() == 936)
        use_zh = true;
#endif
}

// =====================================================================

static std::string trim(const std::string &s)
{
    size_t start = s.find_first_not_of(" \r\n\t");
    size_t end = s.find_last_not_of(" \r\n\t");
    if (start == std::string::npos)
        return "";
    return s.substr(start, end - start + 1);
}

#ifndef _WIN32
static struct termios old_termios;
static bool is_raw_mode = false;

void restore_terminal_handler(int sig)
{
    if (is_raw_mode)
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
        is_raw_mode = false;
    }
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}
#endif

// =====================================================================
// 终极行编辑器：接管输入、完美支持中文/方向键/退格、每次按键整行重绘
// =====================================================================
static std::string readLine(const std::string &prompt, bool hide = false)
{
    std::cout << prompt;
    std::string buf;
    size_t cursor = 0;

#ifdef _WIN32
    char ch;
    while ((ch = _getch()) != '\r')
    {
        if (ch == '\b')
        {
            if (cursor > 0)
            {
                size_t pos = cursor - 1;
                while (pos > 0 && (buf[pos] & 0xC0) == 0x80)
                    pos--;
                buf.erase(pos, cursor - pos);
                cursor = pos;
            }
        }
        else if (ch == 0 || ch == -32)
        {
            char ext = _getch();
            if (ext == 75 && cursor > 0)
            {
                cursor--;
                while (cursor > 0 && (buf[cursor] & 0xC0) == 0x80)
                    cursor--;
            }
            else if (ext == 77 && cursor < buf.size())
            {
                cursor++;
                while (cursor < buf.size() && (buf[cursor] & 0xC0) == 0x80)
                    cursor++;
            }
        }
        else if (ch >= 32)
        {
            buf.insert(cursor, 1, ch);
            cursor++;
            while (cursor < buf.size() && (buf[cursor] & 0xC0) == 0x80)
                cursor++;
        }
        std::cout << "\r\033[K" << prompt << (hide ? std::string(buf.size(), '*') : buf);
        if (buf.size() > cursor)
            std::cout << "\033[" << (buf.size() - cursor) << "D";
        std::cout << std::flush;
    }
    std::cout << "\r\033[K" << prompt << (hide ? std::string(buf.size(), '*') : buf) << "\n";
#else
    termios newt;
    tcgetattr(STDIN_FILENO, &old_termios);
    newt = old_termios;
    newt.c_lflag &= ~(ICANON | ECHO);
    newt.c_lflag |= ISIG;
    newt.c_cc[VMIN] = 1;
    newt.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    is_raw_mode = true;

    std::signal(SIGINT, restore_terminal_handler);
    std::signal(SIGTERM, restore_terminal_handler);

    int ch;
    while ((ch = getchar()) != '\n' && ch != '\r')
    {
        if (ch == 127 || ch == 8)
        {
            if (cursor > 0)
            {
                size_t pos = cursor - 1;
                while (pos > 0 && (buf[pos] & 0xC0) == 0x80)
                    pos--;
                buf.erase(pos, cursor - pos);
                cursor = pos;
            }
        }
        else if (ch == 27)
        {
            int seq1 = getchar();
            if (seq1 == '[')
            {
                int seq2 = getchar();
                if (seq2 == 'D')
                {
                    if (cursor > 0)
                    {
                        cursor--;
                        while (cursor > 0 && (buf[cursor] & 0xC0) == 0x80)
                            cursor--;
                    }
                }
                else if (seq2 == 'C')
                {
                    if (cursor < buf.size())
                    {
                        cursor++;
                        while (cursor < buf.size() && (buf[cursor] & 0xC0) == 0x80)
                            cursor++;
                    }
                }
                else if (seq2 == 'H')
                    cursor = 0;
                else if (seq2 == 'F')
                    cursor = buf.size();
            }
        }
        else if (ch >= 32 || ch < 0)
        {
            buf.insert(cursor, 1, (char)ch);
            cursor++;
            while (cursor < buf.size() && (buf[cursor] & 0xC0) == 0x80)
                cursor++;
        }
        std::cout << "\r\033[K" << prompt;
        if (hide)
            std::cout << std::string(buf.size(), '*');
        else
            std::cout << buf;
        if (buf.size() > cursor)
            std::cout << "\033[" << (buf.size() - cursor) << "D";
        std::cout << std::flush;
    }
    std::cout << "\r\033[K" << prompt;
    if (hide)
        std::cout << std::string(buf.size(), '*');
    else
        std::cout << buf;
    std::cout << "\n";
    tcflush(STDIN_FILENO, TCIFLUSH);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
    is_raw_mode = false;
    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
#endif
    return buf;
}

static const char *kVersion = "2.2.2";
static int doEncrypt(const std::vector<std::string> &pos, bool force, bool remove_source);
static int doWizard();

// ---------------- 版本信息 ----------------
// ---------------- 版本信息 ----------------
static void printVersion()
{
    std::cout
        << " ____  _____ ____ \n"
        << "|  _ \\| ____/ ___|   Deccoder v" << kVersion << "\n"
        << "| | | |  _|| |       Copyright (C) https://github.com/wahfffff9178\n"
        << "| |_| | |__| |___    \n"
        << "|____/|_____\\____|   本程序可以在 GNU 一般公众许可条款下自由分发\n"
        << "\n";
}

// ---------------- 帮助 ----------------
static void printUsage(std::ostream &os)
{
    if (use_zh)
    {
        os << "用法:  deccoder <操作> [...]\n"
              "操作:\n"
              "    deccoder {-h --help}\n"
              "    deccoder {-V --version}\n"
              "    deccoder {-E --encryption} [文件/文件夹路径] <密码> <备注>\n"
              "    deccoder {-D -U --decryption} [dec文件路径] <密码>\n"
              "    deccoder {-R --readinghead} [dec文件路径] <密码>\n"
              "    deccoder {-W --wizard}                         (交互式加密向导)\n"
              "    deccoder {-M --modifyhead} [dec文件路径] <密码>\n"
              "\n"
              "使用 'deccoder {-h --help}' 及某个操作以查看可用选项\n";
    }
    else
    {
        os << "Usage: deccoder <operation> [...]\n"
              "Operations:\n"
              "    deccoder {-h --help}\n"
              "    deccoder {-V --version}\n"
              "    deccoder {-E --encryption} [file/folder path] <password> <remarks>\n"
              "    deccoder {-D -U --decryption} [dec file path] <password>\n"
              "    deccoder {-R --readinghead} [dec file path] <password>\n"
              "    deccoder {-W --wizard}                         (interactive wizard)\n"
              "    deccoder {-M --modifyhead} [dec file path] <password>\n"
              "\n"
              "Use 'deccoder {-h --help}' with an operation to see available options.\n";
    }
}

static void printOpHelp(char op)
{
    switch (op)
    {
    case 'E':
        if (use_zh)
        {
            std::cout << "-E, --encryption  加密文件或整个文件夹（递归处理，自动跳过 .dec 文件）\n"
                         "可用选项:\n"
                         "    -f, --force          覆盖已存在的 .dec 文件\n"
                         "    -r, --remove         加密成功后删除源文件/文件夹\n"
                         "位置参数:\n"
                         "    <路径>   要加密的文件或文件夹\n"
                         "    <密码>   加密密码，传 \"\" 表示无密码\n"
                         "    <备注>   写入加密头的备注文本\n";
        }
        else
        {
            std::cout << "-E, --encryption  Encrypt a file or folder (recursive, skips .dec files)\n"
                         "Options:\n"
                         "    -f, --force          Overwrite existing .dec files\n"
                         "    -r, --remove         Remove source file/folder after successful encryption\n"
                         "Arguments:\n"
                         "    <path>   File or folder to encrypt\n"
                         "    <password> Encryption password, \"\" for no password\n"
                         "    <remarks> Remarks to store in the header\n";
        }
        break;
    case 'U':
        if (use_zh)
        {
            std::cout << "-U, --decryption  解密 .dec 文件，按头部记录的原始文件名还原\n"
                         "可用选项:\n"
                         "    -f, --force          覆盖已存在的目标文件\n"
                         "    -o, --output <路径>  指定输出文件或目录\n"
                         "位置参数:\n"
                         "    <dec文件路径>  <密码>\n";
        }
        else
        {
            std::cout << "-U, --decryption  Decrypt a .dec file to its original name\n"
                         "Options:\n"
                         "    -f, --force          Overwrite existing files\n"
                         "    -o, --output <path>  Output file or directory\n"
                         "Arguments:\n"
                         "    <dec-file>  <password>\n";
        }
        break;
    case 'R':
        if (use_zh)
        {
            std::cout << "-R, --readinghead  只解密头部并输出摘要，不还原正文\n"
                         "可用选项:\n"
                         "    --json               输出完整 JSON 结构\n"
                         "位置参数:\n"
                         "    <dec文件路径>  <密码>\n";
        }
        else
        {
            std::cout << "-R, --readinghead  Decrypt and print header only, no content\n"
                         "Options:\n"
                         "    --json               Output full JSON structure\n"
                         "Arguments:\n"
                         "    <dec-file>  <password>\n";
        }
        break;
    case 'M':
        if (use_zh)
        {
            std::cout << "-M, --modifyhead  只重写加密头，正文密文原样保留\n"
                         "可用选项:\n"
                         "    --remarks <文本>     直接设置备注\n"
                         "    -i, --ip <地址>      设置源 IP\n"
                         "    -e, --edit           调用系统编辑器编辑头部 JSON\n"
                         "不带以上任何选项时进入交互式修改备注。\n"
                         "位置参数:\n"
                         "    <dec文件路径>  <密码>\n";
        }
        else
        {
            std::cout << "-M, --modifyhead  Rewrite the encrypted header, keep the body intact\n"
                         "Options:\n"
                         "    --remarks <text>     Set remarks directly\n"
                         "    -i, --ip <addr>      Set source IP\n"
                         "    -e, --edit           Open header JSON in system editor\n"
                         "Without options, enters interactive remark edit.\n"
                         "Arguments:\n"
                         "    <dec-file>  <password>\n";
        }
        break;
    case 'W':
        if (use_zh)
            std::cout << "-W, --wizard      交互式加密向导，一步步引导完成加密\n";
        else
            std::cout << "-W, --wizard      Interactive wizard to guide you through encryption\n";
        break;
    default:
        printUsage(std::cout);
    }
}

static std::string readAll(const fs::path &p, bool &ok)
{
    std::ifstream f(p, std::ios::binary);
    if (!f)
    {
        ok = false;
        return {};
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    ok = true;
    return ss.str();
}

// ---------------- 操作：加密向导 ----------------
static int doWizard()
{
    std::cout << T("================ 欢迎使用 DEC 加密向导 ================\n\n",
                   "================ Welcome to DEC Encryption Wizard ================\n\n");

    std::string pathStr;
    fs::path path;
    std::error_code ec;

    while (true)
    {
        pathStr = readLine(T("请输入要加密的文件或文件夹路径 (或输入 q 退出): ",
                             "Enter file or folder path to encrypt (or q to quit): "));
        pathStr = trim(pathStr);

        if (pathStr == "q" || pathStr == "Q")
        {
            std::cout << T("已取消。\n", "Cancelled.\n");
            return 0;
        }
        if (pathStr.empty())
            continue;

        if (pathStr.size() >= 2)
        {
            if ((pathStr.front() == '"' && pathStr.back() == '"') ||
                (pathStr.front() == '\'' && pathStr.back() == '\''))
            {
                pathStr = pathStr.substr(1, pathStr.size() - 2);
            }
        }

        path = pathStr;
        if (fs::exists(path, ec))
            break;
        std::cerr << T("错误: 路径不存在，请重新输入。\n", "Error: Path does not exist, please try again.\n");
    }

    std::string password;
    std::cout << "\n";
    std::string choice = readLine(T("是否设置加密密码? (y/N): ", "Set an encryption password? (y/N): "));
    if (!choice.empty() && (choice[0] == 'y' || choice[0] == 'Y'))
    {
        std::string pwd1, pwd2;
        while (true)
        {
            pwd1 = readLine(T("请输入密码: ", "Enter password: "), true);
            pwd2 = readLine(T("请再次输入密码: ", "Confirm password: "), true);
            if (pwd1 == pwd2)
            {
                password = pwd1;
                break;
            }
            std::cerr << T("错误: 两次输入的密码不一致，请重新输入。\n", "Error: Passwords do not match, please try again.\n");
        }
    }

    std::cout << "\n";
    std::string remarks = readLine(T("请输入文件备注 (可直接回车留空): ", "Enter remarks (leave empty to skip): "));
    remarks = trim(remarks);

    std::cout << "\n";
    choice = readLine(T("如果目标 .dec 文件已存在，是否强制覆盖? (y/N): ",
                        "Overwrite existing .dec file if it exists? (y/N): "));
    bool force = (!choice.empty() && (choice[0] == 'y' || choice[0] == 'Y'));

    std::cout << "\n";
    choice = readLine(T("加密成功后是否删除源文件/文件夹? (y/N): ",
                        "Remove source file/folder after successful encryption? (y/N): "));
    bool remove_source = (!choice.empty() && (choice[0] == 'y' || choice[0] == 'Y'));

    std::cout << T("\n================ 确认加密信息 ================\n",
                   "\n================ Confirm Encryption Info ================\n");
    std::cout << T("目标路径: ", "Target path: ") << path.string() << "\n";
    std::cout << T("密码保护: ", "Password: ") << (password.empty() ? T("否", "No") : T("是", "Yes")) << "\n";
    std::cout << T("备注信息: ", "Remarks: ") << (remarks.empty() ? T("(空)", "(empty)") : remarks) << "\n";
    std::cout << T("强制覆盖: ", "Force overwrite: ") << (force ? T("是", "Yes") : T("否", "No")) << "\n";
    std::cout << T("删除源文件: ", "Remove source: ") << (remove_source ? T("是", "Yes") : T("否", "No")) << "\n\n";

    choice = readLine(T("是否开始加密? (Y/n): ", "Start encryption? (Y/n): "));
    if (!choice.empty() && (choice[0] == 'n' || choice[0] == 'N'))
    {
        std::cout << T("已取消。\n", "Cancelled.\n");
        return 0;
    }

    std::cout << T("\n开始处理...\n\n", "\nProcessing...\n\n");
    std::vector<std::string> pos = {path.string(), password, remarks};
    return doEncrypt(pos, force, remove_source);
}

// ---------------- 操作：加密 ----------------
static int doEncrypt(const std::vector<std::string> &pos, bool force, bool remove_source)
{
    if (pos.size() < 3)
    {
        std::cerr << T("错误: 参数不足，需要 <路径> <密码> <备注> (使用 -E -h 获取帮助)\n",
                       "Error: Insufficient arguments, requires <path> <password> <remarks> (use -E -h for help)\n");
        return 1;
    }
    fs::path path = pos[0];
    std::string password = pos[1];
    std::string remarks = pos[2];

    std::error_code ec;
    if (!fs::exists(path, ec))
    {
        std::cerr << T("错误: 路径不存在: ", "Error: Path does not exist: ") << path.string() << "\n";
        return 1;
    }

    fs::path dst = path;
    dst += ".dec";

    if (fs::exists(dst, ec) && !force)
    {
        std::cerr << T("错误: 目标已存在: ", "Error: Target exists: ") << dst.string() << T(" (使用 -f 覆盖)\n", " (use -f to overwrite)\n");
        return 1;
    }

    // 如果是目录，先打包成临时文件
    if (fs::is_directory(path, ec))
    {
        std::cout << T("正在打包文件夹...\n", "Packing directory...\n");
        fs::path tmpArchive = fs::temp_directory_path() / (path.filename().string() + ".tmp");

        std::string err;
        if (!packDirectory(path, tmpArchive, err))
        {
            std::cerr << T("[失败] 打包目录出错: ", "[Fail] Packing directory failed: ") << err << "\n";
            return 1;
        }

        std::cout << T("正在加密归档...\n", "Encrypting archive...\n");
        bool ok = encryptFile(tmpArchive, dst, password, remarks, true, err);
        fs::remove(tmpArchive);

        if (ok)
        {
            std::cout << T("[完成] ", "[Done] ") << path.string() << " -> " << dst.string() << "\n";
            if (remove_source)
            {
                std::error_code rm_ec;
                fs::remove_all(path, rm_ec);
                if (rm_ec)
                    std::cerr << T("警告: 删除源文件夹失败: ", "Warning: Failed to remove source folder: ") << rm_ec.message() << "\n";
                else
                    std::cout << T("[删除] 已删除源文件夹: ", "[Removed] Source folder deleted: ") << path.string() << "\n";
            }
            return 0;
        }
        else
        {
            std::cerr << T("[失败] ", "[Fail] ") << path.string() << ": " << err << "\n";
            return 1;
        }
    }
    else
    {
        // 普通文件
        std::string err;
        if (encryptFile(path, dst, password, remarks, false, err))
        {
            std::cout << T("[完成] ", "[Done] ") << path.string() << " -> " << dst.string() << "\n";
            if (remove_source)
            {
                std::error_code rm_ec;
                fs::remove(path, rm_ec);
                if (rm_ec)
                    std::cerr << T("警告: 删除源文件失败: ", "Warning: Failed to remove source file: ") << rm_ec.message() << "\n";
                else
                    std::cout << T("[删除] 已删除源文件: ", "[Removed] Source file deleted: ") << path.string() << "\n";
            }
            return 0;
        }
        else
        {
            std::cerr << T("[失败] ", "[Fail] ") << path.string() << ": " << err << "\n";
            return 1;
        }
    }
}

// ---------------- 操作：解密 ----------------
static int doDecrypt(const std::vector<std::string> &pos, bool force, const std::string &outPath)
{
    if (pos.empty())
    {
        std::cerr << T("错误: 缺少 <dec文件路径> (使用 -U -h 获取帮助)\n",
                       "Error: Missing <dec file path> (use -U -h for help)\n");
        return 1;
    }
    fs::path src = pos[0];
    std::string password = pos.size() > 1 ? pos[1] : "";

    HeaderInfo h;
    DecError e = readHeader(src, password, h);
    if (e != DecError::Ok)
    {
        std::cerr << T("错误: ", "Error: ") << decErrorText(e) << "\n";
        return 1;
    }

    std::string origName = h.json.getString("original_name");
    if (origName.empty())
        origName = src.stem().string();
    bool is_archive = (h.json.getInt("is_archive") != 0);

    if (is_archive)
    {
        if (origName.size() > 4 && origName.compare(origName.size() - 4, 4, ".tmp") == 0)
        {
            origName = origName.substr(0, origName.size() - 4);
        }

        fs::path dstDir;
        if (!outPath.empty())
        {
            fs::path o = outPath;
            std::error_code ec;
            if (fs::is_directory(o, ec) || outPath.back() == '/' || outPath.back() == '\\')
            {
                dstDir = o / origName;
            }
            else
            {
                dstDir = o;
            }
        }
        else
        {
            dstDir = src.parent_path() / origName;
        }

        std::error_code ec;
        if (fs::exists(dstDir, ec) && !force)
        {
            std::cerr << T("错误: 目标目录已存在: ", "Error: Target directory exists: ") << dstDir.string() << T(" (使用 -f 覆盖)\n", " (use -f to overwrite)\n");
            return 1;
        }

        fs::path tmpArchive = fs::temp_directory_path() / (origName + ".dec_tmp");
        e = decryptBody(src, h, tmpArchive);
        if (e != DecError::Ok)
        {
            std::cerr << T("错误: ", "Error: ") << decErrorText(e) << "\n";
            fs::remove(tmpArchive);
            return 1;
        }

        std::cout << T("正在解包...\n", "Unpacking...\n");
        std::string err;
        if (!unpackArchive(tmpArchive, dstDir, err))
        {
            std::cerr << T("错误: 解包失败: ", "Error: Unpacking failed: ") << err << "\n";
            fs::remove(tmpArchive);
            return 1;
        }
        fs::remove(tmpArchive);

        std::cout << T("---------------解密完成---------------\n\n",
                       "---------------Decryption complete---------------\n\n");
        std::cout << T("解密文件: ", "Decryption file: ") << src.string()
                  << T(" 解密至目标目录 ", " decrypted to target directory ") << dstDir.string() << "\n";
        if (use_zh)
        {
            std::cout << "加密备注: \"" << h.json.getString("remarks") << "\"\n";
            std::cout << "源 IP   : \"" << h.json.getString("source_ip") << "\"\n";
        }
        else
        {
            std::cout << "Encryption Header   : \"" << h.json.getString("remarks") << "\"\n";
            std::cout << "Encryption Source IP: \"" << h.json.getString("source_ip") << "\"\n";
        }
        std::cout << "\n------------------------------------------------------\n";
        return 0;
    }
    else
    {
        fs::path dst;
        if (!outPath.empty())
        {
            fs::path o = outPath;
            std::error_code ec;
            if (fs::is_directory(o, ec))
                dst = o / origName;
            else
                dst = o;
        }
        else
        {
            dst = src.parent_path() / origName;
        }

        std::error_code ec;
        if (fs::exists(dst, ec) && !force)
        {
            std::cerr << T("错误: 目标文件已存在: ", "Error: Target file exists: ") << dst.string() << T(" (使用 -f 覆盖)\n", " (use -f to overwrite)\n");
            return 1;
        }
        if (fs::equivalent(src, dst, ec))
        {
            std::cerr << T("错误: 目标文件与源文件相同: ", "Error: Target file is the same as source: ") << dst.string() << "\n";
            return 1;
        }

        e = decryptBody(src, h, dst);
        if (e != DecError::Ok)
        {
            std::cerr << T("错误: ", "Error: ") << decErrorText(e) << "\n";
            return 1;
        }

        std::cout << T("---------------解密完成---------------\n\n",
                       "---------------Decryption complete---------------\n\n");
        std::cout << T("解密文件: ", "Decryption file: ") << src.string()
                  << T(" 解密至目标文件 ", " decrypted to target file ") << dst.string() << "\n";
        if (use_zh)
        {
            std::cout << "加密备注: \"" << h.json.getString("remarks") << "\"\n";
            std::cout << "源 IP   : \"" << h.json.getString("source_ip") << "\"\n";
        }
        else
        {
            std::cout << "Encryption Header   : \"" << h.json.getString("remarks") << "\"\n";
            std::cout << "Encryption Source IP: \"" << h.json.getString("source_ip") << "\"\n";
        }
        std::cout << "\n------------------------------------------------------\n";
        return 0;
    }
}

// ---------------- 操作：读头 ----------------
static int doReadHead(const std::vector<std::string> &pos, bool jsonOut)
{
    if (pos.empty())
    {
        std::cerr << T("错误: 缺少 <dec文件路径> (使用 -R -h 获取帮助)\n",
                       "Error: Missing <dec file path> (use -R -h for help)\n");
        return 1;
    }
    fs::path src = pos[0];
    std::string password = pos.size() > 1 ? pos[1] : "";

    HeaderInfo h;
    DecError e = readHeader(src, password, h);
    if (e != DecError::Ok)
    {
        std::cerr << T("错误: ", "Error: ") << decErrorText(e) << "\n";
        return 1;
    }

    if (jsonOut)
    {
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

    std::cout << T("---------------头部解析完成---------------\n\n",
                   "---------------Header Analysis complete---------------\n\n");
    std::cout << T("DEC 加密文件 ", "DEC Encrypted File ") << src.string() << ":\n";
    if (use_zh)
    {
        std::cout << "加密备注: \"" << h.json.getString("remarks") << "\"\n";
        std::cout << "源 IP   : \"" << h.json.getString("source_ip") << "\"\n";
    }
    else
    {
        std::cout << "Encryption Header   : \"" << h.json.getString("remarks") << "\"\n";
        std::cout << "Encryption Source IP: \"" << h.json.getString("source_ip") << "\"\n";
    }
    if (h.json.getInt("is_archive") != 0)
    {
        std::cout << T("类型    : 归档 (文件夹)\n", "Type                : Archive (Folder)\n");
    }
    std::cout << "\n------------------------------------------------------\n";
    return 0;
}

// ---------------- 操作：改头 ----------------
static int doModifyHead(const std::vector<std::string> &pos,
                        bool hasRemarks, const std::string &remarks,
                        bool hasIp, const std::string &ip,
                        bool edit)
{
    if (pos.empty())
    {
        std::cerr << T("错误: 缺少 <dec文件路径> (使用 -M -h 获取帮助)\n",
                       "Error: Missing <dec file path> (use -M -h for help)\n");
        return 1;
    }
    fs::path src = pos[0];
    std::string password = pos.size() > 1 ? pos[1] : "";

    HeaderInfo h;
    DecError e = readHeader(src, password, h);
    if (e != DecError::Ok)
    {
        std::cerr << T("错误: ", "Error: ") << decErrorText(e) << "\n";
        return 1;
    }

    Json j = h.json;
    std::string origName = h.json.getString("original_name");
    long long origSize = h.json.getInt("original_size");
    std::string bodyNonce = h.json.getString("body_nonce");

    if (hasRemarks)
    {
        j.set("remarks", remarks);
    }
    else if (hasIp)
    {
        j.set("source_ip", ip);
    }
    else if (edit)
    {
        fs::path tmp = fs::temp_directory_path() / "deccoder_header.json";
        {
            std::ofstream f(tmp, std::ios::binary);
            if (!f)
            {
                std::cerr << T("错误: 无法创建临时文件\n", "Error: Cannot create temp file\n");
                return 1;
            }
            f << j.dump(2);
        }
        const char *ed = std::getenv("VISUAL");
        if (!ed)
            ed = std::getenv("EDITOR");
        if (!ed)
            ed = "vi";
        std::string cmd = std::string(ed) + " \"" + tmp.string() + "\"";
        int rc = std::system(cmd.c_str());
        if (rc != 0)
        {
            std::cerr << T("错误: 编辑器返回非零状态\n", "Error: Editor returned non-zero status\n");
            fs::remove(tmp);
            return 1;
        }

        bool ok = false;
        std::string content = readAll(tmp, ok);
        fs::remove(tmp);
        if (!ok)
        {
            std::cerr << T("错误: 无法读取临时文件\n", "Error: Cannot read temp file\n");
            return 1;
        }
        try
        {
            j = Json::parse(content);
        }
        catch (const std::exception &ex)
        {
            std::cerr << T("错误: 编辑后的内容不是合法 JSON: ", "Error: Edited content is not valid JSON: ") << ex.what() << "\n";
            return 1;
        }
    }
    else
    {
        std::cout << T("当前备注: ", "Current remarks: ") << j.getString("remarks") << "\n";
        std::string line = readLine(T("请输入新备注: ", "Enter new remarks: "));
        j.set("remarks", line);
    }

    j.set("format", (long long)kFormatVersion);
    j.set("original_name", origName);
    j.set("original_size", origSize);
    j.set("body_nonce", bodyNonce);
    j.set("modified_at", nowIso());

    std::string err;
    if (!rewriteHeader(src, h, j, err))
    {
        std::cerr << T("错误: ", "Error: ") << err << "\n";
        return 1;
    }
    std::cout << T("[完成] 已更新加密头: ", "[Done] Updated header: ") << src.string() << "\n";
    if (use_zh)
    {
        std::cout << "加密备注: \"" << j.getString("remarks") << "\"\n";
        std::cout << "源 IP   : \"" << j.getString("source_ip") << "\"\n";
    }
    else
    {
        std::cout << "Encryption Header   : \"" << j.getString("remarks") << "\"\n";
        std::cout << "Encryption Source IP: \"" << j.getString("source_ip") << "\"\n";
    }
    return 0;
}

// ---------------- 入口 ----------------
int main(int argc, char **argv)
{
    detect_language();

#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif

    char op = 0;
    bool help = false, version = false;
    bool force = false, jsonOut = false, edit = false, remove_source = false;
    bool hasRemarks = false, hasIp = false;
    std::string remarks, ip, outPath;
    std::vector<std::string> pos;

    for (int i = 1; i < argc; i++)
    {
        std::string a = argv[i];
        if (a == "-h" || a == "--help")
        {
            help = true;
        }
        else if (a == "-V" || a == "--version")
        {
            version = true;
        }
        else if (a == "-E" || a == "--encryption")
        {
            op = 'E';
        }
        else if (a == "-U" || a == "-D" || a == "--decryption")
        {
            op = 'U';
        }
        else if (a == "-R" || a == "--readinghead")
        {
            op = 'R';
        }
        else if (a == "-M" || a == "--modifyhead")
        {
            op = 'M';
        }
        else if (a == "-W" || a == "--wizard")
        {
            op = 'W';
        }
        else if (a == "-f" || a == "--force")
        {
            force = true;
        }
        else if (a == "-r" || a == "--remove")
        {
            remove_source = true;
        }
        else if (a == "--json")
        {
            jsonOut = true;
        }
        else if (a == "-e" || a == "--edit")
        {
            edit = true;
        }
        else if (a == "--remarks")
        {
            if (i + 1 >= argc)
            {
                std::cerr << T("错误: --remarks 缺少参数\n", "Error: --remarks requires an argument\n");
                return 1;
            }
            remarks = argv[++i];
            hasRemarks = true;
        }
        else if (a == "-i" || a == "--ip")
        {
            if (i + 1 >= argc)
            {
                std::cerr << T("错误: -i 缺少参数\n", "Error: -i requires an argument\n");
                return 1;
            }
            ip = argv[++i];
            hasIp = true;
        }
        else if (a == "-o" || a == "--output")
        {
            if (i + 1 >= argc)
            {
                std::cerr << T("错误: -o 缺少参数\n", "Error: -o requires an argument\n");
                return 1;
            }
            outPath = argv[++i];
        }
        else if (!a.empty() && a[0] == '-' && a != "-")
        {
            std::cerr << T("错误: 未知选项 ", "Error: Unknown option ") << a << T(" (使用 -h 获取帮助)\n", " (use -h for help)\n");
            return 1;
        }
        else
        {
            pos.push_back(a);
        }
    }

    if (version && !op)
    {
        printVersion();
        return 0;
    }
    if (op && help)
    {
        printOpHelp(op);
        return 0;
    }
    if (help)
    {
        printUsage(std::cout);
        return 0;
    }
    if (!op)
    {
        std::cerr << T("没有指定操作 (使用 -h 获取帮助)\n", "No operation specified (use -h for help)\n");
        return 1;
    }

    switch (op)
    {
    case 'W':
        return doWizard();
    case 'E':
        return doEncrypt(pos, force, remove_source);
    case 'U':
        return doDecrypt(pos, force, outPath);
    case 'R':
        return doReadHead(pos, jsonOut);
    case 'M':
        return doModifyHead(pos, hasRemarks, remarks, hasIp, ip, edit);
    }
    return 1;
}
