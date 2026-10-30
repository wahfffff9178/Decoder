// ===================== src/json.cpp =====================
#include "json.h"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <cctype>

namespace dec {

    Json Json::object() { Json j; j.type_ = Type::Object; return j; }
    Json Json::array()  { Json j; j.type_ = Type::Array;  return j; }

    void Json::set(const std::string& k, Json v) {
        if (type_ != Type::Object) { type_ = Type::Object; obj_.clear(); }
        for (auto& kv : obj_) if (kv.first == k) { kv.second = std::move(v); return; }
        obj_.emplace_back(k, std::move(v));
    }

    std::string Json::getString(const std::string& k, const std::string& def) const {
        if (type_ != Type::Object) return def;
        for (auto& kv : obj_) {
            if (kv.first == k && kv.second.type_ == Type::String) return kv.second.s_;
        }
        return def;
    }

    long long Json::getInt(const std::string& k, long long def) const {
        if (type_ != Type::Object) return def;
        for (auto& kv : obj_) {
            if (kv.first == k && kv.second.type_ == Type::Number) return (long long)kv.second.n_;
        }
        return def;
    }

    static void dumpString(std::string& out, const std::string& s) {
        out += '"';
        for (unsigned char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; }
                    else out += (char)c;
            }
        }
        out += '"';
    }

    static void dumpNumber(std::string& out, double d) {
        if (std::floor(d) == d && std::fabs(d) < 1e15) {
            out += std::to_string((long long)d);
        } else {
            char b[40];
            std::snprintf(b, sizeof b, "%.17g", d);
            out += b;
        }
    }

    void Json::dumpTo(std::string& out, int indent, int level) const {
        auto nl = [&](int lv) {
            if (indent <= 0) return;
            out += '\n';
            out.append((size_t)(indent * lv), ' ');
        };
        switch (type_) {
            case Type::Null:   out += "null"; break;
            case Type::Bool:   out += b_ ? "true" : "false"; break;
            case Type::Number: dumpNumber(out, n_); break;
            case Type::String: dumpString(out, s_); break;
            case Type::Array:
                if (arr_.empty()) { out += "[]"; break; }
                out += '[';
                for (size_t i = 0; i < arr_.size(); i++) {
                    if (i) out += ',';
                    nl(level + 1);
                    arr_[i].dumpTo(out, indent, level + 1);
                }
                nl(level); out += ']';
                break;
            case Type::Object:
                if (obj_.empty()) { out += "{}"; break; }
                out += '{';
                for (size_t i = 0; i < obj_.size(); i++) {
                    if (i) out += ',';
                    nl(level + 1);
                    dumpString(out, obj_[i].first);
                    out += ": ";
                    obj_[i].second.dumpTo(out, indent, level + 1);
                }
                nl(level); out += '}';
                break;
        }
    }

    std::string Json::dump(int indent) const {
        std::string out;
        dumpTo(out, indent, 0);
        return out;
    }

    // ---------------- 解析器 ----------------
    namespace {

        class Parser {
        public:
            explicit Parser(const std::string& s) : s_(s), i_(0) {}

            Json parse() {
                skipWs();
                Json v = parseValue();
                skipWs();
                if (i_ != s_.size()) fail("尾部存在多余字符");
                return v;
            }

        private:
            [[noreturn]] void fail(const char* msg) {
                throw std::runtime_error(std::string("JSON 解析失败: ") + msg);
            }
            void skipWs() {
                while (i_ < s_.size() && std::isspace((unsigned char)s_[i_])) i_++;
            }
            void expect(const char* lit) {
                size_t n = std::strlen(lit);
                if (i_ + n > s_.size() || s_.compare(i_, n, lit) != 0) fail(lit);
                i_ += n;
            }
            Json parseValue() {
                if (i_ >= s_.size()) fail("意外结束");
                char c = s_[i_];
                if (c == '{') return parseObject();
                if (c == '[') return parseArray();
                if (c == '"') return Json(parseString());
                if (c == 't') { expect("true");  return Json(true); }
                if (c == 'f') { expect("false"); return Json(false); }
                if (c == 'n') { expect("null");  return Json(); }
                return parseNumber();
            }
            Json parseNumber() {
                const char* start = s_.c_str() + i_;
                char* end = nullptr;
                double d = std::strtod(start, &end);
                if (end == start) fail("非法数字");
                i_ = (size_t)(end - s_.c_str());
                return Json(d);
            }
            std::string parseString() {
                if (i_ >= s_.size() || s_[i_] != '"') fail("需要字符串");
                i_++;
                std::string out;
                while (i_ < s_.size()) {
                    char c = s_[i_++];
                    if (c == '"') return out;
                    if (c == '\\') {
                        if (i_ >= s_.size()) fail("转义不完整");
                        char e = s_[i_++];
                        switch (e) {
                            case '"':  out += '"';  break;
                            case '\\': out += '\\'; break;
                            case '/':  out += '/';  break;
                            case 'b':  out += '\b'; break;
                            case 'f':  out += '\f'; break;
                            case 'n':  out += '\n'; break;
                            case 'r':  out += '\r'; break;
                            case 't':  out += '\t'; break;
                            case 'u': {
                                if (i_ + 4 > s_.size()) fail("\\u 不完整");
                                unsigned cp = (unsigned)std::strtoul(s_.substr(i_, 4).c_str(), nullptr, 16);
                                i_ += 4;
                                if (cp < 0x80) out += (char)cp;
                                else if (cp < 0x800) {
                                    out += (char)(0xC0 | (cp >> 6));
                                    out += (char)(0x80 | (cp & 0x3F));
                                } else {
                                    out += (char)(0xE0 | (cp >> 12));
                                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                                    out += (char)(0x80 | (cp & 0x3F));
                                }
                                break;
                            }
                            default: fail("非法转义");
                        }
                    } else out += c;
                }
                fail("字符串未闭合");
            }
            Json parseArray() {
                i_++; // [
                Json a = Json::array();
                skipWs();
                if (i_ < s_.size() && s_[i_] == ']') { i_++; return a; }
                for (;;) {
                    skipWs();
                    a.arr_.push_back(parseValue());
                    skipWs();
                    if (i_ >= s_.size()) fail("数组未闭合");
                    if (s_[i_] == ',') { i_++; continue; }
                    if (s_[i_] == ']') { i_++; return a; }
                    fail("数组分隔符错误");
                }
            }
            Json parseObject() {
                i_++; // {
                Json o = Json::object();
                skipWs();
                if (i_ < s_.size() && s_[i_] == '}') { i_++; return o; }
                for (;;) {
                    skipWs();
                    std::string key = parseString();
                    skipWs();
                    if (i_ >= s_.size() || s_[i_] != ':') fail("缺少冒号");
                    i_++;
                    skipWs();
                    Json v = parseValue();
                    o.obj_.emplace_back(std::move(key), std::move(v));
                    skipWs();
                    if (i_ >= s_.size()) fail("对象未闭合");
                    if (s_[i_] == ',') { i_++; continue; }
                    if (s_[i_] == '}') { i_++; return o; }
                    fail("对象分隔符错误");
                }
            }

            const std::string& s_;
            size_t i_;
        };

    } // namespace

    Json Json::parse(const std::string& text) {
        Parser p(text);
        return p.parse();
    }

} // namespace dec
