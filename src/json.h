// ===================== src/json.h =====================
#pragma once
#include <string>
#include <vector>
#include <utility>

namespace dec {

    class Json {
    public:
        enum class Type { Null, Bool, Number, String, Array, Object };

        Json() : type_(Type::Null) {}
        Json(bool b)          : type_(Type::Bool), b_(b) {}
        Json(int v)           : type_(Type::Number), n_((double)v) {}
        Json(long long v)     : type_(Type::Number), n_((double)v) {}
        Json(double v)        : type_(Type::Number), n_(v) {}
        Json(const char* s)   : type_(Type::String), s_(s) {}
        Json(std::string s)   : type_(Type::String), s_(std::move(s)) {}

        static Json object();
        static Json array();

        Type type() const { return type_; }
        bool isObject() const { return type_ == Type::Object; }

        // 对象操作
        void set(const std::string& k, Json v);
        std::string getString(const std::string& k, const std::string& def = "") const;  // ← 补回
        long long   getInt(const std::string& k, long long def = 0) const;               // ← 补回

        std::string dump(int indent = 2) const;
        static Json parse(const std::string& text);   // 失败抛 std::runtime_error

    public:
        // 供 JSON 解析器构建数组/对象使用
        std::vector<Json> arr_;
        std::vector<std::pair<std::string, Json>> obj_;

    private:
        void dumpTo(std::string& out, int indent, int level) const;
        Type type_;
        bool b_ = false;
        double n_ = 0;
        std::string s_;
    };

} // namespace dec
