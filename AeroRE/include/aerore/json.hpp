#pragma once

#include <map>
#include <string>
#include <vector>

namespace aerore {

struct Json {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;

    static Json nul() { return {}; }
    static Json boolean(bool v) {
        Json j;
        j.type = Type::Bool;
        j.b = v;
        return j;
    }
    static Json number(double v) {
        Json j;
        j.type = Type::Number;
        j.num = v;
        return j;
    }
    static Json number_u64(unsigned long long v) {
        Json j;
        j.type = Type::Number;
        j.num = static_cast<double>(v);
        j.str = std::to_string(v);
        j.b = true;  // marks integer formatting via str
        return j;
    }
    static Json string(std::string v) {
        Json j;
        j.type = Type::String;
        j.str = std::move(v);
        return j;
    }
    static Json array(std::vector<Json> v = {}) {
        Json j;
        j.type = Type::Array;
        j.arr = std::move(v);
        return j;
    }
    static Json object(std::vector<std::pair<std::string, Json>> v = {}) {
        Json j;
        j.type = Type::Object;
        j.obj = std::move(v);
        return j;
    }

    Json& set(std::string key, Json value) {
        type = Type::Object;
        for (auto& kv : obj) {
            if (kv.first == key) {
                kv.second = std::move(value);
                return *this;
            }
        }
        obj.emplace_back(std::move(key), std::move(value));
        return *this;
    }

    const Json* get(const std::string& key) const {
        if (type != Type::Object) return nullptr;
        for (auto& kv : obj)
            if (kv.first == key) return &kv.second;
        return nullptr;
    }
    std::string get_str(const std::string& key, const std::string& def = "") const {
        const Json* j = get(key);
        if (!j) return def;
        if (j->type == Type::String) return j->str;
        if (j->type == Type::Number) return j->b ? j->str : std::to_string(static_cast<long long>(j->num));
        return def;
    }
    unsigned long long get_u64(const std::string& key, unsigned long long def = 0) const;
    bool get_bool(const std::string& key, bool def = false) const {
        const Json* j = get(key);
        if (!j) return def;
        if (j->type == Type::Bool) return j->b;
        return def;
    }

    static Json parse(const std::string& text);
    std::string dump() const;
};

}  // namespace aerore
