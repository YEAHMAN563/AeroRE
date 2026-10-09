#include "aerore/json.hpp"

#include <cctype>
#include <cmath>
#include <sstream>
#include <stdexcept>

namespace aerore {
namespace {

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}

    Json parse() {
        skip();
        Json j = value();
        skip();
        if (i_ != s_.size()) throw std::runtime_error("trailing json");
        return j;
    }

private:
    const std::string& s_;
    size_t i_ = 0;

    void skip() {
        while (i_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[i_]))) ++i_;
    }
    char peek() const { return i_ < s_.size() ? s_[i_] : '\0'; }
    char get() {
        if (i_ >= s_.size()) throw std::runtime_error("unexpected end of json");
        return s_[i_++];
    }

    Json value() {
        skip();
        char c = peek();
        if (c == '{') return object();
        if (c == '[') return array();
        if (c == '"') return Json::string(str());
        if (c == 't') {
            lit("true");
            return Json::boolean(true);
        }
        if (c == 'f') {
            lit("false");
            return Json::boolean(false);
        }
        if (c == 'n') {
            lit("null");
            return Json::nul();
        }
        if (c == '-' || (c >= '0' && c <= '9')) return number();
        throw std::runtime_error("invalid json value");
    }

    void lit(const char* w) {
        for (const char* p = w; *p; ++p)
            if (get() != *p) throw std::runtime_error("invalid literal");
    }

    Json object() {
        get();
        Json j = Json::object();
        skip();
        if (peek() == '}') {
            get();
            return j;
        }
        while (true) {
            skip();
            if (peek() != '"') throw std::runtime_error("expected key");
            std::string key = str();
            skip();
            if (get() != ':') throw std::runtime_error("expected colon");
            j.set(std::move(key), value());
            skip();
            char c = get();
            if (c == '}') break;
            if (c != ',') throw std::runtime_error("expected comma");
        }
        return j;
    }

    Json array() {
        get();
        Json j = Json::array();
        skip();
        if (peek() == ']') {
            get();
            return j;
        }
        while (true) {
            j.arr.push_back(value());
            skip();
            char c = get();
            if (c == ']') break;
            if (c != ',') throw std::runtime_error("expected comma");
        }
        return j;
    }

    std::string str() {
        if (get() != '"') throw std::runtime_error("expected string");
        std::string out;
        while (true) {
            char c = get();
            if (c == '"') break;
            if (c == '\\') {
                char e = get();
                switch (e) {
                    case '"':
                    case '\\':
                    case '/': out.push_back(e); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        int cp = 0;
                        for (int k = 0; k < 4; ++k) {
                            char h = get();
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp += h - '0';
                            else if (h >= 'a' && h <= 'f') cp += h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') cp += h - 'A' + 10;
                            else throw std::runtime_error("bad unicode escape");
                        }
                        if (cp < 0x80) out.push_back(static_cast<char>(cp));
                        else if (cp < 0x800) {
                            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: throw std::runtime_error("bad escape");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    Json number() {
        size_t start = i_;
        if (peek() == '-') get();
        if (peek() == '0') get();
        else if (peek() >= '1' && peek() <= '9') {
            while (peek() >= '0' && peek() <= '9') get();
        } else throw std::runtime_error("bad number");
        if (peek() == '.') {
            get();
            if (!std::isdigit(static_cast<unsigned char>(peek()))) throw std::runtime_error("bad number");
            while (std::isdigit(static_cast<unsigned char>(peek()))) get();
        }
        if (peek() == 'e' || peek() == 'E') {
            get();
            if (peek() == '+' || peek() == '-') get();
            if (!std::isdigit(static_cast<unsigned char>(peek()))) throw std::runtime_error("bad number");
            while (std::isdigit(static_cast<unsigned char>(peek()))) get();
        }
        std::string tok = s_.substr(start, i_ - start);
        Json j = Json::number(std::strtod(tok.c_str(), nullptr));
        bool integral = tok.find('.') == std::string::npos && tok.find('e') == std::string::npos &&
                        tok.find('E') == std::string::npos;
        if (integral) {
            j.b = true;
            j.str = tok;
        }
        return j;
    }
};

void dump_str(std::ostringstream& os, const std::string& s) {
    os << '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': os << "\\\""; break;
            case '\\': os << "\\\\"; break;
            case '\b': os << "\\b"; break;
            case '\f': os << "\\f"; break;
            case '\n': os << "\\n"; break;
            case '\r': os << "\\r"; break;
            case '\t': os << "\\t"; break;
            default:
                if (c < 0x20) {
                    os << "\\u00" << "0123456789abcdef"[c >> 4] << "0123456789abcdef"[c & 0xF];
                } else {
                    os << static_cast<char>(c);
                }
        }
    }
    os << '"';
}

void dump_into(std::ostringstream& os, const Json& j) {
    switch (j.type) {
        case Json::Type::Null: os << "null"; break;
        case Json::Type::Bool: os << (j.b ? "true" : "false"); break;
        case Json::Type::Number:
            if (j.b && !j.str.empty()) os << j.str;
            else os << j.num;
            break;
        case Json::Type::String: dump_str(os, j.str); break;
        case Json::Type::Array: {
            os << '[';
            for (size_t i = 0; i < j.arr.size(); ++i) {
                if (i) os << ',';
                dump_into(os, j.arr[i]);
            }
            os << ']';
            break;
        }
        case Json::Type::Object: {
            os << '{';
            for (size_t i = 0; i < j.obj.size(); ++i) {
                if (i) os << ',';
                dump_str(os, j.obj[i].first);
                os << ':';
                dump_into(os, j.obj[i].second);
            }
            os << '}';
            break;
        }
    }
}

}  // namespace

unsigned long long Json::get_u64(const std::string& key, unsigned long long def) const {
    const Json* j = get(key);
    if (!j) return def;
    if (j->type == Type::Number) {
        if (j->b && !j->str.empty()) {
            try {
                size_t idx = 0;
                unsigned long long v = std::stoull(j->str, &idx, 0);
                return v;
            } catch (...) {
                return static_cast<unsigned long long>(j->num);
            }
        }
        return static_cast<unsigned long long>(j->num);
    }
    if (j->type == Type::String) {
        try {
            size_t idx = 0;
            return std::stoull(j->str, &idx, 0);
        } catch (...) {
            return def;
        }
    }
    return def;
}

Json Json::parse(const std::string& text) { return Parser(text).parse(); }

std::string Json::dump() const {
    std::ostringstream os;
    dump_into(os, *this);
    return os.str();
}

}  // namespace aerore
