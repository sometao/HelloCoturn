/**
@project seeker
@author Tao Zhang
@since 2020/3/1
@version 0.0.1-SNAPSHOT 2020/6/20
*/
#pragma once
#include <chrono>
#include <regex>


namespace seeker {

using std::string;

class Time {
 public:
  static int64_t currentTime() {
    using namespace std::chrono;
    auto time_now = system_clock::now();
    auto durationIn = duration_cast<milliseconds>(time_now.time_since_epoch());
    return durationIn.count();
  };

  static int64_t microTime() {
    using namespace std::chrono;
    auto time_now = system_clock::now();
    auto durationIn = duration_cast<microseconds>(time_now.time_since_epoch());
    return durationIn.count();
  };
};

class String {
 public:
  static string toLower(const string& target) {
    string out{};
    for (auto c : target) {
      out += ::tolower(c);
    }
    return out;
  }

  static string toUpper(const string& target) {
    string out{};
    for (auto c : target) {
      out += ::toupper(c);
    }
    return out;
  }

  static string trim(string& s) {
    string rst{s};
    if (rst.empty()) {
      return rst;
    }
    rst.erase(0, rst.find_first_not_of(" "));
    rst.erase(s.find_last_not_of(" ") + 1);
    return rst;
  }

  static std::vector<string> split(const string& target, const string& sp) {
    std::vector<string> rst{};
    if (target.size() == 0) {
      return rst;
    }

    const auto spLen = sp.length();
    string::size_type pos = 0;
    auto f = target.find(sp, pos);

    while (f != string::npos) {
      auto r = target.substr(pos, f - pos);
      rst.emplace_back(r);
      pos = f + spLen;
      f = target.find(sp, pos);
    }
    rst.emplace_back(target.substr(pos, target.length()));
    return rst;
  }

  static string removeBlanks(const string& target) {
    static std::regex blankRe{R"(\s+)"};
    return std::regex_replace(target, blankRe, "");
  }

  static string removeLastEmptyLines(const string& target) {
    size_t len = target.length();
    size_t i = len - 1;
    for (; i > 0; i--) {
      if (target[i] == '\n') {
        continue;
      } else if (target[i] == '\r') {
        continue;
      } else {
        break;
      }
    }
    return target.substr(0, i + 1);
  }
};


class ByteArray {
 public:
  template <typename T>
  static void writeData(uint8_t* buf, T num, bool littleEndian = true) {
    size_t len(sizeof(T));
    if (littleEndian) {
      for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)((num >> (i * 8)) & 0xFF);
      }
    } else {
      for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)((num >> ((len - i - 1) * 8)) & 0xFF);
      }
    }
  }

  template <typename T>
  static void readData(uint8_t* buf, T& num, bool littleEndian = true) {
    uint8_t len(sizeof(T));
    num = 0;
    if (littleEndian) {
      for (size_t i = 0; i < len; ++i) {
        num <<= 8;
        num |= (T)(buf[len - 1 - i] & 0xFF);
      }
    } else {  // not tested.
      for (size_t i = 0; i < len; ++i) {
        num <<= 8;
        num |= (T)(buf[i] & 0xFF);
      }
    }
  }


  static void writeData(uint8_t* dst, uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
      dst[i] = *(data + i);
    }
  }

  static void readData(uint8_t* src, uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
      data[i] = *(src + i);
    }
  }


  //// convert from hex to binary
  static std::vector<uint8_t> hex2bin(const std::string& hex) {
    std::vector<uint8_t> result;
    char c;
    for (size_t i = 0; i < hex.size(); i++) {
      c = std::tolower(hex[i]);
      uint8_t high = c >= 'a' ? hex[i] - 'a' + 10 : c - '0';
      c = std::tolower(hex[i]);
      i++;
      uint8_t low = c >= 'a' ? c - 'a' + 10 : c - '0';
      result.push_back(high * 16 + low);
    }
    return result;
  }

  static std::vector<uint8_t> SASLprep(uint8_t* src) {
    std::vector<uint8_t> rst;
    if (src) {
      uint8_t* strin = src;
      for (;;) {
        uint8_t c = *strin;
        if (!c) {
          rst.push_back(0);
          break;
        }
        switch (c) {
          case 0xAD:
            ++strin;
            break;
          case 0xA0:
          case 0x20:
            rst.push_back(0x20);
            ++strin;
            break;
          case 0x7F:
            rst.swap(std::vector<uint8_t>());
            break;
          default:
            if (c < 0x1F) {
              rst.swap(std::vector<uint8_t>());
            } else if (c >= 0x80 && c <= 0x9F) {
              rst.swap(std::vector<uint8_t>());
            } else {
              rst.push_back(c);
              ++strin;
            }
        };
      }
    }

    return rst;
  }

  static int SASLprep0(uint8_t* src, uint8_t* out) {
    if (src) {
      uint8_t* strin = src;
      uint8_t* strout = out;
      for (;;) {
        uint8_t c = *strin;
        if (!c) {
          *strout = 0;
          break;
        }
        switch (c) {
          case 0xAD:
            ++strin;
            break;
          case 0xA0:
          case 0x20:
            *strout = 0x20;
            ++strout;
            ++strin;
            break;
          case 0x7F:
            return -1;
          default:
            if (c < 0x1F) return -1;
            if (c >= 0x80 && c <= 0x9F) return -1;
            *strout = c;
            ++strout;
            ++strin;
        };
      }
    }

    return 0;
  }
};


}  // namespace seeker