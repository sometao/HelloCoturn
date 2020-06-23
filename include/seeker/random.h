/**
@project seeker
@author Tao Zhang
@since 2020/3/1
@version 0.0.1-SNAPSHOT 2020/6/23
*/
#pragma once

#include "seeker/loggerApi.h"
#include "seeker/common.h"
#include <string>
#include <random>

namespace seeker {

using std::string;


class RandomIntGenerator {
  std::mt19937 gen;
  std::uniform_int_distribution<> intDis;

 public:
  RandomIntGenerator(int min, int max, int seed = INT_MIN)
      : gen({seed == INT_MIN ? std::random_device()() : seed}), intDis(min, max) {}

  int operator()() { return intDis(gen); }
};


class RandomDoubleGenerator {
  std::mt19937 gen;
  std::uniform_real_distribution<> doubleDis;
 public:
  RandomDoubleGenerator(double min, double max, int seed = INT_MIN)
      : gen({seed == INT_MIN ? std::random_device()() : seed}), doubleDis(min, max) {}

  int operator()() { return doubleDis(gen); }
};


class Random {
 public:
  // static auto uniformIntDistribution1(int min, int max, int seed = INT_MIN) {
  //  RandomGenerator<int> gen(min, max, seed);
  //  return gen;
  //};

  // static auto uniformDoubleDistribution1(double min, double max, int seed = INT_MIN) {
  //  RandomGenerator<double> gen(min, max, seed);
  //  return gen;
  //};

  static auto uniformIntDistribution(int min, int max, int seed = INT_MIN) {
    static std::random_device rd;
    static std::mt19937 gen{seed == INT_MIN ? rd() : seed};
    std::uniform_int_distribution<> dis(min, max - 1);
    auto func = [=] { return dis(gen); };
    return func;
  };

  static auto uniformDoubleDistribution(double min, double max, int seed = INT_MIN) {
    static std::random_device rd;
    static std::mt19937 gen{seed == INT_MIN ? rd() : seed};
    std::uniform_real_distribution<> dis(min, max);
    auto func = [=]() { return dis(gen); };
    return func;
  };

  static auto getCharMap() {
    static char charMap[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                             'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                             'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                             'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                             '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    return charMap;
  }

  static string randomChars(size_t len) {
    static auto dic = getCharMap();
    static auto rng = RandomIntGenerator(0, 10 + 26 + 26 - 1, Time::currentTime() % INT_MAX);
    string out{};
    for (size_t i = 0; i < len; i++) {
      auto r = rng();
      out += dic[r];
    }
    return out;
  }
};


}  // namespace seeker
