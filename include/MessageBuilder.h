#include <iostream>
#include <vector>
#include <unordered_map>
#include "seeker/common.h"
/*

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 2: Format of STUN Message Header



0                 1
2  3  4 5 6 7 8 9 0 1 2 3 4 5

+--+--+-+-+-+-+-+-+-+-+-+-+-+-+
|M |M |M|M|M|C|M|M|M|C|M|M|M|M|
|11|10|9|8|7|1|6|5|4|0|3|2|1|0|
+--+--+-+-+-+-+-+-+-+-+-+-+-+-+

Figure 3: Format of STUN Message Type Field

*/

#define MAGIC_COOKIE 0x2112A442

namespace HelloCoturn {

using seeker::ByteArray;
using std::string;
using std::vector;


enum class StunMethod {
  Allocate = 0x003,
  Refresh = 0x004,
  Send = 0x006,
  Data = 0x007,
  CreatePermission = 0x008,
  ChannelBind = 0x009,
};

enum class StunClass {
  request = 0x01,
  indication = 0x02,
  successResponse = 0x03,
  errorResponse = 0x04
};



enum class StunAttributeType {
  CHANNEL_NUMBER = 0x000C,
  LIFETIME = 0x000D,
  USERNAME = 0x0006,
  MESSAGE_INTEGRITY = 0x0008,
  ERROR_CODE = 0x0009,
  XOR_PEER_ADDRESS = 0x0012,
  DATA = 0x0013,
  REALM = 0x0014,
  NONCE = 0x0015,
  XOR_RELAYED_ADDRESS = 0x0016,
  EVEN_PORT = 0x0018,
  REQUESTED_TRANSPORT = 0x0019,
  DONT_FRAGMENT = 0x001A,
  XOR_MAPPED_ADDRESS = 0x0020,
  RESERVATION_TOKEN = 0x0022,
  SOFTWARE = 0x8022,
  FINGERPRINT = 0x8028,
};



class MessageBuilder {
 private:
  StunMethod msgMethod;
  StunClass msgClass;
  uint32_t transactionId_p1;
  uint32_t transactionId_p2;
  uint32_t transactionId_p3;

  bool fingerprintEnable;
  bool messageIntegrityEnable;

  const uint16_t headerLength = 20;
  const uint32_t magicCookie = 0x2112A442;
  const uint32_t fingerprintCookie = 0x5354554e;

  std::unordered_map<uint16_t, vector<uint8_t>> attributes;


  static uint16_t paddingLength(uint16_t len) {
    uint16_t padding = 4 - (len % 4);
    padding = padding == 4 ? 0 : padding;
    return padding;
  }

  void addAttr(StunAttributeType attrType, const uint8_t* data, const size_t len) {
    uint16_t typeCode = (uint16_t)attrType;
    if (attributes.find(typeCode) == attributes.end()) {
      std::vector<uint8_t> vec(len);
      for (int i = 0; i < len; i++) {
        vec.at(i) = data[i];
      }
      attributes.emplace(typeCode, std::move(vec));
    }
  }

  void writeHeader(std::vector<uint8_t>& msgData) {
    uint16_t msgType = getMsgType();
    auto dataBuf = msgData.data();
    ByteArray::writeData(dataBuf + 0, msgType);
    ByteArray::writeData(dataBuf + 4, magicCookie);
    ByteArray::writeData(dataBuf + 8, transactionId_p1);
    ByteArray::writeData(dataBuf + 12, transactionId_p2);
    ByteArray::writeData(dataBuf + 16, transactionId_p3);
  }

  void writeAttributes(std::vector<uint8_t>& msgData) {
    auto dataBuf = msgData.data();

    auto bodyBuf = dataBuf + headerLength;
    size_t pos = 0;
    for (auto& pair : attributes) {
      uint16_t t = pair.first;
      vector<uint8_t> v = pair.second;
      uint16_t len = (uint16_t)v.size();
      int padding = paddingLength(len);

      ByteArray::writeData(bodyBuf + pos, t);
      pos += sizeof(t);

      ByteArray::writeData(bodyBuf + pos, len);
      pos += sizeof(len);

      ByteArray::writeData(bodyBuf + pos, v.data(), len);
      pos += len;

      for (int i = 0; i < padding; ++i) {
        ByteArray::writeData(bodyBuf + pos, (uint8_t)0x00);
        pos += 1;
      }
    }

    if (messageIntegrityEnable) {
      uint16_t messageIntegrityAttrLength = 2 + 2 + 20;
      uint16_t dummyMsgLength = headerLength + pos + messageIntegrityAttrLength;
      ByteArray::writeData(dataBuf + 2, dummyMsgLength);
      uint8_t messageIntegrityValue[20];

      //TODO calculate messageIntegrityValue;

      uint16_t t = (uint16_t) StunAttributeType::MESSAGE_INTEGRITY;
      uint16_t len = (uint16_t) 20;

      ByteArray::writeData(bodyBuf + pos, t);
      pos += sizeof(t);
      ByteArray::writeData(bodyBuf + pos, len);
      pos += sizeof(len);
      ByteArray::writeData(bodyBuf + pos, messageIntegrityValue, len);
      pos += len;
    }

    if(fingerprintEnable) {
      uint16_t fingerprintAttrLength = 2 + 2 + 4;
      uint16_t msgLength = headerLength + pos + fingerprintAttrLength;
      ByteArray::writeData(dataBuf + 2, msgLength);

      uint32_t fingerprintValue;
      //TODO calculate fingerprintValue;

      uint16_t t = (uint16_t) StunAttributeType::FINGERPRINT;
      uint16_t len = (uint16_t) sizeof(fingerprintValue);

      ByteArray::writeData(bodyBuf + pos, t);
      pos += sizeof(t);
      ByteArray::writeData(bodyBuf + pos, len);
      pos += sizeof(len);
      ByteArray::writeData(bodyBuf + pos, fingerprintValue);
      pos += len;
    } else {
      uint16_t msgLength = headerLength + pos;
      ByteArray::writeData(dataBuf + 2, msgLength);
    }
  }



  uint16_t getMsgType() {
    uint16_t msgType = 0x0000;
    uint16_t method = (uint16_t)msgMethod;
    uint16_t clz = (uint16_t)msgClass;
    msgType = (msgType << 5) | ((method >> 7) & 0x1f);
    msgType = (msgType << 1) | ((clz >> 1) & 0x01);
    msgType = (msgType << 3) | ((method >> 4) & 0x07);
    msgType = (msgType << 1) | (clz & 0x01);
    msgType = (msgType << 4) | (method & 0x0F);
    return msgType;
  }



 public:
  void setMethod(StunMethod method) { msgMethod = method; }
  void setClass(StunClass clz) { msgClass = clz; }

  void setAttr_REQUESTED_TRANSPORT(){};
  //TODO normal attribute sets.
  //TODO continue here.

  std::vector<uint8_t> buildMsg() { std::vector<uint8_t> msgData(1024); };
};



class StunMessage {
 private:
  uint8_t* header;
  uint8_t* body;


  vector<uint8_t> attrRequestedTransport;

 public:
};


class AllocationMsg {
 private:
  uint8_t* data;
  uint8_t* header;
  uint8_t* body;

  void writeHeader() {}

 public:
  AllocationMsg(uint8_t* tId, const string& software, int liftTime) {}
};

}  // namespace HelloCoturn
