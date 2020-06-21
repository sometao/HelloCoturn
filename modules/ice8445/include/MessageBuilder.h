#include <iostream>
#include <vector>
#include <unordered_map>
#include "seeker/common.h"
#include "hmac.h"
#include "crc32.h"
#include "md5.h"
#include "sha1.h"

#include <iomanip>


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
  request = 0x00,
  indication = 0x01,
  successResponse = 0x02,
  errorResponse = 0x03
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
  uint32_t transactionId[3] = {0, 0, 0};

  bool fingerprintEnable;
  bool messageIntegrityEnable;

  const uint16_t headerLength = 20;
  const uint32_t magicCookie = 0x2112A442;

  std::unordered_map<uint16_t, vector<uint8_t>> attributes;
  std::vector<uint16_t> attributesOrder;

  std::string username;
  std::string password;
  std::string realm;

  // TODO need test.
  void genMessageIntegrity(const uint8_t* data, size_t len, uint8_t out[20]) {
    std::cout << "------ genMessageIntegrity 0 -----------" << std::endl;

    std::vector<uint8_t> passwordVector;
    passwordVector = ByteArray::SASLprep((uint8_t*)password.c_str());
    if (passwordVector.empty()) {
      throw std::exception("password SASLprep failed.");
    }
    std::cout << "------ genMessageIntegrity 1 -----------" << std::endl;


    // long-term credentials
    // MD5 md5;
    //// key = MD5(username ":" realm ":" SASLprep(password))
    // string keyStr{};
    // keyStr += username;
    // keyStr += ":";
    // keyStr += realm;
    // keyStr += ":";
    // keyStr += (char*)passwordVector.data();
    // std::cout << "------ genMessageIntegrity 2 ----------- keyStr:" << keyStr << std::endl;
    // std::cout << "------ genMessageIntegrity 3 -----------" << std::endl;

    // md5.reset();
    // md5.add(keyStr.c_str(), keyStr.size());
    // uint8_t key[16];
    // md5.getHash(key);
    //// out length must be 20 bytes.
    // hmac<SHA1>(data, len, key, 16, out);
    // std::cout << "------ genMessageIntegrity 4 -----------" << std::endl;



    // short-term credentials
    string key((char*)passwordVector.data());
    std::cout << "------ genMessageIntegrity 3 -----------key:" << key << " size=" << key.size() << std::endl;

    hmac<SHA1>(data, len, key.c_str(), key.size(), out);
    std::cout << "------ genMessageIntegrity 4 -----------" << std::endl;
  }


  static void genFingerprint(const uint8_t* data, size_t len, uint8_t fingerprint[4]) {
    static uint8_t fingerprintCookie[4] = {0x53, 0x54, 0x55, 0x4e};

    CRC32 crc32Hasher;

    crc32Hasher.add(data, len);
    crc32Hasher.getHash(fingerprint);

    fingerprint[0] = fingerprint[0] ^ fingerprintCookie[0];
    fingerprint[1] = fingerprint[1] ^ fingerprintCookie[1];
    fingerprint[2] = fingerprint[2] ^ fingerprintCookie[2];
    fingerprint[3] = fingerprint[3] ^ fingerprintCookie[3];
  }


  static uint8_t paddingLength(uint16_t len) {
    uint16_t padding = 4 - (len % 4);
    padding = padding == 4 ? 0 : padding;
    return padding;
  }

  void addAttr(StunAttributeType attrType, const uint8_t* data, const size_t len) {
    if (attrType == StunAttributeType::FINGERPRINT ||
        attrType == StunAttributeType::MESSAGE_INTEGRITY) {
      throw std::runtime_error(
          "FINGERPRINT and MESSAGE_INTEGRITY attributes can not be added by user, they are "
          "auto "
          "generated.");
    }

    uint16_t typeCode = (uint16_t)attrType;
    if (attributes.find(typeCode) == attributes.end()) {
      std::vector<uint8_t> vec(len);
      attributesOrder.push_back(typeCode);
      for (int i = 0; i < len; i++) {
        vec.at(i) = data[i];
      }
      std::cout << "atrr t=" << std::hex << (int)typeCode << std::dec << " len=" << len
                << " size=" << vec.size() << std::endl;
      attributes.emplace(typeCode, std::move(vec));
    }
  }

  void writeHeader(std::vector<uint8_t>& msgData) {
    uint16_t msgType = getMsgType();
    auto dataBuf = msgData.data();
    ByteArray::writeData(dataBuf + 0, msgType, false);
    ByteArray::writeData(dataBuf + 4, magicCookie, false);
    ByteArray::writeData(dataBuf + 8, transactionId[0], false);
    ByteArray::writeData(dataBuf + 12, transactionId[1], false);
    ByteArray::writeData(dataBuf + 16, transactionId[2], false);
  }

  uint16_t calcMsgLength() {
    uint16_t len = 0;

    for (auto& attr : attributes) {
      auto attrLen = attr.second.size();
      uint8_t padding = paddingLength(attrLen);
      len += (2 + 2 + attrLen + padding);
    }

    if (messageIntegrityEnable) {
      len += (2 + 2 + 20 + 0);
    }

    if (fingerprintEnable) {
      len += (2 + 2 + 4 + 0);
    }
    return len;
  }

  void writeAttributes(std::vector<uint8_t>& msgData) {
    std::cout << "------ writeAttributes 0 -----------" << std::endl;
    auto dataBuf = msgData.data();


    auto bodyBuf = dataBuf + headerLength;
    std::cout << "------ writeAttributes 1 -----------" << std::endl;
    size_t pos = 0;

    for (auto& t : attributesOrder) {
      vector<uint8_t> v = attributes.at(t);

      uint16_t len = (uint16_t)v.size();
      uint8_t padding = paddingLength(len);


      ByteArray::writeData(bodyBuf + pos, t, false);
      pos += sizeof(t);

      ByteArray::writeData(bodyBuf + pos, len, false);
      pos += sizeof(len);

      ByteArray::writeData(bodyBuf + pos, v.data(), len);
      pos += len;

      for (int i = 0; i < padding; ++i) {
        ByteArray::writeData(bodyBuf + pos, (uint8_t)0x00);
        pos += 1;
      }
      std::cout << "------ writeAttributes 3 -----------t= " << std::hex << (t) << std::dec
                << " len=" << len << " pos=" << pos << std::endl;
    }

    // for (auto& pair : attributes) {
    //  uint16_t t = pair.first;
    //  vector<uint8_t> v = pair.second;
    //  uint16_t len = (uint16_t)v.size();
    //  uint8_t padding = paddingLength(len);


    //  ByteArray::writeData(bodyBuf + pos, t, false);
    //  pos += sizeof(t);

    //  ByteArray::writeData(bodyBuf + pos, len, false);
    //  pos += sizeof(len);

    //  ByteArray::writeData(bodyBuf + pos, v.data(), len);
    //  pos += len;

    //  for (int i = 0; i < padding; ++i) {
    //    ByteArray::writeData(bodyBuf + pos, (uint8_t)0x00);
    //    pos += 1;
    //  }
    //  std::cout << "------ writeAttributes 3 -----------t= " << std::hex << (t) << std::dec
    //            << " len=" << len << " pos=" << pos << std::endl;
    //}

    if (messageIntegrityEnable) {
      uint16_t messageIntegrityAttrLength = 2 + 2 + 20;
      uint16_t dummyMsgLength = pos + messageIntegrityAttrLength;
      ByteArray::writeData(dataBuf + 2, dummyMsgLength);
      uint8_t messageIntegrityValue[20];

      std::cout << "------ writeAttributes 3.1 -----------" << std::endl;
      genMessageIntegrity(dataBuf, headerLength + pos, messageIntegrityValue);

      std::cout << std::hex;
      for (int i = 0; i < 20; i++) {
        std::cout << std::setw(2) << std::setfill('0') << (int)messageIntegrityValue[i]
                  << " ";  //
      }

      std::cout << std::dec << std::endl;
      std::cout << "------ writeAttributes 3.2 -----------" << std::endl;

      uint16_t t = (uint16_t)StunAttributeType::MESSAGE_INTEGRITY;
      uint16_t len = (uint16_t)20;

      std::cout << "------ writeAttributes 3.3.1 ----------- len=" << len << " pos=" << pos
                << std::endl;

      ByteArray::writeData(bodyBuf + pos, t, false);
      pos += sizeof(t);
      ByteArray::writeData(bodyBuf + pos, len, false);
      pos += sizeof(len);
      ByteArray::writeData(bodyBuf + pos, messageIntegrityValue, len);
      pos += len;
      std::cout << "------ writeAttributes 3.3.2 ----------- len=" << len << " pos=" << pos
                << std::endl;
    }
    std::cout << "------ writeAttributes 4 -----------" << std::endl;

    if (fingerprintEnable) {  // TODO crc32 need test
      uint16_t fingerprintAttrLength = 2 + 2 + 4;
      uint16_t msgLength = pos + fingerprintAttrLength;
      ByteArray::writeData(dataBuf + 2, msgLength, false);

      unsigned char fingerprint[4];

      genFingerprint(dataBuf, headerLength + pos, fingerprint);

      uint16_t t = (uint16_t)StunAttributeType::FINGERPRINT;
      uint16_t len = (uint16_t)sizeof(fingerprint);

      ByteArray::writeData(bodyBuf + pos, t, false);
      pos += sizeof(t);
      ByteArray::writeData(bodyBuf + pos, len, false);
      pos += sizeof(len);
      ByteArray::writeData(bodyBuf + pos, fingerprint, len);
      pos += len;

      std::cout << "------ writeAttributes 5 -----------" << std::endl;

    } else {
      uint16_t msgLength = pos;
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

  void setUsername(const string& u) { username = u; }

  void setRealm(const string& r) { realm = r; }


 public:
  void setMethod(StunMethod method) { msgMethod = method; }
  void setClass(StunClass clz) { msgClass = clz; }


  void setFingerprint(bool enable) { fingerprintEnable = enable; }

  void setMessageIntegrity(bool enable) { messageIntegrityEnable = enable; }

  void setPassword(const string& p) { password = p; }
  void setTransactionId(uint32_t transId[3]) {
    transactionId[0] = transId[0];
    transactionId[1] = transId[1];
    transactionId[2] = transId[2];
  }



  /*
  RFC 5766: 4.7.  REQUESTED-TRANSPORT
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |    Protocol   |                    RFFU                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  void setAttr_REQUESTED_TRANSPORT() {
    StunAttributeType attrType = StunAttributeType::REQUESTED_TRANSPORT;
    uint8_t data[] = {0x11, 0, 0, 0};
    size_t len = 4;
    addAttr(attrType, data, len);
  };

  void setAttr_LIFETIME(uint32_t lifeTime) {
    StunAttributeType attrType = StunAttributeType::LIFETIME;

    uint8_t data[] = {0, 0, 0, 0};
    data[0] = (uint8_t)((lifeTime >> ((4 - 1) * 8)) & 0xFF);
    data[1] = (uint8_t)((lifeTime >> ((4 - 1 - 1) * 8)) & 0xFF);
    data[2] = (uint8_t)((lifeTime >> ((4 - 2 - 1) * 8)) & 0xFF);
    data[3] = (uint8_t)((lifeTime >> ((4 - 3 - 1) * 8)) & 0xFF);

    size_t len = 4;
    addAttr(attrType, data, len);
  };

  void setAttr_USERNAME(const string& uname) {
    setUsername(uname);
    StunAttributeType attrType = StunAttributeType::USERNAME;
    addAttr(attrType, (uint8_t*)uname.c_str(), uname.size());
  };

  void setAttr_NONCE(const uint8_t* nonce, size_t len) {
    std::cout << "setAttr_NONCE len=" << len << std::endl;
    StunAttributeType attrType = StunAttributeType::NONCE;
    addAttr(attrType, nonce, len);
  };

  void setAttr_REALM(const string& realm) {
    setRealm(realm);
    StunAttributeType attrType = StunAttributeType::REALM;
    addAttr(attrType, (uint8_t*)realm.c_str(), realm.size());
  };


  std::vector<uint8_t> buildMsg() {
    std::cout << "------------ buildMsg 0 ---------------" << std::endl;
    std::vector<uint8_t> msgData((uint32_t)headerLength + calcMsgLength());
    std::cout << "------------ buildMsg 1 ---------------" << std::endl;
    writeHeader(msgData);
    std::cout << "------------ buildMsg 2 ---------------" << std::endl;
    writeAttributes(msgData);
    std::cout << "------------ buildMsg 3 ---------------" << std::endl;
    return msgData;
  };
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
