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



class StunMessage {
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

  static void genMessageIntegrity(const uint8_t* data, size_t len, uint8_t out[20],
                                  const std::string& username_, const std::string& password_,
                                  const std::string& realm_) {
    std::cout << "------ genMessageIntegrity 0 ----------- len=" << len << std::endl;

    std::vector<uint8_t> passwordVector;
    passwordVector = ByteArray::SASLprep((uint8_t*)password_.c_str());
    if (passwordVector.empty()) {
      throw std::exception("password SASLprep failed.");
    }
    std::cout << "------ genMessageIntegrity 1 -----------" << std::endl;


    // long-term credentials
    MD5 md5;
    // key = MD5(username ":" realm ":" SASLprep(password))
    string keyStr{};
    keyStr += username_;
    keyStr += ":";
    keyStr += realm_;
    keyStr += ":";
    keyStr += (char*)passwordVector.data();
    std::cout << "------ genMessageIntegrity 2 ----------- keyStr:" << keyStr << std::endl;
    std::cout << "------ genMessageIntegrity 3 -----------" << std::endl;

    md5.reset();
    md5.add(keyStr.c_str(), keyStr.size());
    uint8_t key[16];
    md5.getHash(key);
    // out length must be 20 bytes.
    hmac<SHA1>(data, len, key, 16, out);
    std::cout << "------ genMessageIntegrity 4 -----------" << std::endl;
  }


  static void genFingerprint(const uint8_t* data, size_t len, uint8_t fingerprint[4]) {
    static uint8_t fingerprintCookie[4] = {0x53, 0x54, 0x55, 0x4e};

    CRC32 crc32Hasher;

    crc32Hasher(data, len);
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

    if (messageIntegrityEnable) {
      uint16_t messageIntegrityAttrLength = 2 + 2 + 20;
      uint16_t dummyMsgLength = pos + messageIntegrityAttrLength;
      ByteArray::writeData(dataBuf + 2, dummyMsgLength, false);
      uint8_t messageIntegrityValue[20];

      std::cout << "------ writeAttributes 3.1 ----------- dummyMsgLength=" << dummyMsgLength
                << std::endl;
      genMessageIntegrity(dataBuf, headerLength + pos, messageIntegrityValue, username,
                          password, realm);

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

    if (fingerprintEnable) { 
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
  StunMessage() = default;


  static int parse(uint8_t* data, size_t len, StunMessage& emptyMsg, bool hasFingerprint,
                   const std::string& username_ = "", const std::string& password_ = "",
                   const std::string& realm_ = "") {

    bool checkRst = true;
    if(hasFingerprint) {
      if(!checkFingerprint(data, len)) {
        return -1;
      }
    } 

    if(!username_.empty()) {
      if(!checkMessageIntegrity(data, len, hasFingerprint, username_, password_, realm_)) {
        return -2;
      }
    }


    //check first 2 bits
    uint8_t firstTwoBits = data[0] >> 6;
    if(firstTwoBits != 0) {
      return -3;
    }

    //message type pass
    const uint16_t msgType = ((uint16_t)data[0]) << 8 & data[1];
    uint16_t method = 0x0000;
    method = (method << 5) | ((msgType >> 9) & 0x1f);
    method = (method << 3) | ((msgType >> 5) & 0x07);
    method = (method << 4) | ((msgType >> 0) & 0x0F);
    emptyMsg.setMethod((StunMethod)method);

    uint16_t clz = 0x0000;
    clz = (clz << 1) | ((clz >> 8) & 0x01);
    clz = (clz << 1) | ((clz >> 4) & 0x01);
    emptyMsg.setClass((StunClass)clz);


    //TODO to be continue: parse stunMessage;


  
  
  
  }

  static bool checkMessageIntegrity(uint8_t* data, size_t len, bool hasFingerprint,
                                    const std::string& username_, const std::string& password_,
                                    const std::string& realm_) {
    uint16_t msgLen;
    ByteArray::readData(data + 2, msgLen, false);

    if (hasFingerprint && msgLen < 20 + 24 + 8) {
      return false;
    } else if (!hasFingerprint && msgLen < 20 + 24) {
      return false;
    }

    uint16_t dummyMsgLen;
    if (hasFingerprint) {
      dummyMsgLen = msgLen - 8;
    } else {
      dummyMsgLen = msgLen;
    }

    bool checkRst = true;

    ByteArray::writeData(data + 2, dummyMsgLen, false);
    uint16_t attrType;
    ByteArray::readData(data + dummyMsgLen - 24, attrType, false);
    uint16_t attrLen;
    ByteArray::readData(data + dummyMsgLen - 22, attrLen, false);

    if (attrType != (uint16_t)StunAttributeType::MESSAGE_INTEGRITY || attrLen != 20) {
      checkRst = false;
    } else {
      uint8_t attrValue[20] = {0};
      ByteArray::readData(data + dummyMsgLen - 20, attrValue, 20);

      uint8_t expectValue[20];
      genMessageIntegrity(data, dummyMsgLen, expectValue, username_, password_, realm_);
      for (int i = 0; i < 20; i++) {
        if (attrValue[i] != expectValue[i]) {
          checkRst = false;
          break;
        }
      }
    }

    if (msgLen != dummyMsgLen) {
      ByteArray::writeData(data + 2, msgLen, false);
    }

    return checkRst;
  }


  static bool checkFingerprint(uint8_t* data, size_t len) {
    uint16_t msgLen;
    ByteArray::readData(data + 2, msgLen, false);

    if (msgLen < 24) {
      return false;
    }

    uint16_t attrType;
    ByteArray::readData(data + msgLen - 8, attrType, false);
    uint16_t attrLen;
    ByteArray::readData(data + msgLen - 6, attrLen, false);


    if (attrType != (uint16_t)StunAttributeType::FINGERPRINT || attrLen != 4) {
      return false;
    }

    uint8_t fingerprint[4] = {0};
    ByteArray::readData(data + msgLen - 4, fingerprint, 4);

    uint8_t expectFingerprint[4];
    genFingerprint(data, msgLen - 8, expectFingerprint);
    for (int i = 0; i < 4; i++) {
      if (fingerprint[i] != expectFingerprint[i]) {
        return false;
      }
    }

    return true;
  }



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


  std::vector<uint8_t> binary() {
    std::vector<uint8_t> msgData((size_t)headerLength + calcMsgLength());
    writeHeader(msgData);
    writeAttributes(msgData);
    return msgData;
  };
};



}  // namespace HelloCoturn
