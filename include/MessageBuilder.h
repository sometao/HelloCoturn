#include <iostream>
#include <vector>
#include <unordered_map>

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
*/

#define MAGIC_COOKIE 0x2112A442

namespace HelloCoturn {

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
};




class MessageBuilder {
 private:
  StunMethod msgMethod;
  StunClass msgClass;
  uint8_t* transactionId;

  const uint32_t magicCookie = 0x2112A442;

  std::unordered_map<uint16_t, vector<uint8_t>> attributes;


  
  void addAttr(StunAttributeType attrType, const uint8_t* data, size_t len ) {
    uint16_t typeCode = (uint16_t) attrType;
    if(attributes.find(typeCode) == attributes.end()) {
      std::vector<uint8_t> vec(len);
      for(int i=0; i < value.length(); i++) {
        vec.at(i) = data[i];
      }
      attributes.emplace(typeCode, std::move(vec));
    }
  }


 public:
  void setMethod(StunMethod method) { msgMethod = method;}
  void setClass(StunClass clz) { msgClass = clz;}
  void setAttr_REQUESTED_TRANSPORT() {

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
