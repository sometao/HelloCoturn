#include <iostream>
#include <string>
#include "asio.hpp"
#include "seeker/logger.h"
#include "seeker/random.h"
#include "MessageBuilder.h"
#include <iomanip>

using asio::ip::udp;


seeker::RandomIntGenerator transIdGenerator{INT_MIN, INT_MAX,
                                            (int)seeker::Time::currentTime()};


void printBinary(std::vector<uint8_t>& msg, size_t len = INT_MAX) {
  std::cout << std::hex;

  int index = 0;
  for (uint8_t& d : msg) {
    if(index >= len) {
      break;
    }

    std::cout << std::setw(2) << std::setfill('0') << (int)d << " ";  // 005
    index += 1;

    if (index % 16 == 0)
      printf(" | \n");
    else if (index % 8 == 0)
      printf(" | ");
    else if (index % 4 == 0)
      printf(" ");
  }

  std::cout << "\n";
  std::cout << std::dec;

}

std::vector<uint8_t> buildAllocation(uint32_t lifeTime, const std::string& username = "",
                                     const std::string& password = "",
                                     const std::string& realm = "",
                                     const std::string& nonce = "") {
  using namespace HelloCoturn;
  StunMessage message{};

  uint32_t transId[3] = {0};
  for (int i = 0; i < 3; i++) {
    transId[i] = (uint32_t)transIdGenerator();
  }

  message.setTransactionId(transId);
  message.setMethod(StunMethod::Allocate);
  message.setClass(StunClass::request);

  message.setAttr_REQUESTED_TRANSPORT();
  message.setAttr_LIFETIME(lifeTime);
  if (!username.empty()) {
    message.setAttr_USERNAME(username);
    message.setPassword(password);
    message.setAttr_REALM(realm);
    message.setAttr_NONCE((uint8_t*)nonce.c_str(), nonce.size());
    message.setMessageIntegrity(true);
  }

  message.setFingerprint(true);

  return message.binary();
}



void sendAndReceiveTest1() {
  asio::io_context ioContext;

  std::string host = "152.136.24.142";
  std::string port = "52010";

  udp::resolver resolver(ioContext);
  udp::endpoint remote = *(resolver.resolve(udp::v4(), host, port).begin());

  udp::socket socket(ioContext);
  socket.open(udp::v4());

  std::vector<uint8_t> sendBuf = buildAllocation(600);
  socket.send_to(asio::buffer(sendBuf), remote);

  std::cout << "---------- sendBuf ----------------" << std::endl;
  printBinary(sendBuf);

  std::vector<uint8_t> recvBuf(2048);
  udp::endpoint senderEndpoint;
  size_t len = socket.receive_from(asio::buffer(recvBuf), senderEndpoint);

  std::cout << "got data len=" << len << std::endl;
  std::cout << "---------- recvBuf ----------------" << std::endl;

  printBinary(recvBuf, len);


  HelloCoturn::StunMessage emptyMsg;

  int rst = HelloCoturn::StunMessage::parse(recvBuf.data(), len, emptyMsg, true);
  I_LOG("parse rst={}", rst);

 
  auto method = emptyMsg.getMethod();
  auto clz = emptyMsg.getClass();



  auto username = emptyMsg.getAttr_USERNAME();
  I_LOG("msg method={}", (int)method);
  I_LOG("msg class={}", (int)clz);
  I_LOG("msg username={}", username);


}


/*
expected result:
0000   00 03 00 18 21 12 a4 42 27 82 a6 02 fe fe 80 59
0010   bc 94 c7 12 00 19 00 04 11 00 00 00 00 0d 00 04
0020   00 00 0e 10 80 28 00 04 e9 16 5e 7f
*/
void buildMsgTest1() {
  using namespace HelloCoturn;
  StunMessage message{};

  uint32_t transId[] = {0x2782a602, 0xfefe8059, 0xbc94c712};

  message.setTransactionId(transId);
  message.setMethod(StunMethod::Allocate);
  message.setClass(StunClass::request);


  message.setFingerprint(true);

  message.setAttr_REQUESTED_TRANSPORT();
  message.setAttr_LIFETIME(3600);

  auto msg = message.binary();

  printBinary(msg);

  std::cout << "END." << std::endl;
}


/*
expected result:
0000   00 03 00 68 21 12 a4 42 64 e0 78 3e cf ad 9d 31
0010   f0 37 65 c6 00 19 00 04 11 00 00 00 00 0d 00 04
0020   00 00 0e 10 00 06 00 08 7a 68 61 6e 67 74 61 6f
0030   00 14 00 12 68 65 6c 6c 6f 2e 73 65 65 6b 6c 6f
0040   75 64 2e 6f 72 67 00 00 00 15 00 10 36 30 37 38
0050   64 31 63 32 33 30 66 61 66 32 35 36 00 08 00 14
0060   b8 62 32 24 99 0d d8 24 72 66 25 c0 c7 51 76 42
0070   81 d7 83 a2 80 28 00 04 9c fc 48 03


*/
void buildMsgTest2() {
  using namespace HelloCoturn;
  StunMessage message{};

  std::cout << "--------  1  ------------" << std::endl;
  uint32_t transId[] = {0x64e0783e, 0xcfad9d31, 0xf03765c6};
  std::cout << "--------  2  ------------" << std::endl;

  message.setTransactionId(transId);
  message.setMethod(StunMethod::Allocate);
  message.setClass(StunClass::request);

  message.setPassword("skld123!@#");

  std::cout << "--------  3  ------------" << std::endl;

  message.setAttr_REQUESTED_TRANSPORT();
  message.setAttr_LIFETIME(3600);
  message.setAttr_USERNAME("zhangtao");

  message.setAttr_REALM("hello.seekloud.org");

  uint8_t nonce[16] = {0x36, 0x30, 0x37, 0x38, 0x64, 0x31, 0x63, 0x32,
                       0x33, 0x30, 0x66, 0x61, 0x66, 0x32, 0x35, 0x36};
  message.setAttr_NONCE(nonce, 16);

  message.setMessageIntegrity(true);
  message.setFingerprint(true);

  std::cout << "--------  4  ------------" << std::endl;
  auto msg = message.binary();

  std::cout << "--------  5  ------------" << std::endl;
  printBinary(msg);


  std::cout << "END." << std::endl;
}



int main() {
  seeker::Logger::init();

  std::cout << "hello, coturn" << std::endl;
  std::cout << "hello, SPDLOG_ACTIVE_LEVEL=" << SPDLOG_ACTIVE_LEVEL << std::endl;

  try {
  } catch (std::exception ex) {
    std::cout << "Got exception: " << ex.what() << std::endl;
  }

  // buildMsgTest1();
  // buildMsgTest2();
  sendAndReceiveTest1();

  return 0;
}
