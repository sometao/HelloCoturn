#include <iostream>
#include <string>
#include "asio.hpp"
#include "MessageBuilder.h"
#include "seeker/logger.h"
#include "seeker/random.h"
#include <iomanip>

using asio::ip::udp;


seeker::RandomIntGenerator transIdGenerator{INT_MIN, INT_MAX, (int)seeker::Time::currentTime()};


std::vector<uint8_t> buildAllocation(const std::string& username = "",
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
  message.setAttr_LIFETIME(600);
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



void sendAndReceiveTest() {
  asio::io_context ioContext;

  std::string host = "";
  std::string port = "";

  udp::resolver resolver(ioContext);
  udp::endpoint remote = *(resolver.resolve(udp::v4(), host, port).begin());

  udp::socket socket(ioContext);
  socket.open(udp::v4());

  char sendBuf[2048];
  socket.send_to(asio::buffer(sendBuf), remote);

  char recvBuf[2048];
  udp::endpoint senderEndpoint;
  size_t len = socket.receive_from(asio::buffer(recvBuf), senderEndpoint);

  std::cout << "got data len=" << len << std::endl;
}



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

  std::cout << std::hex;
  int index = 0;
  for (uint8_t& d : msg) {
    std::cout << std::setw(2) << std::setfill('0') << (int)d << " ";  // 005
    index += 1;

    if (index % 16 == 0)
      printf(" | \n");
    else if (index % 8 == 0)
      printf(" | ");
    else if (index % 4 == 0)
      printf(" ");
  }

  std::cout << "END." << std::endl;
}

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
  std::cout << std::hex;
  int index = 0;
  for (uint8_t& d : msg) {
    std::cout << std::setw(2) << std::setfill('0') << (int)d << " ";  // 005
    index += 1;

    if (index % 16 == 0)
      printf(" | \n");
    else if (index % 8 == 0)
      printf(" | ");
    else if (index % 4 == 0)
      printf(" ");
  }

  std::cout << "END." << std::endl;
}



int main() {
  std::cout << "hello, coturn" << std::endl;

  try {
  } catch (std::exception ex) {
    std::cout << "Got exception: " << ex.what() << std::endl;
  }

  buildMsgTest1();
  // buildMsgTest2();

  return 0;
}
