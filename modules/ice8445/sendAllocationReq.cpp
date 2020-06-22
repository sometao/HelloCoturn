#include <iostream>
#include <string>
#include "asio.hpp"
#include "MessageBuilder.h"
#include "seeker/logger.h"
#include <iomanip>

using asio::ip::udp;

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
  MessageBuilder mBuilder{};

  uint32_t transId[] = {0x2782a602, 0xfefe8059, 0xbc94c712};

  mBuilder.setTransactionId(transId);
  mBuilder.setMethod(StunMethod::Allocate);
  mBuilder.setClass(StunClass::request);


  mBuilder.setFingerprint(true);

  mBuilder.setAttr_REQUESTED_TRANSPORT();
  mBuilder.setAttr_LIFETIME(3600);

  auto msg = mBuilder.buildMsg();

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
  MessageBuilder mBuilder{};

  std::cout << "--------  1  ------------" << std::endl;
  uint32_t transId[] = {0x64e0783e, 0xcfad9d31, 0xf03765c6};
  std::cout << "--------  2  ------------" << std::endl;

  mBuilder.setTransactionId(transId);
  mBuilder.setMethod(StunMethod::Allocate);
  mBuilder.setClass(StunClass::request);

  mBuilder.setPassword("skld123!@#");

  std::cout << "--------  3  ------------" << std::endl;

  mBuilder.setAttr_REQUESTED_TRANSPORT();
  mBuilder.setAttr_LIFETIME(3600);
  mBuilder.setAttr_USERNAME("zhangtao");

  mBuilder.setAttr_REALM("hello.seekloud.org");

  uint8_t nonce[16] = {0x36, 0x30, 0x37, 0x38, 0x64, 0x31, 0x63, 0x32,
                       0x33, 0x30, 0x66, 0x61, 0x66, 0x32, 0x35, 0x36};
  mBuilder.setAttr_NONCE(nonce, 16);

  mBuilder.setMessageIntegrity(true);
  mBuilder.setFingerprint(true);

  std::cout << "--------  4  ------------" << std::endl;
  auto msg = mBuilder.buildMsg();

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
  //buildMsgTest2();

  return 0;
}
