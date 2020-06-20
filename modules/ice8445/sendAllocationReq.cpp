#include <iostream>
#include <string>
#include "asio.hpp"
#include "MessageBuilder.h"


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


void buildMsgTest() {
  using namespace HelloCoturn;
  MessageBuilder mBuilder{};

  uint32_t transId[] = {0, 0, 1};

  mBuilder.setTransactionId(transId);
  mBuilder.setMethod(StunMethod::Allocate);
  mBuilder.setClass(StunClass::request);

  // mBuilder.setUsername("zhangtao");
  // mBuilder.setPassword("skld123!@#");
  // mBuilder.setRealm("hello.seekloud.org");
  // mBuilder.setMessageIntegrity(true);

  mBuilder.setFingerprint(true);

  mBuilder.setAttr_REQUESTED_TRANSPORT();
  mBuilder.setAttr_LIFETIME(1800);

  auto msg = mBuilder.buildMsg();

  std::cout << std::hex;
  int index = 0;
  for (uint8_t& d : msg) {
    std::cout << d << " ";
    index += 1;
    if(index % 8 == 0) std::cout << " ";
    if(index % 16 == 0) std::cout << "\n";
  }

  std::cout << "END." << std::endl;

}



int main() {
  std::cout << "hello, coturn" << std::endl;

  buildMsgTest();

  return 0;
}
