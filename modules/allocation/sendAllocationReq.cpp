#include <iostream>
#include <string>
#include "asio.hpp"
#include "MessageBuilder.h"


using asio::ip::udp;

int main() {
  std::cout << "hello, coturn" << std::endl;


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

  return 0;
}
