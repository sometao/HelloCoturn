#include "config.h"
#include "seeker/logger.h"
#include <iostream>
#include <string>


using std::cout;
using std::endl;
using std::string;


int main(int argc, char* argv[]) {
   seeker::Logger::init();
   const string name = "Coturn";
   I_LOG("hello, {}", name);
   W_LOG("BYE");
}


