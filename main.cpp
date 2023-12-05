#include "exaes.hpp"
#include <iostream>

int main(int argc, char *argv[]) {

//	std::string str = aes.encode("hehe", "1234567890123456");
//	std::string str1 = aes.decode(str, "1234567890123456");
//	str1 = aes.removePadding(str1);
    std::string b = AESEncode(0,0,0,"hehe","1234567890123456","");
    std::cout << b;
}
