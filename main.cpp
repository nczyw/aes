#include "exaes.hpp"

int main(int argc, char *argv[]) 
{
  //为什么是这几个中文呢，因为这几个字加密后会出现0x00字样，方便测试bug
  const char * str = "为了那苍白的爱情的继续";
  const char * a = AESEncode(1,0,1,0,str,"1234567890123456","1234567890123456");
  const char * b = AESDecode(1,0,1,0,a,"1234567890123456","1234567890123456");
  printf("%s\r\n",a);
  printf("%s\r\n",b);
  return 0 ;
}
