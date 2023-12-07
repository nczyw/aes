#include "exaes.hpp"

int main(int argc, char *argv[]) 
{
    const char * str = "为了那苍白的爱情的继续";
    const char * a = AESEncode(0,0,1,0,str,"1234567890123456","1234567890123456");
    const char * b = AESDecode(0,0,1,0,a,"1234567890123456","1234567890123456");
  //  printf("%s\r\n",a);
  //  printf("%s\r\n",b);
    return 0 ;
}
