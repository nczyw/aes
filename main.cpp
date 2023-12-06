#include "exaes.hpp"

int main(int argc, char *argv[]) 
{
    char * a = AESEncode(0,0,0,"test","1234567890123456","");
    char * b = AESDecode(0,0,0,a,"1234567890123456","");
    printf("%s\r\n",b);
    return 0 ;
}
