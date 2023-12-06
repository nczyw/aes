#include "exaes.hpp"

int main(int argc, char *argv[]) 
{
    char * a = AESEncode(1,3,2,"test","123456789012345678901234","1234567890123456");
    char * b = AESDecode(1,3,2,a,"123456789012345678901234","1234567890123456");
    printf("%s\r\n",b);
    return 0 ;
}
