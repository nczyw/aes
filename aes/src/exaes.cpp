#include "exaes.hpp"
#include "aes.hpp"

std::string encodeText , decodeText;
char *AESEncode(uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key , const char * iv)
{
    AESEncryption aes((AESEncryption::Aes)level,(AESEncryption::Mode)mode,(AESEncryption::Padding)padding);
    encodeText = aes.encode(text,key,iv);
    return encodeText.data();
}
