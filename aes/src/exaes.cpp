#include "exaes.hpp"
#include "aes.hpp"

std::string encodeText , decodeText;

/**
 * @brief           AES加密函数
 * 
 * @param level     AES加密等级     0:AES_128,1:AES_192,2:AES_256
 * @param mode      加密模式        0:ECB,1:CBC,2:CFB,3:OFB
 * @param padding   填充模式        0:ZERO,1:PKCS7,2:ISO     
 * @param text      需要加密的字符
 * @param key       加密密钥
 * @param iv        偏移
 * @return char*    返回加密后的数据指针
 */
char * AESEncode(uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key , const char * iv)
{
    AESEncryption aes((AESEncryption::Aes)level,(AESEncryption::Mode)mode,(AESEncryption::Padding)padding);
    encodeText = aes.encode(text,key,iv);
    return encodeText.data();
}

/**
 * @brief           AES解密函数
 * 
 * @param level     AES等级     0:AES_128,1:AES_192,2:AES_256
 * @param mode      解密模式        0:ECB,1:CBC,2:CFB,3:OFB
 * @param padding   填充模式        0:ZERO,1:PKCS7,2:ISO     
 * @param text      需要解密的字符
 * @param key       解密密钥
 * @param iv        偏移
 * @return char*    返回解密后的数据指针
 */
char * AESDecode(uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv)
{
    AESEncryption aes((AESEncryption::Aes)level,(AESEncryption::Mode)mode,(AESEncryption::Padding)padding);
    decodeText = aes.decode(text,key,iv);
    decodeText = aes.removePadding(decodeText);
    return decodeText.data();
}