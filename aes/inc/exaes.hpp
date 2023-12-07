#ifndef __EXAES_H
#define __EXAES_H


#include <cstdint>
#include <string>
#include <mutex>

#ifdef _MSC_VER // [
    #define DLLEXPORT     __declspec(dllexport)
    #define DLLIMPORT     __declspec(dllimport)
#else
    #define DLLEXPORT     
    #define DLLIMPORT     
#endif // _MSC_VER ]



extern std::string encodeText , decodeText;
extern std::mutex myMutex;
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief                   AES加密函数
 * 
 * @param ioformat          输出格式        0:16进制  1:base64
 * @param level             AES加密等级     0:AES_128,1:AES_192,2:AES_256
 * @param mode              加密模式        0:ECB,1:CBC,2:CFB,3:OFB
 * @param padding           填充模式        0:ZERO,1:PKCS7,2:ISO     
 * @param text              需要加密的字符
 * @param key               加密密钥
 * @param iv                偏移
 * @return const char*      返回加密后的数据指针
 */
DLLEXPORT const char * AESEncode(uint8_t ioformat , uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv);

/**
 * @brief                   AES解密函数
 * 
 * @param ioformat          输入格式        0:16进制  1:base64
 * @param level             AES等级         0:AES_128,1:AES_192,2:AES_256
 * @param mode              解密模式        0:ECB,1:CBC,2:CFB,3:OFB
 * @param padding           填充模式        0:ZERO,1:PKCS7,2:ISO     
 * @param text              需要解密的字符
 * @param key               解密密钥
 * @param iv                偏移
 * @return const char*      返回解密后的数据指针
 */
DLLEXPORT const char * AESDecode(uint8_t ioformat , uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv);

#ifdef __cplusplus
}
#endif

#endif
