#include "exaes.hpp"
#include "aes.hpp"
#include <iostream>
#include "base64.hpp"

std::string encodeText , decodeText;
std::mutex myMutex;
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
const char * AESEncode(uint8_t ioformat , uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key , const char * iv)
{
  std::lock_guard<std::mutex> lock(myMutex);    //线程安全

  std::string _text(text); std::string _key(key); std::string _iv(iv);
  int keysize = _key.size();
  int _length = 0 ;     
  if(level == 0){     //128位是16Byte密钥
    _length = 16;
  }
  else if(level == 1){  //192位,是24byte
    _length = 24 ;
  }
  else if(level == 2){  //256位,是32Byte
    _length = 32 ;
  }

  //key处理
  if(keysize < _length){ //补0
    for(int i = keysize ; i < _length ; i += 1){
      _key.push_back(0x00);
    }
  }
  else if(keysize > _length){ //截取
    _key = _key.substr(0,_length);
  }

  //iv处理
  int ivsize = _iv.size();
  _length = 16 ;
  if(ivsize < _length){ //补0
    for(int i = ivsize ; i < _length ; i += 1){
      _iv.push_back(0x00);
    }
  }
  else if(ivsize > _length){ //截取
    _iv = _iv.substr(0,_length);
  }
  AESEncryption aes((AESEncryption::Aes)level,(AESEncryption::Mode)mode,(AESEncryption::Padding)padding);
  encodeText = aes.encode(_text,_key,_iv);
  if(ioformat){      //输出base64
    encodeText = base64_encode(reinterpret_cast<const unsigned char*>(encodeText.c_str()), encodeText.length());
  }
  else {              //输出hex
    encodeText = AESEncryption::stringToHex(encodeText);
  }
    
  return encodeText.c_str();
}

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
const char * AESDecode(uint8_t ioformat , uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv)
{
  std::lock_guard<std::mutex> lock(myMutex);

  std::string _text(text);  std::string _key(key); std::string _iv(iv);
  int keysize = _key.size();
  int _length = 0 ;     
  if(level == 0){     //128位是16Byte密钥
    _length = 16;
  }
  else if(level == 1){  //192位,是24byte
    _length = 24 ;
  }
  else if(level == 2){  //256位,是32Byte
    _length = 32 ;
  }

  //key处理
  if(keysize < _length){ //补0
    for(int i = keysize ; i < _length ; i += 1){
      _key.push_back(0x00);
    }
  }
  else if(keysize > _length){ //截取
    _key = _key.substr(0,_length);
  }

  //iv处理
  int ivsize = _iv.size();
  _length = 16 ;
  if(ivsize < _length){ //补0
    for(int i = ivsize ; i < _length ; i += 1){
      _iv.push_back(0x00);
    }
  }
  else if(ivsize > _length){ //截取
    _iv = _iv.substr(0,_length);
  }
  //编码处理
  if(ioformat){   //输入的为base64编码
    _text = base64_decode(_text);
  }
  else{
    _text = AESEncryption::hexToString(_text);
  }
  AESEncryption aes((AESEncryption::Aes)level,(AESEncryption::Mode)mode,(AESEncryption::Padding)padding);
  decodeText = aes.decode(_text,_key,_iv);
  decodeText = aes.removePadding(decodeText);
  return decodeText.c_str();
}