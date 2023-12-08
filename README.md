# C++ 实现AES加密解密
* 你可以在任何平台编译生成动态或者静态数据库，来方便自己程序调用AES加解密dll，因为接口封装采用了C语言，所以dll支持标准的ABI，可以被任何语言调用
* 代码为修改了仓库[Qt-AES](https://github.com/bricke/Qt-AES)而来，将原作者Qt版本的AES加密，修改为C++的.
* 引用了仓库[BASE64加密解密](https://github.com/ReneNyffenegger/cpp-base64).
* 使用C++17 编译 MinGW对C++ 23 不完全支持，生成的dll，报找不到入口
* 开启硬件加速时，暂时只支持非MSVC编译，不使用硬件加速，均可编译
* 为了防止加解密时，内存无限增大，每次调用加解密时，都会清空上一次的内容，用来存放这一次的内容,调用函数后，请及时取走数据，防止下次调用被清空。
* 输出数据类型必须转换成16进制(HEX),或者Base64编码，因为输出的内容可能会包含0x00，字符串的结束符，导致输出不正确，函数中有提供选择输出格式。
* key 在128位时,为16Byte，超出时只截取前16Byte,不足时后面自动补0x00;
* key 在192位时,为24Byte，超出时只截取前24Byte,不足时后面自动补0x00;
* key 在256位时,为32Byte，超出时只截取前32Byte,不足时后面自动补0x00;
* iv  为16Byte,超出时只截取前16Byte,不足时后面自动补0x00;
* 理论支持多线程调用，函数已经处理线程安全问题
## 目前已知问题
* ISO加密，不是添加的随机数，等待修改
## 计划功能
* 添加更多的填充模式
## 函数原型及使用方法如下
```
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
const char * AESEncode(uint8_t ioformat , uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv);

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
const char * AESDecode(uint8_t ioformat , uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv);

//下面是显式调用方法  
Qt为例
#include <QLibrary>  
QLibrary ExAES(QApplication::applicationDirPath() + "/libAES.dll",this);
if(ExAES.load()){
    typedef const char * (*AESEncodeFun)(uint8_t format,uint8_t level , uint8_t mode , uint8_t padding , const char * txt , const char * key , const char * iv);
    AESEncodeFun  AESEncode = (AESEncodeFun)ExAES.resolve("AESEncode");
    AESEncodeFun  AESDecode = (AESEncodeFun)ExAES.resolve("AESDecode");
    if(AESEncode){
        QByteArray a = AESEncode(1,2,1,1,"TEst","1234567890123456","1234567890123456");
        QByteArray b = AESDecode(1,2,1,1,a.data(),"1234567890123456","1234567890123456");
        qDebug() << QString(a);
        qDebug() << QString(b);
    }
    else {
        qDebug() << "Function export failed";
    }
}
else{
    qDebug() << ExAES.errorString();
}

```