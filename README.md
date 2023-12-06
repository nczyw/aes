# C++ 实现AES加密解密
# 代码为修改[原仓库](https://github.com/bricke/Qt-AES)而来，将原作者Qt版本的AES加密，修改为C++的。
* 使用C++17 编译 C++ 23 容易报找不到程序入口
* 开户硬件加速时，暂时只支持mingw编译，不使用硬件加速，均可编译
* 为什么防止加解密时，内存无限增大，每次调用加解密时，都会清空上一次的内容，用来存放这一次的内容,调用函数后，请及时取走数据，防止下次调用被清空。
## 函数原型及使用方法如下
```
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
char * AESEncode(uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv);

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
char * AESDecode(uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv);

//下面是显式调用方法  
Qt为例
#include <QLibrary>  
QLibrary ExAES(QApplication::applicationDirPath() + "/libAES.dll",this);
if(ExAES.load()){
    typedef char * (*AESEncodeFun)(uint8_t level , uint8_t mode , uint8_t padding , const char * txt , const char * key , const char * iv);
    AESEncodeFun  AESEncode = (AESEncodeFun)ExAES.resolve("AESEncode");
    AESEncodeFun  AESDecode = (AESEncodeFun)ExAES.resolve("AESDecode");
    if(AESEncode){
        QByteArray a = AESEncode(0,1,2,"test","1234567890123456","1234567890123456");
        QByteArray b = AESDecode(0,1,2,a.data(),"1234567890123456","1234567890123456");
        qDebug() << a.toBase64();
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