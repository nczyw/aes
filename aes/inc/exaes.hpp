#ifndef __EXAES_H
#define __EXAES_H


#include <cstdint>
#include <string>


#define DLLEXPORT     __declspec(dllexport)
#define DLLIMPORT     __declspec(dllimport)

extern std::string encodeText , decodeText;
#ifdef __cplusplus
extern "C" {
#endif
DLLEXPORT  char * AESEncode(uint8_t level , uint8_t mode , uint8_t padding , const char *text, const char *key ,const char * iv);

#ifdef __cplusplus
}
#endif

#endif
