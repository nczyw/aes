#include "aes.hpp"
#include <cstring>
#ifdef USE_INTEL_AES_IF_AVAILABLE
#include "aesni/aesni-key-exp.h"
#include "aesni/aesni-key-init.h"
#include "aesni/aesni-enc-ecb.h"
#include "aesni/aesni-enc-cbc.h"
#endif

/*
 * Local Functions
 * */

namespace {

    uint8_t xTime(uint8_t x)
    {
        return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    uint8_t multiply(uint8_t x, uint8_t y)
    {
        return (((y & 1) * x) ^ ((y >> 1 & 1) * xTime(x)) ^ ((y >> 2 & 1) * xTime(xTime(x))) ^ ((y >> 3 & 1)
            * xTime(xTime(xTime(x)))) ^ ((y >> 4 & 1) * xTime(xTime(xTime(xTime(x))))));
    }

}

AESEncryption::AESEncryption(Aes level, Mode mode,
    Padding padding)
    : m_nb(4), m_blocklen(16), m_level(level), m_mode(mode), m_padding(padding)
    , m_aesNIAvailable(false), m_state(nullptr)
{
#ifdef USE_INTEL_AES_IF_AVAILABLE
    m_aesNIAvailable = check_aesni_support();
#endif

    switch (level)
    {
    case AES_128: {
        AES128 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
    }
                break;
    case AES_192: {
        AES192 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
    }
                break;
    case AES_256: {
        AES256 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
    }
                break;
    default: {
        AES128 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
    }
           break;
    }

}
std::string AESEncryption::encode(const std::string& rawText, const std::string& key, const std::string& iv)
{
    if ((m_mode >= CBC && (iv.empty() || iv.size() != m_blocklen)) || key.size() != m_keyLen)
        return std::string();

    std::string expandedKey = expandKey(key, true);
    std::string alignedText(rawText);

    //Fill array with padding
    alignedText.append(getPadding(rawText.size(), m_blocklen));

    switch (m_mode)
    {
    case ECB: {
#ifdef USE_INTEL_AES_IF_AVAILABLE
        if (m_aesNIAvailable) {
            char * expKey = new char[expandedKey.size()];
            memcpy(expKey, expandedKey.data(), expandedKey.size());

            std::string outText;
            outText.resize(alignedText.size());
            AES_ECB_encrypt((unsigned char*)alignedText.c_str(),
                (unsigned char*)outText.data(),
                alignedText.size(),
                expKey,
                m_nr);
            delete[] expKey;
            return outText;
        }
#endif
        std::string ret;
        for (int i = 0; i < alignedText.size(); i += m_blocklen)
            ret.append(cipher(expandedKey, alignedText.substr(i, m_blocklen)));
        return ret;
    }
            break;
    case CBC: {
#ifdef USE_INTEL_AES_IF_AVAILABLE
        if (m_aesNIAvailable) {
            uint8_t *ivec = new uint8_t[iv.size()];
            memcpy(ivec, iv.data(), iv.size());
            char * expKey = new char[expandedKey.size()];
            memcpy(expKey, expandedKey.data(), expandedKey.size());

            std::string outText;
            outText.resize(alignedText.size());
            AES_CBC_encrypt((unsigned char*)alignedText.c_str(),
                (unsigned char*)outText.data(),
                ivec,
                alignedText.size(),
                expKey,
                m_nr);
            delete[] ivec;
            delete[] expKey;
            return outText;
        }
#endif
        std::string ret;
        std::string ivTemp(iv);
        for (int i = 0; i < alignedText.size(); i += m_blocklen) {
            alignedText.replace(i, m_blocklen, byteXor(alignedText.substr(i, m_blocklen), ivTemp));
            ret.append(cipher(expandedKey, alignedText.substr(i, m_blocklen)));
            ivTemp = ret.substr(i, m_blocklen);
        }
        return ret;
    }
            break;
    case CFB: {
        std::string ret;
        ret.append(byteXor(alignedText.substr(0,m_blocklen), cipher(expandedKey, iv)));
        for (int i = 0; i < alignedText.size(); i += m_blocklen) {
            if (i + m_blocklen < alignedText.size())
                ret.append(byteXor(alignedText.substr(i + m_blocklen, m_blocklen),
                    cipher(expandedKey, ret.substr(i, m_blocklen))));
        }
        return ret;
    }
            break;
    case OFB: {
        std::string ret;
        std::string ofbTemp;
        ofbTemp.append(cipher(expandedKey, iv));
        for (int i = m_blocklen; i < alignedText.size(); i += m_blocklen) {
            ofbTemp.append(cipher(expandedKey, ofbTemp.substr(ofbTemp.length() - m_blocklen , m_blocklen)));
        }
        ret.append(byteXor(alignedText, ofbTemp));
        return ret;
    }
            break;
    default: break;
    }
    return std::string();
}

std::string AESEncryption::decode(const std::string& rawText, const std::string& key, const std::string& iv)
{
    if ((m_mode >= CBC && (iv.empty() || iv.size() != m_blocklen)) || key.size() != m_keyLen)
        return std::string();

    std::string ret;
    std::string expandedKey;

#ifdef USE_INTEL_AES_IF_AVAILABLE
    if (m_aesNIAvailable && m_mode <= CBC) {
        expandedKey = expandKey(key, false);
    }
    else {
        expandedKey = expandKey(key, true);
    }
#else
    expandedKey = expandKey(key, true);
#endif
    //false or true here is very important
    //the expandedKeys aren't the same for !aes-ni! ENcryption and DEcryption (only CBC and EBC)
    //but if you are !NOT! using aes-ni then the expandedKeys for encryption and decryption are the SAME!!!


    switch (m_mode)
    {
    case ECB:
#ifdef USE_INTEL_AES_IF_AVAILABLE
        if (m_aesNIAvailable) {
            char *expKey = new char[expandedKey.size()];                                //expandedKey
            memcpy(expKey, expandedKey.data(), expandedKey.size());
            ret.resize(rawText.size());

            AES_ECB_decrypt((unsigned char*)rawText.c_str(),
                (unsigned char*)ret.data(),
                rawText.size(),
                expKey,
                m_nr);
            break;
        }
#endif
        for (int i = 0; i < rawText.size(); i += m_blocklen)
            ret.append(invCipher(expandedKey, rawText.substr(i, m_blocklen)));
        break;
    case CBC:
#ifdef USE_INTEL_AES_IF_AVAILABLE
        if (m_aesNIAvailable) {
            uint8_t * ivec = new uint8_t[iv.size()];                                         //IV
            memcpy(ivec, iv.c_str(), iv.size());
            char *expKey = new char[expandedKey.size()];                                //expandedKey
            memcpy(expKey, expandedKey.data(), expandedKey.size());
            ret.resize(rawText.size());

            AES_CBC_decrypt((unsigned char*)rawText.c_str(),
                (unsigned char*)ret.data(),
                ivec,
                rawText.size(),
                expKey,
                m_nr);
            break;
        }
#endif
        {
            std::string ivTemp(iv);
            for (int i = 0; i < rawText.size(); i += m_blocklen) {
                ret.append(invCipher(expandedKey, rawText.substr(i, m_blocklen)));
                ret.replace(i, m_blocklen, byteXor(ret.substr(i, m_blocklen), ivTemp));
                ivTemp = rawText.substr(i, m_blocklen);
            }
        }
        break;
    case CFB: {
        ret.append(byteXor(rawText.substr(0, m_blocklen), cipher(expandedKey, iv)));
        for (int i = 0; i < rawText.size(); i += m_blocklen) {
            if (i + m_blocklen < rawText.size()) {
                ret.append(byteXor(rawText.substr(i + m_blocklen, m_blocklen),
                    cipher(expandedKey, rawText.substr(i, m_blocklen))));
            }
        }
    }
            break;
    case OFB: {
        std::string ofbTemp;
        ofbTemp.append(cipher(expandedKey, iv));
        for (int i = m_blocklen; i < rawText.size(); i += m_blocklen) {
            ofbTemp.append(cipher(expandedKey, ofbTemp.substr(ofbTemp.length() - m_blocklen , m_blocklen)));
        }
        ret.append(byteXor(rawText, ofbTemp));
    }
            break;
    default:
        //do nothing
        break;
    }
    return ret;
}

std::string AESEncryption::expandKey(const std::string& key, bool isEncryptionKey)
{
#ifdef USE_INTEL_AES_IF_AVAILABLE
    if (m_aesNIAvailable) {
        switch (m_level) {
        case AES_128: {
            AES128 aes128;
            AES_KEY aesKey;
            if (isEncryptionKey) {
                AES_set_encrypt_key((unsigned char*)key.c_str(), aes128.userKeySize, &aesKey);
            }
            else {
                AES_set_decrypt_key((unsigned char*)key.c_str(), aes128.userKeySize, &aesKey);
            }

            std::string expKey;
            expKey.resize(aes128.expandedKey);
            memcpy(expKey.data(), (char*)aesKey.KEY, aes128.expandedKey);
            memset(aesKey.KEY, 0, 240);
            return expKey;
        }
                    break;
        case AES_192: {
            AES192 aes192;
            AES_KEY aesKey;
            if (isEncryptionKey) {
                AES_set_encrypt_key((unsigned char*)key.c_str(), aes192.userKeySize, &aesKey);
            }
            else {
                AES_set_decrypt_key((unsigned char*)key.c_str(), aes192.userKeySize, &aesKey);
            }

            std::string expKey;
            expKey.resize(aes192.expandedKey);
            memcpy(expKey.data(), (char*)aesKey.KEY, aes192.expandedKey);
            memset(aesKey.KEY, 0, 240);
            return expKey;
        }
                    break;
        case AES_256: {
            AES256 aes256;
            AES_KEY aesKey;
            if (isEncryptionKey) {
                AES_set_encrypt_key((unsigned char*)key.c_str(), aes256.userKeySize, &aesKey);
            }
            else {
                AES_set_decrypt_key((unsigned char*)key.c_str(), aes256.userKeySize, &aesKey);
            }

            std::string expKey;
            expKey.resize(aes256.expandedKey);
            memcpy(expKey.data(), (char*)aesKey.KEY, aes256.expandedKey);
            memset(aesKey.KEY, 0, 240);
            return expKey;
        }
                    break;
        default:
            return std::string();
            break;
        }
    }
    else
#endif
    {

        int i, k;
        uint8_t tempa[4]; // Used for the column/row operations
        std::string roundKey(key); // The first round key is the key itself.

        // All other round keys are found from the previous round keys.
        //i == Nk
        for (i = m_nk; i < m_nb * (m_nr + 1); i++)
        {
            tempa[0] = (uint8_t)roundKey.at((i - 1) * 4 + 0);
            tempa[1] = (uint8_t)roundKey.at((i - 1) * 4 + 1);
            tempa[2] = (uint8_t)roundKey.at((i - 1) * 4 + 2);
            tempa[3] = (uint8_t)roundKey.at((i - 1) * 4 + 3);

            if (i % m_nk == 0)
            {
                // This function shifts the 4 bytes in a word to the left once.
                // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

                // Function RotWord()
                k = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = k;

                // Function Subword()
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);

                tempa[0] = tempa[0] ^ Rcon[i / m_nk];
            }

            if (m_level == AES_256 && i % m_nk == 4)
            {
                // Function Subword()
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }
            
            roundKey.insert(roundKey.begin() + i * 4 + 0 , roundKey.at((i - m_nk) * 4 + 0) ^ tempa[0]);
            roundKey.insert(roundKey.begin() + i * 4 + 0, (uint8_t)roundKey.at((i - m_nk) * 4 + 0) ^ tempa[0]);
            roundKey.insert(roundKey.begin() + i * 4 + 1, (uint8_t)roundKey.at((i - m_nk) * 4 + 1) ^ tempa[1]);
            roundKey.insert(roundKey.begin() + i * 4 + 2, (uint8_t)roundKey.at((i - m_nk) * 4 + 2) ^ tempa[2]);
            roundKey.insert(roundKey.begin() + i * 4 + 3, (uint8_t)roundKey.at((i - m_nk) * 4 + 3) ^ tempa[3]);
        }
        return roundKey;
    }
}

std::string AESEncryption::removePadding(const std::string& rawText)
{
    if (rawText.empty())
        return rawText;

    std::string ret(rawText);
    switch (m_padding)
    {
    case Padding::ZERO:
        //Works only if the last byte of the decoded array is not zero
        while (ret.at(ret.length() - 1) == 0x00)
            ret.erase(ret.length() - 1, 1);
        break;
    case Padding::PKCS7:
        /*
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
        ret.remove(ret.length() - ret.back(), ret.back());
#else
        ret.remove(ret.length() - ret.at(ret.length() - 1), ret.at(ret.length() - 1));
#endif
*/
        ret.erase(ret.length() - ret.at(ret.length() - 1), ret.at(ret.length() - 1));
        break;
    case Padding::ISO:
    {
        // Find the last byte which is not zero
        int marker_index = ret.length() - 1;
        for (; marker_index >= 0; --marker_index)
        {
            if (ret.at(marker_index) != 0x00)
            {
                break;
            }
        }

        // And check if it's the byte for marking padding
        if (ret.at(marker_index) == '\x80')
        {
           // ret.truncate(marker_index);
            ret = ret.substr(0, marker_index);
        }
        break;
    }
    default:
        //do nothing
        break;
    }
    return ret;
}

uint8_t AESEncryption::getSBoxValue(uint8_t num)
{
    return sbox[num];
}

uint8_t AESEncryption::getSBoxInvert(uint8_t num)
{
    return rsbox[num];
}

void AESEncryption::addRoundKey(const uint8_t round, const std::string& expKey)
{
    std::string::iterator it = m_state->begin();
    for (int i = 0; i < 16; ++i) {
        it[i] = (uint8_t)it[i] ^ (uint8_t)expKey.at(round * m_nb * 4 + (i / 4) * m_nb + (i % 4));
    }
}

void AESEncryption::subBytes()
{
    std::string::iterator it = m_state->begin();
    for (int i = 0; i < 16; i++) {
        it[i] = getSBoxValue((uint8_t)it[i]);
    }
}

void AESEncryption::shiftRows()
{
    std::string::iterator it = m_state->begin();
    uint8_t temp;
    //Keep in mind that QByteArray is column-driven!!

     //Shift 1 to left
    temp = (uint8_t)it[1];
    it[1] = (uint8_t)it[5];
    it[5] = (uint8_t)it[9];
    it[9] = (uint8_t)it[13];
    it[13] = (uint8_t)temp;

    //Shift 2 to left
    temp = (uint8_t)it[2];
    it[2] = (uint8_t)it[10];
    it[10] = (uint8_t)temp;
    temp = (uint8_t)it[6];
    it[6] = (uint8_t)it[14];
    it[14] = (uint8_t)temp;

    //Shift 3 to left
    temp = (uint8_t)it[3];
    it[3] = (uint8_t)it[15];
    it[15] = (uint8_t)it[11];
    it[11] = (uint8_t)it[7];
    it[7] = (uint8_t)temp;
}

void AESEncryption::mixColumns()
{
    std::string::iterator it = m_state->begin();
    uint8_t tmp, tm, t;

    for (int i = 0; i < 16; i += 4) {
        t = (uint8_t)it[i];
        tmp = (uint8_t)it[i] ^ (uint8_t)it[i + 1] ^ (uint8_t)it[i + 2] ^ (uint8_t)it[i + 3];

        tm = xTime((uint8_t)it[i] ^ (uint8_t)it[i + 1]);
        it[i] = (uint8_t)it[i] ^ (uint8_t)tm ^ (uint8_t)tmp;

        tm = xTime((uint8_t)it[i + 1] ^ (uint8_t)it[i + 2]);
        it[i + 1] = (uint8_t)it[i + 1] ^ (uint8_t)tm ^ (uint8_t)tmp;

        tm = xTime((uint8_t)it[i + 2] ^ (uint8_t)it[i + 3]);
        it[i + 2] = (uint8_t)it[i + 2] ^ (uint8_t)tm ^ (uint8_t)tmp;

        tm = xTime((uint8_t)it[i + 3] ^ (uint8_t)t);
        it[i + 3] = (uint8_t)it[i + 3] ^ (uint8_t)tm ^ (uint8_t)tmp;
    }
}

void AESEncryption::invMixColumns()
{
    std::string::iterator it = m_state->begin();
    uint8_t a, b, c, d;
    for (int i = 0; i < 16; i += 4) {
        a = (uint8_t)it[i];
        b = (uint8_t)it[i + 1];
        c = (uint8_t)it[i + 2];
        d = (uint8_t)it[i + 3];

        it[i] = (uint8_t)(multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09));
        it[i + 1] = (uint8_t)(multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d));
        it[i + 2] = (uint8_t)(multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b));
        it[i + 3] = (uint8_t)(multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e));
    }
}

void AESEncryption::invSubBytes()
{
    std::string::iterator it = m_state->begin();
    for (int i = 0; i < 16; ++i){
        it[i] = getSBoxInvert((uint8_t)it[i]);
    }
}

void AESEncryption::invShiftRows()
{
    std::string::iterator it = m_state->begin();
    uint8_t temp;

    //Keep in mind that QByteArray is column-driven!!

    //Shift 1 to right
    temp = (uint8_t)it[13];
    it[13] = (uint8_t)it[9];
    it[9] = (uint8_t)it[5];
    it[5] = (uint8_t)it[1];
    it[1] = (uint8_t)temp;

    //Shift 2
    temp = (uint8_t)it[10];
    it[10] = (uint8_t)it[2];
    it[2] = (uint8_t)temp;
    temp = (uint8_t)it[14];
    it[14] = (uint8_t)it[6];
    it[6] = (uint8_t)temp;

    //Shift 3
    temp = (uint8_t)it[7];
    it[7] = (uint8_t)it[11];
    it[11] = (uint8_t)it[15];
    it[15] = (uint8_t)it[3];
    it[3] = (uint8_t)temp;
}

std::string AESEncryption::getPadding(int currSize, int alignment)
{
    int size = (alignment - currSize % alignment) % alignment;
    switch (m_padding)
    {
    case Padding::ZERO:
        return std::string(size, 0x00);
        break;
    case Padding::PKCS7:
        if (size == 0)
            size = alignment;
        return std::string(size, size);
        break;
    case Padding::ISO:
        if (size > 0) {
            std::string tmp = std::string(size - 1, 0x00);
            tmp.insert(tmp.begin(), '\x80');
            return tmp;
        }
        break;
    default:
        return std::string(size, 0x00);
        break;
    }
    return std::string();
}

std::string AESEncryption::cipher(const std::string& expKey, const std::string& in)
{
    //m_state is the input buffer...
    std::string output(in);
    m_state = &output;

    // Add the First round key to the state before starting the rounds.
    addRoundKey(0, expKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (uint8_t round = 1; round < m_nr; ++round) {
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey(round, expKey);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    subBytes();
    shiftRows();
    addRoundKey(m_nr, expKey);

    return output;
}

std::string AESEncryption::invCipher(const std::string& expKey, const std::string& in)
{
    //m_state is the input buffer.... handle it!
    std::string output(in);
    m_state = &output;

    // Add the First round key to the state before starting the rounds.
    addRoundKey(m_nr, expKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (uint8_t round = m_nr - 1; round > 0; round--) {
        invShiftRows();
        invSubBytes();
        addRoundKey(round, expKey);
        invMixColumns();
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    invShiftRows();
    invSubBytes();
    addRoundKey(0, expKey);

    return output;
}

std::string AESEncryption::byteXor(const std::string& a, const std::string& b)
{
    std::string::const_iterator it_a = a.begin();
    std::string::const_iterator it_b = b.begin();
    std::string ret;

    //for(int i = 0; i < m_blocklen; i++)
    for (int i = 0; i < std::min(a.size(), b.size()); i++) {
        ret.insert(ret.begin() + i, it_a[i] ^ it_b[i]);
    }
    return ret;
}



