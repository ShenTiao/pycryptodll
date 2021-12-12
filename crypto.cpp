#include <pybind11/pybind11.h>
#include <base64.h>
#include <aes.h>
#include <md5.h>
#include <hex.h>
#include <files.h>
#include <osrng.h>
#include <filters.h>
#include <default.h>
#include <des.h>
#include <string>
#include <sstream>
#include <arc4.h>
#define _CRYPTO_UTIL_H_
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

namespace py = pybind11;
using namespace CryptoPP;

/*
*
*   仿射加密部分
*   加密函数：
*   std::string enAffine(std::string inData,int addKey,int mulKey)
*   解密函数：
*   std::string decode(std::string inData, int addKey, int mulKey)
*/
//扩展欧几里得
inline void exEuclidean(int x, int y, int& s, int& t) {
    int r1 = x, r2 = y, s1 = 1, s2 = 0, t1 = 0, t2 = 1;
    int q, r;
    while (r2 > 0){
        q = r1 / r2;

        r = r1 - q * r2; 
        r1 = r2;
        r2 = r;

        s = s1 - q * s2;
        s1 = s2;
        s2 = s;

        t = t1 - q * t2;
        t1 = t2;
        t2 = t;
    }
    //gcd(a,b) = r1;   
    s = s1;
    t = t1;
}

//乘法逆元
int findReverse(int a, int n) { 
    int s, t;
    exEuclidean(n, a, s, t);  
    int a_ = (t >= 0) ? (t % n) : ((t - t * n) % n); 
    return a_;
}

bool checkAffineKey(int addKey, int mulKey) {
    int c, t, mod = 26;
    if (addKey == 1 || addKey % 2 == 0) return false;
    if (mod < addKey) {
        t = mod;
        mod = addKey;
        addKey = t;
    }
    while (!c) {
        c = mod % addKey;
        mod = addKey;
        addKey = c;
    }
    if (mod == 1) return true;
    else return false;
}

//仿射加密
std::string enAffine(std::string inData,int addKey,int mulKey) {
    std::string outData;
    //参数合法检查
    if (checkAffineKey(addKey, mulKey)) return "the key is invaild";
    for (int i = 0; i < inData.size(); ++i) {
        int code = inData[i] - 'a';
        outData += (code * mulKey + addKey) % 26 + 'A';
    }
    return outData;
}

//仿射解密
std::string decode(std::string inData, int addKey, int mulKey) {
    std::string outData;
    for (int i = 0; i < inData.size(); ++i) {
        int code = inData[i] - 'A';
        outData += ((code -addKey+26) *findReverse(mulKey,26))%26 + 'a';
    }
    return outData;
}

/*
*   流密码：RC4部分
*   key length: 16
    key length (min): 1
    key length (max): 256
    iv size: 0
*   
* 
*  
*/

class myRC4P {
    private:
        std::string plain, cipher, recover;
        int keyLength;
};

/*
*   MD5
*/

//MD5校验
std::string encryMD5(std::string& data) {
    std::string digest;
    Weak1::MD5 md5;
    StringSource(data, true, new HashFilter(md5, new HexEncoder(new StringSink(digest))));
    return digest;
}


/*
* 3DES-CBC模式加密实现
*  随机生成Key      std::string randomDesKey()
*  随机生成iv       std::string randomIv()
*  加密   std::string encrypt3des(std::string& inData, std::string& strKey, std::string& eniv)
*  解密   std::string decrypt3des(std::string& inData,std::string& strKey,std::string& eniv)
*/

//随机生成Key
std::string randomDesKey() {
    std::string encoded;
    AutoSeededRandomPool prng;
    SecByteBlock key(DES_EDE3::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    encoded.clear();
    StringSource(key, key.size(), true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

//随机生成iv
std::string randomIv() {
    std::string encoded;
    AutoSeededRandomPool prng;
    byte iv[DES_EDE3::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    encoded.clear();
    StringSource(iv, sizeof(iv), true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource 
    return encoded;
}

//3DES加密
std::string	encrypt3des(std::string& inData, std::string& strKey, std::string& eniv) {
    std::string outData;
    SecByteBlock key(DES_EDE3::DEFAULT_KEYLENGTH);
    byte iv[DES_EDE3::BLOCKSIZE];
    StringSource ss1(strKey, true, new HexDecoder(
        new ArraySink(key.data(), DES_EDE3::DEFAULT_KEYLENGTH)));
    StringSource ss2(eniv, true, new HexDecoder(
        new ArraySink(&iv[0], DES_EDE3::BLOCKSIZE)));
    try {
        CBC_Mode<DES_EDE3>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        //ECB和CBC模式必须填充加密块
        StringSource ss(inData, true, new
            StreamTransformationFilter(e,
                new StringSink(outData)));
    }
    catch (const Exception& e) {
        return e.what();
    }
    std::string encoded;
    encoded.clear();
    StringSource(outData, true,
        new HexEncoder(
            new StringSink(encoded)));
    return encoded;
}

//3DES解密
std::string decrypt3des(std::string& inData, std::string& strKey, std::string& eniv) {
    std::string outData;
    std::string decodeData;
    SecByteBlock key(DES_EDE3::DEFAULT_KEYLENGTH);
    byte iv[DES_EDE3::BLOCKSIZE];
    StringSource ss1(strKey, true, new HexDecoder(
        new ArraySink(key.data(), DES_EDE3::DEFAULT_KEYLENGTH)));
    StringSource ss2(eniv, true, new HexDecoder(
        new ArraySink(&iv[0], DES_EDE3::BLOCKSIZE)));
    StringSource ss3(inData, true, new HexDecoder(
        new StringSink(decodeData)));
    try {
        CBC_Mode<DES_EDE3>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(decodeData, true, new
            StreamTransformationFilter(d,
                new StringSink(outData)));
    }
    catch (const Exception& e) {
        return e.what();
    }
    return outData;
}




PYBIND11_MODULE(pycryptodll, m) {
    m.doc() = "crypto++";

	m.def("retMD5", &encryMD5, "return the MD5 value");
    
    m.def("randomDesKey", &randomDesKey);
    m.def("randomIv", &randomIv);
    m.def("enDES", &encrypt3des, "encry the DES");
    m.def("deDES", &encrypt3des, "decode the des");
}