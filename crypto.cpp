#include <string>
#include <sstream>
#include <cassert>

#include <pybind11/pybind11.h>
#include <base64.h>
#include <hex.h>
#include <files.h>
#include <osrng.h>
#include <default.h>

#include <aes.h>
#include <des.h>
#include <rsa.h>
#include <pssr.h>
#include <sha.h>
#include <filters.h>

#define _CRYPTO_UTIL_H_
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <arc4.h>
#include <md5.h>

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
    int c=1, t, mod = 26;
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
std::string deAffine(std::string inData, int addKey, int mulKey) {
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

//RC4密钥指定长度随机生成
std::string randomARC4key(int len) {
    if (len < 0 || len>256) return "the length of the key is invaild:1-256";
    AutoSeededRandomPool prng;
    SecByteBlock key(len);
    prng.GenerateBlock(key, key.size());
    std::string encoded;
    encoded.clear();
    StringSource ss(key, key.size(), true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    return encoded;
}

//RC4加密函数
std::string encryRC4(std::string& inData, std::string& strKey, int len) {
    SecByteBlock key(len);
    StringSource ss1(strKey, true,
        new HexDecoder(
            new ArraySink(key.data(), len)));
    Weak::ARC4::Encryption enc;
    enc.SetKey(key, key.size());
    std::string outData;
    StringSource ss2(inData, true, new
        StreamTransformationFilter(enc, new
            StringSink(outData)));

    std::string encoded;
    encoded.clear();
    StringSource ss3(outData, true,
        new HexEncoder(
            new StringSink(encoded)));
    return encoded;
}

std::string decryRC4(std::string& inData, std::string& strKey, int len) {
    SecByteBlock key(len);
    std::string decode;
    StringSource ss1(strKey, true,
        new HexDecoder(
            new ArraySink(key.data(), len)));
    StringSource ss2(inData, true,
        new HexDecoder(
            new StringSink(decode)));
    Weak::ARC4::Encryption dec;
    dec.SetKey(key, key.size());
    std::string outData;
    StringSource ss3(decode, true, new
        StreamTransformationFilter(dec, new
            StringSink(outData)));
    return outData;
}

/*
*  MD5
* 
*/

//生成MD5摘要
std::string enmsgMD5(std::string& msg) {
    std::string digest, encoded;
    Weak::MD5 hash;
    StringSource ss(msg, true, new HashFilter(hash, new StringSink(digest)));
    StringSource ss1(digest, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

//验证MD5
bool checkmsgMD5(std::string& digest, std::string& msg) {
    bool result;
    Weak::MD5 hash;
    std::string decoded;
    StringSource ss1(digest, true, new HexDecoder(new StringSink(decoded)));
    StringSource ss(decoded + msg, true, new HashVerificationFilter(hash,
        new ArraySink((byte*)&result, sizeof(result))));
    if (result == true) {
        return true;
    }
    else return false;
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
    StringSource ss(key, key.size(), true,
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
    StringSource ss(iv, sizeof(iv), true,
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
    StringSource ss(outData, true,
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

/*
*  RSA-PSS签名方案
*  RSA加密
*
*/
//密钥保存函数
void Save(const std::string& filename, const BufferedTransformation& bt) {
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

//密钥加载函数
void Load(const std::string& filename, BufferedTransformation& bt) {
    FileSource file(filename.c_str(), true);
    file.TransferTo(bt);
    bt.MessageEnd();
}

//随机生成公钥与私钥并保存
void getRsaKey(std::string pubfilename,std::string prifilename) {
    InvertibleRSAFunction params;
    AutoSeededRandomPool rng;
    params.GenerateRandomWithKeySize(rng, 3072);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

    ByteQueue pubkeyQueue;
    publicKey.Save(pubkeyQueue);
    Save(pubfilename, pubkeyQueue);

    ByteQueue prikeyQueue;
    privateKey.Save(prikeyQueue);
    Save(prifilename, prikeyQueue);
}

//RSA-PSS
std::string getRsaSignature(const std::string& prifilename,const std::string& msg) {
    RSA::PrivateKey prikey;
    std::string signature;
    ByteQueue priqu;
    Load(prifilename, priqu);
    prikey.Load(priqu);

    AutoSeededRandomPool rng;
    RSASS<PSSR, SHA256>::Signer signer(prikey);
    try {
        StringSource ss1(msg, true, new SignerFilter(
            rng, signer, new StringSink(signature), true
        ));
    }
    catch(CryptoPP::Exception& e) {
        return e.what();
    }
    return signature;
}

std::string checkRsaSigature(const std::string& pubfilename, const std::string& signature,const std::string& msg) {
    RSA::PublicKey pubkey;
    std::string recover;
    ByteQueue pubqu;
    Load(pubfilename, pubqu);
    pubkey.Load(pubqu);
    RSASS<PSSR, SHA256>::Verifier verifier(pubkey);
    try {
        StringSource ss1(signature, true, new SignatureVerificationFilter(
            verifier, new StringSink(recover),
            SignatureVerificationFilter::THROW_EXCEPTION |
            SignatureVerificationFilter::PUT_MESSAGE
        ));
        assert(msg == recover);
        return recover;
    }
    catch (CryptoPP::Exception& e) {
        return e.what();
    }
}

/*
*   RSA-OAEP-SHA加密
*
*
*
*
*/

void getRSAOAEPkey(std::string pubfilename, std::string prifilename) {
    InvertibleRSAFunction parameters;
    AutoSeededRandomPool rng;
    parameters.GenerateRandomWithKeySize(rng, 1024);
    RSA::PublicKey publicKey(parameters);
    RSA::PrivateKey privateKey(parameters);
    ByteQueue pubkeyQueue;
    publicKey.Save(pubkeyQueue);
    Save(pubfilename, pubkeyQueue);

    ByteQueue prikeyQueue;
    privateKey.Save(prikeyQueue);
    Save(prifilename, prikeyQueue);
}

std::string encryRSAOAEP(std::string pubfilename, std::string plain) {
    AutoSeededRandomPool rng;
    std::string cipher;
    RSA::PublicKey pubkey;
    ByteQueue pubqu;
    Load(pubfilename, pubqu);
    pubkey.Load(pubqu);
    RSAES_OAEP_SHA_Encryptor e(pubkey);
    StringSource(plain, true,
        new PK_EncryptorFilter(rng, e,
            new StringSink(cipher)));
    return cipher;
}

std::string decryRSAOAEP(std::string prifilename, std::string cipher) {
    AutoSeededRandomPool rng;
    std::string recover;
    RSA::PrivateKey prikey;
    ByteQueue priqu;
    Load(prifilename, priqu);
    prikey.Load(priqu);
    RSAES_OAEP_SHA_Decryptor e(prikey);
    StringSource(cipher, true,
        new PK_DecryptorFilter(rng, e,
            new StringSink(recover)));
    return recover;
}

PYBIND11_MODULE(pycryptodll, m) {
    m.doc() = "crypto++ to python";
    //Afine
    m.def("enAffine", &enAffine);
    m.def("deAffine", &deAffine);
    //ARC4
    m.def("randomARC4key", &randomARC4key);
    m.def("encryRC4", &encryRC4);
    m.def("decryRC4", &decryRC4);
    //MD5
    m.def("enmsgMD5", &enmsgMD5);
    m.def("checkmsgMD5", &checkmsgMD5);
    //DES
    m.def("randomDesKey", &randomDesKey);
    m.def("randomIv", &randomIv);
    m.def("encrypt3des", &encrypt3des);
    m.def("decrypt3des", &decrypt3des);
    //rsa signature
    m.def("getRsaKey", &getRsaKey);
    m.def("getRsaSignature", &getRsaSignature);
    m.def("checkRsaSigature", &checkRsaSigature);
    //rsa encry
    m.def("getRSAOAEPkey", &getRSAOAEPkey);
    m.def("encryRSAOAEP", &encryRSAOAEP);
    m.def("decryRSAOAEP", &decryRSAOAEP);
         
}