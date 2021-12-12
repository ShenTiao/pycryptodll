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
#define _CRYPTO_UTIL_H_
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

namespace py = pybind11;
using namespace CryptoPP;

/*
*
*   ������ܲ���
*   ���ܺ�����
*   std::string enAffine(std::string inData,int addKey,int mulKey)
*   ���ܺ�����
*   std::string decode(std::string inData, int addKey, int mulKey)
*/
//��չŷ�����
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

//�˷���Ԫ
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

//�������
std::string enAffine(std::string inData,int addKey,int mulKey) {
    std::string outData;
    //�����Ϸ����
    if (checkAffineKey(addKey, mulKey)) return "the key is invaild";
    for (int i = 0; i < inData.size(); ++i) {
        int code = inData[i] - 'a';
        outData += (code * mulKey + addKey) % 26 + 'A';
    }
    return outData;
}

//�������
std::string decode(std::string inData, int addKey, int mulKey) {
    std::string outData;
    for (int i = 0; i < inData.size(); ++i) {
        int code = inData[i] - 'A';
        outData += ((code -addKey+26) *findReverse(mulKey,26))%26 + 'a';
    }
    return outData;
}


/*
*   MD5
*/

//MD5У��
std::string encryMD5(std::string& data) {
    std::string digest;
    Weak1::MD5 md5;
    StringSource(data, true, new HashFilter(md5, new HexEncoder(new StringSink(digest))));
    return digest;
}

/*
*AES - CBCģʽ����ʵ��
* key���Ⱦ���MD5ת����
*/
//AES���� CBC
enum AESKeyLength
{
    AES_KEY_LENGTH_16 = 16, AES_KEY_LENGTH_24 = 24, AES_KEY_LENGTH_32 = 32 
};

//������Կkey:MD5����32�ֽ���Կ
const std::string encryAeskey(std::string& strKey) {
    const std::string Key = encryMD5(strKey);
    return Key;
}

//inData����  strKey��Կ
std::string encrypt4aes(const std::string& inData,std::string& strKey,const std::string& iv)
{
    std::string outData = "";
    std::string errMsg = "";
    
    //��Կ����MD5����
    const std::string Key = encryAeskey(strKey);

    if (inData.empty() || Key.empty()) // �жϴ����ܵ��ַ���������Կ�Ƿ�Ϊ��
    {
        errMsg = "indata or key is empty!!";
        return errMsg;
    }

    unsigned int iKeyLen = Key.length();

    if (iKeyLen != AES_KEY_LENGTH_16 && iKeyLen != AES_KEY_LENGTH_24  //�ж���Կ�ĳ����Ƿ����Ҫ��
        && iKeyLen != AES_KEY_LENGTH_32)
    {
        errMsg = "aes key invalid!!";
        return errMsg;
    }

    try
    {
        CBC_Mode<AES>::Encryption e;  //CBC ģʽ����
        e.SetKeyWithIV((byte*)Key.c_str(), iKeyLen, (byte*)iv.c_str());
        //���ܵĹؼ��� outData ���Ǽ��ܺ������
        StringSource ss(inData, true, new StreamTransformationFilter(e, 
            new HexEncoder(new StringSink(outData))));    
    }
    catch (const CryptoPP::Exception& e)
    {
        errMsg = "Encryptor throw exception!!";
        return errMsg;
    }
    return outData;
}

//AES���� indata���� strKey������Կ
std::string decrypt4aes(std::string& inData, std::string& strKey,const std::string& iv)
{
    std::string outData = "";
    std::string errMsg = "";

    //����
    StringSource(inData, true, new HexDecoder(
        new StringSink(inData)
    ));

    //��Կ����MD5����
    const std::string Key = encryAeskey(strKey);

    if (inData.empty() || Key.empty()) // �жϴ����ܵ��ַ���������Կ�Ƿ�Ϊ��
    {
        errMsg = "indata or key is empty!!";
        return errMsg;
    }

    unsigned int iKeyLen = Key.length();

    if (iKeyLen != AES_KEY_LENGTH_16 && iKeyLen != AES_KEY_LENGTH_24  //�ж���Կ�ĳ����Ƿ����Ҫ��
        && iKeyLen != AES_KEY_LENGTH_32)
    {
        errMsg = "aes key invalid!!";
        return errMsg;
    }

    try
    {
        //CBC ģʽ����
        CBC_Mode<AES>::Decryption d;    
        d.SetKeyWithIV((byte*)Key.c_str(), iKeyLen, (byte*)iv.c_str());
        //���ܵĺ�����outData �ǽ��ܵĽ��
        StringSource ss(inData, true,
            new StreamTransformationFilter(d, new HexEncoder(
                new StringSink(outData))));  
    }
    catch (const CryptoPP::Exception& e)
    {
        errMsg = "Encryptor throw exception";
        return errMsg;
    }
    return outData;
}

/*
* 3DES-CBCģʽ����ʵ��
* 
* 
* 
* 
*/

//�������Key
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

//�������iv
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

//3DES����
std::string	encrypt3des(std::string& inData, std::string& strKey, std::string& eniv) {
    std::string outData;
    std::string key, iv;
    StringSource ss1(strKey, true, new HexDecoder(
        new StringSink(key)));
    StringSource ss2(eniv, true, new HexDecoder(
        new StringSink(iv)));
    
    try {
        ECB_Mode<DES_EDE3>::Encryption e;
        e.SetKeyWithIV(key.data(),key.size(),iv.data(),iv.size());
        //ECB��CBCģʽ���������ܿ�
        StringSource ss(inData, true, new 
            StreamTransformationFilter(e,
                new HexEncoder(new StringSink(outData))));
    }
    catch (const Exception& e) {
        return e.what();
    }
    return outData;
}

//3DES����
std::string decrypt3des(const std::string& key, std::string& inData,const std::string iv) {
    std::string outData;
    try {
        CBC_Mode<DES_EDE3>::Decryption e;
        e.SetKeyWithIV((byte*)key.c_str(), key.size(),(byte*)iv.c_str());
        StringSource ss(inData, true, new 
            StreamTransformationFilter(e, 
                new HexEncoder(new StringSink(outData))));
    }
    catch (const Exception& e) {
        return e.what();
    }
    return outData;
}

PYBIND11_MODULE(pycryptodll, m) {
    m.doc() = "crypto++";

	m.def("retMD5", &encryMD5, "return the MD5 value");
    
    m.def("enAESkey", &encryAeskey, "encry the AES key");
    m.def("enAES", &encrypt4aes, "encrypt the AES", py::arg("indata"), py::arg("key"),py::arg("iv"));
    m.def("deAES", &decrypt4aes, "decode the AES", py::arg("indata"), py::arg("key"),py::arg("iv"));

    m.def("randomDesKey", &randomDesKey);
    m.def("randomIv", &randomIv);
    m.def("enDES", &encrypt3des, "encry the DES");
    m.def("deDES", &encrypt3des, "decode the des");
}