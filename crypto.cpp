#include <pybind11/pybind11.h>
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
*   ���������Կkey
*   CBCģʽvi
*/



/*
*   MD5
*/

//MD5У��
std::string retMD5(std::string& data) {
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
    const std::string Key = retMD5(strKey);
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
*/

//3DES����
std::string	encrypt3des(std::string& inData, std::string& strKey, const std::string& iv) {
    std::string outData;
    std::string printKey;
   
    try {
        ECB_Mode<DES_EDE3>::Encryption e;
        e.SetKeyWithIV((byte*)strKey.c_str(), strKey.size(), (byte*)iv.c_str());

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
                new HexEncoder(new StringSink(outData)));
    }
    catch (const Exception& e) {
        return e.what();
    }
    return outData;
}

PYBIND11_MODULE(pycryptodll, m) {
    m.doc() = "crypto++";

	m.def("retMD5", &retMD5, "return the MD5 value");
    
    m.def("enAESkey", &encryAeskey, "encry the AES key");
    m.def("enAES", &encrypt4aes, "encrypt the AES", py::arg("indata"), py::arg("key"),py::arg("iv"));
    m.def("deAES", &decrypt4aes, "decode the AES", py::arg("indata"), py::arg("key"),py::arg("iv"));
}