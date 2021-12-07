#include <pybind11/pybind11.h>
#include <aes.h>
#include <md5.h>
#include <hex.h>
#include <files.h>
#include <osrng.h>
#include <filters.h>
#include <default.h>
#include <string>
#include <sstream>
#define _CRYPTO_UTIL_H_
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

namespace py = pybind11;
using namespace CryptoPP;

//MD5У��
std::string retMD5(std::string& data) {
    std::string digest;
    Weak1::MD5 md5;
    StringSource(data, true, new HashFilter(md5, new HexEncoder(new StringSink(digest))));
    return digest;
}

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
std::string encrypt4aes(const std::string& inData,std::string& strKey)
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

    byte iv[AES::BLOCKSIZE];

    try
    {
        CBC_Mode<AES>::Encryption e;  //CBC ģʽ����
        e.SetKeyWithIV((byte*)Key.c_str(), iKeyLen, iv);
        //���ܵĹؼ��� outData ���Ǽ��ܺ������
        StringSource ss(inData, true, new StreamTransformationFilter(e, new StringSink(outData)));    
    }
    catch (const CryptoPP::Exception& e)
    {
        errMsg = "Encryptor throw exception!!";
        return errMsg;
    }

    return outData;
}

//AES���� indata���� strKey������Կ
std::string decrypt4aes(const std::string& inData, const std::string& strKey)
{
    std::string outData = "";
    std::string errMsg = "";

    if (inData.empty() || strKey.empty()) // �жϴ����ܵ��ַ���������Կ�Ƿ�Ϊ��
    {
        errMsg = "indata or key is empty!!";
        return errMsg;
    }

    unsigned int iKeyLen = strKey.length();

    if (iKeyLen != AES_KEY_LENGTH_16 && iKeyLen != AES_KEY_LENGTH_24  //�ж���Կ�ĳ����Ƿ����Ҫ��
        && iKeyLen != AES_KEY_LENGTH_32)
    {
        errMsg = "aes key invalid!!";
        return errMsg;
    }

    byte iv[AES::BLOCKSIZE];

    try
    {
        CBC_Mode<AES>::Decryption d;    //CBC ģʽ����
        d.SetKeyWithIV((byte*)strKey.c_str(), iKeyLen, iv);
        StringSource ss(inData, true,
            new StreamTransformationFilter(d, new StringSink(outData)));  //���ܵĺ�����outData �ǽ��ܵĽ��
    }
    catch (const CryptoPP::Exception& e)
    {
        errMsg = "Encryptor throw exception";
        return errMsg;
    }

    return outData;
}


PYBIND11_MODULE(pycryptodll, m) {
    m.doc() = "crypto++";
	m.def("retMD5", &retMD5, "return the MD5 value");
    
    m.def("enAESkey", &encryAeskey, "encry the AES key");
    m.def("enAES", &encrypt4aes, "encry the AES", py::arg("indata"), py::arg("key"));
    m.def("deAES", &decrypt4aes, "decode the AES", py::arg("indata"), py::arg("key"));
}