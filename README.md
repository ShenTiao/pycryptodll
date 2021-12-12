## Crypto++实现常用加密算法

加密算法实现部分：通过Crypto++库对常用算法进行实现与再封装。

## 依赖

### Crypto++

Crypto++ 库是开源的 C++ 数据加密算法库，支持如下算法：RSA、MD5、DES、AES、SHA-256 等等，其中对于加密有对称加密和非对称加密。本实验通过 Cryto++ 库对字符串进行 MD5 校验，并用 AES 加密和解密。

[官网](https://cryptopp.com/) [手册](https://cryptopp.com/docs/ref/) [wiki及代码示例](https://www.cryptopp.com/wiki)

#### 安装依赖库

环境：Windows 10 64bit，VS2019。

首先官网Download-Release Notes下载最新压缩包。

下载后解压缩，找到解决方案cryptlib.sln，单独对cryplib进行生成：

![image-20211206170314034](https://s2.loli.net/2021/12/06/2R7Lig8oeplqjAs.png)

配置Release或者Debug或者两者都在x64环境下进行生成，可以在根目录x64/Output/Release下看到已经生成的lib库(以release为例)。

#### 建立SDK

建立一个目录CryptoPP，这里以C:\Program Files\CryptoPP为例，目录下新建目录include和lib，将生成好的lib库放在lib目录下：lib\Release。将解压缩的源文件所有cpp与h文件放置在include目录下。

在VS2019新建一个项目，修改项目配置：

![image-20211206170814097](https://s2.loli.net/2021/12/06/g8PNbseVpDaEqF4.png)

包含目录即刚刚创建的include文件目录，库目录即lib目录。注意：

![image-20211206170900318](https://s2.loli.net/2021/12/06/o93iwY4RUHyqS5v.png)

将运行库切换成/MT模式，链接器配置：

![image-20211206171045887](https://s2.loli.net/2021/12/06/ILkiNmDwXy7RZPY.png)

否则链接失败。



### pybind11

[github](https://github.com/pybind/pybind11)	[文档](https://pybind11.readthedocs.io/en/stable/)	

**pybind11**是一个轻量级的header-only库，它在 Python 中公开 C++ 类型，反之亦然，主要用于创建现有 C++ 代码的 Python 绑定。

核心特性：

![image-20211206171313554](https://s2.loli.net/2021/12/06/ZQMfBw9J1kzj8XK.png)

pybind11可以很好地将C++代码打包成dll库，windows上的pyd文件来导入python代码。

安装pybind11过程与crypto++类似，不同的是pybind11是header-only文件，只需要配置包含目录和库目录与链接依赖项，同时python本身的lib文件与include路径也需要同样添加进去。



### 第一段测试代码

#### C++

打包一段简单的MD5校验代码：

```C++
#include <pybind11/pybind11.h>
#include <md5.h>
#include <hex.h>
#include <files.h>
#include <osrng.h>
#include <filters.h>
#include <default.h>
#include <string>
#define _CRYPTO_UTIL_H_
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

namespace py = pybind11;
using namespace CryptoPP;

std::string& retMD5(std::string& data) {
	std::string digest;
	Weak1::MD5 md5;
	StringSource(data, true, new HashFilter(md5, new HexEncoder(new StringSink(digest))));
	return digest;
}

PYBIND11_MODULE(pycryptodll, m) {
	m.def("retMD5", &retMD5, "return the MD5 value");
}
```

编译提示：

`You may be using a weak algorithm that has been retained for backwards compatibility. Please '#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1' before including this .h file and prepend the class name with 'Weak::' to remove this warning.`

使用向后兼容的弱算法需要添加宏：

`#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1'`

注意22行`pycryptodll`处内容需要与项目同名，否则python解释器报错。

`PYBIND11_MODULE()`宏创建了一个函数，当`import`从 Python 中发出语句时将调用该函数 。模块名称 ( `example`) 作为第一个宏参数给出（不应包含在引号中）。第二个参数 ( `m`) 定义了一个类型变量，`py::module_`它是创建绑定的主要接口。该方法module_::def() 生成将`add()`函数公开给 Python 的绑定代码。

#### Python运行

```python
import pycryptodll
print(m.retMD5("123131"))
```

将pyd文件与py文件放在同目录下，输入以上代码即可调用函数。



## 加密算法部分

### AES(CBC mode)

AES 采用的是对称加密，在密码学中又称 Rijndael 加密法，是美国联邦政府采用的一种区块加密标准。这个标准用来替代原先的 DES ，已经被多方分析且广为全世界所使用。 本次使用CBC模式，密码分组链接模式（CBC模式）：这种模式是先将明文切分成若干小段，然后每一小段与初始块或者上一段的密文段进行异或运算后，再与密钥进行加密。

加密流程图：

![image-20211207170621804](https://s2.loli.net/2021/12/07/Ou7JMUXEsKTpZ8I.png)

CBC模式:

![image-20211207171108714](https://s2.loli.net/2021/12/07/12ETvCjLok9aRbn.png)

接口函数：

```cpp
//将输入Key经过MD5加密生成的32字节密钥，返回密钥值，
const std::string encryAeskey(std::string& strKey) 
//AES加密函数，inData为明文，strKey为MD5加密前输入的key CBC下iv，返回加密字符串
std::string encrypt4aes(const std::string& inData,std::string& strKey,std::string& iv)
//AES解密函数 inData密文 strKey解密密钥 CBC下iv，返回解密字符串
std::string decrypt4aes(const std::string& inData, const std::string& strKey,std::string& iv)
```



### 3DES(CBC mode)

DES 使用一个 56 位的密钥以及附加的 8 位奇偶校验位，产生最大 64 位的分组大小。这是一个迭代的分组密码，使用称为 Feistel 的技术，其中将加密的文本块分成两半。使用子密钥对其中一半应用循环功能，然后将输出与另一半进行“异或”运算；接着交换这两半，这一过程会继续下去，但最后一个循环不交换。DES 使用 16 个循环，使用异或，置换，代换，移位操作四种基本运算。

TripleDES,是对纯文本数据的DES算法的多重应用，以增加原有DES算法的安全性。顾名思义，DES算法被应用了3次。TripleDES有两种变体:第一种是两个key;第二个是三个key。2-key TDEA提供大约80位的安全性，而3-key TDEA提供大约112位的安全性。相反，AES提供的最低安全级别为128。

本次实现2 Key Triple DES:

单次DES加密流程图：![image-20211208164432707](https://s2.loli.net/2021/12/08/VfpBGEvOU4dyZtr.png)

**上图左半部分描述了明文加密成密文的三个阶段。**

　　1、64位的明文经初始置换（IP）而重新排列。

　　2、进行16轮的置换和转换（基于Feistel结构）。

　　3、再做一次置换（IP-1，与初始置换互逆）。

**加密过程与解密过程基本一致。**

**上图右半部分是56位密钥的操作过程。**

　　1、密钥先做一个置换。

　　2、再做16次包含循环左移和置换的操作组合，每次都产生一个子密钥Ki。每一轮的置换操作都完全相同，但由于循环左移而使得每个子密钥不同。

**TripleDES总流程：**

![image-20211208171402234](https://s2.loli.net/2021/12/08/89unBC1RcSaLhyg.png)

忽略奇偶校验位。

2key变体的块大小为8字节(64位)，并使用一个16字节的密钥。

BC模式:

![image-20211207171108714](https://s2.loli.net/2021/12/07/12ETvCjLok9aRbn.png)

函数接口：

```cpp
/*
* 3DES-CBC模式加密实现
*  随机生成Key      std::string randomDesKey()
*  随机生成iv       std::string randomIv()
*  加密   std::string encrypt3des(std::string& inData, std::string& strKey, std::string& eniv)
*  解密   std::string decrypt3des(std::string& inData,std::string& strKey,std::string& eniv)
*/
```

[CBC-Mode]: https://www.cryptopp.com/wiki/CBC_Mode



### RC4

RC4作为流密码，该密码使用 40 位到 2048 位的密钥，并且没有初始化向量(iv)。

注意密钥长度：

> ```
> key length(default): 16
> key length (min): 1
> key length (max): 256
> iv size: 0
> ```
