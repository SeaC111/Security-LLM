mqtt
====

信息收集
----

题目给了pcap流量包和一个ELF二进制文件，所以猜测flag就在pcap里，需要逆向binary去解密流量。

```apl
mqtt_publisher
├── packets.pcap
└── publisher
```

根据题目名搜索一下`mqtt`，得知是一种协议，使用wireshark来分析流量包。

![image-20220920095329154.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cf3f01480fb44a369039501ef77186e0e7216a23.png)

流量包比较短，而且程序只建立了一个TCP连接，直接右键追踪tcp流，将流量转存为十六进制数据。

![image-20220920095531004.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1858403ccdb07d32b6015cdd30e2a6b7891f1c06.png)

运行一下`publisher`，发现程序输出了`>`并且有接受用户输入的行为，所以解密流量包的方式应该就是去逆向还原出作者的输入内容。

定位发送报文的函数
---------

观察到流量中出现了`newmqtt`这个字符串，考虑它可能是头部数据/Magic，所以在IDA中搜索该字符串，发现它是作为`sub_405420`的一个参数进行调用，该函数一共在`main`函数中调用了3次，那么这个函数很可能就是构造并发送包的函数，由于其中使用了一些库函数，加之`lumina`也恢复不了，推荐动态调试来分析包的结构。

调一下就可以知道`sub_40A480`是发包的函数，通过在该处下断点动态调试，就可以知道程序一共发了多少次报文，同时也就能区分流量包中报文的边界了。

packet1分析
---------

第一次发送的是如下的报文，跟流量包中的一样，是一种握手信息，可以不作分析。

![image-20220920103645160.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7b422f7f5efb454605311aababcc7cc4db021b65.png)

packet2分析
---------

程序read了16bytes(参数是16bytes，但实际上&lt;=16都行)，发送了如下的包，

- 前面10字节是头部数据，可以不分析
- 中间4字节是程序设置的固定值，是MQTT报文的Flags和报文id等
- 最后面16字节的就是有效载荷  
    ![image-20220920103535178.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-78bed4c37861576fd695352429b7b8687a8484b3.png)

### 解密

有效载荷是第一次输入经过异或加密后的结果，通过动态调试可以拿到异或的密钥，直接跟密文异或还原出作者输入。

XOR key:

```php
1f65c9880bf5720082ce430c2c34d2b3
```

直接异或报文里的有效载荷即可还原出输入。

```php
33131faf1a1a3f1a4ae13f161002433100
```

packet3分析
---------

程序`read`了40bytes，经过一种移位异或加密和AES加密，发送了如下报文，结构跟packe2相同，有效载荷是最后64bytes，  
![image-20220920103610436.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7eba833f930da5d9d94dad7baf635f2084955757.png)

### 加密1

IDA生成加密算法的伪代码如下

```c
int x= buf2[i];
int n = 0x186B0;
do{

    x = ((x^(x<<5))>>17) ^ (x<<5) ^ x ^ (((x^(x<<5))>>17) ^ (x<<5) ^ x) << 13);
    --n;
}
while (n);
```

通过观察我们可以提取出一些重复部分，化简可得

```c
  for ( i = 0LL; i != 16; ++i )
  {
    x = buf[i]
    n = 0x186B0;
    do
    {
      z= x ^ (x << 5);
      t = (z >> 17) ^ z;
      x = t ^ (t << 13);
      --n;
    }
    while ( n );
    buf[i] = x;
  }
```

这种运算是有限域上的位运算，一般出现在密码学中，但是这道题没有涉及太复杂的运算，可以用简单的方法来还原，参考

[Reversing XOR and Bitwise operation in Python - Stack Overflow](https://stackoverflow.com/questions/26481573/reversing-xor-and-bitwise-operation-in-python)可以写出解密的脚本

### 加密2

使用`Findcrypt`插件可以查找的AES算法使用的一些常数，使用动态调试的方法辅助分析发现加密2是`AES-128-CBC`，

大部分网上的加密算法的实现都有结构体的封装，在各种程序里也会经常见到下面这种调用加密算法的方法。

```c
AES_struct *AES = new AES(key,IV,mode);
AES->update(plaintext,cipher_buf);
```

结合这个经验可知，在AES初始化函数，参数1是AES对象，参数2是key，为第一次`read`的输入，参数3是IV。

```python
key 33131faf1a1a3f1a4ae13f1610024331 #packet2解密结果
IV: 102122232425262728292A2B2C2D3E2F  #程序里写死的
```

### 解密

首先进行AES的解密，使用`Crypto`的标准AES解密即可。

```python
from Crypto.Cipher import AES
key = bytes.fromhex("33131faf1a1a3f1a4ae13f1610024331")
iv = bytes.fromhex("102122232425262728292A2B2C2D3E2F")
c ='''C0 B3 E4 38 7F D0 25 44 21 70 B8 DF F1 4F BA 258B 7E 50 85 DE 72 F4 E2 CB D9 DC 75 4E F5 F9 4904 C5 03 79 CE 18 A3 D8 91 CF 11 C3 82 AE F8 DA88 D7 51 DA 9C B7 3A D9 5E 9C 9D 0A EB AF 05 AB'''
c = c.replace(" ","")
c = bytes.fromhex(c)
aes = AES.new(key,mode=AES.MODE_CBC,iv=iv)
print(aes.decrypt(c).hex())
```

然后是异或移位的解密

```c
#include <stdio.h>
#define rounds 0x186B0

int enc(int xx)
{
    unsigned int x = xx;
    unsigned int n = rounds;
    unsigned int z, t;
    do
    {
        z = x ^ (x << 5);
        t = (z >> 17) ^ z;
        x = t ^ (t << 13);
        --n;
    } while (n);

    return x;
}

int enc2(int xx)
{
    unsigned int x = xx;
    int n = rounds;
    do
    {
        x ^= ((x ^ (32 * x)) >> 17) ^ (32 * x) ^ ((((x ^ (32 * x)) >> 17) ^ x ^ (32 * x)) << 13);
        --n;
    } while (n);
    return x;
}
int Inv_Rshift_xor(int xx, unsigned int shiftamount)
{
    unsigned int x = xx;
    while (x >> shiftamount && shiftamount < 32)
    {
        x ^= x >> shiftamount;
        shiftamount <<= 1;
    }
    return x;
}
int Inv_Lshift_xor(int xx, unsigned int shiftamount)
{
    unsigned int x = xx;
    while ((x << shiftamount) & 0xffffffff && shiftamount < 32)
    {
        // printf("x %08x k : %08x m : %d \n",x,(x << shiftamount)&0xffffffff,shiftamount);
        x ^= (x << shiftamount) & 0xffffffff;
        shiftamount <<= 1;
    }
    return x & 0xffffffff;
}
int dec(int c)
{
    unsigned int x = c;
    unsigned int n = rounds;
    unsigned int z, t;
    do
    {
        t = Inv_Lshift_xor(x, 13);
        z = Inv_Rshift_xor(t, 17);
        x = Inv_Lshift_xor(z, 5);
        // printf("t: %08x z: %08x x: %08x \n",t,z,x);
        --n;
    } while (n);

    return x;
}

int main()
{

    char c[] = {0xe2,0xaa,0xe4,0x28,0x13,0xb0,0xc6,0x84,0x83,0x44,0x28,0xfc,0x55,0x61,0x6c,0x1f,0xc7,0x41,0xcd,0x50,0x5f,0x1d,0xed,0xd8,0x60,0xce,0xe7,0x1c,0x86,0x55,0x3c,0x56,0x7c,0x08,0x64,0x1c,0xdb,0xc8,0x40,0x87,0x98,0x47,0x75,0xaa,0x5c,0xcc,0xcd,0x04,0x1f,0xa0,0xd3,0x5c,0x5a,0xc2,0xa5,0x11,0xe7,0xf8,0x06,0x8c,0xa5,0x86,0xbf,0x13};

    int m[16];
    for (int i = 0; i < 16; i++)
    {
        int cc = *((int *)c + i);
        m[i] = dec(cc);
        printf("%08x\n", m);
        printf("%s\n", (char*)m);
    }
    return 0;
}
```

得到flag

```c
flag{296a5a44623e69db3-87a22a49a8d91896b-d5b7f452-5c7cd3c583a6f}
```

总结
==

在车联网和工业控制网络日渐发展的背景下，协议逆向也是安全人才应该具备的一项技能。在CTF还有实际的安全业务中可以从以下三个方面去入手分析协议。

- 定位发送报文的函数
- 理清报文的结构
- 识别协议内部的加密算法