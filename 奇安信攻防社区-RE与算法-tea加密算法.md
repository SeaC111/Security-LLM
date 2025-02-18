0x00 前言
=======

**"TEA"** 的全称为**"Tiny Encryption Algorithm"** 由于实现简单，加密安全（QQ和微信的一些协议中就是使用的Tea加密），深受ctf出题人的喜爱。因此tea算法成为ctf REer的一种必学算法。

详细介绍如下：

> 在安全学领域，TEA（Tiny Encryption Algorithm）是一种分组加密算法，它的实现非常简单，通常只需要很精短的几行代码。TEA 算法最初是由剑桥计算机实验室的 David Wheeler 和 Roger Needham 在 1994 年设计的。
> 
> TEA算法使用64位的明文分组和128位的密钥，它使用Feistel分组加密框架，需要进行 **64** 轮迭代，尽管作者认为 **32** 轮已经足够了。该算法使用了一个神秘常数**δ**作为倍数，它来源于**黄金比率**，**以保证每一轮加密都不相同**。但**δ的精确值似乎并不重要**，这里 TEA 把它定义为 δ=「(√5 - 1)231」（也就是程序中的 **0×9E3779B9**）。

0x01 标准tea加密与解密
===============

要研究一种加密算法并力图在CTF中做出题来，首先要熟练的掌握算法的标准代码。

首先我们来看加密过程，tea的加密过程，抽取key密钥中的前四位，分别加密数组中的前四个字节与后4个字节,4个字节为一组每次加密两组。总共加密32轮，最后再把加密的结果重新写入到数组中

tea加密流程如图所示：

&lt;img src="<https://s2.loli.net/2022/03/22/PbtHwLMj1SgfiG2.png>" alt="img" style="zoom: 200%;" /&gt;

**加密代码：**

```c
void encrypt(uint32_t* v,uint32_t* key){
uint32_t v0=v[0],v1=v[1],sum=0,i;
uint32_t delta=0x9e3779b9;
uint32_t k0=key[0],k1=key[1],k2=key[2],k3=key[3];
for(i=0;i<32;i++){
    sum+=delta;
    v0+=((v1<<4)+k0)^(v1+sum)^((v1>>5)+k1);
    v1+=((v0<<4)+k2)^(v0+sum)^((v0>>5)+k3);
}
v[0]=v0;v[1]=v1;
}
```

根据加密讨论一下解密的思路

```php
上文中，v0+=xxx与v1+=xxx这两个公式总共执行了32轮，可以记作：
(v0+=xxx)32
(v1+=xxx)32
那么解密的时候，应为三十二轮递减，且v0和v1的顺序应当变换回来
(v1-=xxx)32
(v0-=xxx)32
```

**解密代码：**

```c
void decrypt(uint32_t* v,uint32_t* key){
uint32_t v0=v[0],v1=v[1],sum=0xC6EF3720,i;
uint32_t delta=0x9e3779b9;
uint32_t k0=key[0],k1=key[1],k2=key[2],k3=key[3];
for(i=0;i<32;i++){
    v1-=((v0<<4)+k2)^(v0+sum)^((v0>>5)+k3);
    v0-=((v1<<4)+k0)^(v1+sum)^((v1>>5)+k1);
    sum-=delta;
}
v[0]=v0;v[1]=v1;
}
```

0x02 xTEA算法
===========

TEA 算法发布不久，被发现存在缺陷，作为回应，设计者提出了一个 TEA 的升级版本——XTEA（有时也被称为“tean”）。XTEA 跟 TEA 使用了相同的简单运算，但它采用了截然不同的顺序，为了阻止密钥表攻击，四个子密钥（在加密过程中，原 128 位的密钥被拆分为 4 个 32 位的子密钥）采用了一种不太正规的方式进行混合。总的来说 xTEA就是在TEA算法基础上加了一些内容，而加解密过程基本没变。

&lt;img src="<https://s2.loli.net/2022/03/22/L1wJI7s3ECN2jYn.png>" alt="1024px-XTEA\_InfoBox\_Diagram.svg" style="zoom:50%;" /&gt;

**加解密代码：**

```c
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
{
    unsigned int i;
    uint32_t v0=v[0],v1=v[1],delta=0x9E3779B9,sum=delta*num_rounds;
    for(i=0;i<num_rounds;i++){
        v0+=(((v1<<4)^(v1>>5))+v1)^(sum+key[sum&3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0;v[1]=v1;
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
{
    unsigned int i;
    uint32_t v0=v[0],v1=v[1],delta=0x9E3779B9,sum=delta*num_rounds;
    for(i=0;i<num_rounds;i++){
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0-=(((v1<<4)^(v1>>5))+v1)^(sum+key[sum&3]);
    }
    v[0]=v0;v[1]=v1;
}
```

0x03 xxTEA算法
============

相比TEA,xTEA算法，xxTEA算法的优势是原字符串长度可以不是4的倍数了

![img](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2ab3fff477b20185dd1545e8a4de0abb2cb307e6.png)

加密源码

```c
#include <stdio.h>
#include <stdint.h>
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2)+(y>>3^z<<4))^((sum^y)+(key[(p&3)^e]^z)))
void btea(uint32_t *v,int n,uint32_t const key[4])//n为v数组长度 
{
    uint32_t y,z,sum;
    unsigned p,rounds,e;
    if(n>1)
    {
        rounds=6+52/n;
        sum=0;
        z=v[n-1];
        do
        {
            sum+=DELTA;//循环加密过程
            e=(sum>>2)&3;
            for(p=0;p<n-1;p++)
            {
                y=v[p+1];
                v[p]+=MX;
                z=v[p];
            }
            y=v[0];
            z=v[n-1]+=MX;
        }
        while(--rounds); 
    }
}     
```

解密源码：

```c
 #include <stdio.h>
#include <stdint.h>
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2)+(y>>3^z<<4))^((sum^y)+(key[(p&3)^e]^z)))
void dtea(uint32_t *v,int n,uint32_t const key[4])//n为v数组长度 {
 rounds = 6 + 52/n;
 sum = rounds*DELTA;
    y = v[0];
    do {
        e = (sum >> 2) & 3;
        for (p=n-1; p>0; p--) {
          z = v[p-1];
          y = v[p] -= MX;
        }
        z = v[n-1];
        y = v[0] -= MX;
        sum -= DELTA;
      } while (--rounds);
}
```

根据源码能总结xxTEA算法如下特点：

```php
1. key 128 bit
2. enc => 32*i(i=>2)
3. 特征量`0x9e3779b9`
4. 两层循环，通常记住最外层的循环为rounds=6+52/n
5. 5，2，3，4左右移操作
```

0x04 TEA算法特征总结
==============

根据上文对tea算法的源码分析，我们得出TEA算法的如下特征：

> 1. key 128 bit {2,2,3,4}
> 2. 传入两个32位无符号整数
> 3. 三个累加量，其中最后赋值给传入的参数
> 4. 存在`<<4 , >>5 , xor`等操作
> 5. 特征量：0x9e3779b9

至于xTEA,xxTEA等TEA算法的特殊变种，由于都是在原始TEA算法上做的局部改动，特征上与tea算法没有本质上的不同，只不过可能有位运算位数不同。具体区别如下：

```php
相同点：
1. key 128 bit特征量`0x9e3779b9`
2. 主要加密部分进行移位和异或操作
首先如果题目中出现常量`0x9e3779b9`，那么肯定是`Tea`相关算法了。
区分：
1. Tea的主加密部分为`<<4,>>5,xor`，循环32轮
2. xTea的主加密部分`<<4,>>5,>>11,xor`,循环次数不定，但通常也为32轮，需要传入3个参数
3. xxTea的主加密部分`>>5,<<2,>>3,<<4,xor`,循环次数为`6+52/n`，enc长度大于64
```

0x05 CTF &amp; TEA &amp;&amp; xTEA，xxTEA
========================================

tea
---

### \[2021 MAR DASCTF\]drinkSomeTea

题目能够直接反编译main函数，并给出了tea.png.out附件。main函数逻辑也很清晰，读取flag（一张图片），经过处理之后输出tea.png.out，我们要做的就是恢复加密之前的图片。

![image-20220402101712259](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-762d1fac5c084335ea2b4a2297c4dc7012984ab2.png)

关键函数反编译不了，跟进该地址发现有花指令。

![image-20220402102916493](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3df120f76409d4df2c8da0c9db0dc32131c518f5.png)

![image-20220402102941432](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-aabf6a1b5c26e88a8e35ad0054d0fe7c63f08367.png)

这个jz jnz 无意义的跳转 显然是花指令。下面我们开始去花指令

首先在00401116地址位置（调用地址ida标红位置）按u将代码转化为数据

![image-20220402104228481](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-14cf4ce557fc8b248ef6426be27c2d88b2ea8680.png)

再在00401112地址（jz跳转花指令处）change byte将 74 03 75 01 E8改为90 90 90 90 90（nop）

![image-20220402104355291](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-72f8441ef44c2facee3c7a3a84dc4e0121638efd.png)

![image-20220402103429280](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d81d1774c0eeeab3c1981edd57ead542e39c11d1.png)

最后在 loc\_4010DA处 按p定义为函数，即可成功反编译。

![image-20220402103633223](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-670d6847dbccf66e285c83c18e378c1981476b0f.png)

如果上文tea算法的内容你看懂了，很容易就能看出上述函数是非常明显的一个裸tea算法,最后需要的就是写脚本解密了。

```c
#include<bits/stdc++.h> 
//#define int long long
#define IO ios::sync_with_stdio(false)
#define _BYTE unsigned char
#define HIBYTE(x) (*((_BYTE*)&(x)+1))
#define eps 1e-8
using namespace std;
int ans[500005];
const int N=500003;
void decrypt(int *v,int k[])
{
    int v0=v[0], v1=v[1], sum=0xC6EF3720, i;  
    int delta=0x9e3779b9;                      
    int k0=k[0], k1=k[1], k2=k[2], k3=k[3];   
    for (i=0; i<32; i++) {                         
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);  
        sum -= delta;  
    }                                              
    v[0]=v0; v[1]=v1;  
}
signed main()
{
    int k[6]={0x67616C66,0x6B61667B,0x6C665F65,0x7D216761};
    FILE *fp=fopen("tea.png.out","rb");
    fread(ans,sizeof(int),N,fp);
    fclose(fp);
    for(int i=0;i<N;i+=2)
    {
        decrypt(ans+i, k);
    }
    fp = fopen("tea.png", "wb");
    fwrite(ans, sizeof(int), N, fp);
    fclose(fp);
}
```

### \[MRCTF2021\]Dynamic\_debug

64位elf文件，话不多说，直接开始动调

**绕过长度检测**

![image-20220328162826399](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-709a1bc6cb0851ed826cad81dfc63ec5b13679a8.png)

**smc加密伪代码修复**

按c强制转换代码

![image-20220327175449233](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c8adf9676d5e26b9735bf2af66a7fceaca1cf469.png)

在差不多的随意位置下断点。动调，输入32位字符绕过长度限制

![image-20220327175513153](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5b0eace21e04d84df9a28960a17fe6e1e5000390.png)

![image-20220327175634122](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-58241bcb05de660753b3ba0781cac9f747415ecd.png)

开始位置按p创建函数，f5反编译，看到了主函数

![image-20220327180036244](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8c5228942633a57ea9c5d3314e21ca8f32f15731.png)

跟进关键解密函数发现，得到的伪代码没有变量识别，非常难看。就在这卡了好久。看到了wjh大佬的blog。了解到这里可以尝试修复堆栈我们可以尝试着在这部分之上使用 Keypatch 手动加入一个 **push rbp; mov rbp, rsp**让 IDA 能够识别出堆栈上的变量，紧接着再 F5，就可以看到比较舒服的伪代码了。

![image-20220327180519898](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-22f057fd1f4cb9851e2bf4bfe6723602368f2f98.png)

**tea算法识别+破解**

一眼tea好吧。通过循环执行了 32 次，并且在循环内部对一个变量反复增加 delta 常数 (0x9E3779B9)，循环内部出现了 TEA 运算逻辑等特征。

![image-20220327180554303](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-963c8d114b02fe534d80d35f9713079ed8a76c8b.png)

最后标准tea解密解码即可

```c
#include <cstdio>
void encrypt(unsigned int* v, const unsigned int* k)
{
    unsigned int v0 = v[0], v1 = v[1], sum = 0, i;
    unsigned int delta = 0x9E3779B9;
    unsigned int k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++)
    {
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }
    v[0] = v0;
    v[1] = v1;
}
void decrypt(unsigned int* v, unsigned int* k)
{
    unsigned long v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;
    unsigned long delta = 0x9e3779b9;
    unsigned long k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++)
    {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}
int main()
{
    unsigned int v[] = {
        0x5585A199, 0x7E825D68, 0x944D0039, 0x71726943, 0x6A514306,c 0x4B14AD00, 0x64D20D3F, 0x9F37DB15, 0
    };
    unsigned int k[4] = { 0x6B696C69, 0x79645F65, 0x696D616E, 0x67626463 };
    for (int i = 0; i < 8; i += 2) decrypt(v + i, k);
    printf("%s", v);
    return 0;
}
```

xtea
----

### \[2021虎符Re\]GoEncrypt

一个变种的 xtea加密（delta变成0x12345678）。key和密文通过动态调试获得。主要加密逻辑在`myCipher__Encrypt`函数中

```php
  while ( v16 < 32 )
  {
    v13 = v14;
    v18 = v14 + ((v14 >> 5) ^ (16 * v14));
    v19 = *(_QWORD *)(a7 + 32);
    v20 = *(_QWORD *)(a7 + 24);
    v21 = v17;
    v22 = v17 & 3;
    if ( v22 >= v19 )
      runtime_panicindex(v19, v22, v15, a7);
    v23 = v15 + (v18 ^ (v21 + *(_DWORD *)(v20 + 4 * v22)));
    v17 = (unsigned int)(v21 + 0x12345678);
    v24 = ((unsigned int)v17 >> 11) & 3;
    if ( v24 >= v19 )
      runtime_panicindex(v19, v17, v24, a7);
    ++v16;
    a1 = (v23 + ((v23 >> 5) ^ (16 * v23))) ^ (v21 + *(_DWORD *)(v20 + 4 * v24) + 0x12345678);
    v14 = v13 + a1;
    v15 = v23;
  }
  ((void (__fastcall *)(__int64, __int64, __int64, __int64, __int64))main_end[4])(a1, a10, v15, a8, v13);
  if ( a9 < 4 )
    runtime_panicslice();
  return ((__int64 (__fastcall *)(__int64, __int64, __int64, void *, __int64))main_end[4])(
           a1,
           a8,
           a8 + (((4 - a10) >> 63) & 4),
           main_end[4],
           v25);
}
```

main\_check 给出了flag的正则提示

![image-20220402112057891](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bb2b8c59c57e5c446f695270d4a60d0406c9e5e3.png)

![image-20220402112004714](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b1a13692f5b2ca036844841acf10190f47ead357.png)

然后现在我们还需要key和加密后的数据才能解密，分析了加密过程我们知道这个key就是v20，

我们在v20的赋值语句下一句下个断点，随便输入flag{12345678-1234-1234-1234-12345678abcd}满足前面条件的假flag，就能获取到v20的值。加密数据在比较函数中一直单步f8就可以获得。

得到加密后的值：0EC311F045C79AF3EDF5D910542702CB

解密脚本。

```php
#include <stdio.h>
#include <stdint.h>

void XTEA_decrypt(uint32_t rounds, uint32_t* v, uint32_t* k)
{
    uint32_t delta = 0x12345678;
    uint32_t sum = rounds * delta;
    uint32_t v0 = v[0], v1 = v[1];
    for (int i = 0; i < rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}
int main(){
    uint32_t rounds = 32;
    uint32_t v[2][2] = { { 0x0ec311f0, 0x45c79af3 },
                         { 0xedf5d910, 0x542702cb } };
    uint32_t k[4] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };

    XTEA_decrypt(rounds, v[0], k);
    XTEA_decrypt(rounds, v[1], k);
    printf("%x-%x\n", v[0][0], v[0][1]);
    printf("%x-%x\n", v[1][0], v[1][1]);
}
//flag{3bbcf9ea-2918-4fee-8a2e-201b47dfcb4e}

```

xxtea
-----

### \[2021hgame\] alpacha

函数逻辑非常简单。关键就是识别加密类型了

![image-20220325094604148](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0f20046a1d741150e2c3f6990480200d5ac2c1c9.png)

首先通过findcrypt插件发现TEA加密标识量。

再跟进关键加密函数发现&gt;&gt;5 &gt;&gt;3。看来是写的比较裸奔的一个xxTEA算法

![image-20220325094827313](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e1ab194e723298abf993c32165144315c2f7e857.png)

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define DELTA 0x9e3779b9 
#define MX  (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^  ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
uint32_t cipher[] = { 0xE74EB323, 0xB7A72836, 0x59CA6FE2, 0x967CC5C1, 0xE7802674, 0x3D2D54E6, 0x8A9D0356, 0x99DCC39C, 0x7026D8ED, 0x6A33FDAD, 0xF496550A, 0x5C9C6F9E, 0x1BE5D04C, 0x6723AE17, 0x5270A5C2, 0xAC42130A, 0x84BE67B2, 0x705CC779, 0x5C513D98, 0xFB36DA2D, 0x22179645, 0x5CE3529D, 0xD189E1FB, 0xE85BD489, 0x73C8D11F, 0x54B5C196, 0xB67CB490, 0x2117E4CA, 0x9DE3F994, 0x2F5AA1AA, 0xA7E801FD, 0xC30D6EAB, 0x1BADDC9C, 0x3453B04A, 0x92A406F9}; 
uint32_t * xxtea_uint_decrypt(uint32_t * data, size_t len, uint32_t * key)
{
    uint32_t n = (uint32_t)len - 1;
    uint32_t z, y = data[0], p, q = 6 + 52 / (n + 1), sum = q * DELTA, e;
    if (n < 1)
        return data;
    while (sum != 0) 
    {
        e = sum >> 2 & 3;
        for (p = n; p > 0; p--) 
        {
            z = data[p - 1];
            y = data[p] -= MX;
        }
            z = data[n];
            y = data[0] -= MX;
            sum -= DELTA;
    }
        return data;
}
int main() 
{
    uint32_t key[] = {1, 2, 3, 4};
    xxtea_uint_decrypt(cipher, 35, key);
    for (int i = 0; i < 35; i++)
        {
            printf("%c", (char)cipher[i]);
        } 
}
```

### \[2019红帽杯\]xx

通过这道题还是学习/复习了很多小技巧的，做高质量题目真的会让人愉悦~

main函数虽长，但是逻辑清晰，为我们破解提供了非常大的便利~

本题主要分为三部分处理

第一部分：xxtea加密

![image-20220325095832670](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4d28e4ef48248f483bddb584d4c9a1474899f35b.png)

![image-20220325095821573](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f615467caf8f582215ae3febe9aee3350b8bbc70.png)

第二部分：数组换位

![image-20220325095915733](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-01a32c19b3725bf2a32e1e1d7d3d6220bbd5cda0.png)

第三部分：有规律的异或

![image-20220325095937660](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8f055845ff3547a8b7a5520ffef8a3779dfab32d.png)

我们来倒序分析一下各部分破解，

首先处理原始数据：v30,v31,v30+1,v32存储了本题的加密数据。在栈上存放的位置相连。小端序存放，需将其反过来写。

![image-20220325100300343](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9561a7621a4555c3a93984d74bdc80d9e8d62b96.png)

当然，由于本题数据量小，手工提取或许是效率更高的方式，但是做题的目的是为了学习，万一以后遇到大数据量的题目呢？

如下的代码将data0两位一组，保存为15进制数，再转换为10进制

```python
data0 = "CEBC406B7C3A95C0EF9B202091F70235231802C8E75656FA"#为提取出来的v29,v29+1,v30,v31
data = []
for i in range(0,len(data0),2):
    data.append(int(data0[i]+data0[i+1],16))
```

再处理按规律异或：

```c
 for ( v20[23] = v19[21]; v21 < v18; ++v22 )
  {
    v23 = 0i64;
    if ( v21 / 3 > 0 )
    {
      v24 = *v22;
      do
      {
        v24 ^= v20[v23++];
        *v22 = v24;
      }
      while ( v23 < v21 / 3 );
    }
    ++v21;
  }
```

特别变量解释：

**v24是数组data\[i\]**

**同样也是data\[i\]v20**

```python
for i in range(len(data)-1,-1,-1):
    for j in range(i//3):
        data[i]^data[j]
```

处理数组换位，采取打表的办法

```python
biao = [2,0,3,1,6,4,7,5,10,8,11,9,14,12,15,13,18,16,19,17,22,20,23,21]
num=[1]*24
for i in range (24):
    num[biao[i]]=data[i]
```

以下是如上三部分处理总和的c代码

```c++
#include<stdio.h>
#include<Windows.h>
int main()
{
    int count = 0;
    int b[24];
    int a[] = { 0xCE, 0xBC, 0x40, 0x6B, 0x7C, 0x3A, 0x95, 0xC0, 0xEF, 0x9B, 0x20, 0x20, 0x91, 0xF7, 0x02, 0x35, 0x23, 0x18, 0x02, 0xC8, 0xE7, 0x56, 0x56, 0xFA };

    for (int i = 23; i >=3; i--)
    {

        for (int j = 6-count; j >= 0; j--)
        {
                a[i]^=a[j];     
        }
        if (i % 3 == 0)
        {
            count++;
        }

    }
    for (int i = 0; i < 24; i++)
        printf("0x%x,", a[i]);
    printf("\n");
    b[2] = a[0];
    b[0] = a[1];
    b[3] = a[2];
    b[1] = a[3];
    b[6] = a[4];
    b[4] = a[5];
    b[7] = a[6];
    b[5] = a[7];
    b[10] = a[8];
    b[8] = a[9];
    b[11] = a[10];
    b[9] = a[11];
    b[14] = a[12];
    b[12] = a[13];
    b[15] = a[14];
    b[13] = a[15];
    b[18] = a[16];
    b[16] = a[17];
    b[19] = a[18];
    b[17] = a[19];
    b[22] = a[20];
    b[20] = a[21];
    b[23] = a[22];
    b[21] = a[23];
    for (int i = 0; i < 24; i++)
        printf("0x%x,", b[i]);
    system("pause");
}
```

运行后可以得到数据0xbc,0xa5,0xce,0x40,0xf4,0xb2,0xb2,0xe7,0xa9,0x12,0x9d,0x12,0xae,0x10,0xc8,0x5b,0x3d,0xd7,0x6,0x1d,0xdc,0x70,0xf8,0xdc

按照小端序，四位组成一位数据

然后就是进行xxtea解密，密钥是输入字符的前四位，猜测是“flag”。扒取网上的xxtea解密模板（玩xxtea还是得）

```php
#include <stdio.h>  
#include <stdint.h>  
#include<windows.h>
#define DELTA 0x9e3779b9  
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))  

void btea(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p<n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds*DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p>0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}

int main()
{
    uint32_t v[6] = { (unsigned int)0x40cea5bc, (unsigned int)0xe7b2b2f4,(unsigned int)0x129d12a9,(unsigned int)0x5bc810ae,(unsigned int)0x1d06d73d,(unsigned int)0xdcf870dc };
            uint32_t const k[4] = { (unsigned int)0x67616c66, (unsigned int)0x0, (unsigned int)0X0, (unsigned int)0x0 };
            int n = 6; //n的绝对值表示v的长度，取正表示加密，取负表示解密  
            // v为要加密的数据是两个32位无符号整数  
            // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位  
            //printf("加密前原始数据：%x %x\n", v[0], v[1]);
            btea(v, -n, k);
            printf("加密后的数据：%x %x %x %x %x\n", v[0], v[1],v[2],v[3],v[4],v[5]);
            //btea(v, -n, k);
            //printf("解密后的数据：%x %x\n", v[0], v[1]);

            system("pause");        

}
```

0x06 参考链接
=========

<https://blog.csdn.net/gsls200808/article/details/48243019>

<https://blog.csdn.net/Palmer9/article/details/104409017/>

[https://blog.csdn.net/qq\_37439229/article/details/115424066](https://blog.csdn.net/qq_37439229/article/details/115424066)

<https://www.anquanke.com/post/id/85578>

<https://xz.aliyun.com/t/3825#toc-3>

<https://xz.aliyun.com/t/3831#toc-0>