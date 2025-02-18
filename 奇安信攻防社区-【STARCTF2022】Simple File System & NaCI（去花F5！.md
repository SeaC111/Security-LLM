0x00 日常查壳
=========

给了三个文件，如题名一样，简单的文件系统，不过主逻辑在这个文件

![image-20220418192736295.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-37e9c2d61a1eb1a5fc59ffa38ea4d3e075bc6e34.png)

0x01 分析simlefs
==============

浏览了一遍主函数无疑我们关心的是plantflag

随机数出来的v21和v22我们无法逆，不过关键点就是在参数1的那次进去

![image-20220418193323238.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-dcc71d9539d1fbbb3f793902a5c0385949b9df36.png)

注意在这打开了我们的flag文件，然后进入了关键的函数，像参数为2调用了rand根本没法逆

![image-20220418193926873.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-406ee5960597d1a14751789272131ddd038954e4.png)

观看这个Encode函数完全可逆，v4动调即得，密文通过观察image.flag获得（毕竟在这个文件找不到

![image-20220418193939286.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-093496fd7326197a67832e4bb698c01448ba2951.png)

0x02 GetData!
=============

设置好参数，起飞（开调

![image-20220418194139609.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-61e0012168b4e62677848c5334553db902ff41cc.png)

输入好参数

![image-20220418194524815.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d55caed1914b00f6c8d495bd7a11166fe3c78340.png)

动调可以直接拿到v4的值和加密后的\*CTF{后的值，于是我们可以通过这个值去找密文

![image-20220418195115666.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-759f2ab1f5b4a5d75303f658880749baf61023d7.png)

即可得到

![image-20220418195214843.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ba5267906ed22573d5b9f59d8fefd2840f8293bc.png)

0x03 GetFlag!
=============

拿这个密文直接解密即可得到flag

也可以观察整个文件发现有多出密文，从0x33000开始，每隔0x1000就会有一段密文，读取解密也可

```php
def Decrypt(encFLag):
    flag = ""
    for i in range(len(encFLag)):
        v5 = encFLag[i]
        v5 = (v5 >> 3) | (v5 << 5) & 0xFF
        v5 ^= 0xDE
        v5 = (v5 >> 4) | (v5 << 4) & 0xFF
        v5 ^= 0xED
        v5 = (v5 >> 5) | (v5 << 3) & 0xFF
        v5 ^= 0xBE; 
        v5 = (v5 >> 6) | (v5 << 2) & 0xFF
        v5 ^= 0xEF; 
        v5 = (v5 >> 7) | (v5 << 1) & 0xFF
        flag += chr(v5)
    return flag                         

data = open('C:\\Users\\Pz\\Desktop\\STARCTF\\Simple File System\\image.flag', 'rb').read()
encFlags = [list(data[0x33000 + i * 0x1000: 0x33000 + i * 0x1000 + 32]) for i in range(200)]

for flag in encFlags:
    p = Decrypt(flag)
    if "*CTF" in p:
        print(flag)
        print(p)
        break

# encFlags = open('C:\\Users\\Pz\\Desktop\\STARCTF\\Simple File System\\encFlag.flag', 'rb').read()
# print(Decrypt(encFlags))
```

GetFlag!

![image-20220418195454640.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f0b934143005d7340db9dc1d8d61db0db99a2025.png)

title: STARCTF2022-NaCI
-----------------------

0x00 日常查壳
=========

无壳64位

![image-20220419152650981.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4fac85c3bdc79f8395c0350d385bf6882ccfcdbf.png)

0x01 分析主程序
==========

我们shift + F12通过字符串查找引用，直接找到这个主函数

![image-20220419153100353.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-35a797fab11975193095a68f6ff6ae8180e72a75.png)

F5加密函数！
-------

然而这个函数的F5给不能用了，只能动调去理解这个程序，然而！我摸透了这其中的符文！

![image-20220419154430259.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-02d0e0267d34b5ad28c9466c92e67eddb9aca845.png)

主要是两个点去修复，顺便去个无用指令

1. 奇怪的call
----------

每个call都是这样实现的，再去看看retn

![image-20220419153452942.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c3e949dbccb1b885867b74dc5eacff9858c24374.png)

2. 奇怪的retn
----------

可以发现每次jmp rdi就是一种回跳，而这不就是retn吗

PS:上面的call和retn不是同一组call+retn

![image-20220419153623495.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-424baea49dd239f4e3a05f65b961ec1e44547dcf.png)

所以源程序的特性

1. 把要回来的地址暂存入内存，再jmp到指定地址，同时jmp后还有段花指令
2. 当要跳回时，重新把地址放到rdi，再jmp跳回去

所以我们可以改成

1. 把jmp上面的所有操作去掉，直接改成call(push + jmp)
2. call后面的花全部去掉
3. 再把jmp rdi改成retn(pop + jmp)，这时候直接用的是栈顶的地址其实就是回去的地址

以此为想法写个idapython

```python
start = 0x807FEC0
end = 0x8080AD1

address = [0 for i in range(5)]
callTarget = ["lea", "lea", "mov", "jmp"]
retnTarget = ["lea", "mov", "and", "lea", "jmp"]

def nop(s, e):
    while (s < e):
        patch_byte(s, 0x90)
        s += 1

def turnCall(s, e):
    # nop掉call之前的值
    nop(s, e)
    patch_byte(e, 0xE8)
    # 把后面的花指令去掉
    huaStart = next_head(e)
    huaEnd = next_head(huaStart)
    nop(huaStart, huaEnd)

def turnRetn(s, e):
    nop(s, e)
    # 注意原来是jmp xxx
    # 所以前面nop掉一个 后面改成retn
    patch_byte(e, 0x90)
    patch_byte(e + 1, 0xC3)

p = start
while p < end:
    address[0] = p
    address[1] = next_head(p)
    address[2] = next_head(address[1])
    address[3] = next_head(address[2])
    address[4] = next_head(address[3])

    for i in range(0, 4):
        if print_insn_mnem(address[i]) != callTarget[i]:
            break
    else:
        turnCall(address[0], address[3])
        p = next_head(next_head(address[3]))
        continue

    for i in range(0, 5):
        if print_insn_mnem(address[i]) != retnTarget[i]:
            break
    else:
        turnRetn(address[0], address[4])
        p = next_head(next_head(address[4]))
        continue

    p = next_head(p)
```

shift + F2打开idapython窗口，选择python，run一下

![image-20220419154550063.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8501468acf1b22be99cb58ea5b2510879fc73653.png)

patch完保存一下，让ida重新解析

![image-20220419154355090.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2a4ee287fd16a795cfb6c470741cfac4017a7a2f.png)

保存好再次打开这个文件，进入本函数，F5加密函数！

![image-20220419154720870.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d27161cbc862b97f7ce6b4cd3507d9546fc275f7.png)

0x02 分析加密函数
===========

可以通过创建结构体让程序很好理解，在我们不确定这些子项的具体函数，可以先用ida默认的

![image-20220419155017422.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fe365bd468d093a5cdae17a49ebcb1cd8b7b231b.png)

简单审计一下即可知道大概意思

![image-20220419155448997.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-507306cb776300c1678dadb426d9e2b54ece6e3c.png)

异或加密
----

我们的输入分别小端序放入，经过一个可以逆的异或计算

```C++
__int64 __fastcall XOR(__int64 input)
{
  __int64 v1; // rbx
  __int64 v2; // r13
  __int64 v3; // r15
  _QWORD *v4; // r15
  struct_v5 *v5; // r15
  int v6; // ebx
  int v7; // ebx

  v4 = (v3 - 8);
  *v4 = v1;
  v5 = (v2 + (v4 - 56));
  v5->input = input;
  v5->xorKey = sub_8080360();
  v5->input1 = *(v2 + v5->input);
  v5->highFour = Big(HIDWORD(v5->input1));      // 高四位小端序放入
  v5->lowFour = Big(v5->input1);                // 低四位小端序放入
  for ( v5->count = 0; v5->count <= 43; ++v5->count )
  {
    v5->orgLowFour = v5->lowFour;
    v6 = ROL(v5->lowFour, 1);
    v7 = ROL(v5->lowFour, 8) & v6;
    v5->lowFour = v5->highFour ^ v7 ^ ROL(v5->lowFour, 2) ^ *(v2 + 4 * v5->count + v5->xorKey);
    v5->highFour = v5->orgLowFour;
  }
  v5->input1 = 0LL;
  v5->input1 = ((v5->input1 | v5->lowFour) << 32) | v5->highFour;// 低高互换
  return v5->input1;
}
```

key可以通过动调直接获取，再注意一下结尾的高低32位互换即可

![image-20220419160146104.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e9a0c34dcc457df7bab765efe568c8f601f8ffda.png)

魔改XTEA
------

注意所改变的地方是

1. 轮数变了
2. delta数变了

```C++
__int64 __fastcall XTEA(int count, __int64 a2)
{
  __int64 v2; // r13
  myst *v3; // r15
  __int64 result; // rax

  v3[-1].t1 = count;                            // 轮数为传入的轮数，分别是2 4 8 16
  *&v3[-2].v0 = a2;
  *&v3[-1].key = key;                           // key可以直接拿
  v3[-1].v0 = *(v2 + *&v3[-2].v0);
  v3[-1].v1 = *(v2 + *&v3[-2].v0 + 4);
  v3[-1].sum = 0;
  v3[-1].delta = 0x10325476;                    // delta数变了
  for ( v3[-1].t9 = 0; v3[-1].t9 < v3[-1].t1; ++v3[-1].t9 )
  {
    v3[-1].v0 += (((v3[-1].v1 >> 5) ^ (16 * v3[-1].v1)) + v3[-1].v1) ^ (*(v2 + 4 * (v3[-1].sum & 3) + *&v3[-1].key)
                                                                      + v3[-1].sum);
    v3[-1].sum += v3[-1].delta;
    v3[-1].v1 += (((v3[-1].v0 >> 5) ^ (16 * v3[-1].v0)) + v3[-1].v0) ^ (*(v2
                                                                        + 4 * ((v3[-1].sum >> 11) & 3)
                                                                        + *&v3[-1].key)
                                                                      + v3[-1].sum);
  }
  *(v2 + *&v3[-2].v0) = v3[-1].v0;
  result = v3[-1].v1;
  *(v2 + *&v3[-2].v0 + 4) = result;
  return result;
}
```

0x03 GetFlag
============

直接从Check函数第一个参数拿到密文

![image-20220419161345315.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-00188b5448c07d23024bdd9f9319f6e75526cf0b.png)

EXP

```C
  #include <stdio.h>
  #include <stdint.h>

  #define SHL(x, n) ( ((x) & 0xFFFFFFFF) << n )
  #define ROTL(x, n) ( SHL((x), n) | ((x) >> (32 - n)) )

  unsigned int xorKey[44] = {
      0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0xCD3FE81B, 0xD7C45477, 0x9F3E9236, 0x0107F187, 
      0xF993CB81, 0xBF74166C, 0xDA198427, 0x1A05ABFF, 0x9307E5E4, 0xCB8B0E45, 0x306DF7F5, 0xAD300197, 
      0xAA86B056, 0x449263BA, 0x3FA4401B, 0x1E41F917, 0xC6CB1E7D, 0x18EB0D7A, 0xD4EC4800, 0xB486F92B, 
      0x8737F9F3, 0x765E3D25, 0xDB3D3537, 0xEE44552B, 0x11D0C94C, 0x9B605BCB, 0x903B98B3, 0x24C2EEA3, 
      0x896E10A2, 0x2247F0C0, 0xB84E5CAA, 0x8D2C04F0, 0x3BC7842C, 0x1A50D606, 0x49A1917C, 0x7E1CB50C, 
      0xFC27B826, 0x5FDDDFBC, 0xDE0FC404, 0xB2B30907
  };

  void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
      unsigned int i;
      uint32_t v0=v[0], v1=v[1], delta = 0x10325476, sum=delta*num_rounds;
      for (i=0; i < num_rounds; i++) {
          v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
          sum -= delta;
          v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[(sum & 3)]);
      }
      v[0]=v0; v[1]=v1;
  }

  void XorRol(uint32_t v[2])
  {
    uint32_t encLow = v[1];
    uint32_t encHigh = v[0];
    uint32_t orgLow, orgHigh, v6, v7, v8;
    int i;  

    for ( i = 43; i >= 0; i-- )
    {
        orgLow = encHigh;
        v6 = ROTL(orgLow, 1);
        v7 = ROTL(orgLow, 8) & v6;
        v8 = v7 ^ ROTL(orgLow, 2);
        orgHigh = encLow ^ xorKey[i] ^ v8;

        encHigh = orgHigh;
        encLow = orgLow;
    }
    v[0] = orgLow; v[1] = orgHigh;
  } 

  int main()
  {
      uint32_t v[] = { 0xFDF5C266, 0x7A328286, 0xCE944004, 0x5DE08ADC, 0xA6E4BD0A, 0x16CAADDC, 0x13CD6F0C, 0x1A75D936 };
      uint32_t k[4] = { 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C };
      int i, j;
      uint32_t teaData[8];

  //    uint32_t testData[] = { 0xD4C2E7AE, 0xD2E28713 };
  //    XorRol(testData);
  //    printf("0x%X, 0x%X, ", testData[0], testData[1]);

    for ( i = 0; i <= 3; i++ )
    {
        decipher(1 << (i + 1), v + i * 2, k);
        printf("0x%X, 0x%X, ", v[i * 2], v[i * 2 + 1]);
        teaData[i * 2] = v[i * 2];
        teaData[i * 2 + 1] = v[i * 2 + 1];
    }

    puts("\n");

    for ( i = 0; i <= 3; i++ )
    {
        XorRol(teaData + i * 2);
  //        printf("0x%X, 0x%X, ", teaData[i * 2], teaData[i * 2 + 1]);
    }

    puts("\n");

    unsigned char * t = (unsigned char *)&teaData;
    for ( i = 0; i < 32; i += 4 )
        printf("%c%c%c%c", t[i + 3], t[i + 2], t[i + 1], t[i]);

      return 0;
  }

```

GetFlag!

![image-20220419161304529.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0e6f435904ed6750514dade4216cd292895be1f0.png)