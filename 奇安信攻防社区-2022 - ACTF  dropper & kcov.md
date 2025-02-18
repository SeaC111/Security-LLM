0x00 前言
=======

整体来说，这次逆向题目工作量比较大，并且解题过程中要对常见算法有一定的了解，并对数据比较敏感。

0x01 dropper
============

拿到程序首先进行查壳，64位程序加了upx壳，借助脱壳机脱掉即可。

IDA加载，通过start函数找到主函数`sub_140019470`。

![image-20220625170805163](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-234b851aa6831cd7bdc65ce43c43dd88f5ecdb6c.png)

有很多`qword_xxx`的函数调用，交叉引用发现是用了SMC技术，处理函数为`sub_1400113d4`,解密过程为简单取反。

![image-20220625171019909](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-cda785042936b2239f51d447705717d802d3045c.png)

经过手动(或idapy)smc解密后得到调用的库函数，简单修复(rename)如下

![image-20220625173254653](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-13d00c91501d67b606223983555dab0915a0299b.png)

加载资源，之后`sub_1400113d9`解密资源,发现解密数据头部有MZ，保存为可执行。

```c
f=open(r'dump','rb+').read()
s=[]
for i in range(len(f)):
   s.append(f[i]^0x73)
dst=open(r'new','wb+').write(bytes(s))
```

继续分析new文件，c++的64位程序，去符号了，定位到主函数`sub_7FF7B9BDD080`，结合调试得知首先对输入进行了标准base64编码。

之后在`sub_7FF7B9BD1244`进行128进制转10000进制,可由内部调用的函数看出，最好结合自己的测试输入进行调试。

```python
c=list(b'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=')[::-1]
#test imput: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sum=0
for i in range(len(c)):
    sum=sum*0x80+c[i]
d=[]
while sum:
    d.append(sum%10000)
    sum//=10000
print(d)
```

之后又将内存中的长为360B的数据转为一个10进制大整数，并且通过`sub_7FF7B9BD110E`函数转为10000进制，便于之后运算。

![image-20220627225642164](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4ba1b7ab95c70a79fe7c263b30797555d64f34d9.png)

转换代码如下

```c
{
  int v3; // [rsp+24h] [rbp+4h]
  int v4; // [rsp+44h] [rbp+24h]
  int v5; // [rsp+64h] [rbp+44h]
  int v6; // [rsp+84h] [rbp+64h]
  int i; // [rsp+A4h] [rbp+84h]
  int j; // [rsp+C4h] [rbp+A4h]

  sub_7FF7B9BD17EE((__int64)&byte_7FF7B9BF60F2);
  j_memset(a1, 0, 0x7D0ui64);
  v6 = j_strlen(a2);
  a1[500] = v6 / 4;                             // 4个一组
  if ( v6 % 4 )
    ++a1[500];
  v5 = 0;
  for ( i = v6 - 1; i >= 0; i -= 4 )
  {
    v3 = 0;
    v4 = i - 3;
    if ( i - 3 < 0 )
      v4 = 0;
    for ( j = v4; j <= i; ++j )
      v3 = 10 * v3 + a2[j] - 48;
    a1[v5++] = v3;                              // 将字符串4个一组 转为对应的10进制
  }
  return a1;
}
```

并且调试知在v33首部有check flag的函数入口。

![image-20220627230312820](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e1e0210c4b84baa03f85e305022bafc771e7bbe7.png)

但是直接逆求的话发现结果并不对，F9运行发现在`sub_7FF7B9BD1226`触发了除0异常。

![image-20220627230505860](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-41d694068b9f4b21b618c9eb3942a9812627db5e.png)

之后深入该函数，发现其中第二个函数是将一个常量数组在0-26下标升序快排，得到的第一个元素为0。

![image-20220627232337121](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f023d0abebbe3612f5768461c1f004abdf513f3e.png)

之后在`sub_7FF6E1B88A80`运算会引发除0异常，可以通过import来定位异常处理，不过细心的话看流程图也能看出端倪。

![image-20220627233642163](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-58f1422d50cd1229dd0d299960c6297f2cd3783a.png)

右上的代码块原本是不会被执行到的，但是异常处理后的ip却可能跳转过去，这种重定位也能起到隐藏代码的作用。可以看出该快代码调用了一个函数，内容如下。

![image-20220627233953113](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b7c95b2f8ed46de37949010fe0eb84befc46b811.png)

经过调试发现修改了我们check flag的函数指针，也就是跳到了真正的flag check逻辑，在该块首地址处下个断点，异常后继续执行即可。

![image-20220628000558498](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ebbc9b4da18754cacb2572b31c58550dcecc87dd.png)

最后一步加密运算就是将enc\_data在10000进制下和10个10进制长度为80的大数做加、减、乘运算，在调试过程中能拿到10进制数据，直接以10进制数据运算即可。

```python
import base64
def tentoascii(x):
   s=[]
   while x:
      s.append(x%0x80)
      x//=0x80
   return s
def ten2wan(a):
   res=[]
   while a:
      res.append(a%10000)
      a//=10000
   return  res

def wan2ten(x):
   sum=0
   x=x[::-1]
   for i in range(len(x)):
      sum=sum*10000+x[i]
   return  sum
b1=64584540291872516627894939590684951703479643371381420434698676192916126802789388
b2=11783410410469738048283152171898507679537812634841032055361622989575562121323526
b3=55440851777679184418972581091796582321001517732868509947716453414109025036506793
b4=17867047589171477574847737912328753108849304549280205992204587760361310317983607
b5=7537302706582391238853817483600228733479333152488218477840149847189049516952787
b6=80793226935699295824618519685638809874579343342564712419235587177713165502121664
b7=14385283226689171523445844388769467232023411467394422980403729848631619308579599
b8=55079029772840138145785005601340325789675668817561045403173659223377346727295749
b9=71119332457202863671922045224905384620742912949065190274173724688764272313900465
b10=57705573952449699620072104055030025886984180500734382250587152417040141679598894
enc=[0x000020F1, 0x00001DA9, 0x00000156, 0x00000B37, 0x000007C0, 0x0000066A, 0x000024E0, 0x00000D42, 0x00002077, 0x000007EC, 0x00001BA7, 0x00002071, 0x000000F8, 0x00000291, 0x000003DA, 0x0000157C, 0x00001EF4, 0x00002519, 0x00000C25, 0x00002062, 0x00002253, 0x00000640, 0x000008DF, 0x00001E34, 0x00002140, 0x00000F92, 0x0000039B, 0x0000126F, 0x00002403, 0x00000E65, 0x000001F0, 0x00001868, 0x0000016D, 0x000006B6, 0x00002214, 0x00001603, 0x00001925, 0x000016AE, 0x000012D0, 0x00001831, 0x0000018C, 0x00000BF7, 0x00000E97, 0x000000CE, 0x0000061C, 0x00000390, 0x000019E9, 0x000022A5, 0x00001601, 0x00001A1E, 0x000013D1, 0x00000DBC, 0x0000117D, 0x0000225F, 0x00002272, 0x0000007B, 0x000023E6, 0x0000069F, 0x000002D3, 0x00001BEF, 0x000003E6, 0x000017D4, 0x00002284, 0x000003B8, 0x00000251, 0x00001646, 0x00000176, 0x0000081E, 0x000024C3, 0x00001E85, 0x00001097, 0x00001264, 0x00000A34, 0x00001A3B, 0x00000FE7, 0x000026A6, 0x00001F43, 0x00001832, 0x000021AE, 0x0000023C, 0x000004C2, 0x00002585, 0x000017E7, 0x000015DD, 0x00002610, 0x00001B86, 0x00000D2A, 0x00000716, 0x00001C25, 0x00002099]
enc=wan2ten(enc)
c1=enc
c1+=b10
c1-=b9
c1+=b8
c1-=b7
c1+=b6
c1//=b5
c1-=b4
c1+=b3
c1//=b2
c1-=b1
print(base64.b64decode(bytes(tentoascii(c1))))
```

0x02 KCOV
=========

直接给了一个linux的镜像，通过解压roots可以直接拿到目标程序kcov。

主要逻辑在`sub_4017D2`函数中

![image-20220628001133830](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-658ead5bd09fd3ded9662ecfdee08429f1cf3f1d.png)

对生成后的a1进行了check，如果a1 check成功则会解密一段数据。

```python
s=[0x8C, 0x6C, 0xA0, 0xA5, 0xF2, 0x1B, 0xA9, 0xE4, 0xEA, 0x4E, 0xAB, 0xAF, 0xFF, 0x1B, 0xA0, 0xA5, 0xE5, 0x50, 0xAD, 0xB6, 0xA7, 0x1B, 0x80, 0xA1, 0xF4, 0x5E, 0xE8, 0xAD, 0xF5, 0x1B, 0xB1, 0xAB, 0xF3, 0x49, 0xE8, 0xA2, 0xEA, 0x5A, 0xAF]
x=0x0C4C83B86
m=[]
for i in range(len(s)):
   t=(x>>(8*(i&3)))&0xff
   m.append(t^s[i])
print(bytes(m))
#\nWhat a lucky hacker! Here is your flag
```

之后便是通过a1解密加密的flag，所以关键就在还原a1，a1大小16字节，为之后AES 解密的key。

sub\_4015F8函数

![image-20220628001355978](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b4e4c1eb9103b758fa33ab36692b2b58864e6713.png)

将a1逐列赋值到v3中，通过与一个常量矩阵进行运算得到一个单位矩阵。

```c
for ( i = 0LL; ; ++i )
  {
    result = d_4;
    if ( i >= d_4 )
      break;
    for ( j = 0LL; j < d_4; ++j )
    {
      v8 = 0;
      for ( k = 0LL; k < d_4; ++k )
      {
        v4 = GMUL(tmp_data[k + i * d_4], mkey[j + k * d_4]);
        v8 = call_fun1(v8, v4);
      }
      ans[j + i * d_4] = v8;
    }
  }

__int64 __fastcall GMUL(char a1, unsigned __int8 a2)
{
  unsigned __int8 v3; // [rsp+Dh] [rbp-Bh]
  unsigned __int64 i; // [rsp+10h] [rbp-8h]

  v3 = 0;
  for ( i = 0LL; i < 6; ++i )
  {
    if ( (a2 & 1) != 0 )
      v3 ^= a1;
    a2 >>= 1;
    a1 *= 2;
    if ( (a1 & 0x40) != 0 )
      a1 ^= 0x5Bu;
  }
  return fun1(v3);
}
```

分析发现这个矩阵运算的过程有点类似AES 列混淆，不过后者是在GF(128)上进行的运算，而本题为GF(64)，这也就提示我们key矩阵的值不会超过64。

```c
__int64 __fastcall binlen(unsigned __int64 a1) //二进制位数
{
  __int64 v3; // [rsp+10h] [rbp-8h]

  v3 = 0LL;
  while ( a1 )
  {
    ++v3;
    a1 >>= 1;
  }
  return v3;
}

unsigned __int64 __fastcall fun1(unsigned __int8 a1) 
{
  unsigned __int64 v2; // [rsp+10h] [rbp-18h]
  unsigned __int64 v3; // [rsp+18h] [rbp-10h]
  unsigned __int64 v4; // [rsp+20h] [rbp-8h]

  v2 = binlen(a1);
  v4 = binlen(91uLL);
  v3 = a1;
  while ( v2 >= v4 )
  {
    v3 ^= 91 << (v2 - v4); //模2除法求余数
    v2 = binlen(v3);
  }
  return v3;
}
```

有了余数的存在求逆毫无思绪，好在是求逆矩阵我们可以一行一行的求，一次爆破4个，也就2^24跑4次，脚本如下。

```python
def binlen(x):
   ans=0
   while x:
      ans+=1
      x//=2
   return ans
def fun1(a1):
   v2 = binlen(a1)
   v4 = binlen(91)
   v3 = a1
   while v2>=v4:
      v3^=91<<(v2-v4)
      v2=binlen(v3)
   return v3

def GFMul(a, b):
    p, hi_bit_set = 0, 0
    for counter in range(6):
        if b & 1 != 0:
            p ^= a
        hi_bit_set = a & 0x40
        a = a << 1
        if hi_bit_set != 0:
            a ^= 0x5b  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return fun1(p)

def out(x):
    for i in range(len(x)):
        print(hex(x[i])[2:].zfill(2),end=' ')
    print()

def func(tb,key):
    m = []
    for i in range(3,4): #4
        for j in range(4):
            v7=0
            for k in range(4):
                v4=GFMul(key[k+4*i],tb[j+4*k]) #这里求逆
                #print(k+4*i,j+4*k)
                v7=fun1(v7^v4)
            #print()
            m.append(v7)
    #out(m)
    return m
tb = [44, 4, 23, 13, 2, 45, 57, 51, 7, 22, 52, 24, 29, 26, 11, 40]
key = [0, 5, 5, 14, 61, 13, 62, 24, 8, 40, 59, 15, 1, 60, 3, 51]

for a in range(64):
    for b in range(64):
        for c in range(64):
            for d in range(64):
                key[12],key[13],key[14],key[15]=a,b,c,d
                                """依次替换
                                0 1 2 3
                                4 5 6 7
                                8 9 A B
                                C D E F
                                """
                m=func(tb,key)
                if m[0]==0 and m[1]==0 and m[2]==0 and m[3]==1:
                                """
                                1 0 0 0
                                0 1 0 0 
                                0 0 1 0
                                0 0 0 1
                                """
                    print([a,b,c,d])
                    out(m)
"""
[0, 5, 5, 14]
01 00 00 00
[21, 8, 9, 1]
00 01 00 00 
[10, 6, 12, 3]
00 00 01 00 
[6, 7, 12, 4]
00 00 00 01 
"""
# 拿到key这个key 
"""
for ( i = 0LL; i <= 0xF; ++i )
    a2[4 * (i & 3) + (i >> 2)] = a1[i];  //将a1的内容以矩阵存入a2,
"""
#正确顺序
k=[0,21,10,6,5,8,6,7,5,9,12,12,14,1,3,4]
```

拿到key后愉快的patch即可，运行kcov修改ip跳转到解密函数，patch掉key，运行即可拿到flag。

```python
import idautils 
#k=[0,5,5,14,21,8,9,1,10,6,12,3,6,7,12,4]
k=[0,21,10,6,5,8,6,7,5,9,12,12,14,1,3,4]
adr=0x00007FFF05DD6690 
for i in range(16):
    patch_byte(adr,k[i])
    adr+=8
print('ok')
#ACTF{YOU_dOn_No7_R3ALly_neED_t0_Co1LeC7_KC0v_$INcE_1T_i5_UN$7@ble}
```

措不及防的爆破，悄无声息的异常处理，眼花缭乱的模板 ... 如此高质量的赛题，某人怎么睡的着的，逆向的路还远，你还在坚持吗?