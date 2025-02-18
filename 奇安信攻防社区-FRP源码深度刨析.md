一、什么是 frp？
----------

下载地址：<https://github.com/fatedier/frp>

frp 是一个快速反向代理，可让您将位于 NAT 或防火墙后面的本地服务器暴露到互联网。它目前支持**TCP**和**UDP**，以及**HTTP**和**HTTPS**协议，允许通过域名将请求转发到内部服务。

二、描述
----

随着功能逐渐增多，FRP也愈发臃肿，越来越不适用红队项目了，现在客户端已经达到了`14M`，这是奔着产品去了。

红队项目需要短小精悍，体积小，只保留最核心的功能，其他能减则减。

所以学习一下FRP的优点，有机会开发出适合自己使用的工具。

三、源码分析
------

先来熟悉一下源码

![image-20240825200021480.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-9327008d24957adb5c97fdded6a7cd5c2b28267f.png)

### 3.1 整体流程

#### 3.1.1 服务端

先来看一下服务端，先从`cmd`目录开始，处理命令行，初始化配置文件

![image-20240825204647187.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-de6ed2942fe758723cd7fe97b343cc4c99884fa7.png)

把配置文件传递给服务，并启动运行。

![image-20240825204745242.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a6227c26a69fba3dfef46c8cf6b27f2e87cd5a29.png)

**`server.NewService`**主要是把配置初始化给服务端的各个组件，并返回一个新的服务对象。那么新建服务的时候，都做了什么？

1. 提取`TLS`的配置
2. 如果配置了web服务端口，传入配置，并新建一个http服务。
3. 初始化`Server`对象
4. 如果配置了`TCPMuxHTTPConnectPort`端口，新建`tcpmux.NewHTTPConnectTCPMuxer`服务
5. 遍历并初始化所有`HTTPPlugins`，使用`svr.pluginManager.Register()`初始化
6. 初始化`TCP`组控制器
7. 初始化`HTTP`组控制器
8. 初始化`TCPMux`组控制器
9. 启动`TCP`监听
10. 启动`KCP`监听
11. 如果`QUICBindPort`设置，启动`quic`监听
12. 如果`SSHTunnelGateway`设置，启动`SSHTunnelGateway`监听
13. 启动`websocket`监听
14. 如果`VhostHTTPPort`设置，启动`http`反向代理
15. 如果`VhostHTTPSPort`设置，启动`https`反向代理
16. 启动`tls`监听
17. 初始化`nat hole`服务

之后调用自身的`Run`方法启动运行。

根据参数多线程启动`web GUI`

之后启动一系列监听

![image-20240826170417271.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-cbcacd7b63d64664d1be8d0b0d7fbf4b19a17a12.png)

#### 3.1.2 客户端

同样的先处理配置，遵循命令行配置文件优先，没有的就使用默认。

![image-20240826170821460.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5d7c4d5f15c311bb6706ade6b3f20e1b9778e49f.png)

之后开始启动客户端服务。

先调用`client.NewService`初始化客户端服务

![image-20240826171544956.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-225f96cc4a4827a803c077939b5c17c04350c6dd.png)

调用`svr.Run`启动服务

1. 先设置DNS服务
2. 根据`WebServer`确定是否开启web端
3. 登录客户端，就是根据配置在服务端新建一个连接。
4. 多线程启动保持控制连接`keepControllerWorking()`，保持代理一直处于工作状态

`keepControllerWorking`

`wait.BackoffUntil`：函数用于使用指数退避策略重复执行一个函数,直到满足某个条件或超时。它接受四个参数：

> 第一个参数：是一个匿名函数，也是重复执行的函数。
> 
> 第二个参数：创建一个新的退避管理器实例,并指定相关选项。
> 
> 第三个参数：一个布尔值,指示是否应立即执行退避,或在第一次失败后执行。
> 
> 第四个参数：一个通道,当与服务器(`svr`)关联的上下文被取消时关闭,表示应该中止操作。

![image-20240828201634711.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e3d96a82f4e61765155382f445c4afc842773f4b.png)

### 3.2 代理线程生命周期

#### 3.2.1 根据协议建立连接

先根据配置初始化连接器，接着打开与服务器的底层连接，之后再生成数据流进行数据传输。

![image-20240827194121280.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-053e98a91ffc52bdf18edd3880cc81fe9caff683.png)

##### 3.2.1.1 连接器打开与底层的连接\[open()\]

> 底层连接要么是TCP连接，要么是QUIC连接。  
> 底层连接建立后，可以调用Connect()获取流。  
> 如果未启用 TCPMux，则底层连接为零，每次调用 Connect() 时都会获得一个新的真实 TCP 连接。
> 
> 如果使用`Mux（多路复用）`，返回一个`session`进行后续的数据交互

**QUIC协议：**QUIC 是一种建立在 UDP 之上的新型多路复用传输。

![image-20240827201151200.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6f724b050fbc4a4d89be04114bd4ca5fd2fdfb94.png)

建立连接的时候，主要需要

- 是否启用`TLS`
- 使用`websocket`、`WSS`或者默认协议
- 配置选项：协议、超时时间、心跳时间、代理类型、服务端地址、认证信息

![image-20240827202050220.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-74963a943b340805ab43d14f61397249db8dcc94.png)

**WebSocket**

> **设定协议：**WebSocket 是基于 TCP 的，所以协议被设置为 "tcp"。  
> **添加 WebSocket 钩子：**处理连接时将其升级为 WebSocket 连接。  
> **添加自定义 TLS 钩子：**根据配置进行 TLS 头部字节的处理（通常用于协议验证或调试）。  
> **配置 TLS：**将 TLS 配置应用到连接中。

**WebSocket Secure (`WSS`)** 。`wss` 是 WebSocket 协议的加密版本，使用 TLS（类似于 HTTPS）。

> **设定协议**: 使用 TCP 作为基础协议。
> 
> **添加 TLS 配置钩子**: 优先处理 TLS 配置，确保连接加密。
> 
> **添加 WebSocket 钩子**: 在 TLS 连接成功建立后，再处理 WebSocket 连接的升级。

![image-20240828110021676.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8780bd0204862eeb1efce3f0390a7e064aef500e.png)

![image-20240827202128918.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-63dc3112765bc4f885083f54c632af9c5b6efee8.png)

建立连接这里也称为`拨号（dial）`，如果设置了指定的拨号器（这里的自定义拨号器都是应用层协议），就使用对应的协议类型

![image-20240827203016849.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-82789d4354a3d0a76898d627d5112a90b083e8e7.png)

如果没指定拨号器，默认使用`TCP`或`kcp`

> KCP是一种快速而可靠的协议，可以达到平均延迟降低30%~40%，最大延迟降低3倍的传输效果，但代价是比TCP多浪费10%~20%的带宽。
> 
> KCP 模式使用 UDP 作为底层传输。

![image-20240828101904746.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0cee7460107def06c51f8c7588f880344bc50722.png)

如果前边的流程都没有问题，最终`open()`把新生成的如下这样一个`Session对象`赋值给连接上下文对象的`muxSession`

![image-20240828114536708.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7be6079171b63f9b25bff5baba965bbdc6882f46.png)

##### 3.2.1.2 生成交互流连接\[Connect()\]

Connect 从底层连接返回一个流，如果未启用 TCPMux，则返回一个新的 TCP 连接。

![image-20240828150232429.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7418a7b22f198ff310f5796179fc714f0913fd61.png)

#### 3.2.2 客户端代理认证登录

为了安全性，客户端和服务端正常工作是需要认证的，先初始化登录数据结构

![image-20240828152653447.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f8e15a7bda2f076202bbc2cb850faa53eb077db2.png)

用前边生成的网络流进行客户端认证，成功后跟新客户端代理ID

![image-20240828153559485.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e5d714a31213dd7e149e691316dc4a6a28bc4339.png)

#### 3.2.3 代理控制器

登录成功之后，初始化客户端控制器

![image-20240828155818420.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a5b84f6cd72284bfaa4548233915cdbf1ecdca94.png)

##### 3.2.3.1 生成新的控制器\[NewControl()\]

根据客户端上下文和`Session`上下文初始化控制器

![image-20240828164050758.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f70276421de3b3a00868e15b11b2d70a8b1b038b.png)

如果启用了加密，返回新的加密网络流调度器，未启用加密正常返回流调度器

![image-20240828164843339.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-21f304bd0cfd589e1c56360c1ae258965a39ee81.png)

加密算法如下，采用AES加密，key来自配置中的`Token`

![image-20240828165503088.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4c8f51d8119f7504740c8aeb414f808b15b86e54.png)

接着注册消息处理程序，不同类型的消息由不同的处理器处理

![image-20240828174320310.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-bc68862c0ad73a8dc8b2f052b7b32cdd7caa0777.png)

传入发送调度器，生成消息发送器

生成新的代理管理器，指向控制器的pm

生成新的访客管理器，指向控制器的vm

![image-20240828175115533.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-63d99ff1d5fa136cc96130e8abcdf05a056f252d.png)

##### 3.2.3.2 运行控制器\[Run()\]

**开始工作**

![image-20240828194517459.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-02eb9e92111bb400a641a67b50d3b64c56839437.png)

运行调度器，主要就是多线程启动发送池、接收池

![image-20240828194902574.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-479d43a2487e6f16497a1264a3a2f3bb18c2c691.png)

**更新配置**

![image-20240828182649169.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0a393425916ccec3d73079b7ecff03a2fd176ddf.png)

更新函数主要有两大块，一块是根据名字删除代理。另一块是添加新的代理，并运行检查。

del

![image-20240828190318535.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-3b8cea4c213368367d7e762be7982a3f263035a9.png)

Add

![image-20240828190520970.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b6238c14119f247989809f7ade9af3024e307855.png)

启动主要是启动工作检查和代理连通性检查

![image-20240828193023664.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-187d495df5dc119721bd711318d7dd84ea68742f.png)

到这里就全部运行了。后续就是监控出问题后，结束控制器。

### 3.3 数据交互过程

#### 3.3.1 请求工作连接

在通道控制器建立后，如果有数据，会通过调度器分配给对应的处理函数。直接定位`handleReqWorkConn()`方法。

先获取一个网络流，接着初始化一个工作连接结构体，这个结构体主要是商量每个连接的认证信息。通过网络流把该结构体对象发送到服务端，并且接收成功认证连接后，服务端返回的开始信息。然后把代理名、网络流、开始信息当作参数，初始化工作连接句柄

![image-20240829103728503.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1c7743cb057cc7b41bc5d2c12d1c401f30b097cf.png)

#### 3.3.2 代理分配

在代理管理器中，根据名字获取对应的代理包装器

![image-20240829104532636.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4424024ce4259cd8672570b269cb284598b08f28.png)

在代理包装器中，分配给对应类型的代理

![image-20240829104822792.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0b28e4e72c0587eeb7b49cb63ce92eba2fdac3ab.png)

默认使用TCP协议处理

![image-20240829105033546.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-d8d93fcf230c10ef839cffffda1732a19395e710.png)

还有其他几种如下：

![image-20240829105308402.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-970876cde3204fdda7ebf0a28b4e6db7c820bcb5.png)

#### 3.3.3 TCP工作连接处理器

接着来看`TCP工作连接`的通用处理程序。

> 设置限制器
> 
> 设置加密器
> 
> 设置压缩器

![image-20240829110317141.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f95f2653c2035f95cc56cecd60f193a290c15ea5.png)

> 构造插件信息

![image-20240829124112918.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4b7c29b5f33fe3fd7631fcacbe9eeee199a33477.png)

接着把插件信息传递给代理插件处理器

![image-20240829140427530.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-fe47e68025f05aab500d7d95fe2714e3e5595d61.png)

下边开始把处理两个网络流。生成本地网络流，远程网络流

![image-20240829140809471.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-3a2e4b8a4c9eb2afd0bb5aa66eaf06d7a57a0a1c.png)

#### 3.3.4 TCP协议数据交换

先创建一个匿名函数，接收四个参数：

- number 排序、标识
- to 待写入数据
- from 待读取数据
- count 写入/读取大小

把数据从`from`复制到`to`。

然后创建两个多线程，调用该函数，to、from互换位置。这样随时在任意一端发送数据，同时不用等待即可发送。

![image-20240829141636011.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-34589a65b156479eaaeeb92fd52c056a7c63b5e7.png)

到这里，数据交互的过程分析完了。但是好像又没分析完，感觉少点什么？通道也有了，数据交换也有了，少点什么那？插件好像没分析，插件是在那个步骤中起到作用了？想起来了吧，少了把数据写入通道的步骤。刚好这个步骤在插件中进行。

#### 3.3.5 插件写入、读取数据-socks5

插件是从`handle`调用开始的，里边有这么多。挑一个最常用的`socks5`进行后续分析。

![image-20240829162916435.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-211e712b244c4eac0036c06903d12389ca3aec38.png)

先把`io读写器`和网络流包装到一块，调用`ServeConn()`函数进一步处理。

![image-20240829163347110.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-82ccfade3edd8865777a51680068fb5b2c801e1f.png)

在`ServeConn()`函数中，先获取版本，对比是不是`Socks5`

![image-20240829164554734.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-704f818d6e1d19f344c84fcb63cd070bbccd1f14.png)

接着创建一个新的请求对象，值从`bufConn`读取器中获取。数据结构如下：

```go
request := &Request{
    Version:  socks5Version,
    Command:  header[1],
    DestAddr: dest,
    bufConn:  bufConn,
}
```

把新创建的`requests`对象和`conn`交给请求处理器处理

![image-20240829165138173.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-9fbccddfe08f8e3fe6cffc677001c92d76078ae9.png)

请求处理器`handleRequest()`，先获取需要的目的地址格式

![image-20240902154007355.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-60efeb0ce57144744a84e5946fad123e16ee34ef.png)

大家应该都知道，`socks5`代理建立后，可以任意访问内网的主机。访问不同的主机就需要更换不同的目的地址。

![image-20240902154822374.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1dab498701a4cd6ead60546270a3db99b6a6abba.png)

有三个命令，实际作者公开源代码的版本只实现了建立连接命令，另外两个功能函数为空。这里建立连接命令就很好理解了，把代理使用者的请求数据发向目的地址。

![image-20240902155205879.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-512a3e791f30e1ee1e720d323a4dd2f1462182ca.png)

在`handleConnect()`函数中，会先用`tcp协议`（socks5基于TCP）和目的地址建立连接。

![image-20240902160138766.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f3bb88280cbf2139b80d1e5d23addc3ccc427fb7.png)

启动两个线程，先把发过来的请求发送给目标机，再把目标机的响应发送给vps，这样就达到了高效数据交换的目的。

![image-20240902160859623.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a8c41a80c7236570f2a44dcd56870fbd2d747017.png)

后边就是线程报错的相关处理了。至此SOCKS5代理分析完毕。

四、进行瘦身
------

瘦身也就是减小编译后的程序的体积，先来分析一下影响体积的因素有哪些？

- 代码量
- 编译方法、编译程序
- 其他

### 4.1 减少代码量

主要从一下几方面减少代码量：1、 去掉无用代码 2、去掉非必要功能

#### 4.1.1 去掉无用代码

比如注释符、和一些说明，在我们红队使用过程中，都属于无用代码。![image-20240903104724244.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ce4b80aba56dcbfeee53e28bb400e0a0fb263a7b.png)

这些是客户端使用到的代码

![image-20240903105121387.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-89636450d5f764ca4cafdd7bd26af622ad601e77.png)

手动一个一个删很显然浪费时间，写了个脚本批量删除

![image-20240903110342606.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-acae7a6bf70d1e7c4dab3330fa606725f2e0a485.png)

再次编译后，和源文件对比，确实小了，但小的不多。

![image-20240903110647475.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-91835f4f5f203ec419f61e30ce4983f269c23f3f.png)

#### 4.1.2 去掉非必要功能

前边源码分析的时候，就发现了很多用不到的功能和占位的代码。现在把他们一一去除，看一下效果。

从头开始，这个功能很明显用不到，这行代码，连同函数所在的文件，一块删除。

![image-20240903111025167.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-9f0df2968009e3bfd06dec11a68c7fd9151f2880.png)

去掉目录方式读取配置文件

![image-20240903111455937.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8ac6800cd8403b4626ef1ea2d246712be15b1d78.png)

去掉web UI

![image-20240903112132643.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7acf2fb3d42211624ab92ee790c19cb46fd3c945.png)

去掉用不到的插件

![image-20240903115217104.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-67683adc6131114529ecf9aaec2a97e1bd201500.png)

再次编译，这次少了`1M`

![image-20240903115505648.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2138e42ff70f6661a8abd524fbbdb9ea7030efad.png)

### 4.2 编译方法

本地未作任何更改的情况下，和GitHub下载的`frpc.exe`做对比，大小也不一样。

### 4.3 总结

前边几种方法下来，效果并不明显。这也跟语言特性有关系，go编译的本来就大，要想最大化缩小体积，用`C++`应该是最好的。

不过这样较小代码量也不是没用，应该可以起到免杀的效果。