零、java审计初识
==========

> Java 代码审计是指在编写、修改或审核 Java 代码时，使用一些技巧来查找和修复代码中的漏洞和弱点。通俗来说，JAVA代码审计就是通过阅读java源代码的方式发现应用程序中可能存在的安全问题。
> 
> 由于JAVA是编译型语言，由于即使只有class文件也可以进行审计。
> 
> - 对于`未编译`的JAVA源代码直接阅读源码。
> - 对于`编译的`class或者jar文件需要进行反编译。

JAVA编译
------

> jar包本质上是将所有class文件、资源文件压缩打成一个包。

##### 关于编译型语言和解释型语言

1. 编译型语言是直接转换为机器码执行，不同的平台CPU的指令集不同。 解释型语言是解释器直接加载源码运行，代价就是运行效率低
2. 编译型语言如C、C++，解释型语言如Python、Ruby

Java鉴于解释型编译型之间，是先编译成一种“字节码”，然后根据不同平台编写虚拟机，以虚拟机加载“字节码”运行。如JVM。

#### JAVA编译过程:

**Java源代码** ——（编译）——&gt; **Java字节码** ——（解释器）——&gt; **机器码**

**Java源代码** ——（编译器 ）——&gt; **jvm可执行的Java字节码** ——（jvm解释器） ——&gt; **机器可执行的二进制机器码** ——&gt;**程序运行**

**采用字节码的好处：**高效、可移植性高

##### .java代码：

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b75d36cdefff709f597c0f346254428d8c7ad96f.png)

##### .class代码直接打开：

![image-20221230140525108](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-fcc04c702e963e43effabe9e2c81c77b682b19ca.png)

##### .class反编译后的文件（右边）

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-4c9775c31d25701b3e4fcbd1bde852123d906e2f.png)

#### 反编译工具：

> - IDEA 默认会使用 Fernflower 对字节码文件进行反编译。
> - jar包本质上是将所有class文件、资源文件压缩打包成一个包。

工具：

- fernflower
- jad
- jd-gui
- idea自带插件

安卓反编译
-----

同理，安卓也是可以通过对打包后的apk进行反编译的，当然也存在相应的防护机制，比如打包时混淆，反编译后就可能会出现一些乱码之类的，或者进行加壳加固等等。

### 工具：

- 方法：
    
    
    - dex反编译
    - odex反编译
    - ……
- 工具：
    
    
    - JD-GUI
    - Procyon-Decompiler
    - jadx
    - Apktool
    - Androidkiller
    - ……

一、Java审计之路
==========

> 个人感觉审计其实就是代码功底的比拼，6成代码功底，3漏洞经验，1成靠运气~

初级：
---

- java环境搭建、调试
    
    
    - jdk、mysql、maven、tomcat等环境搭建，利用ide进行调试
- java基础学习
    
    
    - java反射机制、JAVA动态代理机制 、java设计模式
    
    [1\_Head First Java(第2版)中文版.pdf](..%5C..%5C..%5CThe%20Book%20of%20life%5C%E6%A2%A6%E4%B8%8E%E5%BD%93%E4%B8%8B%EF%BC%88%E4%B8%AA%E4%BA%BA%E6%95%B4%E7%90%86%E7%89%88%EF%BC%89%5C%E2%96%B6%E3%80%90%E7%BC%96%E7%A8%8B%E3%80%91____%E5%85%B6%E4%BB%96%E8%AF%AD%E8%A8%80%E8%AF%AD%E6%B3%95%E7%B1%BB%5CJAVA%5C1_Head%20First%20Java(%E7%AC%AC2%E7%89%88)%E4%B8%AD%E6%96%87%E7%89%88.pdf)
    
    [Java 全栈知识体系-基础知识点](https://pdai.tech/md/java/basic/java-basic-lan-basic.html)
- java web学习
    
    
    - 如何开发、如何工作、如何整合……
    - Request &amp; Response、Filter
    - servlet、SSH、SSM
    - Struts2 、SpringMVC、SpringCloud
    
    <https://www.javasec.org/javaweb/MemoryShell/>
- 常规漏洞审计
    
    
    - SQL注入
    - 文件处理类
    - XSS注入
    - 配置错误类
- java cms审计
    
    
    - 实战、案例复现等 search：java代码审计 cms

![20210108093706532](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a6f4c653c4159313a683e43b41e6d375701ad357.png)

![20190412175130351](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-93540344afc9f3ab439ee0cbe9a241414bb18af4.png)

中级
--

- JDK安全特性、序列化反序列化等。
    
    
    - 常见gadget：ysoserial （CC）、Marshaller、jdk 7u21 、jndi、URLDNS....
        
        
        - <https://dandelioncloud.cn/article/details/1433096378116554753/>
        - 复现失败常见原因及问题点：
            
            
            - 一般使用到了设计模式，不是开发，难理解，难操作，需要理解其中设计模式后这块代码就好理解了。
            - 大多数是因为java版本的问题，随着版本更新，一些不安全的地方也会随之改进或者直接配置默认安全了，可以多查询下版本安全问题，切换版本环境复现。
            - 对于一些难以理解的，可以先学会利用，再看其他利用链，待基础更进一步或者有更好理解的文章之后回头来看，可能会理解更容易。
            - 一定要学会工具链：marshalsec和ysoserial，且payload生成的源码也可以看看
- JAVA高级漏洞（需要基础才能了解完所有的漏洞类型）
    
    
    - 实战类型的代码审计，我们必须对语言安全的基础要有所要了解，每一种语言会有少许的差别。工欲善其事必先利其器，所以搭建自己的审计工具也是重中之重
    - fortify、checkmarx使用分析及规则熟悉。
    - 漏洞类型
        
        
        - jndi注入
        - 表达式注入
        - **反序列化漏洞**（重头戏）
            
            
            - rce、fileupload、xxe、DOS等等
        - xxe、ssrf
        - 协议漏洞（tomcat ajp、jmx协议等等）
        - 逻辑漏洞（框架一些目录变量、SSTI、zip slip等等）
- JAVA组件漏洞（深入理解相应组件流程及安全漏洞点）
    
    
    - 例如-三方应用开发问题:随着语言体系的越发灵活，第三方开发库也随之越来越多，每一种语言都有自己固定的坑，如何正确规范安全的开发将会是重中之重
        
        
        - xml解析三方应用安全问题
        - json解析
        - 反序列化
    - fastjson、log4j、weblogic等等
    - 接口安全（restful、swagger）
- JAVA框架漏洞（深入理解相应框架流程及安全漏洞点）
    
    
    - 审计java类型的业务系统，难度不在于漏洞本身的呈现和利用，在于整个框架流程的分析，极具优势的面向对象开发，也造就了阅读人员的困难，剥茧抽丝一步步渗透到代码的最底层，从而找到漏洞点
    - spring、struts2、springboot、mybatis、普元EOS开发框架、用友NC等等

高级
--

- 底层安全机制（JEP 290等）
- 安全防护技术
    
    
    - RASP技术、IAST技术
- 自动化/CodeQL.....
- 漏洞研究。
    
    
    - bincat、tomcat等容器安全，webserver、rmi、osgi等服务器安全、漏洞挖掘
    - 选择研究对象-漏洞总结-漏洞挖掘利用。
        
        
        - 总结近10年所有CVE漏洞，如下格式整理，漏洞描述、漏洞模块、漏洞成因、漏洞影响范围和参考链接

其他
--

语言扩展审计

- **Python、C#、Go、PHP**
    
    
    - 命令执行、缓冲区溢出、格式化字符串、反序列化
- **Vue、nodejs**
    
    
    - 劫持、命令执行、注入
- **Swift、java 嵌入式（APP、数据库）**
    
    
    - 迭代器问题、缓冲区溢出、第三方安全、内存安全
- **Java和.NET交互整合**
    
    
    - JAVA主要承担DAL（数据访问层），主要与DB交互，以及其他通信，由.NET主要承担BLL（业务逻辑层）

二、审计工具
======

Foytify
-------

Fortify SCA 22.2.1 Windows &amp; Linux  
​  
Linux: <https://mega.nz/file/z1UBBQiJ#AhTBG-udyzCed7b17hGuWAE4ME4pQouUMsNUI8hk5hE>  
Windows: <https://mega.nz/file/y9FjUQzQ#rZqrw0nbrNt8BX416Xc0xkutmC1eBfDvHMo9FIVjrOU>  
Password: Pwn3rzs  
​  
Just unzip and use it!  
​  
Enjoy!  
​  
<https://mega.nz/file/z1UBBQiJ#AhTBG-udyzCed7b17hGuWAE4ME4pQouUMsNUI8hk5hE>

Fortify SCA ，是一个静态的、白盒的软件源代码安全测试工具。它通过内置的五大主要分析引擎：数据流、语义、结构、控制流、配置流等对应用软件的源代码进行静态的分析，分析的过程中与它特有的软件安全漏洞规则集进行全面地匹配、查找，从而将源代码中存在的安全漏洞扫描出来，并给予整理报告。

优点：速度、精确、语种多几乎所有语种

缺点：集成性太差

- 自定义规则： <https://blog.csdn.net/liweibin812/article/details/87274054>
- 扫描Android项目 [https://blog.csdn.net/weixin\_36087674/article/details/112102571](https://blog.csdn.net/weixin_36087674/article/details/112102571)

checkmarx
---------

Checkmarx是一家以色列高科技软件公司，是世界上著名的代码安全扫描软件Checkmarx CxSAST的生产商，拥有应用安全测试的业内前沿解决方案-CxSAST、CxOSA、CxIAST 。Checkmarx提供了一个全面的白盒代码安全审计解决方案，帮助企业在软件开发过程中查找、识别、追踪绝大部分主流编码中的技术漏洞和逻辑漏洞，帮助企业以低成本控制应用程序安全风险。CxSAST无需搭建软件项目源代码的构建环境即可对代码进行数据流分析。通过与各种SDLC组件的紧密集成，CxSAST可实现分析过程的完全自动化，并为审计员和开发人员提供对结果和补救建议的即时访问。

优点：规则自定义、集成性强

缺点：速度慢，精确率，语种少

CodeQL
------

codeql是一门类似SQL的查询语言，通过对项目源码（C/C++、C#、golang、java、JavaScript、typescript、python）进行完整编译，并在此过程中把项目源码文件的所有相关信息（调用关系、语法语义、语法树）存在数据库中，然后编写代码查询该数据库来发现安全漏洞（硬编码/XSS等）。 CodeQL 是开发人员用来自动化安全检查的分析引擎，安全研究人员用来执行变体分析。

在 CodeQL 中，代码被视为数据。安全漏洞、错误和其他错误被建模为可以针对从代码中提取的数据库执行的查询。您可以运行由 GitHub 研究人员和社区贡献者编写的标准 CodeQL 查询，也可以编写自己的查询以用于自定义分析。查找潜在错误的查询直接在源文件中突出显示结果。

`非商业的开源半自动化代码审计工具`，作用主要是通过编写好的语句查询代码中可能存在的安全隐患。暂不支持php

**参考资料：**

[CodeQL的自动化代码审计之路（上篇）](https://mp.weixin.qq.com/s?__biz=MzkzNjMxNDM0Mg==&mid=2247485471&idx=1&sn=c879ac61f71d5d11ed20b7529606e110&chksm=c2a1dc96f5d655803c87c6b7601ede9ecadd59bc6d8a46cedbeb7eef13f64b7d1acdd0de4593&token=980532188&lang=zh_CN&scene=21#wechat_redirect)

其他
--

### **[JavaID](https://github.com/Cryin/JavaID)**

java源码静态代码分析及危险函数识别工具

### **代码卫士**

- 推荐---【缺陷周话】系列

<https://www.freebuf.com/sectool/188469.html>

### seay

常用于php代码审计

### RIPS

<https://sourceforge.net/projects/rips-scanner/>

PHP代码安全审计

### VCG

<http://downloads.informer.com/visualcodegrepper/>

C、C#、C++、VB、PHP、Java、PL、SQL

### Visual Studio代码分析

.NET代码审计

### [KunLun-M](https://github.com/LoRexxar/Kunlun-M)

KunLun-M是一个完全开源的静态白盒扫描工具，支持PHP、JavaScript的语义扫描，基础安全、组件安全扫描，Chrome Ext\\Solidity的基础扫描。

### [Dependency\_Check](https://www.owasp.org/index.php/OWASP_Dependency_Check)

OWASP 出的 插件安全问题检测工具，可以自动检查，引入的第三方库是否有已知的安全漏洞。

#### 安装使用：

安装方式有两种：一种以插件模式在项目中运行，一种以命令行模式运行。

**插件模式**

作为 maven 的插件使用，用法很简单，直接在项目的 pom.xml 写入。

```xml
<plugin\>  
    <groupId\>org.owasp</groupId\>  
    <artifactId\>dependency-check-maven</artifactId\>  
    <version\>3.3.2</version\>  
    <executions\>  
        <execution\>  
            <goals\>  
                <goal\>check</goal\>  
            </goals\>  
        </execution\>  
    </executions\>  
</plugin\>
```

然后，执行 `mvn verify` 就可以了。

更多详细可参考:[https://blog.csdn.net/weixin\_34117211/article/details/89565029](https://blog.csdn.net/weixin_34117211/article/details/89565029)

**命令行模式：**

独立于项目之外运行，不需要修改pom.xml配置

1. 在github下载[`DependencyCheck`](https://github.com/jeremylong/DependencyCheck/releases)

![image-20221230173512296](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-423f959dfba934f3b41a725c3f997aa80647aeae.png)

2. 解压运行：

命令行下，运行`dependency-check.bat --project 项目名 --out 输出名 -s 源码路径`。

> *程序会自动从NVD更新漏洞库，所以需要点时间（应该还要翻墙）。*

![image-20221230174150897](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-36718eded62a24d6b053bc77e77a0d4c0e3dbae0.png)

3. 使用说明

```php
\# 更新CPE数据库      
dependency-check \--updateonly  
\# 在项目顶层执行，扫描整个项目  
dependency-check \-n \-o ./ \-f CSV  \-s /ssssss/xxxxxx/  
\# scan路径指定某个jars包，扫描整个jars包  
dependency-check \-n \-o ./ \-f CSV  \-s /ssssss/xxxxxx/jars  
\# scan路径指定某个jar，扫描单个jar包  
dependency-check \-n \-o ./ \-f CSV  \-s /ssssss/xxxxxx/jars/xxxx.jar  
​  
\# 常用命令参数如下：  
\# -h  --help    # 输入帮助信息  
\#  --project <name>   # 被扫描项目名称，可以随意命名 建议test 该名称会展示在报告中若确实报告部分展示空白  
\# -n  --noupdate     # 禁止自动更新CPE数据，默认4h自动拉取 建议添加，若无CPE本地库由于网络原因会频繁造成扫描失败  
\#  -o  --out <path>  # 报告输出路径  
\#  -f  --formate <formate> # 报告输出格式 默认HTML 建议 CSV  
\#  -s  --scan <path> # 待扫描路径的，建议写绝对路径。可以扫目录，也可以直接扫压缩文件，zip，war，tgz等  
\#  -l  --log <file>  # 输出扫描过程中的日志到文件  
```

​

4. 结果报告

*(不知道为啥扫描老是0个问题，暂用下网图)*

![img](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-55455373b5f5f2de83c908b9b697327dfe0fc6f6.png)

- Dependency # 被扫描的第三依赖库机器版本
- Highest Severity # 所有关联的CVE的最高漏洞等级
- CVE Count # 关联的CVE个数
- Confidence # 正确识别CPE的程度
- Evidence Count # 识别CPE的数据个数

可能会出现retirejs的问题，可以参考:

<https://blog.csdn.net/kingwinstar/article/details/123989655>

<https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json>

### FindSecBugs

是专门用于检测Java Web应用安全漏洞的插件，支持多种IDE，还可以和SonarQube等代码分析平台集成。

[IDEA中安装FindSecBugs](https://github.com/find-sec-bugs/find-sec-bugs/wiki/IntelliJ-Tutorial)

### chatgpt

> 可作为智能java代码解读、审计等
> 
> <https://chat.openai.com/chat/> （注册需要国外手机号，可花一卢比接受一条短信<https://sms-activate.org/getNumber>）

![image-20230104143440182](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-4c4949640ebe58521349c214c37009a694649f42.png)

### 更多参考：

[代码审计工具汇总](https://cloud.tencent.com/developer/article/1823658)

三、JAVA审计基础环境
============

大致环境信息：

- **JDK**：JDK8、JDK11……
- **数据库**：mysql、oracel……
- **web容器**：tomcat、weblogic……
- **项目管理**：Maven、Gradle……
- **IDE**：IDEA、Eclipse、jdk-gui（反编译查看）等

JDK介绍与安装
--------

> - 由于jdk版本特性不同，很多版本不向下兼容，一些软件再新的jdk中无法正常运行，推荐用主流的jdk8。
> - 有些漏洞复现对jdk版本有要求，只有在低版本或者特定的版本下才能复现成功，推荐用jdk版本控制应用。

### 什么是jdk？

JDK，全称Java SE Development kit(JDK)，即java标准版开发包，是Oracle提供的一套用于开发java应用程序的开发包，它提供编译，运行java程序所需要的各种工具和资源，包括java编译器，java运行时环境，以及常用的java类库等。

还有一个JRE，它和JDK什么区别呢？

JRE，全称Java Runtime Environment即Java运行环境。它是Java语言程序运行所需的软件环境。

JDK中包含了JRE。

> jdk的版本信息可以参考：[Java--Java版本和JDK版本](https://blog.csdn.net/MinggeQingchun/article/details/120578602)

### JDK安装：

> 进行绿色版安装之前，建议先程序安装一个官方的jdk版本、安装jre，避免绿色版安装后出现jar运行不了、无jre环境、java程序加载报错等问题。

1. **获取jdk版本**

官方下载地址，

<https://www.oracle.com/java/technologies/javase/javase8u211-laterarchive-downloads.html> 。

第三方jdk下载（推荐，可直接下载绿色版）

[https://www.azul.com/downloads/?version=java-7-lts&amp;architecture=x86-64-bit&amp;package=jdk&amp;show-old-builds=true](https://www.azul.com/downloads/?version=java-7-lts&architecture=x86-64-bit&package=jdk&show-old-builds=true)

> 这里有个Oracle JDK 和 OpenJDK的知识，有兴趣的可以了解下。个人感觉差异不大，一个商业版（Oracle JDK）一个开源版（OpenJDK），除了一些特别的商业功能模块外，其他功能组件模块都差不多。
> 
> - 英文：<https://www.baeldung.com/oracle-jdk-vs-openjdk>
> - 中文:<https://javaguide.cn/java/basis/java-basic-questions-01.html#oracle-jdk-vs-openjdk>

2. 程序安装一个jdk版本。

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b436a214e066c73f715eaef37ef61100a9dd45a0.png)

3. **绿色版-设置环境变量**

1）新建JAVA\_HOME环境变量：选择在系统变量新建

```php
 JAVA\_HOME  
D:\\Tools\\Compilation-environment\\java\\zulu8.28.0.1-jdk8.0.163-win\_x64 （jdk解压后的路径）
```

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-d76d75eb7255029aa1765bcd7644661308aabb46.png)

2）设置Path：在系统变量中编辑 Path，新建`%JAVA_HOME%\bin`条目

```php
%JAVA\_HOME%\\bin (JDK中的bin文件路径）
```

3）设置CLASSPATH： 注意：变量值可以只填一个点，后面的变量写不写都是可以的，如果不放心的话可以加上。 设置CLASSPATH的目的：防止出现找不到或无法加载主类问题。

```php
CLASSPATH  
.;%JAVA\_HOME%\\lib;%JAVA\_HOME%\\lib\\dt.jar;%JAVA\_HOME%\\lib\\tools.jar
```

4）安装成功：

![image-20221227171543283](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-81fbd9ce55e5a9d86a2cbbbda26d70fc62de01b0.png)

### jdk版本切换

程序安装和绿色版共用时，需要将环境变量`PATH`中`%JAVA_HOME%\bin`路径优先级高于程序安装的环境变量路径`D:\Program Files\Zulu\zulu-8\bin\`

![image-20230103134106914](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-61f53122e199378b0d8372703fe04d259a9550d0.png)

实际调试中，经常会遇到jdk版本切换的情况，可以使用`脚本来切换各版本环境变量`。

```bat
%1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit cd /d "%~dp0"  
@echo off  
echo 当前Java版本  
java \-version  

:menu  
echo \=================================================================================================  
echo 请选择要切换的jdk版本  
echo 1：Java jdk 1.8  
echo 2：Java jdk 11  
echo 3：Java jdk 15  
echo 4：Java jdk 17  
echo 0: 取消  
echo \=================================================================================================  
set /p ch\=请选择：  
if "%ch%"\=="1" goto java1.8  
if "%ch%"\=="2" goto java11  
if "%ch%"\=="3" goto java15  
if "%ch%"\=="4" goto java17  
if "%ch%"\=="0" goto exit  
goto menu  
​  

:java1.8  
set JAVA\_HOME\=D:\\Program Files\\Java\\jdk1.8.0\_351  
set JAVA\_VERSION\=1.8  
goto exec  
​  
:java11  
set JAVA\_HOME\=D:\\Tools\\Compilation-environment\\java\\zulu11.54.25-ca-jdk11.0.14.1-win\_x64  
set JAVA\_VERSION\=11  
goto exec  

:java15  
set JAVA\_HOME\=D:\\Tools\\Compilation-environment\\java\\zulu15.44.13-ca-jdk15.0.9-win\_x64  
set JAVA\_VERSION\=15  
goto exec   
​  
:java17  
set JAVA\_HOME\=D:\\Tools\\Compilation-environment\\java\\jdk17.0.5  
set JAVA\_VERSION\=17  
goto exec   

:exec  
reg add "HKEY\_LOCAL\_MACHINE\\SOFTWARE\\JavaSoft\\Java Development Kit" /v CurrentVersion /t REG\_SZ /f /d "%JAVA\_VERSION%"  
reg add "HKEY\_LOCAL\_MACHINE\\SOFTWARE\\JavaSoft\\Java Runtime Environment" /v CurrentVersion /t REG\_SZ /f /d "%JAVA\_VERSION%"  
setx "JAVA\_HOME" "%JAVA\_HOME%" /m  
​  
del /f "C:\\Windows\\System32\\java.exe"  
copy /Y "%JAVA\_HOME%\\bin\\java.exe" "C:\\Windows\\System32\\java.exe"  
del /f "C:\\Windows\\System32\\javaw.exe"  
copy /Y "%JAVA\_HOME%\\bin\\javaw.exe" "C:\\Windows\\System32\\javaw.exe"  
del /f "C:\\Windows\\System32\\javaws.exe"  
copy /Y "%JAVA\_HOME%\\bin\\javaws.exe" "C:\\Windows\\System32\\javaws.exe"  
​  
set JAVA32\_PATH\=C:\\Program Files (x86)\\Common Files\\Oracle\\Java\\javapath  
del /f "%JAVA32\_PATH%\\java.exe"  
mklink "%JAVA32\_PATH%\\java.exe" "%JAVA\_HOME%\\bin\\java.exe"  
del /f "%JAVA32\_PATH%\\javaw.exe"  
mklink "%JAVA32\_PATH%\\javaw.exe" "%JAVA\_HOME%\\bin\\javaw.exe"  
del /f "%JAVA32\_PATH%\\javaws.exe"  
mklink "%JAVA32\_PATH%\\javaws.exe" "%JAVA\_HOME%\\bin\\javaws.exe"  
​  
:exec  
:set JAVA\_PATH\=C:\\Program Files\\Common Files\\Oracle\\Java\\javapath  
:del /f "%JAVA\_PATH%\\java.exe"  
:mklink "%JAVA\_PATH%\\java.exe" "%JAVA\_HOME%\\bin\\java.exe"  
:del /f "%JAVA\_PATH%\\javaw.exe"  
:mklink "%JAVA\_PATH%\\javaw.exe" "%JAVA\_HOME%\\bin\\javaw.exe"  
:echo  
​  
​  
echo \=================================================================================================  
echo 已切换到Java%JAVA\_VERSION%  
pause  
goto exit  
:exit
```

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-eac2852a40de2df32decf1d705db36249594963f.png)

其他脚本：

<https://www.mobaijun.com/posts/772710478.html>

<https://www.cnblogs.com/yuxuefeng/p/16143440.html>

<https://github.com/SkyBlueEternal/jdk-change>

### 问题：java环境配好后jar文件打开闪退，无打开方式，无反应（待填坑）

解决：

- 命令行中使用`javaw -jar xxx.jar` 打开一次程序后，再看看打开方式是否有`Java(TM) Platform SE binary`应用

![image-20230103151907797](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-f5ff0288745831644ab08f8d83c488e25344cc91.png)

- 环境变量配置有问题，重装配置。检测jdk、jre是否正常，是否存在java.exe、javaw.exe、javac.exe等。
- 直接选择路径中的`javaw.exe`程序打开`.jar`应用。
- 设置注册表
    
    
    - 打开注册表编辑器`regedit` ---&gt; `HKEY_CLASSES_ROOT\Applications\javaw.exe\shell\open\command`， 添加数值数据：`“C:\Program Files\Java\jre1.8.0_231\bin\javaw.exe”-jar “%1”`

> 解决到有打开方式了，命令行打开一切正常，但双击还是闪退，待后续解决了。

### JDK版本安全特性简记

> 在JDK 6u132, JDK 7u122, JDK 8u113 中Java提升了JNDI 限制了Naming/Directory服务中JNDI Reference远程加载Object Factory类的特性。系统属性 com.sun.jndi.rmi.object.trustURLCodebase、com.sun.jndi.cosnaming.object.trustURLCodebase 的默认值变为false，即默认不允许从远程的Codebase加载Reference工厂类。如果需要开启 RMI Registry 或者 COS Naming Service Provider的远程类加载功能，需要将前面说的两个属性值设置为true。
> 
> 参考:<https://paper.seebug.org/942/>

![image-20221230160548461](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-0ea61be612975b82895f7755ea81f380c9303478.png)

数据库
---

常见的数据库有 MySQL、PostgreSQL、Oracle，除此之外还有现在比较流行的非关系型数据库 Redis、Mongodb、Memcached 等等。

web容器
-----

`Java Web`应用在开发完后，通常会以`war`包的形式发布，我们需要把这个`war`包部署到自己的`Web容器`（也可以说是Web服务器）里去，容器在启动后会自动解压`war`包，处理用户发来的HTTP请求，将`jsp`编译成`servlet`，管理`servlet`的整个生命周期。

常见的 Web 容器有 Tomcat，JBoss，Jetty，Weblogic，不同的容器在功能、性能上有所差异，但仅仅是做代码审计用[`Tomcat`](http://tomcat.apache.org/)就足够了。

项目管理
----

> - 一个完整的Java项目，必然会引入一些外部的第三方库。
> - 在传统的项目管理中项目是存在很大问题的,例如jar包不统一甚至不兼容,使得项目中的jar依赖包库很混乱,又或者说对于项目工程的升级维护操作很繁琐,又或者说不同IDE下项目结构布置等问题，由此,`Maven诞生了`

### Maven

Maven 是一个项目管理工具，它包含了一个项目对象模型（Project Object Model），反映在配置中，就是一个 pom.xml 文件。是一组标准集合，一个项目的生命周期、一个依赖管理系统，另外还包括定义在项目生命周期阶段的插件(plugin)以及目标(goal)。

简而言之，maven就是用来管理项目源码、配置文件、处理java项目依赖关系的一个工具，并使用pom.xml来描述项目信息，**通过pom.xml文件的配置获取jar包**，而不用手动去添加jar包。类似于nodejs的npm、python的pip。

详细关于Maven的基础知识以及安装教程可以参考链接：<https://www.cnblogs.com/whgk/p/7112560.html>

#### pom.xml

pom.xml文件以xml的 形式描述项目的信息，包括项目名称、版本、项目id、项目的依赖关系、编译环境、持续集成、项目团队、贡献管理、生成报表等所有项目信息。

> 可以通过pom.xml信息快速检查第三方库是否存在已知的安全漏洞。

- **project - project**
    
    
    - 是 pom.xml 中描述符的根
- **modelVersion** **-** **modelVersion**
    
    
    - 指定 pom.xml 模型版本。maven 2和 3 只能为 4.0.0。
- **parent - maven**
    
    
    - 支持继承功能。子 POM 可以使用 parent 指定父 POM ，然后继承其配置。
- **groupId**
    
    
    - 团体、组织的唯一标识符。团体标识的约定是，它以创建这个项目的组织名称的逆向域名(reverse domain name)开头。一般对应着 java 的包结构。
    - 比如如com.winner.trade，maven会将该项目打成的jar包放本地路径：/com/winner/trade
- **artifactId**
    
    
    - 本项目的唯一标识符。一个groupId下面可能多个项目，就是靠artifactId来区分的
    - 比如我们的 tomcat、commons 等。不要在artifactId 中包含点号(.)
- **version**
    
    
    - 本项目所处的版本信息。
- **dependencies**
    
    
    - 配置定义本项目的依赖关系
    - 每个dependency都对应这一个jar包

一份maven-pom.xml全配置信息：

```xml
<?xml version="1.0" encoding="UTF-8"?>  
<project xmlns\="http://maven.apache.org/POM/4.0.0"  
         xmlns:xsi\="http://www.w3.org/2001/XMLSchema-instance"  
         xsi:schemaLocation\="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd" \>  
    <parent\>  
        <groupId\>org.springframework.boot</groupId\>  
        <artifactId\>spring-boot-starter-parent</artifactId\>  
        <version\>2.3.12.RELEASE</version\>  
        <relativePath/>  
    </parent\>  
​  
    <modelVersion\>4.0.0</modelVersion\>  
    <groupId\>org.example</groupId\>  
    <artifactId\>WebProject</artifactId\>  
    <packaging\>jar</packaging\>  
    <name\>demo</name\>  
    <version\>1.0-SNAPSHOT</version\>  
    <description\>项目描述</description\>  
    <url\>project home page</url\>  
    <prerequisites\>  
        <maven\>2.0</maven\>  
    </prerequisites\>  
    <issueManagement\>  
        <system\>issue系统名称</system\>  
        <url\>issue系统路径</url\>  
    </issueManagement\>  
    <ciManagement\>  
        <system\>持续集成系统名称</system\>  
        <url\>持续集成系统url</url\>  
        <!--配置用于在构建失败时通知开发人员/用户，包括用户信息和通知模式。  -->  
        <notifiers\>  
            <notifier\>  
                <sendOnError\>true</sendOnError\>  
                <sendOnFailure\>true</sendOnFailure\>  
                <sendOnSuccess\>true</sendOnSuccess\>  
                <sendOnWarning\>true</sendOnWarning\>  
                <address\>该配置已废除</address\>  
                <configuration\>  
                    <custom\>一些列自定义属性</custom\>  
                </configuration\>  
            </notifier\>  
        </notifiers\>  
    </ciManagement\>  
​  
    <inceptionYear\>记录项目的开始年份，用于生成版权信息</inceptionYear\>  
    <mailingLists\>  
        <mailingList\>  
            <name\>名称</name\>  
            <subscribe\>可用于订阅邮件列表的电子邮件地址或链接。如果是一个邮件地址，那么会在生成文档的时候自动生成mailTo信息</subscribe\>  
            <unsubscribe\>取消订阅的邮件列表的电子邮件地址或链接</unsubscribe\>  
            <post\>可用于向邮件列表发送邮件的电子邮件地址或链接。</post\>  
            <archive\>指向URL的链接，您可以在该URL中浏览邮件列表存档。</archive\>  
            <otherArchives\>  
                <otherArchive\>到可浏览列表存档的备用url的链接。</otherArchive\>  
            </otherArchives\>  
        </mailingList\>  
    </mailingLists\>  
    <!--关于这个项目的一个提交者的信息。-->  
    <developers\>  
        <developer\>  
            <id\>SCM中开发人员的唯一ID。</id\>  
            <name\>贡献者的全名。</name\>  
            <email\>贡献者的电子邮件地址。</email\>  
            <url\>投稿者主页的URL。</url\>  
            <organization\>贡献者所属的组织。</organization\>  
            <organizationUrl\>组织的URL地址。</organizationUrl\>  
            <roles\>  
                <role\>角色</role\>  
            </roles\>  
            <!--贡献者所在时区 -11 到 12 -->  
            <timezone\> 8</timezone\>  
            <!--设置某些属性，没有特定格式-->  
            <properties\>  
                <p1\>属性1</p1\>  
            </properties\>  
        </developer\>  
    </developers\>  
    <!--描述还不是提交者的项目贡献者。-->  
    <contributors\>  
        <!--属性和developer差不多，没有id-->  
        <contributor\>  
        </contributor\>  
    </contributors\>  
    <licenses\>  
        <license\>  
            <name\>许可证的完整合法名称。</name\>  
            <url\>license文本的官方url。</url\>  
            <distribution\>  
                <!--这个项目可能被分发的主要方法。repo:可以从Maven存储库下载;manual:用户必须手动下载和安装依赖。-->  
            </distribution\>  
            <comments\>与本许可证有关的附录信息。</comments\>  
        </license\>  
    </licenses\>  
    <scm\>  
        <connection\>源控制管理系统URL,该url的源库只读。</connection\>  
        <developerConnection\>和connection一样，不过该url针对开发者，源库不是只读。</developerConnection\>  
        <tag\>目前项目使用的tag，默认情况下，开发中是HEAD</tag\>  
        <url\>scm库浏览器访问的url</url\>  
    </scm\>  
    <!--项目的开发组织信息。-->  
    <organization\>  
        <name\>组织名称</name\>  
        <url\>组织主页 </url\>  
    </organization\>  
    <!--构建项目所需的信息。-->  
    <build\>  
        <!--项目资源路径,相对路径-->  
        <sourceDirectory\>src/main/java</sourceDirectory\>  
        <!--项目的脚本路径，相对路径-->  
        <scriptSourceDirectory\>src/main/sql</scriptSourceDirectory\>  
        <!--测试资源路径-->  
        <testSourceDirectory\>src/test</testSourceDirectory\>  
        <!--项目输出路径-->  
        <outputDirectory\>target/classes</outputDirectory\>  
        <!--测试输出路径-->  
        <testOutputDirectory\>target/test-classes</testOutputDirectory\>  
        <!--build的拓展信息-->  
        <extensions\>  
            <extension\>  
                <groupId\>com.aliyun</groupId\>  
                <artifactId\>quotas20200510</artifactId\>  
                <version\>1.0.1</version\>  
            </extension\>  
        </extensions\>  
        <defaultGoal\>项目的默认目标</defaultGoal\>  
        <!--所有资源路径-->  
        <resources\>  
            <resource\>  
                <!--资源的存储路径-->  
                <directory\>src/main/resources</directory\>  
                <!--包含的文件-->  
                <includes\>  
                    <include\>\*\*/\*.xml</include\>  
                </includes\>  
                <!--排除的文件-->  
                <excludes\>  
                    <exclude\>\*\*/\*.doc</exclude\>  
                </excludes\>  
                <!--资源需要打包到哪儿-->  
                <targetPath\>org/apache/maven/messages</targetPath\>  
                <!--是否使用过滤，默认false,true则使用filters的properties进行过滤-->  
                <filtering\>false</filtering\>  
            </resource\>  
        </resources\>  
        <testResources\>  
            <!--测试用的资源路径，与resources一致配置-->  
        </testResources\>  
        <!--放置构建生成的所有文件的目录。-->  
        <directory\>target/generated-sources</directory\>  
        <!--打包生成的文件名称，默认是${artifactId}-${version}-->  
        <finalName\>${artifactId}-${version}</finalName\>  
        <!--启用filtering时的筛选器属性列表-->  
        <filters\>  
            <filter\>没有固定格式的文件列表</filter\>  
        </filters\>  
        <!--构建时需要的插件-->  
        <pluginManagement\>  
            <plugins\>  
                <plugin\>  
                    <groupId\>org.apache.maven.plugins</groupId\>  
                    <artifactId\>artifactId</artifactId\>  
                    <version\>version</version\>  
                    <!--一些其他属性配置-->  
                </plugin\>  
            </plugins\>  
        </pluginManagement\>  
        <!--和pluginManagement配置一样，不知所以-->  
        <plugins\>  
        </plugins\>  
    </build\>  
    <!--一个项目本地构建概要文件的列表，它将在激活时修改构建过程。-->  
    <profiles\>  
        <profile\>  
            <id\>build profile的唯一标识</id\>  
            <!--自动触发包含该概要文件的条件逻辑。  -->  
            <activation\>  
                <!--指定此配置文件是否默认激活的标志。-->  
                <activeByDefault\>false</activeByDefault\>  
                <!--指定当检测到匹配的JDK时将激活此配置文件。比如配置1.8，那么当项目使用jdk1.8的时候启动该构建过程，！1.8则匹配除1.8以外的所有版本-->  
                <jdk\>1.8</jdk\>  
                <!--指定当检测到匹配的操作系统属性时激活此配置文件。-->  
                <os\>  
                    <name\>${os.name}</name\>  
                    <!--操作系统类型-->  
                    <family\>windows</family\>  
                    <!--用于激活概要文件的操作系统的体系结构。-->  
                    <arch/>  
                    <!--操作系统版本-->  
                    <version\>10.1</version\>  
                </os\>  
            </activation\>  
        </profile\>  
    </profiles\>  
    <!--该项目的子模块信息-->  
    <modules/>  
    <!--配置远程仓库和拓展-->  
    <repositories\>  
        <repository\>  
            <id\>仓库的唯一标识</id\>  
            <url\>仓库的url</url\>  
            <name\>仓库的名称</name\>  
            <!--如何处理从这个存储库下载releases版本-->  
            <releases\>  
                <!--是否启用 -->  
                <enabled\>true</enabled\>  
                <!--更新策略，always，daily（默认），interval:XXX,never(仅在本地不存在的情况下)-->  
                <updatePolicy\>always</updatePolicy\>  
                <!--校验失败时的策略，ignore，fail，warn（默认值）-->  
                <checksumPolicy\>warn</checksumPolicy\>  
            </releases\>  
            <!--如何处理从这个存储库下载快照。配置参考releases-->  
            <snapshots\>  
​  
            </snapshots\>  
            <!--此存储库用于定位和存储工件的布局类型,legacy或default-->  
            <layout\>default</layout\>  
        </repository\>  
    </repositories\>  
    <!--插件的仓库配置-->  
    <pluginRepositories\>  
        <pluginRepository\>  
            <id\>仓库的唯一标识</id\>  
            <url\>仓库的url</url\>  
            <name\>……</name\>  
        </pluginRepository\>  
    </pluginRepositories\>  
    <!--可以在整个POM中作为替代使用的属性，如果启用，则用作资源中的过滤器。-->  
    <properties\>  
        <maven.compiler.source\>8</maven.compiler.source\>  
        <maven.compiler.target\>8</maven.compiler.target\>  
    </properties\>  
    <dependencies\>  
        <dependency\>  
            <groupId\>org.springframework.boot</groupId\>  
            <artifactId\>spring-boot-starter-web</artifactId\>  
            <!--版本信息，可以通过parent自动寻找依赖，maven2开始，可以指定范围-->  
            <version\>2.3.12.RELEASE</version\>  
            <!--依赖的类型，默认是jar,还有war，ejb-client，test-jar等，更多的类型可以由extensions定义。-->  
            <type\>jar</type\>  
            <!--依赖的分类器。这允许区分属于同一个POM但构建方式不同的两个工件，并在版本之后添加到文件名中。\[不是很明白\]-->  
            <classifier\>jdk14</classifier\>  
            <!--定义该依赖的生命周期；compile，runtime，test，system，provided-->  
            <scope\>compile</scope\>  
            <!--当scope为system时启用，该属性不推荐使用，该属性可能会在后面的版本中被替换。该属性指定依赖在文件系统上得路径，需要绝对路径-->  
            <systemPath\>/HOME</systemPath\>  
            <!--从依赖中排除的引用-->  
            <exclusions\>  
                <exclusion\>  
                    <groupId\></groupId\>  
                    <artifactId\></artifactId\>  
                </exclusion\>  
            </exclusions\>  
            <!--指示要使用此库，依赖项是可选的。默认是false，如果是true，则本项目作为依赖被引用时，该依赖不会被加载-->  
            <optional\>false</optional\>  
        </dependency\>  
    </dependencies\>  
    <!--定义maven站点上生成报告的规范，在执行mvn site时使用-->  
    <reporting\>  
        <!--默认false，如果为true，那么默认的报告不会包含在生成报告中-->  
        <excludeDefaults\>false</excludeDefaults\>  
        <!--报告输出目录，默认是${project.build.directory}/site-->  
        <outputDirectory\>${project.build.directory}/site</outputDirectory\>  
        <!--生成报告用到的插件-->  
        <plugins/>  
    </reporting\>  
    <!--从该文件继承的项目的默认依赖项信息。 可以参考spring-boot-dependencies-->  
    <dependencyManagement\>  
        <dependencies\>  
        </dependencies\>  
    </dependencyManagement\>  
    <!--能够将站点和构件分别部署到远程web服务器和存储库的项目的分布信息。-->  
    <distributionManagement\>  
        <!--将项目部署到远程仓库上所需的信息-->  
        <repository\>  
            <!--仓库的唯一标识符。用来匹配存储库和setting.xml中的配置-->  
            <id\>repo</id\>  
            <!--仓库的名称-->  
            <name\>lwl</name\>  
            <!--仓库地址-->  
            <url\>url</url\>  
            <!--仓库定位和存储组件的布局类型：default、legacy-->  
            <layout\>default</layout\>  
            <!--是否为快照分配由时间戳和构建号组成的唯一版本，还是每次使用相同的版本,默认true-->  
            <uniqueVersion\>true</uniqueVersion\>  
        </repository\>  
        <!--配置同上，快照库配置-->  
        <snapshotRepository\>  
            <……\>  
        </snapshotRepository\>  
        <!--发布的站点信息-->  
        <site\>  
            <!--站点id，与setting.xml匹配-->  
            <id\>id</id\>  
            <name\>name</name\>  
            <url\>url</url\>  
        </site\>  
        <!--当前项目的下载地址-->  
        <downloadUrl\>downloadUrl</downloadUrl\>  
        <!--在组件被移至新的group ID和artifact ID时的重新定位信息-->  
        <relocation\>  
        </relocation\>  
        <!--该项目在仓库中的状态，默认none，可选值：converted（存储库管理器将其从Maven 1 POM转换而来），partner（直接从合作伙伴Maven 2存储库同步），deployed（是从Maven 2上部署的实例），verified（是否已手工验证为正确和最终）-->  
        <status\>none</status\>  
    </distributionManagement\>  
</project\>
```

#### Maven加速

maven镜像地址因某些原因可能会出现下载超时、找不到包等错误情况，国内使用建议做好加速处理。

参考：<https://blog.csdn.net/sl1992/article/details/78653234>

IDE
---

做任何一门语言的代码审计，一个强大的IDE是必不可少的，好的IDE可以极大提高我们审计的效率。对于java程序的开发与审计，推荐使用idea，内置代码检测工具强大、还有很多插件、ui也不错。

### Eclipse

> Eclipse是一款基于Java的开源可扩展开发平台，Eclipse不是一门编程语言，而是一个框架和一组服务。Eclipse为开发者提供了一个标准的插件集，包括Java开发工具（Java Development Kit，JDK）。虽然Eclipse 是使用Java语言开发的，但它的用途并不限于 Java 语言；还提供支持C/C++、COBOL、PHP、Android等编程语言的插件。

### IDEA

> IDEA 全称IntelliJ IDEA，是Java 语言开发的集成环境。IntelliJ在业界被公认为最好的java开发工具，尤其在智能代码助手、代码自动提示、重构、JavaEE支持、各类版本工具(git、svn等)、JUnit、CVS整合、代码分析、 创新的GUI设计等方面的功能可以说是超常的。IDEA是JetBrains公司的产品，这家公司总部位于捷克共和国的首都布拉格，开发人员以严谨著称的东欧程序员为主。它的旗舰版本还支持HTML，CSS，PHP，MySQL，Python等。免费版只支持Java,Kotlin等少数语言。

TIPS：

- `社区版本(Community)`可以用于纯jvm和Android 开发，但不支持web端和企业端的开发。也就是说社区版无法web或企业端代码的运行调试等，推荐使用`最终版（ultimate）`
- 最终版（ultimate）激活方法,有条件的还是支持下正版。
    
    
    - <http://www.javatiku.cn/idea/3866.html>
    - <http://idea.javatiku.cn/>

#### 常用快捷键：

| 常用快捷键 | 描述 |
|---|---|
| F7 | 步入 |
| F8 | 步过 |
| F9 | 下一个断点 |
| 双击Shift | 查找任何内容，可搜索类、资源、配置项、方法等,还能搜索路径 |
| ALT+F8 | 评估表达式 |
| Ctrl+F | 文件内查找字符串 |
| Ctrl + Shift + F | 按照文本的内容查找 |
| Ctrl + N | 按类名搜索类 |
| Ctrl + F12 | 查看当前类结构 |
| Ctrl + H | 查看类的层次关系 |
| Alt + F7 | 查找类或方法在哪被使用 |
| Ctrl + Shift + R | 搜索类 |

![image-20221121153045006](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a72b1cf65f89e02a91960d5128d92065a46f2dbd.png)

#### tips

##### 插件

- Chinses
    
    中文语言包

![image-20221230174640245](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b20d38ead3ff78877c3af479d28804d9a2f50f98.png)

- Free Mybatis plugin：
    
    可以从mapper.xml直接跳到对应的java方法
- GenerateAllSetter
    
    可以在new对象的时候一键生成所有的setter
- JRebel
    
    热部署的神器
- Mybatis Log Plugin
    
    可以直接看到执行的sql
- String Manipulation:字符串操作 提供：驼峰转换、大小写、首字母大小写、转移、编码、解码、排序、删除空行、删除换行符、等字符串相关操作。 快速使用：选中要操作的字符串，alt+M 或则 alt+shift+M 弹出操作选择框
- aixcoder-code-completer：代码完成器和代码搜索引擎 AiXcoder 是基于最新的深度学习技术的功能强大的代码完成器和代码搜索引擎。它有可能向您推荐一整套代码，这将有助于您更快地进行编码。AiXcoder 还提供了一个代码搜索引擎，可帮助您在GitHub上搜索API用例。
- RestfulToolkit
    
    一套Restful服务开发辅助工具集，提供了项目中的接口概览信息，可以根据URL跳转到对应的接口方法中去，内置了HTTP请求工具，对请求方法做了一些增强功能，总之功能很强大！
- Maven Helper
    
    解决Maven依赖冲突的好帮手，可以快速查找项目中的依赖冲突，并予以解决！
- Alibaba Java Coding Guidelines
    
    阿里巴巴《Java 开发手册》配套插件，可以实时检测代码中不符合手册规约的地方，助你码出高效，码出质量。
    
    > 插件不易多，不然容易卡、启动慢等等

使用IDEA搭建MAVEN项目：
----------------

1. 打开IDEA，点击 `Create New Porject` ，选择 `Maven` ，如下图所示：

![image-20221226171336642](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-7a9fc088353c62104c108149fd3a66903939701a.png)

![image-20221226171432740](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a70707c613fcf54805517df4dfc16f8f218f0171.png)

2、点击create（在真实需求中，可以根据自己的项目，选择不同模板）。一个最基本的 Maven项目结构 如下图所示：

![image-20221226171614678](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e0898b70b0eecc2ba01166a22d74028187e66478.png)

常见JAVA项目架构示例
------------

#### **java 基础项目：一**

![image-20221226140921129](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-9e91a6a2290cfdb4f60c8ef4b05bb8c09a19860a.png)

- src目录为源码文件夹，存放的是.Java文件
- bin目录是工程输出路径，存放了编译生成的.class文件
- .project是项目文件，项目的结构都在其中定义，比如lib的位置,src的位置,classes的位置
- .classpath的位置定义了你这个项目在编译时所使用的$CLASSPATH

#### **java 基础项目：二**

![image-20221226155656384](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-d5a633a29046c20b71ae2369166badabbc6c34ca.png)

- src目录为源码文件夹，存放的是.Java文件
- External Libraries是运行Java程序所需要的依赖库

#### java web项目：一

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-257c962e4a39755ddbea7704519cb94d78b44892.png)

- src 和 src\_test

存放java 源程序，也就是你写的 java 代码，在这里为了便于管理把 src 一分为二，变成 src 和 src\_test。

- JRE System Library

存放Java SE 的常用库文件集合，也就是 jar 包

- Apache Tomcat v7.0

这个项目所依赖的服务器（Tomcat）的目录

- Web App Libraries

自己导入的项目依赖 jar 包

- Referenced Libraries

编译环境下使用的 jar 包

- build

eclipse新建的 Dynamic web project 默认是将类编译在 build 文件夹下。可以在本地的项目名\\build\\classes 下查看

- WebContent

存放 JSP，JS，CSS，图片等文件，是项目访问的默认路径，也是工程的发布文件夹

- common

存放公用的 JSP，JS，CSS，图片等文件

- META-INF

存放一些 meta information 相关的文件的这么一个文件夹, 一般来说尽量不要自己手工放置文件到这个文件夹。

- WEB-INF

WEB-INF 目录是一个专用区域， 容器不能把此目录中的内容提供给用户。这个目录下的文件只供容器使用，里面包含不应该由客户直接下载的资源

- web.xml

发布描述符是 J2EE Web 应用程序不可分割的一部分。它们在应用程序发布之后帮助管理 Web 应用程序的配置。

- Tomcat 目录结构

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a55b6ef053f4815b6458c563346f19694590169e.png)

#### java web项目：二（maven推荐的项目目录）

![image-20221226165324903](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-24938df55c6dfb595f9e13929e1554131b119d95.png)

maven官方推荐：<https://maven.apache.org/guides/introduction/introduction-to-the-standard-directory-layout.html>

大型项目应划分多个工程（project,模块），每个工程的目录结构也同样遵从相同约定。

程序目录结构应遵从maven默认约定（即使采用ANT构建），以统一规范，简化构建配置。一个典型的JavaEE应用（对应公司某产品、或某个项目的程序），目录结构如下：

| 目录 | 用途 |
|---|---|
| src/main/java | Application /Library 的java源代码（再分package） |
| src/main/flex | 增加：flex源码，包含mxml定义、assets和as脚本 |
| src/main/resources | Application/Library 的资源文件，如多字符集boundle，位图，配置文件等（单独建立conf等子目录） |
| src/main/resources/conf | 增加：准备封到JAR包中的配置文件（默认包下conf/目录） |
| src/main/filters | 【暂不用】Resource filter files |
| src/main/assembly | 【暂不用】Assembly descriptors |
| src/main/config | 【暂不用】maven配置文件 |
| src/main/webapps | Web 应用的网页，WEB-INF目录等所在，详见本表下方说明 |
|  |  |
| src/test/java | 单元测试的源代码 |
| src/test/resources | 测试使用的资源文件，如集成测试脚本等 |
| src/test/resources/conf | 增加：测试用例需要的配置文件 |
| src/test/filters | 【暂不用】Test resource filter files |
| src/site | 【暂不用】Site |
|  |  |
| target | maven编译目录，包含中间过程文件和最终的工件（如jar） |
|  |  |
| pom.xml | Maven工程的配置文件，以此控制maven构建行为 |
| LICENSE.txt | 产品/本工程的版权信息文件 |
| README.txt | 产品/本工程的说明文件 |

为规范war包结构，对src\\main\\webapp目录做如下约定：

| 目录 | 存放内容 |
|---|---|
| css | 存放.css格式文件（可再分目录） |
| skins | 存放皮肤文件（按主题划分的framework的位图） |
| images | 存放图片，按产品、功能模块划分子目录 |
| js | JavaScript文件（对象、函数库） |
| include | 存放被包含的JS文件片段【注：JSP文件互相不要包含，通过模板/组件/标签库/BEAN实现重用】 |
| resources | 存放JSF组件、相关资源等 |
| templates | 模板文件存放地，按类别划分子目录 |
| pages | 网页目录（静态和动态网页，除index.jsp），按产品、功能模块划分子目录 |
| webapp下其他目录 | 解释为模块名，认为其中全部为网页，可再分子目录 |
| META-INF | 存放清单文件、services等配置信息 |
| WEB-INF | 网站配置文件目录，存放WEB.XML等配置信息 |
| WEB-INF/classes | 未打包的项目编译代码，禁止手工修改。 |
| WEB-INF/conf | 存放struts,spring,hibernate,JSF等的配置文件 |
| WEB-INF/lib | 存放第三方JAR包，使用MAVEN构建时此目录禁止手动放入文件！ |
| WEB-INF/pages | 高安全性的网页目录，如登录信息维护等 |
| WEB-INF/tld | JSP标签库定义文件存放目录 |

#### java 微服务项目：zheng

> 微服务是一种架构模式，微服务简单来说就是功能模块拆分后可以单独负责唯一职责的微应用，也就叫微服务。多个负责自己专一功能的微服务放在一起就叫做服务集群。

基于Spring+SpringMVC+Mybatis分布式敏捷开发系统架构，提供整套公共微服务服务模块：集中权限管理（单点登录）、内容管理、支付中心、用户管理（支持第三方登录）、微信平台、存储系统、配置中心、日志分析、任务和通知等，支持服务治理、监控和追踪，努力为中小型企业打造全方位J2EE企业级开发解决方案。

<https://gitee.com/shuzheng/zheng>

![image-20221226165749018](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-413020b6a2e92bf557bf22823abb18e9dc90e23b.png)

组织架构：

zheng  
├── zheng-common -- SSM框架公共模块  
├── zheng-admin -- 后台管理模板  
├── zheng-ui -- 前台thymeleaf模板\[端口:1000\]  
├── zheng-config -- 配置中心\[端口:1001\]  
├── zheng-upms -- 用户权限管理系统  
| ├── zheng-upms-common -- upms系统公共模块  
| ├── zheng-upms-dao -- 代码生成模块，无需开发  
| ├── zheng-upms-client -- 集成upms依赖包，提供单点认证、授权、统一会话管理  
| ├── zheng-upms-rpc-api -- rpc接口包  
| ├── zheng-upms-rpc-service -- rpc服务提供者  
| └── zheng-upms-server -- 用户权限系统及SSO服务端\[端口:1111\]  
├── zheng-cms -- 内容管理系统  
| ├── zheng-cms-common -- cms系统公共模块  
| ├── zheng-cms-dao -- 代码生成模块，无需开发  
| ├── zheng-cms-rpc-api -- rpc接口包  
| ├── zheng-cms-rpc-service -- rpc服务提供者  
| ├── zheng-cms-search -- 搜索服务\[端口:2221\]  
| ├── zheng-cms-admin -- 后台管理\[端口:2222\]  
| ├── zheng-cms-job -- 消息队列、任务调度等\[端口:2223\]  
| └── zheng-cms-web -- 网站前台\[端口:2224\]  
├── zheng-pay -- 支付系统  
| ├── zheng-pay-common -- pay系统公共模块  
| ├── zheng-pay-dao -- 代码生成模块，无需开发  
| ├── zheng-pay-rpc-api -- rpc接口包  
| ├── zheng-pay-rpc-service -- rpc服务提供者  
| ├── zheng-pay-sdk -- 开发工具包  
| ├── zheng-pay-admin -- 后台管理\[端口:3331\]  
| └── zheng-pay-web -- 演示示例\[端口:3332\]  
├── zheng-ucenter -- 用户系统(包括第三方登录)  
| ├── zheng-ucenter-common -- ucenter系统公共模块  
| ├── zheng-ucenter-dao -- 代码生成模块，无需开发  
| ├── zheng-ucenter-rpc-api -- rpc接口包  
| ├── zheng-ucenter-rpc-service -- rpc服务提供者  
| └── zheng-ucenter-web -- 网站前台\[端口:4441\]  
├── zheng-wechat -- 微信系统  
| ├── zheng-wechat-mp -- 微信公众号管理系统  
| | ├── zheng-wechat-mp-dao -- 代码生成模块，无需开发  
| | ├── zheng-wechat-mp-service -- 业务逻辑  
| | └── zheng-wechat-mp-admin -- 后台管理\[端口:5551\]  
| └── zheng-ucenter-app -- 微信小程序后台  
├── zheng-api -- API接口总线系统  
| ├── zheng-api-common -- api系统公共模块  
| ├── zheng-api-rpc-api -- rpc接口包  
| ├── zheng-api-rpc-service -- rpc服务提供者  
| └── zheng-api-server -- api系统服务端\[端口:6666\]  
├── zheng-oss -- 对象存储系统  
| ├── zheng-oss-sdk -- 开发工具包  
| ├── zheng-oss-web -- 前台接口\[端口:7771\]  
| └── zheng-oss-admin -- 后台管理\[端口:7772\]  
├── zheng-message -- 实时通知系统  
| ├── zheng-message-sdk -- 开发工具包  
| ├── zheng-message-server -- 服务端\[端口:8881,SocketIO端口:8882\]  
| └── zheng-message-client -- 客户端  
├── zheng-shop -- 电子商务系统  
└── zheng-demo -- 示例模块(包含一些示例代码等)  
 ├── zheng-demo-rpc-api -- rpc接口包  
 ├── zheng-demo-rpc-service -- rpc服务提供者  
 └── zheng-demo-web -- 演示示例\[端口:9999\]

四、 IDEA调试
=========

一款好用的IDE(集成开发环境)将有效的提高代码操作效率，JAVA个人还是推荐IDEA作为IDE。

> 于2001年1月首发的IntelliJ IDEA，属于针对Java、Scala和Kotlin等JVM语言开发的Java IDE三大类。目前，它有两个功能强大的不同版本：Apache 2许可社区版和专用商业版本。它的实用功能包括：链完成、语言注入、静态成员完成、静态代码分析、以及代码智能完成。此外，通过插件，它可以扩展并获得多语言的体验，并能使用高级错误检查功能，来更快、更轻松地进行错误检查。

IDEA快捷键总结
---------

### 常用快捷键

| 快捷键 | 描述 |
|---|---|
| F7 | 步入 |
| F8 | 步过 |
| F9 | 下一个断点 |
| 双击Shift | 查找任何内容，可搜索类、资源、配置项、方法等,还能搜索路径 |
| ALT+F8 | 评估表达式 |
| Ctrl+F | 文件内查找字符串 |
| Ctrl + Shift + F | 按照文本的内容查找 |
| Ctrl + N | 按类名搜索类 |
| Ctrl + F12 | 查看当前类结构 |
| Ctrl + H | 查看类的层次关系 |
| Alt + F7 | 查找类或方法在哪被使用 |
| Ctrl+P | 显示参数提示 |

![image-20221121153045006](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a72b1cf65f89e02a91960d5128d92065a46f2dbd.png)

### 搜索类快捷键

| 快捷键 | 描述 |
|---|---|
| Ctrl + F | 文件内查找字符串 |
| Ctrl + Shift + F | 按照文本的内容查找 |
| `双击Shift` | 查找任何内容，可搜索类、资源、配置项、方法等，还能搜索路径 |
| Ctrl + Shift + R | 全局资源查找和替换 |
| `Ctrl + N` | 按类名搜索类，比如 Java，Groovy，Scala 等类文件 |
| Ctrl + Shift + N | 按文件名搜索所有文件，可以使用"hello.java:111"直接跳转到hello.java的111行 |
| Ctrl + Shift + Alt + N | 符号搜索，包括接口名，类名，函数名，成员变量等 |
| **Ctrl + Shift + A** | 可以查找所有Intellij的命令，并且每个命令后面还有其快捷键 |

### 查看类快捷键

| 快捷键 | 描述 |
|---|---|
| Alt + Q | 查看类定义信息 |
| Ctrl + P | 查看参数定义 |
| Ctrl + Q | 查看Documentation |
| `Ctrl + F12` | 查看当前类结构 |
| Ctrl + Shift + V | 查看剪贴板 |
| `Ctrl + H` | 查看类的层次关系 |
| Ctrl + Shift + H | 查看方法的层次关系 |
| Ctrl + Alt + H | 查看方法的调用层次结构 |
| Ctrl + Shift + I | 弹框查看方法实现 |
| **Alt + F7** | 查找类或方法在哪被使用 |
| Ctrl + *-* | 折叠代码 |
| Ctrl + *+* | 展开代码 |
| Ctrl + Shift + *-* | 折叠当前类的所有方法 |
| Ctrl + Shift + *+* | 展开当前类的所有方法 |
| Alt + Num | 切换窗口，常用的有1-项目结构，3-搜索结果，4/5-运行调试 |
| Ctrl + Tab | 切换标签页 |
| Ctrl + E / Ctrl + Shift + E | 打开最近打开过的或编辑过的文件 |
| F11 | 添加、取消书签 |
| Ctrl + F11 | 带标志的书签 |
| Shift + F11 | 查看所有书签 |

### 编辑类快捷键

| 快捷键 | 描述 |
|---|---|
| Ctrl + Z | 撤销 |
| Ctrl + Shift + Z | 取消撤销 |
| Ctrl + X | 剪切行 |
| Ctrl + C | 复制 |
| Ctrl + V | 粘贴 |
| Ctrl + R | 替换 |
| `CTRL + D` | 拷贝当前行到下一行 |
| Ctrl + Y | 删除当前行 |
| Ctrl + W | 自动按语法选中代码 |
| Ctrl + Shift + W | 反向自动按语法选中代码 |
| Delete | 删除 |
| Alt + Delete | 带检查的安全删除，可用于方法 |
| **Ctrl + Shift + U** | 英文大小写切换 |
| Ctrl + O | 覆盖父类方法 |
| Ctrl + I | 实现接口方法 |
| `Alt + Enter` | 最常用的快捷键，含包选择导入，帮助创建等 |
| `Ctrl + Shift + Space` | 智能补全 |
| `Ctrl + Shif t +Enter` | 自动补全末尾的字符 |
| Alt + Insert | 在包中就是选择文件类型用于新建；在文件中就是添加构造器，Getter/Setter,toString实现等 |
| Ctrl + Alt + Insert | 在当前文件夹下选择文件类型用于创建 |
| Ctrl + Alt + T | 选择并进行代码包围 |
| `Ctrl + J` | 插入Live Template，比如main方法，我直接Ctrl + J，然后输入main回车就会自动补全main()方法 |
| Ctrl + Alt + J | 选择Live Tmeplate |
| `Ctrl + 斜杠` | 单行注释 |
| `Ctrl + Shift + 斜杠` | 多行注释 |
| **Ctrl + Alt + L** | 格式化代码 |
| `Ctrl + Alt + O` | 格式化import列表，去掉未使用的导包 |
| **Ctrl + Shift + ↑** | 整行（方法）上移 |
| **Ctrl + Shift + ↓** | 整行（方法）下移 |
| Ctrl + Shift + J | 转换为单行连接 |
| Ctrl + Delete | 从光标处往后删除 |
| Ctrl + Backspace | 从光标处往前删除 |

### 定位类快捷键

| 快捷键 | 描述 |
|---|---|
| `F2` | 定位到下一处的错误地方 |
| `Shift + F2` | 定位到上一处的错误地方 |
| F3 | 移动到下一处匹配 |
| Shift + F3 | 移动到上一处匹配 |
| `Ctrl + B或Ctrl+鼠标左键` | 跳转声明处 |
| **Ctrl + Alt + B** | 跳转到实现处 |
| **Ctrl + G** | 跳转到指定的行 |
| Alt + Shift + Enter | 将光标定位到上一行 |
| Shift + Enter | 将光标定位到下一行 |
| Alt + ↑或↓ | 上一个方法或下一个方法 |
| `Alt + ←或→` | 切换到左边窗口或右边窗口 |
| **Ctrl + ←或→** | 移动光标到前/后单词 |
| **Ctrl + Shift + ←或→** | 选择光标前/后单词 |
| Ctrl + Alt + ← | 跳转上一次光标所在的位置 |
| Ctrl + Alt + → | 跳转下一次光标所在的位置 |
| Ctrl + Shift + Alt + ↑ | 定位到上一处修改过的地方 |
| Ctrl + Shift + Alt + ↓ | 定位到下一处修改过的地方 |
| Ctrl + \[ | 将光标定位到代码块开始处 |
| Ctrl + \] | 将光标定位到代码块结尾处 |
| Ctrl + U | 跳转到父类 |
| Ctrl + Shift + Alt + U | 图表方式查看继承结构 |
| Ctrl + Alt + Home | 跳转项目的启动、入口类，如Junit测试类与被测试的类之间跳转 |
| Alt + Home | 跳转顶部的项目导航条 |
| End | 光标移到末尾 |
| Home | 光标移到行首 |

### 选择类快捷键

| 快捷键 | 描述 |
|---|---|
| `Alt + J` | 选中下一处当前选择的内容 |
| Shift + Alt + J | 取消选中下一处当前选择的内容 |
| Ctrl + Alt + Shift + J | 全部选中当前文件中当前选择的内容 |
| **Ctrl + Tab** | 切换操作页面 |
| Ctrl + E | 最近操作过的文件列表 |
| Ctrl + Shift + E | 最近修改过的文件列表 |
| Ctrl + A | 选择当前全部 |
| Ctrl + W | 逐层往外扩展并选中内容 |
| Ctrl + Shift + W | 取消逐层往外扩展选中的内容 |
| Ctrl + Shift + ← | 从光标处起，依次往左选中内容 |
| Ctrl + Shift + → | 从光标处起，依次往右选中内容 |
| Shift + Home | 从光标处起，一次选中至本行的头部 |
| Shift + End | 从光标处起，一次选中至本行的尾部 |

### 窗口切换快捷键

| 快捷键 | 描述 |
|---|---|
| Ctrl + F4 | 关闭当前Tab |
| Ctrl + Shift + \] | 切换到下一个项目 |
| Ctrl + Shift + \[ | 切换到上一个项目 |
| Shift + ESC | 关闭、隐藏当前面板 |
| Ctrl + Shift + F12 | 关闭、隐藏所有面板 |

### 新建类快捷键

| 快捷键 | 描述 |
|---|---|
| Alt + Insert | 可以新建类、方法等任何东西 |
| Ctrl + Alt + T | 创建单元测试用例 |

### 运行调试类快捷键

| 快捷键 | 描述 |
|---|---|
| Shift + F10 | 普通运行当前 |
| Shift + F9 | Debug运行当前 |
| Alt + Shift + F10 | 普通运行所选 |
| Alt + Shift + F9 | Debug运行所选 |
| Ctrl + F2 | 停止当前运行 |
| F8 | 跳到下一步 |
| Ctrl + F8 | 添加、取消断点 |
| Ctrl + Shift + F8 | 查看所有断点 |
| Alt + Shift + F8 | 强制跳到下一步 |
| F7 | 进入代码内部 |
| Shift + F8 | 退出代码内部 |
| F9 | 断点调试的Continue |
| Alt + F9 | 运行到光标处 |
| Ctrl + Alt + F9 | 强制运行到光标处 |
| Ctrl + F9 | 编译项目 |
| Ctrl + Shift + F9 | 编译当前 |

### 文件操作快捷键

| 快捷键 | 描述 |
|---|---|
| F5 | 复制当前文件 |
| F6 | 移动当前文件 |
| Ctrl + C | 复制文件名 |
| Ctrl + Shift + C | 复制文件的完整路径 |

### 重构快捷键

| 快捷键 | 描述 |
|---|---|
| F5 | 拷贝 |
| F6 | 移动 |
| Shift + F6 | 重命名 |
| Ctrl + Alt + Shift + T | 重构汇总，重构当前 |
| Ctrl + Alt + V | 抽取变量 |
| Ctrl + Alt + C | 抽取常量 |
| Ctrl + Alt + F | 抽取字段 |
| Ctrl + Alt + P | 抽取参数 |
| Ctrl + Alt + M | 抽取方法 |
| Ctrl + Alt + N | 内联 |
| Ctrl + F6 | 修改签名 |

### 版本控制快捷键

| 快捷键 | 描述 |
|---|---|
| `Alt + 反引号` | VCS操作 |
| Ctrl + T | 拉取远程仓库 |
| Ctrl + K | 提交本地暂存区 |
| Ctrl + M | 查看提交信息历史列表 |
| Ctrl + Alt + A | 添加版本控制 |
| Ctrl + Shift + K | 提交远程仓库 |
| Ctrl + Alt + Z | 撤销当前的修改 |
| Ctrl + Enter | commit、提交 |
| Alt + Shift + C | 查看最近的修改 |

Debug调试基本信息
-----------

代码审计第一步，要熟练使用debug调试。

> Debug用来追踪代码的运行流程，通常在程序运行过程中出现异常，启用Debug模式可以分析定位异常发生的位置，以及在运行过程中参数的变化；并且在实际的排错过程中，还会用到Remote Debug。
> 
> debug调试又名断点调试，它指的是在程序指定位置设置断点，当程序运行到这个断点时会暂停执行并保留当前状态，我们可以通过查看`暂停时的程序状态来定位和排查问题`。
> 
> Debug调试大致分为本地调式和远程调试，本地调试一般用于CMS、框架等等，远程调试一般用于中间件、web服务器等等。

### Debug 开篇

#### 自动激活Debug窗口

在设置里勾选Show debug window on breakpoint，则请求进入到断点后自动激活Debug窗口

![image-20221128204110366](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1dcb169c5edda0e610d776f886c8515534a70f0c.png)

#### 工具栏或状态栏

如果你的IDEA底部没有显示工具栏或状态栏，可以在View里打开，显示出工具栏会方便我们使用。可以自己去尝试下这四个选项。

![image-20221128204157279](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-3d09e8aaaff73227f09810bc6f2baad8e888883d.png)

#### **Debug模式启动：**

IDEA中以绿色的甲虫图标来显示该服务，启动后就可以进行调试了。

![image-20221121183821618](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-4abd4a9207e300a92789073f25234bb0357ac0db.png)

![image-20221121211053367](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-df7411e591506248b5b29f3b93a3e999436b8652.png)

#### **断点：**

在左边行号栏单击左键，或者快捷键Ctrl+F8 打上/取消断点，断点行的颜色可自己去设置。

![image-20221121210515456](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-318d7dbf5ab28271ab367df11d30e4c6df78d8bd.png)

#### **Debug窗口：**

访问请求到达第一个断点后，会自动激活Debug窗口。如果没有自动激活，可以去设置里设置。

![image-20221122151324422](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-10096fb39fddb0a91779d05e3006762663f596e8.png)

#### **调试按钮：**

一共有8个按钮，调试的主要功能就对应着这几个按钮，鼠标悬停在按钮上可以查看对应的快捷键。在菜单栏Run里可以找到同样的对应的功能。

![image-20221122150316291](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-8580271692590a05c405651fcb3066ec34b103b1.png)

从左到右依次如下：

`Show Execution Point` (Alt + F10)：如果你的光标在其它行或其它页面，点击这个按钮可跳转到当前代码执行的行。

`Step Over` (F8)：步过，一行一行地往下走，如果这一行上有方法不会进入方法。

`Step Into` (F7)：步入，如果当前行有方法，可以进入方法内部，一般用于进入自定义方法内，不会进入官方类库的方法，如第25行的put方法。

`Force Step Into` (Alt + Shift + F7)：强制步入，能进入任何方法，查看底层源码的时候可以用这个进入官方类库的方法。

`Step Out` (Shift + F8)：步出，从步入的方法内退出到方法调用处，此时方法已执行完毕，只是还没有完成赋值。

`Drop Frame` (默认无)：回退断点。所谓的断点回退，其实就是回退到上一个方法调用的开始处，在IDEA里测试无法一行一行地回退或回到到上一个断点处，而是回到上一个方法。

> 回退的方式有两种，一种是Drop Frame按钮，按调用的方法逐步回退，包括三方类库的其它方法，第二种方式，在调用栈方法上选择要回退的方法，右键选择Drop Frame，回退到该方法的上一个方法调用处，此时再按F9(Resume Program)，可以看到程序进入到该方法的断点处了。
> 
> 断点回退只能重新走一下流程，之前的某些参数/数据的状态已经改变了的是无法回退到之前的状态的，如对象、集合、更新了数据库数据等等。

`Run to Cursor` (Alt + F9)：运行到光标处，你可以将光标定位到你需要查看的那一行，然后使用这个功能，代码会运行至光标行，而不需要打断点。

`Evaluate Expression` (Alt + F8)：计算表达式,可以使用这个操作在调试过程中计算某个表达式的值，而不用再去打印信息。

#### **服务按钮：**

可以在这里关闭/启动服务，设置断点等。

![image-20221122151336036](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-3c6215fc88db802c27af21eb57f7b9ece942af6d.png)

`Rerun 'xxxx'`：重新运行程序，会关闭服务后重新启动程序。

`Update 'tech' application` (Ctrl + F5)：更新程序，一般在你的代码有改动后可执行这个功能。而这个功能对应的操作则是在服务配置里，如图2.3。

`Resume Program` (F9)：恢复程序，比如，你在第20行和25行有两个断点，当前运行至第20行，按F9，则运行到下一个断点(即第25行)，再按F9，则运行完整个流程，因为后面已经没有断点了。

`Pause Program`：暂停程序，启用Debug。目前没发现具体用法。

`Stop 'xxx'` (Ctrl + F2)：连续按两下，关闭程序。有时候你会发现关闭服务再启动时，报端口被占用，这是因为没完全关闭服务的原因，你就需要查杀所有JVM进程了。

`View Breakpoints` (Ctrl + Shift + F8)：查看所有断点，后面章节会涉及到。

`Mute Breakpoints`：哑的断点，选择这个后，所有断点变为灰色，断点失效，按F9则可以直接运行完程序。再次点击，断点变为红色，有效。如果只想使某一个断点失效，可以在断点上右键取消Enabled，则该行断点失效。

> 在菜单栏Run里有调试对应的功能，同时可以查看对应的快捷键。
> 
> ![image-20221128204241135](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-6bd2fdd7a5198c78902f7d2bc6d7207166387d2e.png)

#### 方法调用栈：

这里显示了该线程调试所经过的所有方法，勾选右上角的`[Show All Frames]`按钮，就不会显示其它类库的方法了，否则这里会有一大堆的方法。

![image-20221122151718497](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-87959d6565517062fd08ed0d19ff419b750b8d5c.png)

#### **Variables：**

在变量区可以查看当前断点之前的当前方法内的变量情况。

![image-20221122151759981](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-9352b13e4444df1abcaf9c4c4475981985309dc2.png)

#### **Watches：**

查看变量，可以将Variables区中的变量拖到Watches中查看

高版本idea将Variables和watches做了整合，只需要不勾选`Show Watches in Variables Tab`即可查看独立的Watches窗口：

![image-20221128202837817](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b9bbd1be0c7c5c18780449d215f573c07151b335.png)

新增一个`Watch`元素username后即可在 Wathces窗口中查看到。

![image-20221128203138143](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-2d7c73b4f1e6d67985d0cc8fa7f02efe783c47ef.png)

### 断点管理界面

> 对话框默认快捷键是：`Ctrl + Shift +F8`，在这里你可以`管理`你**所有的**断点（增删改）

![image-20221123165311545](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a8c693b06e5813cf259635ff36ed61b8c4edc2e2.png)

### 断点概念

**断点：**是一种附加在源代码特定点上面暂停程序执行的`特殊标记`。在`调试模式（debug）`下可以触发`特定的动作`，比如打印线程调用栈信息、计算值、打印指定表达式的指、检查当前程序状态和行为等等。

> tips:
> 
> - 断点一旦设置就会一直保存在工程中直到手工删除，临时断点除外。
>     
>     
>     - 在 IDEA 中，默认断点将会一直存在。有时候仅仅想需要暂停第一次，临时查看，这个时候我们可以使用临时断点。使用快捷键 Ctrl + Alt + Shift +F8 可以快速创建临时断点或者按住 ALt，然后再创建断点。
> - 断点必须在调试模式（debug模式）下生效。
> - 如果带有断点的文件在外部进行了修改，例如，通过 VCS 更新或在外部编辑器中更改，并且行号已更改，则断点将相应地移动。请注意，进行此类更改时，IntelliJ IDEA必须运行，否则它们将被忽略。.
>     
>     如：skip all breakpoints
>     
>     ![image-20221128193525065](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-78737ba8b82b731cf0d074849f46b5de7e3f4aa4.png)

### 断点类型

IDE 中通常会提供几种类型的断点：

| Line breakpoint（行断点） | Method breakpoint（方法断点） | Field watchpoint（变量断点） | Exception breakpoint（异常断点） | Temporary line breakpoint（临时行断点） |
|---|---|---|---|---|
|  |  |  |  | 勾选Remove once hit属性 |

`Line breakpoint（行断点）`：在指定代码行设置断点，属于行级别的断点，设置在任意可执行的代码行上面。

`Temporary line breakpoint（临时行断点）`：与行断点类似，不同之处在于该类型的断点在被激活之后会被立即删除

`Field watchpoint（变量断点）`：读取或者修改属性时会激活属性断点，读取监控，监控其整个生命周期值的变化

`Method breakpoint（方法断点）`：它是标记在方法那一行的断点，有自己特有的属性参数，`断点运行后会自动跳转到对应的实现类`

`Exception breakpoint（异常断点）`：当程序抛出指定异常时会激活异常断点。与行断点不同，异常断点不需要与源代码映射（不需要打在具体某一行代码上），因为`异常断点是应用程序级别的`

![image-20221128193640333](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-29c02af7a6ff8c2451f22cedce60998371c08e69.png)

![image-20221128193746019](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-eaabaf31230087ce3dc52774cf392f6dff955d36.png)

### 断点参数（属性）

断点可以通过设置不同的`参数（属性）`进行定制化，这些叫`断点参数（属性）`。**不同类型的断点支持的断点参数（属性）也不尽相同**。

> 在断点管理界面即可设置断点参数（属性）。

#### **`Line breakpoint（行断点）`**

![image-20221128190940623](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-f1ec2ff14c537e9de4006fb09e003541e78cf950.png)

存在以下属性：

Suspend：有没有让你诧异到，它竟然是个复选框并且还可以不被选中。若它不被选中的话断点的相关动作依然激活执行，只是线程不会被组塞了而已。它的两种阻塞策略如下：  
\- All：阻塞该程序内所有线程（默认）  
\- Thread：只阻塞当前断点所在线程（在多线程调试、远程调试中强烈建议使用这种方式）  
Condition：这就是所谓的条件断点，只有书写的表达式返回true时候断点才会被激活  
Log：  
\- 勾选"Breakpoint hit message"：断点激活时输出提示日志  
\- 勾选"Stack trace"：断点激活时输出程序调用栈信息  
\- 勾选"Evaluate and log"：并在下面的输入框中输入"args"，断点激活时会计算并输出变量 args 的值  
\- 他哥三是可以同时被勾选的（因为都是复选框~）

#### `Temporary line breakpoint（临时行断点）`

把`Remove once hit`这个复选框给勾选上（此类型断点其实使用较少）

![image-20221128191406332](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-5018c74708c43ee8ca1d6b2ec4a0dcbf2679b2ba.png)

#### `Field watchpoint（属性断点）`

![image-20221128191531256](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-eca5f006d2e593350907a046de83509cd5ddcb13.png)

独有属性：

`Watch`：选中"Filed Access" 读取的时候都会断住。选中"Filed madification"表示修改的时候都会断住

#### `Method breakpoint（方法断点）`

![image-20221128191925240](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-efc9e7c24b3e5f789404dbc29b5b3c97aa91ee34.png)

独有属性

 Watch：  
\- “Method entry”：进入方法时激活断点  
\- “Method exit”：出去方法时激活断点  
\- “Emulated”：会将方法断点优化成方法中第一条和最后一条语句的行断点，这样会优化调试的性能，因此在IDE中会默认选中，但在调试native方法或者没有行号信息的远程代码时不要勾选此选项

#### `Exception breakpoint（异常断点）`

异常断点属于非常特殊的一种断点类型，`它不对应任何一行代码`，因为它属于**程序级别的断点**。 它不能像上面在代码处直接创建，只能通过上面的断点对话框来创建。

![image-20221128192545207](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1c42615e31ae0b28bb51022d9d498a2af98e7390.png)

当程序抛出相对应的异常时将会触发，作用范围为全局，图标为红色闪电。

![image-20221128192727559](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-388c9f72ee597e9fc773e5282beb2428204aad4c.png)

独有属性：

Notification：  
\- “Catch excetion”：程序在捕获（Try Catch）这个异常时激活断点  
\- “Uncatch excetion”：不catch捕获异常时激活断点

### 断点的状态

IDE中的断点状态通常分为八种，分别对应不同的情景。

![image-20221128194022393](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-07a0c1f0c2569b956569b154089da57f96b0025d.png)

- **常规状态**：默认（原始）状态。
- **禁用状态**：断点暂时处于禁用状态，不会被执行。
- **已验证状态**：编译器会检查断点的设置是否合理。如果是，则将断点标记为已验证。
- **静音状态**：断点暂时处于静音状态，不会被执行；其与禁用状态功能类似，不同点在于使用场景。
- **依赖状态**：当一个断点的触发依赖于另一个断点时，显示为依赖状态。
- **挂起状态**：挂起状态有两种类型，第一种是挂起全部线程，第二种是只挂起当前线程。当断点状态设置成了第二种方式后，只有当前线程会被堵塞，其他线程（程序）会正常执行，这在Spring Boot程序的测试中十分有用。
- **无效状态**：断点的设置不是合理的，被标记的代码永远不可能被执行到。
- **警告状态**： 如果断点的设置是合理的，但是存在其他问题，则编译器会向您发出警告。例如当被标记的方法可能不会被执行到时。

### 条件断点

就是断点在满足条件的时候才会阻塞，不过一般也只能书写一些较简单的判定

![image-20221128194925296](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-320b5752ed08f527b72e48029e20f98894debd11.png)

### 中断断点

点击右键，有一个Force Return，然后再点击Resumer Program，就可以直接终止返回了。

### 远程调试

#### 什么是远程调试

所谓的远程调试就是服务端程序运行在一台远程服务器上，我们可以在本地服务端的代码（**前提是本地的代码必须和远程服务器运行的代码一致**）中设置断点，每当有请求到远程服务器时时能够在本地知道远程服务端的此时的内部状态。

> 简单的意思：本地无需启动项目的状态下能够实时调试服务端的代码

#### 为什么要远程调试

远程调试是调试分布式系统的一个利器。因为现在都以微服务部署，你不可能在本地同时启动N个服务来做本地调试。

更重要的是如果测试时候测出发现你的bug，这时候你若想定位问题，通过远程调试直接连接到测试服务（甚至是线上服务）不失为一种最为高效的解决方案，并且它还能有非常好的保护现场的辅助能力~

#### 开启远程调试

启动远程调试主要分两步： ![image-20221128195153806](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-cbbf3ec5ad68bdb3f775d387f12018470c9c6bad.png)

`第一步：要让远程服务器运行的代码支持远程调试，也就是启动的时候必须加上特定的JVM参数：`

1. java -agentlib:jdwp\\=transport\\=dt\_socket,server\\=y,suspend\\=n,address\\=${debug\_port} demo.jar (适用于JDK8以上)  
    ​
2. java -Xdebug -Xrunjdwp:transport\\=dt\_socket,suspend\\=n,server\\=y,address\\=${debug\_port} demo.jar（适用于JDK8以下）  
    ​

`第二步：idea使用remote链接远程端口（注意ip:port要对应上）：”Edit Configurations” -> “Remote” 配置好后debug启动~~~`

当你看到控制台这样的字样，就证明你链接成功了，进而你可以像调试本地代码一样随意的打各种类型的断点进行调试了~ ![image-20221128195203437](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-5fba34940542992f72356da698e67de6dd256877.png)

> 需要注意的是：远程调试时请确保你本地的代码和远程的一模一样。

参考:

<https://blog.csdn.net/f641385712/article/details/93145454>

<https://blog.csdn.net/pastxu/article/details/124413443>

漏洞调试技巧
------

本地调试-Log4j调试
------------

**漏洞利用简记：**

1. 启动web服务A
2. 将恶意类放在web服务A目录下
3. 利用漏洞加载A服务下恶意类，执行恶意类
    
    
    1. 加载分为远程加载和本地加载
    2. 加载类，一般就在后台后端去执行
    3. 远程时可能会因为jdk版本出现无法加载类，rmi、ldap无法使用等。

**本地调试：**

通过断点main去发现具体实现流程。

**漏洞触发路径如下所示：**

1、获取Logger，并调用error方法

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-4c38c212eb5434c9187e810409875d866fd6a13d.png)

2、error方法内会调用logIfEnabled方法，注意，debug、info、warn、error、fatal等公共API都会调用logIfEnabled方法

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-08be5d1e144b80e875b2e4c7abfd409fc3b7b884.png)

3、logIfEnaled方法会调用logMessage方法

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-0b970d2a07a8da84d410261dc15e4814e9bc5d81.png)

4、接着会根据进入下列调用链：

logMessageSafely-&gt; logMessageTrackRecursion -&gt;tryLogMessage-&gt;Logger.log-&gt; DefaultReliabilityStrategy.log-&gt; LoggerConfig.log-&gt;processLogEvent-&gt;callAppenders-&gt; callAppenderPreventRecursion -&gt; callAppender0 -&gt; tryCallAppender -&gt; append -&gt; tryAppend -&gt; directEncodeEvent -&gt;PatternLayout.encode-&gt;toText-&gt;toSerializable-&gt; PatternFormatter.format ，这里主要功能就是通过遍历formatters一段一段的拼接输出的内容，当格式化完成后，最终会调用MessagePatternConverter类的converter.format()方法，当日志字串带有**”${”**的时候会特殊处理，将输入内容从workingBuilder分割出来，赋值给value，然后调用config.getStrSubstitutor().replace()方法。

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-0c59f5aa9243466f69ce3953d90834987199773f.png)

5、字串会交给StrSubstitutor做replace -&gt; substitute处理，首先遍历字符，通过正则判断，获取 **“${”** 对应的 **“}”**的位置， 并提取中间的字串，，得到“**jndi:xxx**”

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-4698789f65d108e5515b27624718be9b76d22f0f.png)

![image-20230106222544076](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1ac4a5b86c97dff8569902069219eba85ea312b5.png)

后续再进行递归调用substitute()，继续截取${}中的内容，是否还有${}，以及分隔符之类的判断。

6、Substitute方法会调用resolveVariable，

![image-20230106223010209](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-07ac9feb91df8a330610e3696e862758fc96189d.png)

这里可以看到resolver所支持的关键词{date……}

![image-20230106220302324](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-35d6737679b0ca7f8c93b651881c0a19b9958bb6.png)

payload用的jdni:xxx，所以这里后续会用到JndiLookup这个解析器

![image-20230106223419147](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1c298485151f2d5b8c8adfbcc44871379ae9445c.png)

7、跟进调用的Interpolator类的lookup方法，可以看到这里先分割前面的关键词jndi部分和后面的payload内容部分，再去获取解析器，最后通过解析器去lookup

![image-20230106223722328](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b36f129726c56e1744739cd77756940088a182df.png)

8. 持续跟进代理，调用JndiLookup类的lookup方法，这里会初始化JNDI客户端，再去调用jnidManager.lookup方法。

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-38e0a63581167c372a767af20ac24d3ab44c0284.png)

7、最后jndiManager的lookup方法会解析jndi资源，也就是jdni注入内容了。这里"xxx"是一个dnslog地址，如果“xxx“部分是可执行的恶意程序，那么该程序将会被执行，从而产生非常严重的危害。

![](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-669b9fbdb80061bc621fdf7db8ebf81e818dfef4.png)

![image-20230106224710649](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-c6b844c0157ca103c053891ad60d5d325e3c1ab3.png)

调试完成，显示易见的，通过调试可以理清代码执行流程、定位问题点。

远程调试-Hack-javasec
-----------------

> springboot项目debug调试
> 
> 实现web服务运行中进行debug调试

附（一）、资料：
========

### 一些资料

- java web安全-园长

<https://www.javasec.org/>

- java安全的一些总结，主要是安全审计相关

<https://github.com/Maskhe/javasec/>

- 代码审计指南

<https://xu-an.gitbook.io/sec/lan/java/zhinan#2.-shu-ju-xiao-yan-lei-lou-dong>

- 我正在「炼石计划@Java代码审计」和朋友们讨论有趣的话题，你⼀起来吧？

<https://t.zsxq.com/08en3X3L6>

- fortify 代码分析规则

<https://vulncat.fortify.com/zh-cn/weakness?q=>

- jdk版本下载

[https://www.azul.com/downloads/?version=java-7-lts&amp;architecture=x86-64-bit&amp;package=jdk&amp;show-old-builds=true](https://www.azul.com/downloads/?version=java-7-lts&architecture=x86-64-bit&package=jdk&show-old-builds=true)

- Spring Boot 相关漏洞学习资料，利用方法和技巧合集，黑盒安全评估 check list

<https://github.com/LandGrey/SpringBootVulExploit>

- snyk漏洞库

<https://security.snyk.io/vuln?search>

- 国家信息安全漏洞共享平台

<https://www.cnvd.org.cn/flaw/list>

- tide漏洞情报平台（整合cve、cnvd、cnnvd等主流漏洞库）

<http://vul.tidesec.com/>

- fortify
    
    
    - 基本使用
        
        [https://mp.weixin.qq.com/s/thMx\_85LC4KGTbaCal09JA](https://mp.weixin.qq.com/s/thMx_85LC4KGTbaCal09JA)
    - 自定义规则： <https://blog.csdn.net/liweibin812/article/details/87274054>
    - 扫描Android项目 [https://blog.csdn.net/weixin\_36087674/article/details/112102571](https://blog.csdn.net/weixin_36087674/article/details/112102571)
- checkmarx
    
    
    - 基本使用
        
        <https://mp.weixin.qq.com/s/pjQd7AKTn8G4hjCkLEVmFg>

### 一些项目：

- **迷你天猫商城**

链接：<https://pan.baidu.com/s/1bdoakek5JYP9MRrYgMSLsw> 提取码：y39z

- **java漏洞靶场**

<https://github.com/tangxiaofeng7/SecExample>

- **Java漏洞平台，结合漏洞代码和安全编码，帮助研发同学理解和减少漏洞，代码仅供参考** <https://github.com/j3ers3/Hello-Java-Sec>
- **java-sec-code**

<https://github.com/JoyChou93/java-sec-code>

- **常用漏洞复现环境：**
    
    
    - [Vulhub](https://github.com/vulhub/vulhub)
    - [VulFocus](https://github.com/fofapro/vulfocus)
- **Github标签**

<https://github.com/topics/javaweb>

### 相关标准

- **Java语言源代码漏洞测试规范 GB/T 34944-2017**

<http://www.gb688.cn/bzgk/gb/newGbInfo?hcno=6B5F14F93B5FEBF63C631A17903EA29D>

- 引用

> 《中华人民共和国网络安全法》
> 
> 《网络安全等级保护基本要求》国家推荐标准GB/T22239-2019
> 
> 《信息安全技术 信息安全等级保护基本要求》国家推荐标准GB/T 22239 2008 国家信息安全漏洞库分类(已获得CNNVD兼容性资质认证)
> 
> 《 C/C++语言 源代码漏洞测试规范》国家推荐标准GB/T 34943-2017
> 
> 《Java语言 源代码漏洞测试规范》国家推荐标准GB/T 34944-2017
> 
> 《Java语言 源代码缺陷控制与测试指南》行业推荐标准SJ/T 11683-2017
> 
> 《C/C++语言 源代码缺陷控制与测试指南》行业推荐标准SJ/T 11682-2017
> 
> Cert Java(国际规范)
> 
> Cert C/C++(国际规范)

### 参考信息：

[https://blog.csdn.net/weixin\_53798995/article/details/127555808?spm=1001.2101.3001.6650.2&amp;utm\_medium=distribute.pc\_relevant.none-task-blog-2%7Edefault%7EYuanLiJiHua%7EPosition-2-127555808-blog-123262568.pc\_relevant\_aa&amp;depth\_1-utm\_source=distribute.pc\_relevant.none-task-blog-2%7Edefault%7EYuanLiJiHua%7EPosition-2-127555808-blog-123262568.pc\_relevant\_aa](https://blog.csdn.net/weixin_53798995/article/details/127555808?spm=1001.2101.3001.6650.2&utm_medium=distribute.pc_relevant.none-task-blog-2~default~YuanLiJiHua~Position-2-127555808-blog-123262568.pc_relevant_aa&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2~default~YuanLiJiHua~Position-2-127555808-blog-123262568.pc_relevant_aa)

<https://pdai.tech/md/java/jvm/java-jvm-debug-idea.html>

<https://blog.csdn.net/f641385712/article/details/93145454>