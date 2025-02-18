> 本篇文章是Android逆向系列的第二篇，是一篇安卓工具的总结，涉及到开发工具、逆向分析工具、动态调试工具、安卓模拟器和抓包工具五个部分。从Android Killer的逆向分析到JEB的动态调试，再到后面BurpSuite和Fiddler抓取HTTP和HTTPS包，每一个过程都详细的介绍到，为之后的进一步学习铺好基础。

一、安卓开发工具
--------

安卓开发工具主要是一些Java开发环境、集成开发环境和安卓开发环境等

### 1、JDK和JRE

可以去官网下载，选择jdk8u111版本进行安装

JDK：Java Development Kit是Java的开发工具包，JDK包含了JRE，同时还包含了编译java源码的编译器javac，还包含了很多java程序调试和分析的工具。

JRE： Java Runtime Environment是Java运行时环境，包含了java虚拟机，java基础类库

**安装过程：**

**1）双击启动安装程序**

![h1OGMF.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-287c05202bce1a106007c7257bed89c010f01d2c.png)

**2）默认安装路径**

![h1OK5q.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-461c58c302008c6a5ba7c93d3cbf306a7a30ebce.png)

**3）jre路径选择**

![h1OQP0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3a8ddb3faf8e3c029901f7348d453efcd19922c8.png)

**4）配置环境变量**

```php
JAVA_HOME
C:\Program Files\Java\jdk1.8.0_111
```

![h1O12T.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d6da13a8a0332c7f222efe0c74e78b6eb61c6340.png)

```php
%JAVA_HOME%\bin
```

![h1OlGV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-99857b32c1f8b90e39ae30a3b5955b7aa9b79efa.png)

```php
C:\Program Files\Java\jre1.8.0_111\bin
```

![h1O3xU.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b7f1490f4a0d6bc132f10c835b3f6f7ae4abd0ae.png)

### 2、adt-bundle

`adt-bundle`用于在Windows操作系统上搭建安卓开发环境

下载地址：[http://dl.google.com/android/adt/adt-bundle-windows-x86\_64-20140702.zip](http://dl.google.com/android/adt/adt-bundle-windows-x86_64-20140702.zip)

直接下载下来拷贝至C盘即可

### 3、Eclipse

在`adt-bundle`中配带了`Eclipse`

1）双击启动

![h37G8S.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7d945e0a7006d964061a3b7e78b98a5f2dc17d11.png)

2）选择Finish

![h378C8.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1a4b0f7018fc46285038ccb6686a80141cf7e602.png)

3）创建Java Project

![h37Jgg.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a7701da1bd83a19ec6373fc784d84aa5dd15da77.png)

#### 配置Java编译环境

![h37lUP.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ddcd36cd1d29dbcbc0b0ae28d0d4aa965f44d8ad.png)

#### 配置Java运行环境

![h3714f.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bcb3f9f4ba85db9280a8e9b7b813057bead55657.png)

#### 配置文本文件编码

![h37ejH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7216348c09ce56acceb456737517aa93ab2f296d.png)

#### 打开Logcat界面

LogCat界面主要用于查看报错信息及进程信息

![h37uDA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e4ac7aacf8dff157e285fa5cea8d45de20dfcf10.png)

#### 配置Java代码提示

便于后面的Java代码编写，这部分可配可不配

```php
abcdefghijklmnopqrstuvwxyz.
```

![h37QEt.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f9e201329300d0c4dbbdd26b4649390867c80c14.png)

#### 创建Class文件

![h37KHI.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-029ec3d63af4ef1c17ff49411a1049092e19d86b.png)

```java
public class try001 {

    /**
     * @param args
     */
    public static void main(String[] args) {
        // TODO Auto-generated method stub
        System.out.println("Hello World!");
    }

}
```

![h37nud.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6ee74188b169d5bee83b4e29f95712130e0a3295.png)

### 4、Android Studio

‎Android Studio是一个为Android平台开发程序的集成开发环境，以IntelliJ IDEA为基础构建而成。类似于上面的Ecilpse，一般情况下两者都有使用，暂时不过多介绍，后面会使用到再详细介绍。

在官网直接下载即可，双击安装

#### 安装类型

![h377xe.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9ca22e5e92291d35378604c7f3c230912efd5c50.png)

#### 确认安装

![h37bKH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9ac824abe6603c8a95fa67ac069f75312163ea10.png)

二、安卓逆向工具
--------

这部分介绍的安卓逆向工具是一些用于安卓反编译、逆向分析的工具，可以将源程序反编译成可读代码，如Android Killer、Jadx和JEB等工具

### 1、Android Killer

`Android Killer`是一款安卓逆向工具，集Apk反编译、Apk打包、Apk签名、编码互转、ADB通信等特色功能于一身，支持logcat日志输出，语法高亮，基于关键字项目内搜索，可自定义外部工具，简化了用户在安卓应用中的各种琐碎工作。

下载地址：<https://www.androiddevtools.cn>

#### Android Killer下载安装

**1）下载后，解压至C盘**

![h1OjJ0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-49772980ecbcc37d5500f50474ddcc3d5a3f6e5c.png)

免安装直接使用。

**2）简单配置**

如果打开报错，就修改下jdk路径

![h1OXiq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bdfce3845e69350379cd48e582aa4dbcde859cc4.png)

#### 加载APKtool工具

默认情况下会自带一个apktool工具，这里加载额外的apktool

![h1OxzT.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-082f90f3c2ca50207a0ab8c4f152a736ce79e26a.png)

#### Android Killer简单使用

对apk进行反编译

![h1OvWV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dce615932afa1b066cb9638839f17b4589280fc6.png)

### 2、Android逆向助手 v2018 少月版

下载地址：CSDN上有

安装前需确认存在JDK，其功能包括反编译、重打包，格式转换等。简单的功能都列在主页了，其中最好用就是**签名apk功能**

![h37vIP.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c72bdf9b87a2115b12170d80764c8d8af900dc1b.png)

### 3、Jadx 反编译工具

Jadx工具用于将dex文件反编译成Java代码文件，分为命令行窗口和可视化窗口两种类型

命令行窗口工具，直接进入目录的cmd中，通过jadx命令进行反编译

![h37zPf.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-34887e48ca35f3decf6b117f5955d2cc5d5f7d68.png)

可视化窗口工具Jadx-gui，打开后导入文件即可开始反汇编

#### 载入文件及介绍

载入贪吃蛇apk文件，主要反编译有两个文件，源代码和资源文件，资源文件对应apk中的文件（这里用压缩软件打开apk文件查看到）

![h3HmGT.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3fd004ca91e5155bb35ea37520af6e4f37124902.png)

#### 简单搜索类

![h3HeiV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fa69a5dcea6c0b38bdb60e6a4b21b676db730611.png)

#### 函数跳转

选择函数，按住`Ctrl+左键`可以直接跳转至函数声明处。比如这里的`BuyFailed()`

![h3HVI0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a3d3d16f50578c8d6041793b6aabed0da7b5e4f9.png)

### 4、JEB 反编译工具

JEB是一款Android应用程序反编译工具，用于逆向分析、代码审计，具有静态分析和动态分析的能力

下载地址：<https://www.pnfsoftware.com>

#### 双击bat文件启动

![h3HMM4.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2d420fb346ad14b05a1914722607dadb40a99192.png)

#### 选取一个apk文件进行反编译

Manifest文件是清单文件（元数据文件），用来定义扩展或档案打包相关数据包含了不同部分中的名/值对数据

Bytecode是字节码，里面内容是smali代码

![h3HQsJ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-893ffd6ecfa1ed3053858af6a4989ef2a83e3a57.png)

#### 简单使用

在smali文件中按`q`可以反编译回java代码

按`Ctrl+b`下断点

三、安卓调试工具
--------

这部分为安卓调试工具，主要先介绍下载及安装，JEB动态调试在本文的第六节中介绍，其余的IDEA和IDA会在后面的动态调试文章中体现

### 1、JEB

JEB是一款Android应用程序反编译工具，同时也具备动态调试的功能，下文将以一个小例子进行演示。

**第六部分简单演示了JEB的动态调试过程**

### 2、IDEA

IDEA 全称 IntelliJ IDEA，是java编程语言开发的集成环境，在智能代码助手、代码自动提示、重构、JavaEE支持、各类版本工具(git、svn等)、JUnit、CVS整合、代码分析、 创新的GUI设计等方面的功能可以说是超常的

下载地址：<https://www.jetbrains.com/idea>

安装过程参考：[01-IDE工具之IDEA的简介、下载与安装、初步配置](https://segmentfault.com/a/1190000024573669)

动态调试见后文

### 3、IDA

下载地址：百度

安装后有32位的和64位，这里的位数是针对软件而言的，而不是针对操作系统版本，这里先简单安装下，在后面IDA动态调试中会有专门一篇文章来介绍。

四、安卓辅助工具
--------

> 这部分主要是一些辅助工具，查询信息、是否加壳等。对于没有真机的情况下还介绍了一些上手还可以的安卓模拟器

### 1、APK helper

APK helper工具用于查看apk文件简单信息，包括包名、证书、版本、文件信息等

![h3HYi6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d2b8625cc3e374957f986a8be1a08dcf9a7251ef.png)

### 2、PKiD 查壳工具

PKiD工具，将apk文件拖入可以查看是否加壳

![h3HGIx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d0cd98cafe1b76ebb99a093b9f68239e256516ee.png)

### 3、安卓模拟器

如果没有真机做实验的情况下，可以使用安卓模拟器用于实验，大部分的模拟器都可以完成实验内容，但是注意的是安卓模拟器也是一个虚拟机，不建议在虚拟机内安装模拟器，一是安装不了，二是十分卡顿。这里介绍几款不错的安卓模拟器。

1. 雷电模拟器

下载地址：<https://www.ldmnq.com>

2. 网易MuMu

下载地址：<https://mumu.163.com>

3. 逍遥模拟器

下载地址：<https://www.xyaz.cn>

4. 蓝叠模拟器

下载地址：<https://www.bluestacks.cn>

五、安卓抓包工具
--------

> 这部分介绍如何使用工具抓取安卓手机上的流量，主要是BurpSuite和Fiddler工具，还有安装证书抓取HTTPS的过程。

### 1、BurpSuite

BurpSuite抓取手机上的流量需要先设置手机和电脑为同一局域网

#### 在BurpSuite中配置

设置一个新的代理监听器

![h3Hxm9.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f44e11cffa7d3504c7f923789e45f5af6d91ea42.png)

#### 手机wifi设置代理

![h3bST1.jpg](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9a52b6387454586c2852361f48a4d4a0061de5ea.jpg)

#### 访问应用-抓取流量

在手机上随便访问一些app，可以在BurpSuite中看到抓取的包

![h3bCY6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91ba30e4cac095abfbab182165100af534509083.png)

#### 抓取HTTPS流量-下载证书

浏览器中输入代理IP和端口，点击右上角的CA Certificate按钮下载cacert.der证书。默认下载是`.der`格式的证书，手机上无法打开.der文件，下载好后需要将其改为`.crt`文件。

![h3HzwR.jpg](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e299abeefa692f40bf7ff0362147b30b54dd7d1a.jpg)

#### 抓取HTTPS流量-导入证书

在设置-安全-从存储设备安装中，选择cacert.crt证书，安装即可

![h3b9Fx.jpg](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-80898593d4bf1b1db4f01aff2c8ed77df927d91d.jpg)

#### 访问https的网址

在浏览器中访问https://www.baidu.com，BurpSuite中成功抓取到。

![h3bPfK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0619a7649042a3b9a4dd4add76f2866e68a5681c.png)

### 2、Fiddler

先简单介绍Fiddler抓包工具的一些基础操作，稍微熟悉下

#### 清除目前抓到的包

选项栏中选择`Remove all`删除所有的包

![h3bJmj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-932cf411654b00a7c20a440f3f946f08a27cd53e.png)

#### 抓包及指定抓包

左下角的Capturing图标来关闭/开启抓包功能，旁边可以对包进行选择

![h3b8XQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6414630fe7c6c94e8f6b1503cd6c8725ba7d58ac.png)

```php
All Processes 抓取所有通过Fiddler代理的request包
Web Browsers  抓取PC中浏览器的代理请求包 (需要选中Capturing)
Non-Browser   抓取除浏览器外的代理请求包
Hide All      隐藏所有的代理请求包
```

#### 配置抓取HTTPS流量

下载、安装证书，配置监听端口即可

![h3bY0s.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b09f3b005353ff025c8e8db1ac646e92f2928ca.png)

### 3、HTTP Debugger Pro

下载地址：百度

#### 直接双击安装

默认下一步简单安装

![h3bWh6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-33d6307f904f955d81969b2c4440671c97faa93f.png)

#### 解密SSL-添加证书

进入页面后，点击黄色框中的**解密 SSL**，选择添加证书即可。

![h3bRtx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e42e8fcc313504bc1d834b102e445721b4ae3140.png)

之后即可抓包，也可以抓模拟器上的数据包

六、JEB静态分析+动态调试
--------------

### 1、简单介绍

本次调试的目的：实现任意用户注册，无视注册码

调试程序截图如下，失败返回无效用户名或注册码

![h3b7Bd.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fcacfb19b3a878d337e86c662a7ce7e5bec2fdd8.png)

### 2、静态分析

#### 1）将注册机.apk文件导入至JEB中

![h3bHHA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c25bde24efa9261081b58490cd476eba8c7b38ae.png)

#### 2）简单查看反编译后的Java代码

关键点在于checkSN函数，传入两个参数arg11和arg12，分别对应用户名和注册码

```php
MessageDigest类为应用程序提供信息摘要算法的功能，这里提供MD5算法
messageDigest.update(str)输入待加密的字符串
messageDigest.digest()加密后的字节数组
```

主要的逻辑就是：将输入的用户名作为参数1并进行MD5加密，之后进行处理得到一个注册码，也就是说这里的注册码是实时根据用户名生成的，之后在将输入的注册码进行比较，相同则返回True。

![h3bqAI.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8f7cd84ea1eeae1ef6b46eb13df1a3fe404b1c40.png)

跟进`equalsIgnoreCase()`函数找到生成的注册码即可，接下来交给动态调试

### 3、动态调试

#### 1）雷电模拟器中启动注册机apk

随意尝试用户名和注册码进行注册，返回提示无效用户名或注册码

![h3bLNt.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c39b4674e7f077d3b3fa39d52eedf0731446a14d.png)

#### 2）JEB下断点

选定`equalsIgnoreCase()`函数，按`q`返回到对应汇编代码处，下好断点

![h3bO4P.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b6640563e2041b90834d14b3e7f2bf2b3d3d176c.png)

#### 3）连接到模拟器进行动态调试

> 需要adb工具，在之前安装SDK时配带

选择`Debugger -> Start`，选择雷电模拟器和注册机apk的进程

![h3bxgS.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6e847a2a88c90a3a508c355249c037efbb13aa51.png)

#### 4）找到校验值（破解点）

发现`equalsIgnoreCase()`函数需要两个变量v6和p2，查看v6的值"222275aa4840481c"

![h3bv38.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-120cccb61da31e2a34ff94b4f91dfedc31ffcca3.png)

#### 5）成功注册

重新启动注册机apk，输入admin和注册码222275aa4840481c，注册成功

![h3bj9f.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ea1da5cf35f0e9c7ef1f7d9c051aeb9fb7d267bd.png)

### 4、小结

初入门移动安全逆向apk的第一个小项目，虽然简单，只是一个破解得到注册码，但学到JEB工具的静态分析及动态调试，简单分析Java代码等