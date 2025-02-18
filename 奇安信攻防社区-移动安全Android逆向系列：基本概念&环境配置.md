> 本篇文章是Android逆向系列的第一篇，简单介绍下Android的概念包括apk结构、虚拟机和apk的打包流程，详细描述搭建安卓逆向的环境，包括部分Android工具包及逆向工具，最后再简单上手Android Killer工具进行一些基础的操作，也顺带加深熟悉下apk文件结构，为后续的逆向破解打好基础。

一、Android概念介绍
-------------

### 1、apk基本结构

找个apk文件，使用压缩包软件将它打开，可以发现其具有如下文件

![h1L5DJ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-198eb072de0cf0bd3e0851f54c8a6d84401ba546.png)

- `assets`文件用于存放需要打包到Android应用程序的**静态资源文件**，例如图片资源文件、JSON配置文件、渠道配置文件、二进制数据文件、HTML5离线资源文件等。与res/raw目录不同的是, assets目录支持任意深度的子目录,同时该目录下面的文件不会生成资源ID。
- `lib`文件夹中存放的是当前apk需要的**so文件**，so文件是利用底层的C/C++代码实现的
- `META-INF`文件是所用到的**证书签名文件**，包含几个文件  
    `MANIFEST.MF` (摘要文件) ：程序遍历APK包中的所有文件，对非文件夹非签名文件的文件，逐个用SHA1生成摘要信息，再用Base64进行编码。如果APK包的文件被修改，在APK安装校验时，被修改的文件与MANIFEST.MF的校验信息不同，程序将无法正常安装。  
    `CERT.SF` (对摘要文件的签名文件) ：对于生成的MANIFEST.MF文件利用SHA1-RSA算法对开发者的私钥进行签名。在安装时只有公共密钥才能对其解密。解密之后将其与未加密的摘要信息进行比对,如果相符则文件没有被修改。  
    `INDEX.LIST`：APK索引文件目录  
    `CERTRSA`：保存公钥、加密算法等信息
- `res`文件夹目录存放**应用的资源文件**，包括图片资源、字符串资源、颜色资源、尺寸资源等，这个目录下面的资源都会出现在**资源清单文件R.java**的索引中
- `AndroidManifest.xml`是Android项目的系统**清单文件**，Android应用的四大组件`Activity、Service、BroadcastReceiver和ContentProvider`均在此配置和声明
- `classes.dex`应用程序的**可执行文件**，Android的所有代码都集中在此。可以通过反编译工具`dex2jar`转化成jar包，再通过jdax-gui查看其代码。如果一个apk中方法数超过65535，会进行了分包处理，即有多个dex文件。如果未超过则只有一个dex文件。
- `resources.arsc`是**资源索引表**，用来描述具有ID值的资源的配置信息。

### 2、各种虚拟机|混淆点

#### JVM

JVM指的是是Java虚拟机，运行的是.java文件编译后的.class文件。

#### DVM

DVM指的是Dalvik虚拟机，运行的是.dex文件。Dalvik虚拟机在Android4.4及以前使用的都是Dalivk虚拟机。APK在打包过程中先通过javac编译处.class文件，再使用dx工具处理成.dex文件，此时Dalvik虚拟机才可以解析执行。另外单个dex文件的最大为65535KB，超出需要使用两个及以上的dex文件，这导致在启动时会有个合包的过程，使得apk启动慢。

#### ART

ART指的是ART虚拟机，运行的也是.dex文件。ART虚拟机是在Android5.0才引入的Android虚拟机。在安装APK的时候就将dex直接处理成可直接供ART虚拟机使用的机器码，ART虚拟机将.dex文件转换成可直接运行的.oat文件，ART虚拟机天生支持多dex，不会有一个合包的过程，所以ART虚拟机会很大的提升APP冷启动速度。缺点是APK占用空间大和安装速度慢，因为需要生成可运行.oat文件。

### 3、apk打包流程

从官网的流程图中看出整个打包流程共分为七个步骤：

![h1LTER.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ae8a30ea82df03b497f06d52bdaf52065322d7b5.png)

1. 打包资源文件，生成R.java文件
2. 处理aidl文件，生成相应的.Java文件
3. 编译项目源代码，生成class文件
4. 转换所有的class文件，生成classes.dex文件
5. 打包生成APK文件
6. 对APK文件进行签名
7. 对签名后的APK文件进行对齐处理

详细见此文 [Android中apk打包流程](https://zhuanlan.zhihu.com/p/348198783)

二、Android工具安装及环境配置
------------------

### 1、JDK及JRE安装

可以去官网下载，选择jdk8u111版本进行安装

JDK：Java Development Kit是Java的开发工具包，JDK包含了JRE，同时还包含了编译java源码的编译器javac，还包含了很多java程序调试和分析的工具。

JRE： Java Runtime Environment是Java运行时环境，包含了java虚拟机，java基础类库

**安装过程：**

**1）双击启动安装程序**

![h1OGMF.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-636b7232ecf27bc3da98b46e7694c83d616ed57e.png)

**2）默认安装路径**

![h1OK5q.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f1cb6c183d0b731e6c4531e789de76101a197ec3.png)

**3）jre路径选择**

![h1OQP0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-144344835241c9ffbff99986eea9238df87a0b5b.png)

**4）配置环境变量**

```php
JAVA_HOME
C:\Program Files\Java\jdk1.8.0_111
```

![h1O12T.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9db8064ea9cd8938324e10503bf9b079eafe3c8.png)

```php
%JAVA_HOME%\bin
```

![h1OlGV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de1a49e2101475b4927751699797d706a7e99309.png)

```php
C:\Program Files\Java\jre1.8.0_111\bin
```

![h1O3xU.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5540d85c4ea9949a8784a2efff77f717370074bb.png)

### 2、SDK安装

SDK（Software development kit）是软件开发工具，提供了Android调试工具等，如adb

下载地址：<https://www.androiddevtools.cn>

adb工具：命令行模式调试apk，定位追踪，删除apk中的广告部分

**1）下载好后，解压至c盘目录下**

![h1Oyse.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-150ff74b887562b0a3ac96d4438734e5284a9f71.png)

**2）配置环境变量**

```php
C:\sdk\tools
C:\sdk\platform-tools
```

![h1OsMD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a732f600d6238294577ac8f6d40dd12de28603c8.png)

### 3、Android NDK安装

Android NDK（Native Development Kit）原生开发工具，用于编译生成so文件、可执行文件。（适用于ARM架构）

下载地址：<https://developer.android.com/ndk/downloads>

参考：[NDK 使用入门](https://developer.android.com/ndk/guides?hl=zh-cn)

**1）下载解压至C盘**

![h1OgZd.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab2624deab3708f51d5b257f8d6d681e6fdf4bb7.png)

**2）配置环境变量**

```php
C:\android-ndk-r10e
```

![h1O6qH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4e8e378b93951fe3cf120760dc6645e79d89663a.png)

**3）构建build**

![h1O2dA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fb261a723279c99067139f15820566e3f7dc3284.png)

### 4、Android Killer安装

`Android Killer`是一款安卓逆向工具，集Apk反编译、Apk打包、Apk签名、编码互转、ADB通信等特色功能于一身，支持logcat日志输出，语法高亮，基于关键字项目内搜索，可自定义外部工具，简化了用户在安卓应用中的各种琐碎工作。

下载地址：<https://www.androiddevtools.cn>

#### 0x01 Android Killer下载安装

**1）下载后，解压至C盘**

![h1OjJ0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0d5d6a4624a7dba9e07dbcd99f2e7e8eca7bfe98.png)

免安装直接使用。

**2）简单配置**

如果打开报错，就修改下jdk路径

![h1OXiq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-89b4990a400030e8b02234ad371d6c0b03089a17.png)

#### 0x02 加载APKtool工具

默认情况下会自带一个apktool工具，这里加载额外的apktool

![h1OxzT.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a02dfd679e214cdff31f86e553163795bab1354d.png)

#### 0x03 Android Killer简单使用

对apk进行反编译

![h1OvWV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7c45f75f8de71b7a43d2c497d0430578fe39a260.png)

三、上手Android Killer反编译apk
------------------------

> 刚开始入门，这部分使用Android Killer工具进行两个简单的操作，修改apk程序名和图标，稍微练下手，为后续操作打好基础。

### 1、修改apk程序名称

**1）将apk文件导入进Android Killer中**

反编译好后，在**工程搜索**中搜索`@string/app_name`，将其修改为`摸鱼小游戏`

**2）点击左上角的编译选项**

将修改后的apk文件进行回编译

![h1XEJx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-470c65673da6fbd534b3991aa98d157f2491ac01.png)

**3）安装已修改的apk**

成功将原来的文件名修改为`摸鱼小游戏`

![h1XeSK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-629dcbb996823414a8f16c553d7bfd29d770e876.png)

### 2、修改apk程序图标

**1）导入apk进Android Killer反编译**

直接拉进去，等待一会即可

**2）搜索icon.png图标位置**

在工程搜索中输入`/icon/png`进行搜索

![h1XVW6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0f07e8750d676b8b6065ce53e6b112027d28ef37.png)

这里切记需要是**png格式**的图片文件，而不是只是将后缀名改下，可以通过在线网站进行转换

**3）修改好后进行回编译**

点击左上角的编译选项

![h1XAF1.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-571c9492e3c8c7ba28aa234aece3bc8131c526c3.png)

**4）安装该程序**

![h1XmQO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-102f48f30fad1ae03b4bcf213eddb9e93c22daa5.png)