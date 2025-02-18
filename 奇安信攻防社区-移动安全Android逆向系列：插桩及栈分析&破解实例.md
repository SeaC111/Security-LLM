> 本篇文章是Android逆向系列的第四篇，介绍插桩操作和栈分析，通过插桩操作可以在静态分析程序代码时测试出程序的特征属性，接着介绍DDMS工具来学习栈跟踪分析技术，之后再以四个破解实例深入了解程序的静态分析技能，找到关键位置，达到去广告等目的。通过这四篇安卓逆向文章，大致可以了解安卓基本知识和逆向流程，并且由浅入深地熟悉安卓程序静态分析过程及相关工具的使用。

一、插桩操作
------

### 1、概念简介

插桩指的是保证程序原有逻辑完整性的基础上**插入一些程序代码，用于测试程序的特征数据**，并以此来进行分析。

这里基于Android Killer工具对Smali代码进行插桩操作，并配合DDMS进行测试。

### 2、Android Killer插桩操作-Log信息输出

随便打开个apk程序，点击入口进入smali代码处

![hYv8HK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b42faca6e83279ad84635e800ef6076e0d16a448.png)

跳转到`onCreate()`方法处，下面smali代码中的三个关键字分别代表的含义为：

```php
.locals     寄存器个数
.param      参数
.prologue   代码起点(插桩操作在此进行)
```

![hYvJAO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-384606b2b14698838d9b00505675333b7d9698bc.png)

在`.prologue`后进行插桩操作

![hYvQj1.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0f33a52181fac5361a44ca2e193153d07f31bf05.png)

回编译，在模拟器上安装该程序，结合DDMS进行测试，选择对应的包名（可以通过`adb shell dumpsys activity top`或者反编译获取到），在日志输出窗口中看到有该测试项。

![hYv3B6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-497d07d2922eefca6032f423fe271fe95bff2032.png)

二、栈跟踪及分析
--------

### 1、DDMS工具介绍

DDMS 的全称是Dalvik Debug Monitor Service，是SDK中的一个工具，是 Android 开发环境中的Dalvik虚拟机调试监控服务。主要功能：查询进程正在运行的线程和堆信息、文件系统，日志信息Logcat、广播状态信息、虚拟地理坐标等

#### 1）启动DDMS

在已配置sdk的环境变量后，直接在cmd中输入命令启动DDMS

```php
ddms
```

![htC1ud.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3b213d0052b8e034488fcf74c16ec788591a623.png)

#### 2）DDMS界面介绍

> 这部分简单介绍DDMS的界面，简单能看懂哪些信息就可以了，深入了解见后续文章或baidu

启动后显示的界面如下

![htCQjH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de211eec2972d2701a140b430352582b5cdb06e0.png)

主要分为四个窗口，左上角为**设备信息窗口**，记录设备名称及设备正在执行中的程序信息（如包名，进程号，端口）。左下角为**过滤器窗口**，控制过滤的信息。右上角是**功能窗口**，提供查看堆信息等功能。右下角为**信息输出窗口**，记录产生的日志信息（Logcat）。

##### 1 设备信息窗口

直接呈现了三列信息，分别是包名、进程号和端口。**端口号从8600端口依次增加**，8700是DDMS接收所有连接终端返回信息的端口，即base端口

![htCK3D.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4e9fe6451ea30704a055d18e3c23cf79d54a1181.png)

##### 2 过滤器窗口

主要设置过滤器选项，用于过滤日志信息，在Logcat中显示处过滤后的结果。点击加号设置过滤器，填写过滤器名和包名两项最基本的即可完成一个过滤器。

![htCm4K.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cc03aab3878a73ed67057456abae00a512c6653f.png)

##### 3 功能窗口

各种功能，包含基本信息、线程信息、系统信息和网络信息。

![htCu9O.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2653b474ccf8048d3a6970105a7e65c67b8389ef.png)

##### 4 信息输出窗口

主要使用Logcat，结合之前的过滤器，可以看到过滤后的信息

![htCMge.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a9afd4951384953791a9f2f375a873c2d433ea24.png)

### 2、system.err标签学习

在DDMS中的输出窗口中有一栏为标签栏，我们打开测试软件，选中对应包名，可以在输出窗口中找到system.err的标签，简单学习下

输出的text中，栈是从下往上走的，下面是父类，上面是子类，即父类调用子类。

![hYv1nx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8cc1edd0e051d5e9dc858a374486871aad927cd7.png)

### 3、Android Killer插桩-StackTrace栈跟踪

在入口函数代码处选择`loadData()`函数中添加栈跟踪代码，由于我们加入的代码也是两个寄存器，`.locals`的值就可以不用修改。

![hYvxDx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-183ffbae3bfbbad008441a31005c2ec13e59f423.png)

之后回编译测试下，打开该软件同时打开DDMS软件，在输出窗口中找到刚刚插入的跟踪代码`print trace`，也可以看到整个system.err是从下往上调用的。

![hYx9UO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7cbb25329c26eff4345214583dcc00d166aa7e27.png)

### 4、登录界面的栈跟踪

先点击左上角的暂停分析栈按钮，弹出选项框，第一个为自定义过略，第二个是打印所有。

![hYxC5D.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7fba25521180cf2e26144c30dd3c3463b1b2a4ba.png)

在程序内点击登录后，再回来重新点击下暂停分析栈按钮，就会出现一个方法剖析图，里面出现刚刚那个时间段调用的各个方法。

![hYxiPe.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1f84ba0014711566951c8eb2a03c652b81e87893.png)

在每个方法中会显示父节点和子节点的信息

![hYxpVK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-960e0b38beafbafeb810a62b2e6f26fadf7ca64b.png)

找到`onclick()`方法，简单跟踪下

![hYvzb6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d8024445c04290aca16be957bdde3b0583875fe9.png)

三、破解实例1-起名软件
------------

### 1、软件试用

启动该软件，发现部分功能需要VIP会员，所以尝试突破VIP会员的限制。

目标：突破VIP会员的限制！

![hYzdmt.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b46af98900f1da1b5553573c4723241634852a55.png)

![hYztld.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4677ac14c54c4f6a8f396b3d0f66da4ce5192830.png)

逆向分析程序

### 2、Jadx 反编译Java代码

反编译出来后进行逆向分析程序

#### 1）加载软件进行反编译

#### 2）查询字符串

输入刚刚程序中提示没有VIP的字符串，找到对应的反编译代码

![hYzN6A.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8cd2fe4c71226f0a9a04171f34af77e4846656fc.png)

#### 3）简单分析目标代码

首先发现if语句中调用了`GlobalVar.getInstance().GetVip()`方法获取到VIP的信息后进行跳转，无VIP则跳转至else语句中执行`radioButton.setChecked(false)`方法，后续就是弹出提示框。思路：如果将判断条件改掉，不走else的语句试试

![hYz3FO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a20de39f2f5804fe0d12c2c5c99ca7b1eb666e52.png)

#### 4）查看所在包名，在Android Killer中分析

包位置：`com.meiyiming.gsname`

![hYzQw6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7b621a26704e2a90406914e84fbbc58bf581af53.png)

### 3、Android Killer 反编译Smali代码

#### 1）找到包com.meiyiming.gsname的smali代码

发现没有`GetVip()`方法，直接搜索试试

![hYzYSH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1830852913f3133d6cfafbe544b0596e704c53f0.png)

在左边发现有巨多smali代码，是因为dex文件反编译成smali代码时会将所有的内部类、抽象类、接口类全部提取出来，单独存放，所以可以看到那么多smali代码

#### 2）搜索GetVip字符串

搜索列表显示多个结果，有些是虚函数的调用，要找到函数的定义位置处，下方红框内，

![hYz8YD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2c26ddc97ce55dc7eb88265b2c049d73904a5abe.png)

#### 3）分析GetVip的Smali代码

首先获取SessenID的值，如果是VIP用户为1，否则为0，将结果保存至v1寄存器中。将寄存器v2设置为1，再调用equals方法比较寄存器v1和v2的值，相同返回1，不用返回0至v1寄存器中。通过`if-eqz v1`进行判断，v1为0跳转至cond\_0处。

![hYzGfe.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f945490abc0946c82836fb1bab23209f8033a177.png)

#### 4）回编译该apk程序进行测试

![hYzw0P.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b50ad4614ecf8e3517a8d6c9e466e4e7fd2cf07.png)

成功突破VIP的限制！！！！

### 4、小结

突破VIP的权限，主要思路为先是通过工具反编译源代码，在Java和Smali代码层中分析逻辑，找到关键函数`GetVip()`并研究实现及调用的逻辑，在一些if判断中进行修改达到突破VIP的效果

四、破解实例2-文件管理器
-------------

### 1、软件试用

启动后退出会出现广告页面

![ht9UX9.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fb543445cc4ff1baa775d0d968b745cc1269a337.png)

### 2、调试分析 | 修改广告页面

#### 1）adb动态调试分析

使用命令查看退出广告页面的activity栈顶信息，模拟器上先退出该应用，当弹出广告时在cmd中输入下面的命令

```php
 adb shell dumpsys activity top
```

![ht9N6J.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dd60abe11129503302d86670b51b11e2255e42ad.png)

找到一个类文件，在Jadx中分析看看

```php
 com.AddDouDouWall2.WebPageDownLoadMainActivity
```

#### 2）Jadx 搜索类分析

搜索上面得到的类名，在URL跳转中找到URL如下，访问试试

```php
 http://www.doudoubird.com:8080/ddn_app/selectAppList?aidx=2
```

![ht9tl4.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-553f65aa3524e93f102ced3a35f8f7c235bebdf9.png)

可以看出是刚刚apk软件退出时呈现的页面

![ht9YpF.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-99bb5c5d42e478a7b19d623b3325ad2af10fae2a.png)

那么我们**思路就可以是将该跳转页面改为钓鱼页面**，实现钓鱼的目的，这里使用`www.baidu.com`来模拟测试下

#### 3）Android Killer修改跳转页面

首先搜索该广告页面，将该页面修改为百度，回编译查看效果

![ht98YT.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1d88eba5baada5e952a5427a78562f59b43e151.png)

可以看到返回后的广告页面成功修改为百度

![ht9GfU.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-09531ea55994c5409bd840c7a7019997150b29f4.png)

### 3、调试分析 | 删除退出广告

#### 1）Jadx源代码分析

继续分析`WebPageDownLoadMainActivity`类，在跳转url后面还有两行代码：

```php
 addContentView(this.webView, params);
 startService(new Intent(this, DownLoadManagerService.class));
```

![ht9lT0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b68c55b36da64ede9dddfa18dbf53d1eeb3a9e37.png)

发现调用了startServer方法，据此我们查找startServer关键字

#### 2）Android Killer分析

查找startServer关键字，在`WebPageDownLoadMainActivity.smali`中找到startServer的调用，。分析后尝试将该调用行进行注释，回编译测试后发现无效，继续分析。

![ht93kV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7f21e6ea3077f305c5666a643a6516c6b74270f2.png)

#### 3）分析WebPageDownLoadMainActivity类的调用

##### 1 查找该类的用例

在Jadx中直接右键该类，选择查找用例

![ht9uOs.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bab77c062d2ed821b14e67ad4f23beac70d6dd9c.png)

第三个为调用关系，点击查看

![ht9eSg.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5522a0c0012af67f3a217502dd73985566431d8f.png)

##### 2 简单分析onDestroy()方法

先看一部分，`isNetworkAvailable()`方法查询当前网络状态，有网络则执行`startActivity()`，这里新出现了`startActivity()`方法关键字，我们在Android Killer中查找下对应的smali代码。

```php
 public void onDestroy() {
     Intent iii;
     w a2;
     if (isNetworkAvailable(this)) {
         startActivity(new Intent(this, WebPageDownLoadMainActivity.class));
     }
     ……
 }
```

##### 3 分析onDestroy()的smali代码

根据Jadx标签的包名信息，在Android Killer中找到对应的smali代码

![ht9VfS.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fba95555c9c70cb78f624ef0de05c8aae1b4ab57.png)

```php
 com.speedsoftware.rootexplorer.RootExplorer
```

![ht9nyj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b5e4861ec854e2de261a5437ce6d2ad3726af3db.png)

```php
 .method protected onDestroy()V
     .locals 5

     .line 41
     invoke-virtual {p0, p0}, Lcom/speedsoftware/rootexplorer/RootExplorer;->isNetworkAvailable(Landroid/content/Context;)Z

     move-result v0

     if-eqz v0, :cond_0

     .line 17
     new-instance v0, Landroid/content/Intent;

     const-class v1, Lcom/AddDouDouWall2/WebPageDownLoadMainActivity;

     invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

     .line 18
     .local v0, "iii":Landroid/content/Intent;
     invoke-virtual {p0, v0}, Lcom/speedsoftware/rootexplorer/RootExplorer;->startActivity(Landroid/content/Intent;)V

     :cond_0
     const/4 v2, 0x1

     const/4 v1, 0x0

     move v0, v1

     :goto_0
```

先调用`isNetworkAvailable`方法查询网络状态，返回至v0寄存器，v0=1时，继续执行下面的代码，执行startActivity方法，v0=0时直接跳转至`:cond_0`处。于是我们修改判断条件使得该判断会直接跳转至`:cond_0`处。将`if-eqz`修改为`if-neq`

![ht9mlQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4e6c9ea0e12240666b5c5ff47975a1e43fc0dc3f.png)

#### 4）回编译进行测试

退出广告成功去除

五、破解实例3-行车软件
------------

### 1、软件试用

安装进入程序后，页面中间有广告

我们的目标就是去除页面中的广告

![htC3DA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-38bf70cf99c402f2c3889e62ea0487c2b6f7bc43.png)

### 2、调试分析

#### 1）广告点分析

通过DDMS工具中Logcat功能，结合之前的过滤器，可以看到过滤后的信息

![htCMge.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a9afd4951384953791a9f2f375a873c2d433ea24.png)

在上面的Logcat中发现了广告点，右键查看详细信息复制出url信息

```php
atrace.chelaile.net.cn
```

我们就有思路：将该url更改为本地地址127.0.0.1，那么就请求不到网络了。

#### 2）Android Killer修改广告请求url

##### 1 搜索关键字

搜索上面的url信息

![htC5r9.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b3feeb7918e5c146aa86de55a0e34ebbe970ccc.png)

##### 2 替换为本地地址

将所有的`atrace.chelaile.net.cn`地址替换为本地地址`127.0.0.1`

![htC4KJ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8b1da2f7ccbc9b670c58f5f2f289c9d99af0dbb1.png)

##### 3 回编译测试效果

可以发现页面中的广告已成功去除掉

![htCW2F.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a699d2694152afa31f7a268ae45857c744bd7fe0.png)

### 3、小结

本次破解实验主要学习了DDMS工具的使用，熟悉页面基本窗口及作用啥的，能看得懂就行，更深的东西以后再学，通过DDMS找到页面中的广告信息（在栈里面会有提示出来），根据给出的url在Android Killer中搜索，替换为本地地址127.0.0.1，回编译即可。

六、破解实例4-去广告
-----------

### 1、软件试用及简介

正常的apk中，在加载时都会出现广告，那么我们如何通过安卓逆向技术将广告去除呢？

![htPnZn.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9875f2f08865cb3adc010ea8715e0627955597b1.png)

### 2、逆向分析

#### 1）分析AndroidManifest.xml

首先需要分析广告出现在哪，使用`Android Killer`工具进行反编译，查看`AndroidManifest.xml`的`activity`组件

![htPKI0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b903bc0c8ff504e3ead144402ea484b67ea326c.png)

#### 2）adb工具检测Android的Activity任务栈

`Activity`是直接控制程序界面的组件，这里使用`adb`工具的shell指令查看`Activity`栈顶信息

```php
adb devices     查看设备信息
adb shell dumpsys activity top  查看activity栈顶信息
```

启动雷电模拟器并打开该apk程序，输入上面的指令

![htPQiV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bbdee74a9675149798b436eecf75c140472ecfce.png)

可以发现这里的activity服务名字和上面反编译中圈起的服务名字相同，为

```php
com.mosads.adslib.Splash.MosSplashActivity
```

由此分析出该该activity组件是控制第一个页面的，即控制广告页面，那么我们将此页面进行删除并修改即可去除掉广告页面。

参考：[使用Adb shell dumpsys检测Android的Activity任务栈](http://blog.csdn.net/xx326664162/article/details/52385720)

#### 3）修改AndroidManifest.xml

![htPeqs.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-046af2f25b6d66f0f0a218434f74eda026ec7d2e.png)

`Ctrl+s`保存并在左上角点击编译按钮进行回编译

![htPuaq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0a847452cd9e8b01292c29e489b1e0d6a85207be.png)

#### 4）安装修改后的apk程序

直接安装，点击迅速加载无广告

### 3、小结

这次的apk去广告上手实验还是非常顺利的，主要是找到广告的加载点，对于该程序是找到程序载入的第一个页面，结合adb工具的shell指令在`AndroidManifest.xml`文件中找到控制第一个加载页面的组件名字，修改`AndroidManifest.xml`程序载入的广告页面，从而达到去除apk程序广告的效果。