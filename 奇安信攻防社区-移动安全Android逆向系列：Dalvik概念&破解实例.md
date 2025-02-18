> 本篇文章是Android逆向系列的第三篇，开始介绍Dalvik虚拟机的相关知识，认识dex和smali文件格式和熟悉Dalvik字节码及指令集，对Dalvik指令集有个大概的了解就可以开始简单的反编译静态分析了，后面提及了安卓开发四大组件和使用Eclipse开发一个简单的apk例子，最后以一个破解实例加深全文的知识概念，进一步熟悉工具的使用及Dalvik指令集。

一、Dalvik
--------

### 1、Dalvik介绍

Dalvik是google专门为Android操作系统设计的一个虚拟机，Dalvik VM是基于寄存器的，而JVM是基于栈的；Dalvik有专属的**文件执行格式dex（dalvik executable）**，而JVM则执行的是java字节码。Dalvik VM比JVM速度更快，占用空间更少。

在Java代码中我们无法修改某个逻辑，所以需要将**java代码翻译成smali代码**，也就是将**dex文件转换为smali文件**。可以这样理解，dalvik里面的smali是可以修改的，而java代码是修改不了的，那么我们想要去破解也就是把Java代码改成smali代码，修改smali代码之后再回编译回去同时java逻辑也发生了改变，这是一种破解的思路。

> Smali格式是dex格式的一种直观可读形式
> 
> Smali文件可以认为是Davilk的字节码文件
> 
> 详见后续的Smali介绍

### 2、Dalvik寄存器命名法

Dalvik虚拟机参数传递方式中的规定：假设一个函数使用到M个寄存器，其中函数的参数是N个，那么参数使用最后的N个寄存器，局部变量使用从头开始的前M-N个寄存器

Dalvik寄存器有两种命名法

**v命名法**

v命名法采用以小写字母“v”开头的方式表示函数中用到的局部变量与参数，所有的寄存器命名从v0开始，依次递增。

参数寄存器 v(m-n)~vm  
局部变量寄存器 v0~vn

**p命名法**

基本上类似，主要是参数寄存器是使用p命名寄存器，而局部变量寄存器还是使用v命名寄存器

参数寄存器 p0~pn  
变量寄存器 v0~vn

### 3、v命名法Smali代码分析

Smali代码如下图，首先看第一行

```smali
static public DecryptDemo->getHelloWorld(Ljava/lang/string;I)Ljava/lang/string;
```

第一行中调用了一个`getHelloWorld()`方法，括号内的表示有两个参数`Ljava/lang/String`和`I`，用分号`;`隔开，返回值的类型为`Ljava/lang/String`

中间部分的`.regsize:[5]`表示有5个寄存器

第一个红框中调用了方法将v2、v3寄存器值存入，返回了一个v2。第二个红框中调用了方法将v0、v4寄存器值存入，返回一个v0。

invoke-virtual虚方法调用，调用的方法运行时确认实际调用，和实例引用的实际对象有关，动态确认的

![h8anhT.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a20243496badb69e97ba13ee0214fda9ded9b597.png)

### 4、p命名法Smali代码分析

同样第一行可以看出调用了一个`getHelloWorld()`方法，两个参数`Ljava/lang/String`和`I`，用分号`;`隔开，返回值的类型为`Ljava/lang/String`

```php
invoke-virtual {v1, p0}, Ljava/lang/stringBuilder;->append (Ljava/lang/String;)Ljava/lang/StringBuilder;

move-result-object v1
```

第一个红框在`LJava/lang/StringBuilder`类中调用了一个append的方法拼接传来的String，返回一个`LJava/lang/StringBuilder`类型，传入参数位于p0处，传出参数位于v1处，返回的是一个move-result-object

第二个红框类似，调用了一个append的方法拼接传来的String返回一个`LJava/lang/StringBuilder`类型，传入参数位于p1处，传出参数位于v0处

![h8amNV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-524507cd0d4ea07defe79313389219b5cf0dc9fa.png)

### 5、dex文件反编译工具

Dalvik 虚拟机并不支持直接执行 JAVA 字节码，所以会对编译生成的 .class 文件进行翻译、重构、解释、压缩等处理，这个处理过程是由 dx 进行处理，处理完成后生成的产物会以 .dex 结尾，称为 Dex 文件。

[浅谈 Android Dex 文件](https://tech.youzan.com/qian-tan-android-dexwen-jian/)

整个编译/反编译涉及到的工具及流程如下：

**1）编译出smali文件流程**

```php
.java ==> .class ==> .dex ==> .smali
```

**2）dx.jar脚本将class文件打包成dex文件**

```php
dx --dex --output=Test.dex com/xxx/ooo/Test.class
```

**3）Baksmali.jar脚本将dex文件反编译成smali文件**

```php
java -jar baksmali.jar -o smali_out/ source.dex
```

**4）smali.jar脚本将smali文件打包成dex文件**

```php
java -jar smali.jar smali_out/ -o source.dex
```

### 6、Dalvik字节码类型

Davilk字节码只有两种类型：基本类型和引用类型，对象和数组都是引用类型。

基本类型和无返回值的void类型都是用一个大写字母表示  
对象类型用字母L加对象的全限定名来表示  
数组类型用`[`来表示

> 全限定名是什么？
> 
> 以String为例，其完整名称是java.lang.String，那么其全限定名就是`java/lang/String;`。即java.lang.String的”.”用”/”代替,并在末尾添加分号”;”做结束符

具体规则如下所示:

```php
类型描述符   Java类型
V           void
Z           Boolean
B           byte
S           string
C           char
I           int
J           long
F           float
D           double
L           Java对象类型
[           数组类型
```

解释下Java对象类型：L可以表示java类型中的任何类，比如在Java代码中的`java.lang.String`对应在Davlik中描述是`Ljava/lang/String`

[深入理解Dalvik字节码指令及Smali文件](https://blog.csdn.net/u010164190/article/details/52089794)

二、Dalvik指令集
-----------

上面只是简单了解了Dalvik字节码，具体每个方法涉及到的逻辑还需要Dalvik指令集来解释，下面介绍Dalvik指令集，由于Dalvik虚拟机是基于寄存器架构的，其指令集的风格更偏向于x86中的汇编指令

### 数据定义指令

**const**指令定义代码中变量、常量、类等数据

| 指令 | 描述 |
|---|---|
| const/4 vA,#+B | 将数值符号扩展为32后赋值给寄存器vA |
| const-wide/16 vAA,#+BBBB | 将数值符号扩展为64位后赋值个寄存器对vAA |
| const/high16 vAA, #+BBBB0000 | 将数值右边零扩展为32位后赋给寄存器vAA |
| const-string vAA,string@BBBB | 通过字符串索引高走字符串赋值给寄存器vAA |
| const-class vAA,type@BBBB | 通过类型索引获取一个类的引用赋值给寄存器vAA |

### 数据操作指令

**move**指令用于操作代码中的数据

| 指令 | 描述 |
|---|---|
| move vA,vB | 将vB寄存器的值赋值给vA寄存器,vA和vB寄存器都是4位 |
| move/from16 vAA,VBBBB | 将vBBBB寄存器(16位)的值赋值给vAA寄存器(7位),from16表示源寄存器vBBBB是16位的 |
| move/16 vAAAA,vBBBB | 将寄存器vBBBB的值赋值给vAAAA寄存器,16表示源寄存器vBBBB和目标寄存器vAAAA都是16位 |
| move-object vA,vB | 将vB寄存器中的对象引用赋值给vA寄存器,vA寄存器和vB寄存器都是4位 |
| move-result vAA | 将上一个invoke指令(方法调用)操作的单字(32位)非对象结果赋值给vAA寄存器 |
| move-result-wide vAA | 将上一个invoke指令操作的双字(64位)非对象结果赋值给vAA寄存器 |
| mvoe-result-object vAA | 将上一个invoke指令操作的对象结果赋值给vAA寄存器 |
| move-exception vAA | 保存上一个运行时发生的异常到vAA寄存器 |

### 比较指令

cmp/cmpl用于比较两个寄存器值，cmp大于结果表示1，cmpl大于结果表示-1。

| 指令 | 说明 |
|---|---|
| cmpl-float vAA,vBB,vCC | 比较两个单精度的浮点数.如果vBB寄存器中的值大于vCC寄存器的值,则返回-1到vAA中,相等则返回0,小于返回1 |
| cmpg-float vAA,vBB,vCC | 比较两个单精度的浮点数,如果vBB寄存器中的值大于vCC的值,则返回1,相等返回0,小于返回-1 |
| cmpl-double vAA,vBB,vCC | 比较两个双精度浮点数,如果vBB寄存器中的值大于vCC的值,则返回-1,相等返回0,小于则返回1 |
| cmpg-double vAA,vBB,vCC | 比较双精度浮点数,和cmpl-float的语意一致 |
| cmp-double vAA,vBB,vCC | 等价与cmpg-double vAA,vBB,vCC指令 |

### 跳转指令

用于跳转至不同的地址处，Davlik提供了三种跳转指令，goto、swicth和if跳转

| 指令 | 操作 |
|---|---|
| goto +AA | 无条件跳转到指定偏移处(AA即偏移量) |
| packed-switch vAA,+BBBBBBBB | 有规律分支跳转指令.vAA寄存器中的值是switch分支中需要判断的,BBBBBBBB则是偏移表(packed-switch-payload)中的索引值, |
| spare-switch vAA,+BBBBBBBB | 无规律分支跳转指令,和packed-switch类似,只不过BBBBBBBB偏移表(spare-switch-payload)中的索引值 |
| if-eq vA,vB,target | vA,vB寄存器中的相等,等价于java中的if(a==b),比如if-eq v3,v10,002c表示如果条件成立,则跳转到current position+002c处.其余的类似 |
| if-ne vA,vB,target | 等价与java中的if(a!=b) |
| if-lt vA,vB,target | vA寄存器中的值小于vB,等价于java中的if(a`<`b) |
| if-gt vA,vB,target | 等价于java中的if(a`>`b) |
| if-ge vA,vB,target | 等价于java中的if(a`>=`b) |
| if-le vA,vB,target | 等价于java中的if(a`<=`b) |

### 返回指令

**return**指令用于返回方法的执行结果

| 指令 | 说明 |
|---|---|
| return-void | 什么也不返回 |
| return vAA | 返回一个32位非对象类型的值 |
| return-wide vAA | 返回一个64位非对象类型的值 |
| return-object vAA | 反会一个对象类型的引用 |

### 方法调用指令

```php
invoke-virtual:     调用实例的虚方法(普通方法)
invoke-super:       调用实例的父类/基类方法
invoke-direct:      调用实例的直接方法
invoke-static:      调用实例的静态方法
invoke-interface:   调用实例的接口方法
```

### 实例操作指令

操作对象实例相关

| 指令 | 描述 |
|---|---|
| new-instance vAA,type@BBBB | 构造一个指定类型的对象将器引用赋值给vAA寄存器.此处不包含数组对象 |
| instance-of vA,vB,type@CCCC | 判断vB寄存器中对象的引用是否是指定类型,如果是,将v1赋值为1,否则赋值为0 |
| check-cast vAA,type@BBBB | 将vAA寄存器中对象的引用转成指定类型,成功则将结果赋值给vAA,否则抛出ClassCastException异常. |

### 空操作指令

nop指令无实际意义，一般用于代码对齐

还有些指令未介绍到，稍微了解下就可以了，在实际试验中遇到再进行解释学习

参考：[深入理解Dalvik字节码指令及Smali文件](https://blog.csdn.net/u010164190/article/details/52089794)

三、安卓开发四大组件
----------

提到安卓开发，必然会提及其四大组件Activity、Service、BroadcastReceiver、ContentProvider，其功能分别为

```php
Activity: 控制程序界面的呈现
service: 提供后台运行服务
BroadcastReceiver: 提供接收广播功能
ContentProvider: 支持多个应用存储和读取数据
```

### 1、Activity活动

Activity提供了一个用户完成相关操作的界面，一个apk中通常含有多个Activity活动，需要在`Android Manifest.xml`中进行声明才可以调用。

**Activity生命周期**

Acticity流程开始，先调用`onCreate()`方法创建Acticity，再调用`onStart()`方法使该Acticity由不可见转为可见，接着调用`onResume()`方法，使得用户可以操作界面获得焦点，Acticity开始运行。之后暂停调用`onPause()`方法，使得页面失去焦点无法操作（可重新调用`onResume()`获得焦点继续操作），再调用`onStop()`方法使得界面不可见（若是对话框可见），此时可以调用`onRestart()`方法重新恢复到`onStart()`状态前，或者调用`onDestroy()`方法后，Acticity界面全部消失，Acticity流程结束。

![h8wJfK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-921b48558a1fba26c0158eace321ca8df65207cf.png)

### 2、Service服务

Service服务，不能与用户交互的，不能自己启动的，运行在后台的程序如果我们退出应用时, Service进程并没有结束，它仍然在后台运行，那我们什么时候会用到Service呢？比如我们播放音乐的时候，有可能想边听音乐边干些其他事情，当我们退出播放音乐的应用，如果不用Service，我们就听不到歌了，所以这时便就得用到Service了，又比如当我们一个应用的数据是通过网络获取的，不同时间(一段时间)的数据是不同的这时候我们可以用Service在后台定时更新，而不用每打开应用的时候在去获取。

**Service生命周期**

Service的生命周期并不像Activity那么复杂，它只继承了`onCreate(), onStart(), onDestroy()`三个方法，当我们第一次启动Service时，先后调用`oncreate()`和`onStart()`这两个方法，当停止Service时，则执行`onDestroy()`方法，这里需要注意的是，如果Service已经启动了，当我们再次启动Service时,不会在执行`oncreate()`方法，而是直接执行`onStart()`方法。

### 3、BroadcastReceiver广播接收者

BroadcastReceiver 用于接收和发送**系统级**的通知，使得Android的任意一个应用可以接收来自于系统和其他应用的消息

### 4、ContentProvider内容提供者

ContentProvider 用于不同应用程序之间实现数据共享的功能，提供了一套完整的机制，允许一个程序访问另一个程序中的数据且同时能保证被访数据的安全性。使用ContentProvider是 Android 实现**跨程序共享数据的标准方式**

ContentProvider两种实现方法：

1. 使用现有的内容提供器来读取和操作相应程序中的数据
2. 创建自己的内容提供器给我们程序的数据提供外部访问接口。

应用程序通过内容提供器对其数据提供了外部访问接口API，任何其他的应用程序就都可以对这部分数据进行访问。例如：Android系统中自带的电话簿、短信、媒体库等程序都提供了类似的访问接口API。

四、Eclipse 开发工具使用
----------------

> 这部分简单介绍下Eclipse，并开发一个简单的apk并在模拟器/真机上运行

### 1、新建安卓应用项目

**1）新建Android Application Project**

![h8atN6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5850f2a03fd69612207e5411995af2ef7e1cd68e.png)

**2）填写新建应用的名字**

![h8afgg.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9ee5bf40ae1dbe07b6f4c461c151f01de9c29ce0.png)

**3）设置应用程序的图标**

![h8a5uj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9f6cf9ef547433467cb7f95202e85e019013bfb3.png)

**4）选择空白组件**

选择activity组件，有不同的类型，可以自行选择，这里方面先选择空白组件的

![h8aW8S.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f87aa4a16691320985b69e83ffe7998ece70fefe.png)

之后选择`Finish`即可

### 2、项目文件介绍

第一步创建完项目后，显示如下的页面

![h8ahvQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6208730a76bd8ae9a5590e8609deb73a722e463b.png)

在左边项目栏中可以找到主程序的代码`MainActivity.java`，双击查看

![h8aRC8.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-93b570208e6ef75f9a6450cea4317d5f22ddef1b.png)

`AndroidManifest.xml`是任何应用程序的清单文件，包含了程序所有的声明和一些配置信息，比如安卓的版本和一些安卓图标名字等配置的信息

![h8asHI.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-59eed3a173a0b51dcbc6028f68afe000b9f77c37.png)

Eclipse提供了`Manifest.xml`的图形化操作和代码操作如下

![h8ag4f.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-da9482d2f606303fa61eb76a7e6b004b6afb8cca.png)

### 3、构建项目

在左边的选项栏随便添加些组件即可，深入学习请自行google安卓开发

![h8a6Et.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9a87f6343018c24b90298a7d1b2c6fc3d37468a1.png)

### 4、运行项目

将新建的项目导出运行

![h8acUP.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-45d150e6d504c2d4a14791094e9713994741b313.png)

选择雷电模拟器

![h8arDA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4cf4918ecaad17aff72ea5f3dc08f76123954ab8.png)

双击启动

![h8aIDs.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de8d49cb1fc15074db5250107fda53e531cc4c31.png)

五、Jadx-gui 反编译工具使用
------------------

> 这里介绍下Jadx工具钢的简单使用，接下来进入第六节的破解实例中
> 
> 小技巧：直接拖进去再按搜索类才完整地完成反编译工作

### 1、载入文件及介绍

载入贪吃蛇apk文件，主要反编译有两个文件，源代码和资源文件，资源文件对应apk中的文件（这里用压缩软件打开apk文件查看到）

![h3HmGT.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ac8db8ab4258d105501123b006c1267045e0823.png)

### 2、简单搜索类

![h3HeiV.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b35f4225b6c96121030d0e71df82c20f505ba222.png)

### 3、函数跳转

选择函数，按住`Ctrl+左键`可以直接跳转至函数声明处。比如这里的`BuyFailed()`

![h3HVI0.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab8ff6e7ff459a570d4addb64855d092c1c819b0.png)

六、贪吃蛇apk破解
----------

### 1、贪吃蛇apk破解简介

在Jadx中搜索到**支付失败**的字符串，发现`BuyFailed()`和`BuySccess()`函数，我们可以将这两个函数调整位置或者修改，不过在Java代码层不能修改，只能在Smali代码层中修改，先了解下Smali代码和一些底层的知识

### 2、apk程序上手研究

在商店页面中点击购买按钮，显示支付失败，如下图。

**我们的目标：免费购买全部皮肤**

![h8dk8O.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-96b404e9131c91bf30ac8d94409937c44e081d4a.png)

### 3、Jadx 工具反编译分析

拖入该文件，搜索"支付取消"的位置，简单查看该处代码，可以发现支付取消和支付失败均会跳转至`BuyFailed()`方法处，而支付成功会跳转至`BuySccess()`方法处，我们可以想到将成功方法覆盖失败方法进而实现免费购买的效果，接着跟进在Smali代码层分析。

![h8dA2D.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ba1fe647f2e6187610fb96c2640f5cfa1939b5bc.png)

### 4、Android Killer 工具反编译|Smali代码分析

将apk程序拖进Android Killer进行反编译，在工程搜索中搜索"支付取消"字眼，跳转到含有该字符的smali代码处

![h8dFPK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-554474b74bcbff4ba634f8b20c01b78880f48ff1.png)

但是此时有个小问题，怎么确定这里的smali代码对应的是刚刚看到的Java代码呢？Android Killer提供了反编译回Java代码的功能，点击下图上方的标志，查看Java源码，可以发现是一致的。

![h8duVI.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-280505bfb80fced1c937c6571accdacd0fdc240c.png)

### 5、替换smali代码|回编译

找到支付成功的smali代码处，如下红框部分

![h8dKat.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-592a095d22efcb65a7837da5bcfc931f5ffcad4b.png)

将其覆盖支付失败和支付取消的smali代码处

![h8dlPf.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-727c0deea85211ae49988114c043afbde9e46ad0.png)

保存并回编译

### 6、查看效果

可以发现，已经可以免费购买了

![h8dMIP.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-723fe5f730ed73bdb24920173fc22cc556a32fbd.png)