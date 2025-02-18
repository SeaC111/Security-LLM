1 前言
====

对针对服务器的渗透测试而言，修改APP内容的意义是绕过一些弹窗、前端逻辑等。当然 也可以用来开挂，出去就说你是自学的^ ^。

2 对APP进行基础分析并脱壳
===============

2.1 分析
------

拿到APP，先使用APK Messenger和GDA看一下壳：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684201739688-d84b361e-7e27-4a2b-a020-8e64a0b45a50.png)

这里注意，查壳软件最好一次使用多个。因为各个查壳软件使用的规则不同，可能出现加壳APP不显示已加壳的情况。比如这个APP在APK Messenger里就显示未加壳，但其实是有壳的：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1713751937936-c3a03f6d-3c5b-4403-a21f-b0758546f8d6.png)

2.2 脱壳
------

脱壳最主要的目的是还原被混淆、抽取的函数，便于上钩子或调试、阅读代码。

### 2.2.1 脱出dex文件并删改、修复

使用工具为BlackDex，请注意此APK分位数版本，需要按照手机位数下载32位或64位。

打开工具，直接选择APK自动脱壳：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681375222324-a54570aa-3831-46ab-a1db-29f46ece905a.png)

脱出来了四个dex文件：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681440838646-36b6810a-7c52-4210-a5dc-b4d0ce7e3225.png)

将APK用解压缩软件打开，对比两边的dex文件大小：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681440880345-2e465cdc-3a8c-42b0-9294-679175164517.png)

可以看到有两个dex文件与原始dex大小相同，删去这两个dex。

剩下的dex留个备份，然后用NP管理器打开进行dex文件修复，选择全部修复：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681436996892-68726ccb-39f8-4749-8fca-7c512932429a.png)

### 2.2.2 查找真实入口并进行替换

gda打开或使用baksmali（前者是国人写的软件，后者貌似是什么官方工具，都很容易下载）反编译dex文件**（指的是原dex文件，不是脱下来的）**，然后查找真实appname。

这里使用backsmali，命令为 java -jar .\\baksmali-2.5.2.jar d .\\cookie\_3561024.dex。

全局搜索.field static className:Ljava/lang/String;找到对应的字段（这个需要搜索的字段每个加固是不一样的，毕竟加固相当于自定义读取器，每个厂家代码不同）：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681435267476-129e267b-37df-4246-8a6e-ef0d58112d5e.png)

向下看，找到赋值部分：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681439911517-dd6eb7a0-4f9b-414b-aec0-8bdabc538b52.png)

可以看到值为com.nursinghome.monitor.base.MyApp，这就是APK的真实入口名。

电脑端使用apktool对apk进行反编译（命令参考上面章节），得到smali源码文件夹。

在文件夹中找到AndroidManifest.xml文件，找到application元素的android:name字段，替换为刚才找到的值：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681437934210-6b751fc6-0bbd-4c61-a712-ecdea17224db.png)

### 2.2.3 重新编译APK并删除加固文件、替换dex

替换完成后，保存文件，使用apktool重新编译：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681441280037-63b8469a-cfeb-4b0e-bc93-a8b871d2ed7e.png)

然后用解压缩软件打开编译后的APK文件，查找并删除以下文件：

- 0O等类似开头长得很混乱的文件，如0OO00l111l1l
- tencent\_stub
- tosversion
- 其他名字中带有shell的文件（主要是so文件）

然后，删除根目录下的classes{n}.dex文件，放入第一步中修复好的dex文件并将它们重命名为classes{n}.dex。

### 2.2.4 重新签名，安装

跟第八节中的步骤一样。打开NP管理器，选择APK文件，可以看到加固已经没有了，但是显示校验不通过。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1713751987708-973abc84-3816-4c9d-99fe-90117a16aa3e.png)

点击功能，选择签名然后安装签名后的APK即可：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1681440439215-021f7549-0f70-479e-a83a-1d783bc4eecb.png)

3 静态审计和动态代码分析
=============

这个APP的话，其实代码写的还可以，没有特别离谱的部分，静态是可以看出来的。

而且动态调试主要调试的是SMALI代码，看的也是Dalvik寄存器。没有一定的经验是不建议直接动态调试的。

静态审计代码推荐使用Jadx，可以直接查看JAVA代码。动态调试推荐JEB。动态调试的环境能使用真机就使用真机。使用模拟器会出现各种各样预料之外的情况。

3.1 静态审计之前：Android代码讲解
----------------------

无论是静态审计还是动态调试，都需要具备一些代码基础（最好自己上手写一个简单的Android应用）。也许有些情况只需要修改一下if表达式的true/false，但更多情况需要我们跟随Intent、追踪函数。

我们这里的目标是去除开屏广告。开屏广告是无论如何都会被展示的，所以不能通过修改逻辑表达式的值来跳过，而是要通过Intent进行跳过。

[Android中Intent的介绍\_android intent\_休以希的博客-CSDN博客](https://blog.csdn.net/u010845516/article/details/122423619)

Intent是Android中的重要组件，很多Activity之间的跳转操作都通过Intent执行（微信小程序中也有类似的组件）。我们可以将Intent理解为一种跳转指令，activity.startActivity(intent)会令APP跳转到destActivity。

开屏广告之类的占满整个屏幕的广告绝大多数会以Activity存在（我不知道谁会把它写成Fragment，但是完全没必要，所以可能性是可以忽略不计的），所以要跳过开屏广告，**我们要找的第一行代码是跳转到广告Activity的Intent，第二行是广告Activity中跳出的Intent。**

另外，拿到代码先看抽象程度，如果没有混淆的很厉害可以先找类名、函数名等关键词，如果参数等完全被混淆我们可以找APP中出现的中文（这些中文按照Android的代码规范需要存储在特定的xml文件里），如：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684204813735-2c4c3fc8-52f1-496e-aed0-1a27bb74d669.png)

然后我们可以根据其对应的“name”查找调用地点（搜索R.string.name），进而定位到其所属的Activity或代码。如：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205339746-9ddba3bf-f751-4ef7-93e7-8e8488d481f8.png)

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205362111-bf8bac8a-99f2-4183-b1f7-9f038f076d6c.png)

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205376747-4b104298-c9cd-4075-9fdd-5f6399e6cfbb.png)

或者我们也可以继续搜索资源（布局文件），使用@string/name，找到其所属的Activity或Fragment，如：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205485094-bd8bf920-9b19-4d68-afdc-171e95e98ee1.png)

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205503993-25031e0e-359a-49bf-af60-070d1a8857db.png)

3.2 静态审计
--------

先看下混淆程度，查看主包下类名混淆程度：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205607103-ae90c73e-ce5e-4788-be41-f4f888f26d6c.png)

还能接受，程度不重。我们先找一下广告所属的类，尝试搜索类名Ad：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205768024-e61172c7-73d2-463c-9a2a-2fcfcab07f51.png)

可以看到明文的类名还是挺多的。我们先看看能不能找到Activity类，缩小范围：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205821281-773f3dc2-a39d-4e51-a318-62ee32e6c149.png)

找到了，名字就叫AdActivity。

然后我们开始寻找两个Intent。先在AdActivity里找跳出Intent，看代码，文件中搜索startActivity：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684205957477-142482f8-cff6-4722-96e4-100d11ce5a74.png)

有两处跳转，一处跳转到登陆，一处直接跳转到主页面。这里我们可以思考一下如何绕过广告框比较合适。本来最简单的方法是直接复制这里的Intent替换进入AdActivity的Intent。但是这里明显有额外的逻辑。那么我们可能需要在进入AdActivity后促使其自动执行跳转的方法b。

然后我们继续查找跳转到AdActivity的Intent。

跳转到某某Activity的代码为new Intent(content,xxActivity.class)，可以全局搜索new Intent(this, xxActivity.class)或xxActivity.class（记得关掉正则表达式）。这里试试第一种：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684206519190-7c682fb7-5071-4502-a8a4-acfd268b9ffc.png)

果不其然，找到了。

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684206633274-5fa0ca22-b850-4d00-83c4-ead801f143a3.png)

3.3 动态代码分析调用路径
--------------

由于静态审计处并不方便查看代码调用逻辑，我们使用动态分析来查看AdActivity内部的调用链。

使用JEB打开APP，找到第一个Intent startActivity时的代码，再次解析跳转到SMALI并Ctrl+B上断点：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684208669873-e260ea96-77d4-4a76-90ad-399eb25f99ba.png)

手机打开APP（最好在开发者选项里设置一个等待调试器），JEB打开调试器，链接到目标进程：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684208718722-7e36c337-e647-46ab-ae4f-7a8b36f65ea9.png)

附上进程后，使用跳过![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684209295694-34546307-82cc-4b7a-b38f-dc7105e98f39.png)和进入![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684215533578-65189d47-6d4c-4b0c-9b88-5c7de2ab0933.png)查看代码的执行流程。

3.3 修改代码并重新打包
-------------

从上面的动态和静态审计中可以找到很多种修改APP绕过广告的方式。我们这里使用最简单的一种：直接将计时器的时间设为0，使其立刻跳转。

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684216995407-3276ec93-63f0-44fd-9c6f-fd106cc220ea.png)

关键代码如上所示。

apktool直接反编译APP，然后寻找此方法（通过搜索函数名可以快速查找到）：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684217453709-f433e50b-d82c-4c37-bcdd-1fffac240230.png)

参数对应如下所示：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684217827597-51d32404-cb2a-466b-8023-49d2d50e0329.png)

对照原JAVA函数调用：

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684217885256-da24cb02-4908-44d8-bea8-77956ef87f73.png)

可以看出，我们需要找到寄存器v4的上一次赋值，将其改为0f（float）。

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1684218187241-132d62bb-b7d7-45f3-ba13-3d1df3973bb4.png)

然后重新打包，签名，安装，绕过成功。  
绕过前有五秒广告（我中间点了一下跳过）：

![视频录制-2.gif](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-363eae0d9233cdcc90cb8bbd15aa2062b67cf9ef.gif)  
绕过之后广告界面直接消失：

![视频录制 1.gif](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-509b861dcc5446c8abdf41d131b3e4d8a204a0d2.gif)