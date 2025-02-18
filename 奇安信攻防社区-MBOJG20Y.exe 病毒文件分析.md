0x01 样本概况
=========

样本信息
----

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1adfdfc1cb47ecc620c9b8b7667973f73d227e4c.png)

测试环境及工具
-------

- 测试环境：Windows 10 专业版 64 位
- 工具：die、exeinfope、PEiD、x64dbg、火绒剑、dnSpy32、ILSpy

分析目标
----

- 初步分析病毒文件
- 查看病毒主要行为
- 详细分析病毒文件

0x02 具体行为分析
===========

初步分析病毒文件
--------

静态分析：首先使用各种查壳工具对样本进行查壳和运行平台信息，样本无壳：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a9edb63269e9292a807dae8d59ac3f9b81566a0a.png)

查看病毒主要行为
--------

使用工具：火绒剑

1：全选 “执行监控”，查看程序执行记录  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ed9c41c1453cf613080e9bf7018d41e9e9edf963.png)

2：选择 “文件监控” 下的 “设置文件属性”、“文件被修改”、“写入文件”、“创建文件” 子项，查看程序对文件的操作。发现程序无上述操作。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d825e6b572a2ee4f52da3aec954ef72bd526f182.png)

3：选择 “注册表监控” 下的 “删除注册表项值”、“设置注册表项值”、“创建注册表键” 来查看程序对注册表的操作。程序也无所选操作。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-53f991c034f35c1770fc61e7b7d2ee4a6f97299e.png)

4：全选 “进程监控” 来查看程序对进程的操作。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b321256b77a74391e2f976516b650ef7b5d73bf8.png)

5：全选 “网络监控” 查看文件对网络连接的操作  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ab25c90c56c8a4bcb90c55fa1ff3cf5053ebe6b4.png)

其所连接的 IP 进过微步在线勘察后发现是一个远控类的恶意软件或勒索软件：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b72ece82dd87ea29303baf07a82266e130bb5fea.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-18e934be2090f960ab9405ec8312488a110b29b1.png)

6：全选 “行为监控” 查看程序的所有行为。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-05801ca370cc7609cc631a1bab9da61d39548b98.png)

详细分析病毒文件
--------

借助 ILSpy 和 dnSpy32 两款工具，动静结合地分析这个病毒。  
主要用到的是 ILSpy，只有到了静态分析无法确定时才用到 dnSpy32。

**分析发现——程序主体分为三大板块：**

1. \\u0005 自定义类创建名称为 Form2 的窗体，其带有三个自动点击的按钮样式，每个按钮绑定一个自定义事件。
2. \\u0003 自定义类创建名称位 Form1 的窗体，无其它过多行为和样式。
3. FacadeMapper 自定义类下载恶意链接 [http://91.243.44.142/pi-Rategev\_Pcikzryl.jpg](http://91.243.44.142/pi-Rategev_Pcikzryl.jpg) 所指向的内容并将资源传给 \\u0005 处理。

**把文件放入 ILSpy 程序中进行静态代码分析：**  
1：从第三个板块 FacadeMapper 自定义类开始分析，该类以单线程模式激活、启动、展示 \\u0005 和 \\u0003 定义的窗体。  
其还通过自定义函数 PushProperty() 和 RateProperty() 下载远程 url [http://91.243.44.142/pi-Rategev\_Pcikzryl.jpg](http://91.243.44.142/pi-Rategev_Pcikzryl.jpg) 指向的恶意文件到比特流中并返回，以作进一步处理。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b0fc11d0b6719b86fe5f206889042f5c30572eda.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-66c38df9689f2632c58e2a882b94d99a393d30ed.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-17695244bf226122f39234e5be99b692fdeed847.png)

2：接着分析第一个板块 \\u0005 自定义类，该类创建了一个窗体和其内的三个按钮来执行一系列连续的操作，达到执行恶意文件中指定代码的功能。  
通过给窗体绑定 InvokeProperty() 事件来依次生成 3 个按钮的点击事件从而按顺序触发 button1、button2、button3 中与点击事件绑定的 InsertProperty、IncludeProperty、ManageProperty自定义函数。  
这三个自定义函数分别是对第三版块 FacadeMapper 传入的远程资源的比特流进行 "加载托管程序集"、"锁定程序集中指定类型对象"、"调用程序集中指定类型指定名称的成员函数" 的操作来执行远程恶意文件的指定代码。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cf72b261f27db1228478a1f9bf3862c841f1c01c.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e3c2a00b756e2c32fa59e14a1126de9763545bc7.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1581c5379df6d2b2a0d32ca1d4c5392ee8d86732.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-328f43d5e1a17037b3e52a29e5fe0895c2628f33.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1ee1fee87882094859ca27965e94de0a63d278fd.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-44789846c0b0e709a2d00c8e7cc10522e9c3f3be.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e7f863db1ebd44408c960223503eb80c7755db80.png)

3：接着分析第二个版块 \\u0003 自定义类，该类通过 SetupProperty 自定义函数生成一个名称为 Form1 的窗体，并通过绑定的伴随事件 Runproperty 来生成 \\u0005 类的实例并通过 .show() 方法展示其 Form2 窗口。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7d757e6216d1df0ebb4050eb8ba48a74f67e4cdb.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2bad73ad97dc79d9d1fe47b5769d7d0252568c11.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-664538dbdd73806660e4d2816c837d570712f58f.png)

3：使用 dnSpy32 进行动调，查看代码执行情况  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c90d99f9f7cb6fd22a25e5c1560abd526084575f.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d3b998b37135d549ad7da196c829957c4bdc1662.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-67e8b2327b9c88811de68a212dcb9e2da4ec7fba.png)

**综上，现将其总结如下：**

1. 程序通过 FacadeMapper 自定义类以比特流形式下载恶意链接 [http://91.243.44.142/pi-Rategev\_Pcikzryl.jpg](http://91.243.44.142/pi-Rategev_Pcikzryl.jpg) 所指向的内容并将资源传给 \\u0005 类处理。
2. \\u0005 类创建窗体以及三个按钮控件，把 FacadeMapper 类传过来的比特流进行分步处理，提取并执行指定位置的恶意代码。
3. 最后通过 \\u0003 类把 \\u0005 类创建的窗体 Form2 展现出来，而 \\u0003 类自身的 Form1 窗体则由 FacadeMapper 生成其对象实例时调用和展现。
4. 由于 url 指向的资源文件已经失效且程序无其它过多行为，所以现阶段程序并不具备特别威胁性。

0x03 参考资料
=========

> <https://blog.csdn.net/wzy0754/article/details/67636659>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.windows.forms.application.setcompatibletextrenderingdefault?view=windowsdesktop-6.0>  
> <https://www.cnblogs.com/gyc19920704/p/6509926.html>  
> <https://www.cnblogs.com/jiayan1578/p/11926459.html>  
> [https://blog.csdn.net/qq\_34702563/article/details/86714043](https://blog.csdn.net/qq_34702563/article/details/86714043)  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.windows.forms.control.suspendlayout?view=windowsdesktop-6.0>  
> <https://blog.csdn.net/yansanhu/article/details/5658285>  
> <https://docs.microsoft.com/zh-cn/dotnet/csharp/language-reference/keywords/base>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.windows.forms.control.clientsize?view=windowsdesktop-6.0>  
> <https://docs.microsoft.com/zh-tw/dotnet/api/system.windows.forms.autoscalemode?view=windowsdesktop-6.0>  
> <https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.containercontrol.autoscaledimensions?view=windowsdesktop-6.0>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.windows.forms.button.performclick?view=windowsdesktop-6.0>  
> <https://cloud.tencent.com/developer/article/1812673>  
> <https://zhidao.baidu.com/question/129357332.html>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.windows.forms.form.dispose?view=windowsdesktop-6.0>  
> <https://www.cnblogs.com/1175429393wljblog/p/5013367.html>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.net.webclient.downloaddata?view=net-6.0>  
> <http://c.biancheng.net/view/2986.html>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.idisposable.dispose?view=net-6.0>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.resources.resourcemanager.-ctor?view=net-6.0>  
> [https://blog.csdn.net/xiao\_\_1bai/article/details/125090233](https://blog.csdn.net/xiao__1bai/article/details/125090233)  
> <https://s.threatbook.cn/report/file/c35435a0675f7561c9095b0516ce57b6ff60d71f289d3b1a9a669752b70f1b3a>  
> <https://x.threatbook.cn/v5/ip/91.243.44.142>  
> <https://docs.microsoft.com/zh-cn/dotnet/csharp/language-reference/keywords/override>  
> <https://www.52pojie.cn/thread-1641298-1-1.html>  
> <https://www.52pojie.cn/thread-1643486-1-1.html>  
> <https://www.virustotal.com/gui/file/c35435a0675f7561c9095b0516ce57b6ff60d71f289d3b1a9a669752b70f1b3a>