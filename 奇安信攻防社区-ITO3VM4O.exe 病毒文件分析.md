0x01 样本概况
=========

样本信息
----

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-397e9654bd75175f6295bc2098fdb1ed98769a6a.png)

测试环境及工具
-------

- 测试环境：Windows 10 专业版 64 位
- 工具：die、exeinfope、PEiD、x64dbg、火绒剑、dnSpy32、ILSpy

分析目标
----

- 初步分析病毒文件
- 查看病毒主要行为
- 详细分析病毒文件
- 手工查杀病毒

0x02 具体行为分析
===========

初步分析病毒文件
--------

静态分析：首先使用各种查壳工具对样本进行查壳和运行平台信息，样本无壳，以下是查到的结果：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f4197b101298d10ef98c0efe09e88fd6db9dbf77.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5c69926e7c003774a74d6f56e194b36d64f73a0b.png)

从上面图中我们可以知道这是一个 .NET 平台下的程序，使用的语言是 C#。

查看病毒主要行为
--------

使用工具：火绒剑

1：先分析第一个大项 —— “执行监控”。子项有“模块加载”“进程退出”“进程启动”，都是很重要的，所以全选分析。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-520aa13363fbae6460de99d4c7dfaccbf76190d9.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ca41fdc344388f024ca6d34a81f9e8e923b227da.png)

从上面的图中可以看到文件开始运行后加载所需动态链接库，在10秒后出发系统异常然后退出。

2：分析第二个大项 —— “文件监控”。由于子项太多，且大多不需要详细分析，故只选择如下几项来进行分析。

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fd62e324c4d1a5c7f62b62f4c152a99affb2706a.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d957001f6151ad827f12af0f446b316976a9c14f.png)

3：分析第三个大项 —— “注册表监控”。同样的，我们只需选择“删除注册表项值” “设置注册表项值”“创建注册表键”这三个子项逐一分析即可。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a63ba2ebf9db977d5243f4d5297c537298e57ed6.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-98ea94005140ccc0ec8bc50b5d96e2c0eac0e770.png)

4：分析第四大项 —— “进程监控”。由于每一个操作都可能是重要的行为，为了避免遗漏，这里我们选择全部的子项进行分析。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-180336564ba01b9525db49f1824a05017311da25.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-53e2e14d174f5fece703bbddb531c84be758ca8c.png)

5：分析第五大项 —— “网络监控”。同样的，由于每一个操作都可能是重要的行为，为了避免遗漏，这里我们选择全部的子项进行分析。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bd3a8535d87b22c1e3e3c667b20292c97d795b3b.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd04598c75f4a05943f0cd31f408516d3e98124e.png)

其所连接的 IP 进过微步在线勘察后发现是一个远控类的恶意软件或勒索软件：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-26993f56f84d48aef458964574224a6d37900c14.png)

6：分析第六大项 —— “行为监控”。这个项目可以说是对病毒全部行为的汇总，因而我们全选，这也能为我们之前的分析起到查漏补缺的作用。点击“确定”。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-04b6e7244bf116e6d34d2567a29354828928dc51.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c57c495525a046694b5eb47750c6f58c0a5c89de.png)

详细分析病毒文件
--------

现在开始详细分析，即借助 ILSpy 和 dnSpy32 两款工具，动静结合地分析这个病毒。当然，主要用到的是 ILSpy，只有到了静态分析无法确定时才用到 dnSpy32。

**把文件放入 ILSpy 程序中进行分析：**  
1：byte 类型的变量 Buffer 通过 Account 和 Rhbpuseciwgwjqu 自定义函数把 url 参数 [http://91.243.44.142/arx1-Kvaooraq\_Lwbhqgmh.bmp](http://91.243.44.142/arx1-Kvaooraq_Lwbhqgmh.bmp) 所指向的文件内容以二进制比特流的方式下载存储到自身中。

其中有一个根据时间差值执行的空操作的反调试函数 Dynamic()。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bce6f307f165519a738b047e68322f0783dc37ab.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cbad112974e1ec8492b26a5816fffa72a2b2f823.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a4c5acce1b7c5e7d6e85694da053f3070a18b7b3.png)

2：由 main 函数中的 Delege() 函数调用了 USA()、World()、Mouse() 三个函数，把一整个程序串了起来。  
进行的行为是根据前面下载的 URL 资源文件进行远程加载托管程序集并使用反射功能生成对应实例，最后再进行调用实例的特定方法来执行恶意代码。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7119f03d5dcf139948fee84c57b81c4f66b5d692.png)

3：使用 dnSpy32 进行动调，查看代码执行情况  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0f8443c917cbd8777ab95d565c201bc16977b682.png)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d3768d5733fbef81e06ba7509ca9e0d55fc68d59.png)

**综上，现将其总结如下：**

1. 根据 URL 以比特流形式下载其指向的的文件。
2. 根据下载的比特流进行远程加载托管程序集并调用其中特定对象中的方法，所以 url 所指向的文件以 bmp 结尾是一个幌子，实际上是一个恶意代码文件。
3. 通过时间差值进行反调试，但是一个空操作。
4. 如果对应的 url 资源没下载成功或下载的资源中没有对应的对象及其成员，就直接抛出一个异常后再无其它操作。所以对于现在来说 url 已经失效，程序不具备特别威胁性。

0x03 参考资料
=========

> <https://x.threatbook.cn/v5/ip/91.243.44.142>  
> <https://q.cnblogs.com/q/89507/>  
> <https://cloud.tencent.com/developer/ask/sof/56111>  
> <https://vimsky.com/examples/usage/c-sharp-dictionary-add-method.html>  
> [https://blog.csdn.net/qq\_43339052/article/details/110445417](https://blog.csdn.net/qq_43339052/article/details/110445417)  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.reflection.assembly.load?view=net-6.0>  
> <https://www.cnblogs.com/weifeng123/p/8855629.html>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.reflection.assembly.gettype?view=net-6.0>  
> <https://docs.microsoft.com/zh-cn/dotnet/api/system.delegate.createdelegate?view=net-6.0>  
> <https://www.jianshu.com/p/63454fb25866>  
> <https://blog.csdn.net/sandykwx/article/details/8512016>  
> <https://s.threatbook.cn/report/file/8820fe6c0f2d9f702a91f92a275a534de63e88de46f2baa05d50d4d7855bf319>  
> [https://www.52pojie.cn/forum.php?mod=viewthread&amp;tid=1096117&amp;extra=page%3D1%26filter%3Dtypeid%26typeid%3D62](https://www.52pojie.cn/forum.php?mod=viewthread&tid=1096117&extra=page%3D1%26filter%3Dtypeid%26typeid%3D62)  
> <https://blog.csdn.net/zlmm741/article/details/106686632?spm=1001.2014.3001.5502>