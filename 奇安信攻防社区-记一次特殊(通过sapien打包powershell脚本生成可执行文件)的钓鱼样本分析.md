0x01 背景
=======

某次应急事件中拿到一个攻击者使用的钓鱼样本，这个样本比较有意思和之前的分析有些不同，第一次分析也算曲折，此文记录下对该样本的分析过程。

样本如下：

![image-20230626151411608.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8494c3f77e33bdde85f8567763f60860ad4f7e87.png)

伪装成某某OA的一个升级的程序（发起钓鱼的攻击者，通过伪装成某某OA工作人员）

0x02 样本行为分析
===========

一般笔者拿到样本之后会先丢到虚拟机里面跑下（这里要注意一些反虚拟机操作），然后看下各方面的特征，如注册表修改、新建进程、网络外联情况等。

运行样本：

![image-20230626162050100.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-81292409b0a3f28b920f083aca6521c39646b1da.png)

首先通过ApateDNS看到可疑dns请求：  
![image-20230626162606685.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1a9611516b902635aa0d458e764e4563cfe58405.png)  
进一步查看sysmon：可以看到对应时间，是进程mobsync.exe发起的上面可疑域名的dns请求：

![image-20230626162653585.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4a82b7403ee7cd5a939624c23cd2b88325067fdf.png)

同时我们往前看几条，也就是发起dns前，可以看到有一个进程创建操作，详情如下：

![image-20230626162856500.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1453c9fa0bd8140551f705871e5e1300c3890cae.png)

如上图，我们可以看到这个mobsync.exe其父进程就是样本进程，所以这个进程我们的样本进程创建运行的，所以我们这里其实是直接就拿到了c2地址。

进一步我们看下mobsync.exe这个进程干了些啥，如下图pcmonitor监测到其修改涉及internet Explorer 安全区域的信息的注册表，来增加成功回连的概率：

![image-20230626161827122.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9dd2b49b081468f812afe783e047f51fbf8f2ee5.png)

这里笔者进一步通过inetsim 模拟真实环境，其实就是给样本一个回连的https服务，看看其网络行为：

inetsim记录如下：如下图，好家伙直接空手套白狼，拿到回连的url了，ps:看着就像CS；  
![image-20230626163753476.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f8ea7991a0e999600c222d9ca36b8c551c9b1e10.png)

通过模拟环境的行为分析到这就差不多了，接下来就是样本文件逆向分析了，毕竟谁知道上面的这个些是不是攻击者给我们设置的陷阱呢？（比如当他的反虚拟化比我们的反反虚拟化做的多的时候，那么攻击者的样本里面检测到这个是虚拟环境，就随便弄些行为让我们分析的人去分析，回连一些正常域名/IP等，ps：这个样本回连域名正好就是这个情况，比较特殊，所以全文笔者都把域名脱敏了）。光从行为侧去下结论是不太行的。

0x03 样本逆向分析
===========

一、前置工作：
-------

先来看下样本结构：

通过die我们可以看到其用Smart Assembly做了一次混淆

![image-20230626171032169.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-73877359dccacf2ecc8066406f9b5523310d7cf4.png)

直接通过de4dot来反混淆：拿到解混淆之后的：

![image-20230626171335807.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d2802f98b868f90780053c1852fdee7053862a3b.png)

再丢到die里面：

![image-20230626171701246.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e71df548d2b069ff701123b1643fd7d85b12cc67.png)

首先这个exe没有导入和导出表，只有两个节，代码节和资源节：

![image-20230626172005102.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-67d22a74ddf9cfc9d62ec17ebe104eb15c9b4773.png)

除此之外，翻资源节的时候发现，存在一个比较特殊的标记，sapien powershell v5 host xxx的

![image-20230626174503940.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4b55a1df27726bb165a896e9a1fe9f2f4c4b8248.png)

笔者google找了下这个东西：发现是一个叫[PowerShell Studio](https://www.sapien.com/software/powershell_studio)的特征，是sapien公司的。

![image-20230626175650764.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4e18efc0ca482fb1da036b686f925049594a85a5.png)

接着直接问chatgpt这个是干啥的：

![image-20230626180029574.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e2518852698d55062328a5d3f805e735b041ffee.png)

我们可以得到一个结论这个工具可以用来对powershell代码保护以及封装成一个可执行文件。所以我们这里的样本文件很大可能是这么来的。

如下图，通过启发式扫描，这个样本可能是一个.net的c#程序（这里也印证了上面我们的推测，因为powershell也是基于.net的，所以兼容c#），但是也正是因为这个基于.net所以我们的ida之类的反编译工具不太行了。

![image-20230626172048962.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2fbe6f14e1761d7a4922e37d7eb0e793297e249a.png)

接着我们用dnspy来反编译这个通过.net c#开发的exe文件，将其从中间语言还原成c#源码：

定位入口：

![image-20230626173131242.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-585579b08f97ee951917f60bf67d613ffa4f0275.png)

二、代码分析：
-------

### 1、静态分析：

主函数代码如下：

![image-20230626173149091.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e20627e7dc1fe930cd07fa2d3d1862508ebe1fca.png)

如上图，可以看到，这个样本逻辑里面还是做了一些反调试操作的，第65-68行通过kernel32里面的IsDebuggerPresent()函数来检测进程是否被调试；

还有第69行的Class7.smethod3方法，如下图是其实现，可以看到是通过kernel32里面的CheckRemoteDebuggerPresent()来检测当前进程是否被调试：

![image-20230626173748504.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a7dbbf29543cbb2a3398960527608903c0e8a1f2.png)

接着，来到主要方法 Class9.smethod\_11():

![image-20230626174043113.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-44648440d2782c654b24f19775f5e9d021b53966.png)

接着我们跟进该方法：

![image-20230626181205489.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c7ab66856380e6dee8cc494696c18e91f3549f1b.png)

直到如下下图处，非常可疑，这里读取资源段里面的内容，并赋值给array3数组。

![image-20230626181256676.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-44f709d021252c6141e884e0bd9260d178b82fd8.png)

然后调用了一个smethod\_7的方法对这个array3数组进行操作，最后得到var4，这个函数传入了一个特殊的写死的数组和num2

![image-20230626181535596.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4a433e67918429722236c7d00fff8e217d6aecfb.png)

写死的数组内容如下：

![image-20230626181616585.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5d9a181ab48cea478f500ee6e15a3d0af8eea49c.png)

num2其实就是array3的长度：

![image-20230626181739534.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ff863f85569c0a7692767cfe850fe5dc5949769b.png)

分析到这的时候，笔者猜测这里这个函数在做一些解密操作。

我们跟进来看下Class9的smethod\_7来看下，如下图，简单看下，其实就是一个长度for循环，对传入的byte\_0参数进行一顿操作，其中包括加106，减byte\_1里面对应for轮数的索引的值（超过长度会自动清零 338-342行），之后对一堆情况判断，比如但钱轮数是否是5的倍数，是的话byte\_0的对应字节要加2，等等之类的

![image-20230626182226238.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-618a7b49aa010338071b89c3ac9ff1995b462d34.png)

这里我们没必要去深入分析，因为不需要知道具体是这么干的，我们只需要知道这个函数就是在解密就行。解密的逻辑就是上图。

当然要是搁以前我肯定是不会去分析的，但是现在不一样了，现在我们有gpt了，直接让gpt来分析具体功能细节，反正我又不用动手，如下图是gpt对该函数的分析结果：和我们看的差不多。

![image-20230626182811116.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8fac1ac93925bc78ccb916de91e625cc9e8bab7b.png)

接着我们回到上层函数：解密后的array4变量的内容放到了text2里面：

![image-20230626183012417.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b2b75b949c7d6063e4282522b8a2a8047114a67c.png)

接着我们跟下这个text2：如下图，被丢到class2.method\_3里面了：

![image-20230626183250892.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0e3f214c129a9e4929acee3cd091b4c30a91be2d.png)

跟进方法：如下图，我们还是重点关注传入的解密后的tex2，也就是这里的形参tstring\_10，下图，我们看到就是进行了一个替换操作，把之前的里面`#SAPIENPRESETS`替换成`$PSScriptRoot = \"{0}\"\r\n`+`$PSCommandPath = \"{0}\"\r\n`，其实这里就是获取当前路径和运行的进程路径

![image-20230626183750627.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b41bb600bf33354207ed6b83187976751ed2d106.png)

替换之后直接丢到`Runspace.CreatePipeline.Commands.addscript()`里面，这里其实就是把我们解密后的内容当成powershell脚本语言运行了；

分析到这，我们静态分析就差不多了；

### 2、动态分析

这里我们直接在下面打一个265行打个断点，然后dump下string\_10变量内容，直接拿到攻击者的powershell脚本：

![image-20230626184440397.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-edc024f6485a23accc80259fde1fab2e5e9b1ea0.png)

如下图，我们拿到运行的脚本：

![image-20230626185144381.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2d1c883db00cd868b899eff61e038cea2ce2f2fc.png)

dump下来，用unicode编码打开：

![image-20230626200254214.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ff6ddf047c0d2e00b2cdf7146161ab1c742e37fa.png)

如下图是最后还原的代码：

![image-20230626200529462.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d2fbcc736e3a5b490d0e338f97ba7821582ace96.png)

下面一堆代码，特别长，主要是一些ui之类的命令和资源的存储，比如运行样本的图标之类的，我们来看关键的地方：

首先发现一个函数inject\_Apc的函数：函数实现如下，就是一个简单的APC注入，shellcode加载，稍有不同的是这里是为了不影响主进程的运行，是通过创建一个新进程mobsync.exe进程来加载shellcode：

![image-20230626201057504.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3bd4e133350e3239a33c79f9c8a2ba29ad618944.png)

![image-20230626201754681.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-daf8a0c028368d5e25b8124cacbf7ad9a9648f10.png)

除此之外，我们也来简单看下这个钓鱼样本的功能实现：也就是如下三个按钮都是干啥的：

![image-20230626201839179.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-6f8b40d021231c7de397768eabb47b9ccfd39b1e.png)

直接ctrl+F click ，找到对应按钮事件：就是对应的上面三个按钮：

![image-20230626202023448.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a26aa5a0d38eabc33e07afb0b2dd075afc27d0de.png)

首先是进程检查：其实现如下：就是检索计算机上运行的进程信息，没有其他的远控操作了。

![image-20230626202104112.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4518c722fbc74357e86c3e5bef2aa77146642f20.png)

接着看补丁检查：其实现如下：效果就是将会返回一个对象数组，每个对象代表一个安装的快速修复工程。这些对象包括有关修复程序名称、描述、安装日期和时间以及其他相关信息的属性；除此之外没有其他远控操作了。

![image-20230626202250527.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ee454d5a39f99ea7601c1afe0775eecec48dd4d0.png)

最后一个应用检查，其实现如下：效果就是获取计算机上的所有软件信息；除此没有其他远控操作。

![image-20230626202323893.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-907e19d187762c1b49c6418dcd2a16f288c7b9ad.png)

所以全部分析下来，我们会发现这个样本，只要双击运行就会上线，至于里面的一些按钮都是一些正常功能。（毕竟也还是要装一下的，避免运维人员一看就觉得有问题，然后就上报，g了）

### 3、shellcode分析

最后一步shellcode分析：

这个没啥好说的，笔者把shellcode扣下来的时候，windowsdefender直接杀了，应该没啥研究价值，所以这里笔者就直接模拟跑下得到如下结论：

如下图，可以看到，这个shellcode”动态“加载了wininet.dll ，然后调用internetconnectA回连c2地址，发送get请求（其实就是一个Cobaltstrike 的shellcode），这里拉取`/themes/default/js/jquery-3.3.2.slim.min.js` 其实就是在拉beacon，对cobaltstrike shellcode上线过程感兴趣的话可以阅读下笔者之前写的对csshellcode分析的文章[cs shellcode分析](https://forum.butian.net/share/2017)

![image-20230626203325885.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3722c09281cd7fc5c8cd6dcf0e0556e5e637777c.png)

0x04 反思
=======

就这种技术，我们不妨从攻防的视角来看下如何免杀于绕过。

一、防守方的角度
--------

### 1、如何去检测这种样本

笔者目前的思路是：

我们可以通过yara规则去静态检测，可疑的可执行文件中是否存在上文提到的sapien powershell studio的标记（如下图）；

![image-20230626204732537.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2fd65eb0bf334d49d89f7d285b3747391c3abb33.png)

```php
strings:  
        $a = "SAPIEN PowerShell.v5" wide  
condition  
        all of them and uint16(0) == 0x5A4D
```

这个误报情况应该不会高了，因为一般客户处的业务基本没有把powershell脚本封装成exe的需求，以及在笔者的视角中也没有想到相关其他误报场景。

### 2、如何去分析这种样本

这种样本将powershell代码加密藏到资源段中了，我们只要反编译拿到源码，直接找源码里面的获取资源数据的地方，就能找到解密的地址，然后打断点，直接就拿到了封装进去powershell脚本的地址了。

二、攻击方的角度
--------

那么当杀软将这种可以执行任意powershell代码的exe程序标记成恶意文件的时候，红队视角如何对其进行免杀呢？

- 首当其冲的就是要去特征化，把SAPIEN PowerShell studio的特征去掉，这样能保证静态免杀。
- 其次分析代码的时候，笔者发现这个样本没有做反虚拟机操作和反沙箱操作，这里可以加一些相关操作来提升分析的难度，如下al-khaser项目里面提到的一些vm的特征，注册表，服务、进程、文件等，以及对抗沙箱的定时、睡眠等

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-539c7a19768c942a237049931be69088558566c6.png)

0x05 总结
=======

通过这次的样本，发现了新的攻击手段，通过sapien powershell studio将powershell代码打包成exe,这样就能不调用powershell情况下，执行任意powershell代码，算是学习到了一种新的绕过手段把。同时也掌握了对该类样本的快速分析方法，下次遇到相同类型的样本能够迅速的分析。

笔者才疏学浅，若文中存在错误观点，欢迎斧正。