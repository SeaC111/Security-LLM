从西方APT组织的攻击历史及已经泄露的网络武器看，高隐藏、高持久化(Low&amp;Slow)是其关键特征，而 Rootkit 则是达成此目的的重要技术之一。

在上一篇文章“【Rootkit 系列研究】序章：悬顶的达摩克利斯之剑”里，我们介绍了Rootkit的技术发展历程、Rootkit背后的影子以及 Rootkit 检测基本思想。本文首先从Rootkit的**生存期**、**可达成的效果**，以及**运用这项技术展开攻击的可行性**和**Windows Rootkit现状分析**四个角度展开讨论，并结合历史攻击事件，分析掌握这项技术的APT组织所**关注的目标群体**和**可能造成的影响**，最后总结**Rootkit在不同层次攻击活动中所处的地位**。

**1.** **“低调”的Windows Rootkit**
-------------------------------

当你听到Rootkit时，你的第一反应是什么，高难度、高隐藏？是的，近年来，随着Windows安全机制的不断完善，往Windows系统中植入一个Rootkit的技术门槛也被不断拔高。可就算Rootkit在所有安全产品检出的恶意软件中占比率极低，也并不代表它带来的威胁就可以忽略，恰恰相反，**Rootkit的高门槛使其更多地被运用在更高质量的攻击活动中，从这一角度来看，每一个客户场景出现的Rootkit背后都可能隐藏着长期的攻击活动**。

对于攻击者来说，**高投入的同时也意味着高收益**，开发一款Rootkit不算简单，但发现一个Rootkit同样不简单，一个普通恶意样本的生存期可能在投入使用时便结束了，而一个**Rootkit的生存期可以长达数年，甚至更久**。

从Vista开始Windows会对加载的驱动进行签名验证，这使得攻击者的**植入成本变高**，而PatchGuard也增加了攻击者对系统内核篡改的成本。基于此，Windows Rootkit在野的声音仿佛小了许多，我们对它的关注度也在降低，但它带来的威胁真的就可以忽视了吗？还是说更应该理解为“小声音，高威胁”。

从下图我们可以看出，无论Windows Rootkit在野声音有多小，它都未曾消失过

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-be2488617a3b2c9ad89aeac3a66041e84817123b.png)

**2.** **从生存期看Windows Rootkit**
-------------------------------

让我们把APT攻击的阶段简化，在初始打点阶段攻击者可能会采用漏洞利用或钓鱼攻击，毫无疑问，近几年也是钓鱼攻击大行其道地几年。

以文档钓鱼为例，收到的钓鱼邮件可能会像这样

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-05064b3de2e9cdade4e4352c6697de90bd625bc1.png)

当然，我们也可能收到**伪装成文档的PE**文件

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-cabccf1d780328c776c5b5b9e1edfe5fbc8284d0.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9b7dcf1e751aeadb37400c7eb89f020f80d5b27c.png)

它也有可能长这样

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-79fb336209aaca1e7c7e7f602be7892e4b163b88.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4d7a7bf6a6ee5efa2daa2291124d0e4e49cfe0da.png)

尽管形式还算多样，但细心的你一定已经发现了，它们或多或少都存在着一些**可识别的特征**，在经历过钓鱼的反复洗礼后，甚至会有部分人不管什么邮件都直接丢VT跑一圈（当然这样做不好，毕竟误传敏感文件还是比较严重的），这些特征让攻击活动变得非常容易暴露。

再假定攻击活动已经进行到权限维持之后，我们也会排查到下述类似情况

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-abfae23095da925261357cb10b426c0a3ab39e34.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-54e94115d5de4ba0467f0ec5f951f821565014d2.png)

当然，这样做会显得有些过于直接，攻击者可能会采用更为复杂的手法，比如DLL劫持，一方面避免了持久化的痕迹，另一方面在免杀上也取得了一定效果，但我们仍然可以观测到

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0c54c6966f02dc2b2c7bf4db58d04cf04ca9baa7.png)

这样来看，发现一个异常也不算太难，对吧，毕竟攻击者在每个环节都或多或少地留下了一些痕迹，无论我们哪个环节捕获到了威胁，都可以向前和向后反溯，还原攻击链路。但由于真实环境足够复杂，也不是所有人员都具备安全知识和安全意识，导致攻击活动通常也能成功，甚至持续很长时间不被发现。但至少，当你感知到它可能存在威胁时，还是能比较容易地发现它。

那么，这样的威胁我们还是可以称之为**“摆在明面上”**的威胁，你只需要更加耐心和细心地将它们找出来，**而随着安全体系建设地逐渐完整和全员安全意识地不断提高，此类攻击的生存期也会不断缩短**。

回过头来，我们再看一看Windows Rootkit，历史上APT组织Strider曾利用一款名为Remsec的恶意软件对多个国家，**包括政府机构在内**的系统进行了**长达五年**之久的监控

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-6da10a748c143efd652ac89216229775591afc5c.png)

其实这里少说了一个词“至少”，该Rootkit帮助攻击者完成了**至少长达五年**的攻击活动，这期间**包括俄罗斯、伊朗、卢旺达、中国、瑞典、比利时在内**的多个国家的**政府机构、科学研究中心、军事组织、电信提供商和金融机构**都有被感染。

且该Rootkit的**功能非常完善**，具有密码窃取、键盘记录、后门控制等多种功能，试想这样一个恶意软件对上述目标进行着长达至少五年的监控，是否足够让人警惕呢？

Remsec被发现之时，研究员们对它的评价是**“一种几乎不可能被检测到的恶意软件”**，而这也是一直以来大家对Rootkit的认识，这一点是否非常值得我们深思呢，究竟是Windows Rootkit慢慢销声匿迹了，还是**受限于能力不足**导致其检出率如此之低，而生存期又如此之长呢？

其实对于攻击者来说，**打点技巧是多种多样的**，并不一定要选择像钓鱼这样会留下明显痕迹的技巧，对于那些使用未知技巧，甚至是0day进行攻击的活动，我们想要在打点阶段捕获它们的可能性较低，这种情况下，**捕获攻击者在后门植入、持久化等阶段留下的痕迹**，并基于此反溯，还原攻击链路会是一个不错的选择，**而Rootkit会把这些痕迹通通隐藏，让我们的命中难度剧增**。下图显示了近年来在野0day数量

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c0c0dd4441957a9e88fad54b0df7d696d9fa7f44.png)

**3.** **从达成效果看Windows Rootkit**
--------------------------------

那么Rootkit究竟能达成什么样的效果呢？

以一个操作图形接口的Rootkit为例，它在任务管理器中隐藏了calc.exe

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9c480f72b90db7e2023357c52e18f0b0ff517cb3.png)

换句话说，Rootkit可以把攻击者不想让你发现的**攻击痕迹进行隐藏**，比如我们在进程异常排查中，会关注那些有着**异常通信**或是**可疑模块加载**的进程。

以白加黑技术为例，该技术虽然能在免杀上取得良好效果，但如果同时存在异常通信和可疑模块(未签名的dll)，我们就还是能较为容易地定位到异常点。

而通过一些简单的技巧，就可以在一定程度上对白加黑利用中的恶意dll进行隐藏

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-170ad62adf9e962f1c9d82974981d4fb3916db34.png)

而Rootkit能达成的隐藏效果，会远胜于上图情况，当使用Rootkit从分析工具中**彻底隐去**这些异常点时，你还能快速地判定该进程有问题吗？

当然，此处仅是过滤了异常模块，**这也只是Rootkit能做到的一小部分**，除此以外，服务、端口、流量等也都可以通过Rootkit进行操作，那么你想看到什么，攻击者就可以让你看到什么，**“摆在明面上”的威胁就转变成了“隐藏在暗地里”的威胁**，想在主机上发现异常就会变得极其困难。

**4.** **从可行性来看Windows Rootkit**
--------------------------------

前面的内容提到，Windows引入了两大安全机制来对抗Rootkit，分别是签名验证和PatchGuard，我们将针对这两个点分别展开讨论。

### **4.1签名验证**

关于这部分内容，国外安全研究员Bill Demirkapi在Black Hat 2021的议题《Demystifying Modern Windows Rootkits》中给出了答案，相应的解决方案分别为**直接购买**、**滥用泄露证书**和**寻找“0day”驱动**。

##### **4.1.1 购买证书**

这种方式其实没什么好说的，攻击者唯一需要考虑的问题，就是**购买渠道是否足够可靠**，是否存在身份暴露的风险。

##### **4.1.2 滥用泄露证书**

从可行性上来说，**Windows根本不关心证书是否已经过期或者已经被吊销**，通过泄露的证书，攻击者就可以生成在任意Windows版本下都有效的驱动签名

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-727fc1aa8b5574235d7435f77b7fb88eee9faf7e.png)

由于不需要购买证书，在降低成本的同时也避免了因购买渠道不可靠而暴露身份的风险，此外，通过这种方式进行植入所需的前置条件也不算多，与挖掘“0day”驱动的方式相比，技术难度降低很多，当然，**掌握了泄露证书的情报后，相关安全厂商可以针对此类Rootkit进行查杀拦截**

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9690442af4b9fe6ebaa9404f0625b5bb9a1773b1.png)

下图是收集到的一些历史泄露证书，从此图可以看出**泄露的情报并不少见**

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e12f4e582cfd128417211209fb0df5eb3e34e9b0.png)

##### **4.1.3 “0day”驱动利用**

从可行性来说，**一定存在着可被利用的“0day”驱动**，而历史上，就曾有知名的APT组织利用具有合法签名驱动程序来进行恶意驱动的加载，该组织是**俄罗斯APT黑客组织Turla**，它利用的合法驱动为VirtualBox，下文是对该利用过程的描述

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d2c6b7cf5b65d424e4e865c02fa3f91176b1db49.png)

### **4.2 PatchGuard**

网上有着包含win7、win10在内的不少开源项目，攻击者可通过集成这些项目**绕过PatchGuard**，往内核中植入恶意代码，实现Rootkit功能  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8221f6ad7a67e51ed095dc078cb65c7d17cbf35e.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-7fa1bdd6a3962659fb488ed8a40def059b28fe4f.png)

**5.** **从现状来看Windows Rootkit**
-------------------------------

当我们尝试在VT上进行Hunting，会发现**无效证书的利用非常普遍**

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-519de8d376b323f85ea0a6a2d402a8139f40f549.png)

其实，就算你遇到一个**有着合法签名的Rootkit**也不算什么新鲜事了

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d45a58ab3cec5d931fdbaaef0920a1a071fcede2.png)

回过头来单看2021，Windows Rootkit攻击更多地集中在游戏行业（我想，这也是它们相对而言较快暴露的一个原因，传播量变大的同时，也遭受了更多的关注），但当Rootkit**调转枪头对准更高价值的目标**时，当它们的目的不再是简单地获利时，当它们的**动静更小**，**隐藏更具针对性时**，我们是否做好应对准备了呢？毕竟从技术角度而言，APT组织又有什么理由拒绝Rootkit呢?

值得注意的是，当APT组织拿起Rootkit这个武器时，它们枪头要对准的将会是**包括政府、军事在内的各种重要组织机构**，它们的目的将不再是简单地获利，而是**对目标地长期监控**和**重要情报的窃取**，这一点从历史APT运用Rootkit进行的攻击事件中不难发现。

**6.** **总结**
-------------

基于社工和钓鱼结合的攻击活动虽能以**较小的成本**拿下目标，但留下的**明显痕迹**会导致其生存期骤减，很容易在**打点阶段就暴露**，而通过其它未知渠道打点后，借助合法进程、机制完成恶意活动(如Lazarus对Get-MpPreference的利用)，或通过白加黑(如dll劫持，LOLBINS)等方式进行后门安置和权限维持等，虽然在免杀层面有着不错的效果，却**不能很好地隐匿攻击痕迹**。

Rootkit更多地对应在后门安置、持久化阶段，掌握这项技术的攻击者也会有着**更高的技术水平**，他们或许会**更青睐于一些高级的打点技巧**，以**降低每个环节被捕获的可能性**，当然，**越高价值的目标越会吸引更高成本的投入**，我们想要从容应对也就更加困难，而事实上，是否有APT组织正利用着此技术进行攻击活动也尚未可知。

**参考链接：**

1.[https://en.wikipedia.org/wiki/Project\_Sauron](https://en.wikipedia.org/wiki/Project_Sauron)

2.[https://en.wikipedia.org/wiki/Project\_Sauron](https://en.wikipedia.org/wiki/Project_Sauron)

3.<https://www.sciencealert.com/scientists-just-found-an-advanced-form-of-malware-that-s-been-hiding-for-at-least-5-years>

4.<https://arstechnica.com/information-technology/2016/08/researchers-crack-open-unusually-advanced-malware-that-hid-for-5-years/>

5.<https://arstechnica.com/information-technology/2016/08/researchers-crack-open-unusually-advanced-malware-that-hid-for-5-years/>

6.<https://www.inverse.com/article/19401-project-sauron-malware-strider>

7.<https://www.infosecurity-magazine.com/news/project-sauron-has-been-spying/>

8.<https://www.infosecurity-magazine.com/news/project-sauron-has-been-spying/>

9.<https://www.ptsecurity.com/ww-en/analytics/rootkits-evolution-and-detection-methods/>

10.<https://decoded.avast.io/martinchlumecky/dirtymoe-rootkit-driver/>

11.<https://i.blackhat.com/USA-20/Wednesday/us-20-Demirkapi-Demystifying-Modern-Windows-Rootkits.pdf>

12.<https://www.lastline.com/labsblog/dissecting-turla-rootkit-malware-using-dynamic-analysis/>

13.<https://www.chinaz.com/2021/1022/1319390.shtml>