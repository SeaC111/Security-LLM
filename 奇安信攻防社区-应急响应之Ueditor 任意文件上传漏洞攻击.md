前言：
---

七一重保期间，某合作公司向我司紧急求救，APT系统出现攻击告警，现场工作人员发现有ip针对他们系统进行Ueditor 文件上传漏洞攻击，并成功上传木马文件。于是我只能又又又背上电脑出发了（苦逼的网安人）。

处置：
---

1、提前在电话中与客户沟通情况，建议能否先将服务器的外部通信关闭，避免再出现一些其它问题，客户同意了我的建议，简单粗暴的将服务器关闭了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e9872bee016d5251881024ecf39138a47238c1f0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e9872bee016d5251881024ecf39138a47238c1f0.jpg)  
2、到现场后，查看APT系统，发现了攻击告警。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dc6c7d84c9b5b8a064a5c82bdfbbbf3d6e59fdd8.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dc6c7d84c9b5b8a064a5c82bdfbbbf3d6e59fdd8.jpg)  
上传木马成功（这waf，关键时刻咋不起作用呢）。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-33099c08afd6c604373100ddf49dfa06b235dbdd.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-33099c08afd6c604373100ddf49dfa06b235dbdd.jpg)  
3、将服务器重新启动，先将外网通道关闭，然后进入以下路径，查看问题文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-51e0bcaee0df7962ae215a89019b70301704e65d.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-51e0bcaee0df7962ae215a89019b70301704e65d.jpg)  
发现就是普通的冰蝎aspx马子，悬着的心也放下一半。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-17f9548c12f130e93feda0002be481dd4e07b526.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-17f9548c12f130e93feda0002be481dd4e07b526.jpg)  
4、对于文件列表中的一些有问题的文件，都先保存在了本地，然后将服务器中的文件进行了删除处理，在其中发现一些关于黄赌毒的黑页。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f07debffab1ac16bb629fb97bf9d07965c9856da.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f07debffab1ac16bb629fb97bf9d07965c9856da.jpg)  
5、同时为了保险起见，立即对网站进行了后门扫描。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2482244e0605af684a269531f803b36b917e7f1c.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2482244e0605af684a269531f803b36b917e7f1c.jpg)  
6、对攻击者IP和上传文件的域名进行分析，在威胁情报平台上都显示为恶意。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-6ef396b010d8596d7187bda24938eb5274fd13fc.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-6ef396b010d8596d7187bda24938eb5274fd13fc.jpg)

发现都是香港的IP，也没有进行备案。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-13aa37390d3ebecbc6a2caf537300d74ec5587e6.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-13aa37390d3ebecbc6a2caf537300d74ec5587e6.jpg)  
5、访问攻击者的木马地址，将文件下载下来  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fa5e9191d7ba1eeccbfd042d49d5211ab97c968b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fa5e9191d7ba1eeccbfd042d49d5211ab97c968b.jpg)  
发现只是一个gif文件和冰蝎aspx马子合成的图片马。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f473d18c136cecf1cd41b1ad9e23c8ef85e2c29d.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f473d18c136cecf1cd41b1ad9e23c8ef85e2c29d.jpg)  
6、放进云沙箱运行也会报毒。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5af93c383b5b56ce6da217c884958ae5b1a4c5d0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5af93c383b5b56ce6da217c884958ae5b1a4c5d0.jpg)

成因：
---

ueditor的官方网站已经停止访问了，但是我们可以在github上下载源码包：<https://github.com/fex-team/ueditor/releases/tag/v1.4.3.3>

1、我们首先来看net/controller.ashx 文件，我们可以看到第14行接收了一个名为action参数。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e8833150c2fa7168e4bc21b5771cd4815d3a9278.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e8833150c2fa7168e4bc21b5771cd4815d3a9278.jpg)  
2、然后action会通过switch case去判断，当action等于catchimage（远程文件抓取）时，执行以下代码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d8d1a3ad447d6e4c3e5c67b6293da201a1ace9c0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d8d1a3ad447d6e4c3e5c67b6293da201a1ace9c0.jpg)  
我们去CrawlerHandler中查看，我们发现当Sources为空或长度为零时，返回"参数错误：没有指定抓取源"  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c2382102e5243cdf6ab390bef1816f10473d5bd5.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c2382102e5243cdf6ab390bef1816f10473d5bd5.jpg)  
所以我们测试漏洞是否存在的时候，会访问Ueditor/net/controller.ashx?action=catchimage,查看返回包是否为"参数错误：没有指定抓取源"  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d3ce538179e4e6568edc934a8c41821350f37827.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d3ce538179e4e6568edc934a8c41821350f37827.jpg)  
3、当source的值不等于空的时候，就执行下面代码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d03ce17eed128ade0a251bcdeb43625cccc70065.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d03ce17eed128ade0a251bcdeb43625cccc70065.jpg)  
4、我们定位到Crawler方法处，65行是创建一个请求，将响应内容赋值给response  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-726dc16522d0b8abe7d00803c46a1993593cb4a2.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-726dc16522d0b8abe7d00803c46a1993593cb4a2.jpg)  
5、观察下面的这行代码，它是从响应里的ContentType去匹配是否有image。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a937dcb5c7e78c500be3f311452f2821de1d36d7.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a937dcb5c7e78c500be3f311452f2821de1d36d7.jpg)  
6、如果是image，进入下面一行代码，会将文件保存在服务器中，所以只要自定义下ContentType:image/jpeg，就可以抓取任意类型的文件了，就造成了任意文件上传漏洞  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e7c005847877c8a2d05f8a08775225951efac44f.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e7c005847877c8a2d05f8a08775225951efac44f.jpg)  
tips：  
可能有些朋友会有疑惑，为什么常见的利用方式是上传xxx.gif?.aspx,因为文件的后辍名是通过截断最后一个 . 来获取的（我们通过查看GetFileName()的官方文档发现，该方法是通过截取url中最后一个.来获取文件名的），url里面xxx.gif?.aspx会被默认当成xxx.gif解析但是传递给我们的文件却是.aspx结尾的文件。

复现：
---

1、首先访问Ueditor/net/controller.ashx?action=catchimag，发现返回"参数错误：没有指定抓取源"，证明存在文件上传漏洞。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-59c53938059b74ad1afc4525ba2bf24174144831.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-59c53938059b74ad1afc4525ba2bf24174144831.jpg)  
2、先上传一个html页面试一下,可以看到上传成功。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d91c759bee3049b4e91baf0c4c2cb3c9e41bc7f6.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d91c759bee3049b4e91baf0c4c2cb3c9e41bc7f6.jpg)  
3、再传一个图片马试一下，发现也上传成功。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c7e340466ffef07727b5fc77228707531f78558a.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c7e340466ffef07727b5fc77228707531f78558a.jpg)

修复：
---

1、由于系统开发商赶来还需要一段时间，所以先从软件层面将漏洞修补一下。  
配置防火墙策略，禁止外网ip访问admin目录（漏洞存在于admin目录下）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8428fd00c3879d7d1b1ea3d84cc8e9be3fa31cdc.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8428fd00c3879d7d1b1ea3d84cc8e9be3fa31cdc.jpg)

2、禁止外网IP访问f\_load目录（上传后的文件存在于f\_load目录）。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bef7df98cd810afa70eced7846333a602b5e506b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bef7df98cd810afa70eced7846333a602b5e506b.jpg)  
3、当用户访问admin/Ueditor/net/controller.ashx?action=catchimage时，跳转到admin/Logout.aspx页面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e7fad78ac8c59e718468dcad39030938265c4e10.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e7fad78ac8c59e718468dcad39030938265c4e10.jpg)  
4、当开发人员到达现场后，立即让他们将上传成功后的回显关闭了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-36909b772fbee5ab7443d2e6874bebaa243a3bfb.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-36909b772fbee5ab7443d2e6874bebaa243a3bfb.jpg)

总结：
---

当遇到类似的应急响应事件后，可以按照以下几个步骤进行处理：  
1、先对需要处理的事件现场情况进行详细的了解，与客户商量先将受害服务器进行断网关机处理，如果有主机安全管理设备，先对所有主机资产进行病毒查杀。  
2、先将木马文件、可疑文件保存本地，然后将服务器上的可疑文件进行清除。  
3、分析木马文件是哪种类型的木马，会造成什么危害，再做出下一步处置。  
4、分析漏洞成因，复现漏洞。  
5、先使用waf、防火墙等设备紧急修复漏洞，再等研发人员来彻底修复漏洞。