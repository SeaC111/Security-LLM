摘要
==

奇安信技术研究院星图实验室利用自研的天问软件供应链安全分析平台，发现了用于传播SysJoker恶意软件的两个npm包`mos-sass-loader`和`css-resources-loader`，两个包均由同一个账号上传至npm公开仓库中，最早出现时间为2021年10月7日。

概述
==

2022年1月11日，intezer发布了一个报告\[1\]，揭露了一个跨**Windows, Linux, macOS**三个平台的恶意软件SysJoker，并推测该恶意软件最初的攻击向量是一个受感染的npm包。根据intezer提供的SysJoker恶意后门相关信息，奇安信技术研究院星图实验室利用自研的天问平台，对npm生态监测历史数据进行了扫描分析，证实**SysJoker**确实通过npm传播，我们发现早在2021年10月7日，传播SysJoker的恶意包`mos-sass-loader`就出现在npm生态中，且存在时间长达19天，此后在2021年10月25日，攻击者又上传了新的恶意包`css-resources-loader`，但仅存在1天。

mos-sass-loader分析
-----------------

##### mos-sass-loader文件结构

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-58a2f125220eb76a1cad799eabb96f43d791ad38.jpg)

##### 攻击者发布及删除该包的时间：(2021.10.7—2021.10.26)，存在19天。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c9d8d95fe52921136743331a83bceca4cee2f545.jpg)

##### 依据抓取到的包相关元数据，发现gitHead信息。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0089a7b95c1c3cfe564c72982ba6a867adc155e4.jpg)

##### 根据gitHead信息，通过git记录找到了上传者的github账号：moshee411(<https://github.com/moshee411>）

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b23789b739511f783d194ae5b033fdd7b84dd767.jpg)

其中SASS-Loader项目即为上传到npm源中的恶意包mos-sass-loader1.0.0版本。同时该github还有两个早期项目，其中未发现有用信息。

该包的元数据中包含了该包的npm上传账号：moshe.411 (moshe411@bezeqint.net)，与其github账号moshee411相似。经分析，域名bezeqint.net为以色列电信供应商所有，网站主页默认语言为希伯来语，该域名提供对外注册服务，近一年天穹沙箱分析的恶意样本中有5个样本与该域名的子域名mailmx.bezeqint.net有关联。在历史数据中检索，通过bezeqint.net域名邮箱注册的npm账号仅涉及这两个包。

该包的元数据中还包含了一个作者自己指定的名称：Maik Jonson，经过搜索未找到更多可以证实攻击者身份的信息。

通过包中README文件的分析可以得知，该包是对sass-loader包的仿冒，这是一个周下载量超千万次的流行npm包。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-fc17b4058bac3a5a69f5e36837bd8fe673f10502.jpg)

##### mos-sass-loader共有两个版本，差异对比如下：

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-edfd8c6937769b10a801867b25147ebaea4f2cd1.jpg)

css-resources-loader分析
----------------------

##### css-resources-loader文件结构

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-52a81e21e4c0482f92239cba2d0ecdc4fa422adb.jpg)

##### 攻击者发布及删除该包的时间（2021.10.25—2021.10.26），仅存在1天。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-82c0d20eb75e5062fb88c2ec05f5dfba65a39c19.jpg)

##### 该恶意包共发布过10个版本，各个版本信息差异对比如下：

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f17187d91a16f9b217a600129a4303eb5dca511a.jpg)

通过各版本发布时间及版本间差异分析可以看到，攻击者一直在修改启动恶意后门的脚本。

- 分析反混淆后的js代码结构，可以大致看出，该js代码会调用SysJoker后门运行，并将运行结果写入文件保存。由于反混淆有信息丢失，无法判断多个版本之间的具体修改细节。

通过对包中README文件分析可知，该包是对style-resources-loader 的仿冒，这也是一个周下载量在40万次的流行包。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b28fa30896d776f3306d30440f6eb00312189b52.jpg)

总结
==

SysJoker恶意软件早在2021年10月就在npm生态中出现，并通过仿冒两个热门的npm包进行传播，且传播时间长达20天。

所仿冒的包均是用于Web资源打包时加载静态样式（CSS/SASS）的处理模块，这些包使用率极高，攻击者目标明确。建议使用了`sass-loader`和 `style-resources-loader` 的用户进行自查，是否已经受到攻击。  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-777fa91cf976d654a9195b82fc55d380d478207d.jpg)

发现两个早期状态的SysJoker后门，疑似攻击者调试过程中使用，不排除已传播感染的可能。

IoCs
====

### Windows

- d1d5158660cdc9e05ed0207ceba2033aa7736ed1
- 0bf2615f85ae7e2e70e58d5d70491cea37c4e80f (新增IoC)

### Mac

- 554aef8bf44e7fa941e1190e41c8770e90f07254
- 8b49f61ce52f70dc3262c3190a6c7f2f7d9fdae8 (新增IoC)

参考文献
====

1. New SysJoker Backdoor Targets Windows, Linux, and macOS