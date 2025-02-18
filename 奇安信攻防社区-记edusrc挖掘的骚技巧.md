0x1 前言
------

这里主要还是介绍下新手入门edusrc漏洞挖掘以及在漏洞挖掘的过程中信息收集的部分哈！（主要给小白看的，大佬就当看个热闹了）下面的话我将以好几个不同的方式来给大家介绍下edusrc入门的漏洞挖掘手法以及利用github信息收集的过程以及给师傅们分享一些比较好用的工具哈。

0x2 信息收集——github
----------------

#### 介绍

在漏洞挖掘的过程前期我们进行信息收集，github和码云搜索相关的信息，代码库，运气好的话可以在库中发现一些重要配置如数据库用户密码等。

这里先给师傅们分享一下**手工gtihub搜索语法**:

```php
in:name baidu              #标题搜索含有关键字
baiduin:descripton baidu         #仓库描述搜索含有关键字
in:readme baidu             #Readme文件搜素含有关键字
stars:>3000 baidu           #stars数量大于3000的搜索关键字
stars:1000..3000 baidu      #stars数量大于1000小于3000的搜索关键字
forks:>1000 baidu           #forks数量大于1000的搜索关键字
forks:1000..3000 baidu      #forks数量大于1000小于3000的搜索关键字
size:>=5000 baidu           #指定仓库大于5000k(5M)的搜索关键字
pushed:>2019-02-12 baidu    #发布时间大于2019-02-12的搜索关键字
created:>2019-02-12 baidu   #创建时间大于2019-02-12的搜索关键字
user:name                  #用户名搜素
license:apache-2.0 baidu    #明确仓库的 LICENSE 搜索关键字
language:java baidu         #在java语言的代码中搜索关键字
user:baidu in:name baidu     #组合搜索,用户名baidu的标题含有baidu的等等..
```

然后再给师傅们分享下**github官方文档**：  
[GitHub检索文档](https://docs.github.com/en/search-github/searching-on-github/searching-for-repositories)  
![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-eb2abb332bd93508de59d6b56245a1f7f7702c36.png)

#### 自动化工具——GitDorker

[GitDorker工具下载](https://github.com/obheda12/GitDorker)  
GitDorker 是一款github自动信息收集工具，它利用 GitHub 搜索 API 和作者从各种来源编译的大量 GitHub dorks 列表，以提供给定搜索查询的 github 上存储的敏感信息的概述。

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-ee4e7d7949d8420db29cb83f7f2c760ccd3e3fc0.png)

**挖掘泄漏方法:**  
可以从域名开始找比如: xxx.com 我们就使用github.com 等平台等搜索语法对包含xxx.com进行搜索，再一一进行逐个排查或者直接使用上方等自动化工具，直接跑也可以。

0x3 关注edusrc开发商排行
-----------------

随着edu平台的跟新，我发现他多了一个开发商排行，这样等于是给我们列出来了edu用户的系统公司，就可以节省我们的时间再去查找开发商来找对应的系统.

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-0b47b7c1b4f72cc93bb6e45fc5b7a2c9987ee192.png)

那么我们知道这些开发商后，我们只需要把这些开发商是产品进行收集，然后一些空间安全引擎比如使用FOFA、鹰图等进行产品查找不就可以达到系统通杀的效果呢？

**我们任意看几个：**  
下面这个一看就是该开发商下的有XSS漏洞通杀  
![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-cdce925a781363b7be09f1f878ebee1720de11a4.png)

再看下面这个标题，很明显存在大量的弱口令漏洞，且修复率不是很高，那么师傅们这不就可以尝试下了嘛

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-c0cf387465daba39a188b4820988b2cf61c3eb3b.png)

0x4 漏洞猎杀
--------

可以看见对于系统的弱口令通杀还是通杀挺多的，当你通过弱口令进入后台后，继续挖掘可以扩大rank值。

#### 具体操作

1、首先我们需要确定我们的目标厂商  
开发商名称：北京网瑞达科技有限公司

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-ca7217265c216a69048b947611749aa6d3870e10.png)

2、然后就可以使用我们的空间安全搜素引擎了，比如我平常常用的FOFA以及鹰图，都是蛮不错的

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-e2e8d89a25b6fef2d6c1d0b20476217a53faf0fc.png)

这里需要主要的是这里FOFA还给我们整理了icon图标，可以找对应的icon，然后也是同一系统，然后也是可以打一个通杀的

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-446f74469b2ed9adf4ef66e57b8b5871be1607cd.png)

对于这些都是属于网瑞达公司的这个产品，点进去你可以发现全是教育网段的！

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-5c34b8ef8976e13d0a76c9ca87eeca815c1d39b4.png)

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-74c6cc4f77d9cdb4cef53ce1f042ff01ee5b3724.png)

3、接下来就是比如你可以去找该系统或者该学校的手册，然后去里面找找有没有系统的默认弱口令，因为很多学校系统都不该密码，运维人员也少，所以维护也没，这就可以去找下系统的默认弱口令了，然后再进去打一套别的漏洞，提高危害rank。

你也可以先尝试常见弱口令，比如admin/admin admin/123456一类的，不成功就是寻找手册  
关键字查找方法：xxxxx（公司名部分关键字任意组合）xxxxx（某某系统）操作手册、默认密码、管理员手册（这里自己补充能涉及密码的关键词）

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-325441f03fd89555b5dd993f7ad9be4164add87d.png)

可以看见有很多文档，需要自己花自己整理，找到有效的数据。

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-3ba2b046d9529c1409d36c8dc008ca3cfc065cec.png)

继续在里面找，还可以看到别的关键信息  
在我们的眼里这些是弱口令，但是在运维眼里这些密码均为强口令了，给自己减少工作量，有多少运维会去改密码呢？

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-ec2e436b17c7bc024e0c3674ab6df50c36ce99f5.png)

其中也可以使用Google浏览器进行信息收集，也是会发现一些不一样的收获的，我们可以看到下面的检索内容，就可以很明显的看到这几个学校使用的系统就是我们的目标开发商的系统  
![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-e7d30a09f10853a171bcd3e990ca57705b6bc9ce.png)

当然如果你没办法找到手册，那就自己构造密码：方法也很简单，通过企查查一类的网站对公司信息收集

![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-1b401484009d3ea883e8a034cf0d33fdea2c988c.png)  
![img](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-e956f9f7e14dc54b190f2fcb357cc587e3a2a37d.png)

#### 浅谈

可以得知网站命令习惯：wrd wrdtech webvpn 这一类信息（这里的信息你收集的越多，构造的字典爆破的机会越大，其余同理，自己扩展）  
我们就可以利用wrd这些来组合密码，比如wrd@123 wrd@admn123456 wrd!@#qwe123 这样构造弱口令去爆破，这里你可以花1—2天 如果一旦突破那么就是一个通杀！相对于还是划算，没成功就等于锻炼了信息收集能力。

```php
123456
admin
admin@123
1qaz@WSX
10ding
dm1n$
10@ding
@dm1n$
wrd@admn123456
wrd@123
wrd!@#qwe123
```

这几个是我收集该系统时候收集的密码，账号可以使用admin/root跑一下

0x5 总结
------

这篇文章主要是给师傅们分享下在挖掘edusrc的时候，一些信息收集的姿势以及怎么利用现有的资源以及环境去收集更多的有用的信息。然后怎办利用收集到的信息进行打点src，师傅们要是感兴趣的话可以尝试下我这篇文章的src挖掘骚姿势。  
嘿嘿嘿，希望这篇文章对师傅们有帮助！！！

**文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担！**