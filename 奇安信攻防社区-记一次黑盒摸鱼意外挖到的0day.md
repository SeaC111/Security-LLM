一、前言
----

本文所涉及的漏洞已提交至CNVD并归档，涉及站点的漏洞已经修复，敏感信息已全部打码。

二、漏洞挖掘过程
--------

随手摸鱼，开局fofa海选，相中了这个xx中心。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fa0b36a34f134edac9c9310f126be27cbb4890db.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fa0b36a34f134edac9c9310f126be27cbb4890db.png)  
登录框嘛，老规矩，掏出大字典跑一波弱口令  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cb29773e4dbbde89e8fe1aba24e2a15a910b50ae.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cb29773e4dbbde89e8fe1aba24e2a15a910b50ae.png)  
emmm，发现密码是加密的，并且加密脚本也没有写在前端，但是没关系，用户名还没加密，本来就是随手摸鱼，输一个最常见的弱口令123456，然后掏出我的用户名大字典（其实众所周知很多时候密码跑不出来改为跑用户名会有大惊喜）。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fd62dc3db5332b61285085f84f9b8fbc40b11e97.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fd62dc3db5332b61285085f84f9b8fbc40b11e97.jpg)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3b695ba2af4d35b43ec593b75512cf2af346d192.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3b695ba2af4d35b43ec593b75512cf2af346d192.png)  
好家伙，经典test用户，开门红，摸进去看一下，界面长这样  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-812a12bf4cda393de616c2681aa4f72d42218fae.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-812a12bf4cda393de616c2681aa4f72d42218fae.png)  
看了一圈没什么太值得注意的地方，于是点了一下信息保存  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-08b886dd5b9363b445f0c998c6cab3df77454bb5.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-08b886dd5b9363b445f0c998c6cab3df77454bb5.png)  
这里挨着测了下sql和xss，嗯，都没有  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-99dbabf711f1b0ece6c27d8aaed4a0dede2527af.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-99dbabf711f1b0ece6c27d8aaed4a0dede2527af.jpg)  
回过头来看着这个userId参数，直觉告诉我这里得出一个经典的越权漏洞。  
先放着，修改了一下loginName和userName两个参数为admin，发现页面没有任何变化，然后修改了一下userId，随手打了个002110，还是没啥变化emmm，反手把这个参数丢进Intruder从 001980遍历到002100，最终发现当userId为002000时，用户可成功越权至admin用户  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-70c385a3a598c81ef2143dcd91f8c5b6c30ae50e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-70c385a3a598c81ef2143dcd91f8c5b6c30ae50e.png)  
测到这里本来准备交洞下播了，又突然想到这个系统怕不是目标单位自己开发的，于是到首页找了下特征fofa一波  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-77509c89dc5673b2c99d8d3eaf99ab5faac92585.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-77509c89dc5673b2c99d8d3eaf99ab5faac92585.png)  
好家伙，281个站点，顺着网去找了下公司，发现这个洞各项要求都符合颁发证书的条件，于是反手提交CNVD并嫖了个证书。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-09ac86e63474395eaed42f02cedf19b095f99ca2.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-09ac86e63474395eaed42f02cedf19b095f99ca2.jpg)

三、结语
----

黑盒摸鱼，纯属运气。日常挖洞中遇到什么xx系统、xx管理中心出洞的时候都可以找特征fofa一波试试，涉及大量站点那就赚翻了~