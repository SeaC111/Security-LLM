0x1应急过程
=======

（1）、通过对涉事终端主机的外联排查，发现恶意ip“xx.xxx.xx.136”，并获取到进程PID为6304。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-de3fbd0e103560fa0b737d55f4d1d4efd2c6b37b.png)

（2）、通过PID找到名为credwiz.exe的进程，并在相应文件夹中发现了Duser.dll文件，通过在云沙箱中运行发现为响尾蛇的木马。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-afbd518f37993027a8f400b6b0e932bb517c68a3.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-80a45949af1248cd41a256ab6209a1ca053e218f.png)

（3）、使用火绒剑进行扫描，再次出现告警，也验证了该文件为恶意木马文件。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e9ae3cbc058b7e34753259ba4f88e2597098e209.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-10b6e2f0a2ec28e5674290292e1a414cb101a3b2.png)

0x2病毒分析
=======

（1）、通过开源资料发现，响尾蛇组织会利用系统文件的白加黑绕过防护软件，达到免杀的效果,在近几年的活动中主要使用cmdl32.exe+cmpbk32.dll与credwiz.exe+duser.dll的两种组合，而这次被攻击的就是credwiz.exe+duser.dll组合。  
（2）、该事件中攻击者使用了两个文档漏洞CVE-2017-0199和CVE-2017-11882，  
首先钓鱼邮件中的附件文档会利用CVE-2017-0199从xx.xxx.xx.200上下载并运行一个rtf文件

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e42dbaf7ce7c9f5d02940ff47f27ad45092b5680.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f308bdc5ad9f5abb56a15fe29735373303d5904b.png)

运行rtf文件后，会触发CVE-2017-11882漏洞，从xx.xxx.xx.200上下载并运行一个hta文件  
通过HTA文件进行初始恶意文件释放和配置，利用白加黑（对可信文件credwiz.exe加载的库文件Duser.dll进行替换）加载恶意载荷并连接远程服务器接收恶意指令。  
（3）、credwiz.exe运行后，Duser.dll作为调用文件被导入。Duser.dll运行后，首先测试网络连通性

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d17b4dd3be6967d7e4b9ce799c75ceccb5be0ebb.png)

然后连接远控：ap-xxx.net

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-49a39421c6c6d1e1ecc70fe402b6b192be680c55.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4d18540361e04d3e71816adcbe12240067e3ec53.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-beb6c1166485cf638db7b7655c5d4f1da19ed349.png)

然后根据从远控收到的命令继续执行各种操作。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4e28af4ae7c659de8f6f10baaf6e9f21aa42a7bb.png)

根据获取到的命令值定向到指定的功能模块

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3022cfef21fa05a8b41aafdca9bf1cd33cb967ab.png)

0x3总结
=====

SideWinder组织的credwiz的木马病毒感染大概总结为以下流程。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e2a6f77bd0ad86f7e80bf67149793d6726927d4f.png)