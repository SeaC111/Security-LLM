### 0x00 前言

最近在玩免杀,发现了一些免杀思路

### 0x01 powershell加载shellcode介绍

UNIX系统一直有着功能强大的壳程序（shell），Windows PowerShell的诞生就是要提供功能相当于UNIX系统的命令行壳程序（例如：sh、bash或csh），同时也内置脚本语言以及辅助脚本程序的工具，使命令行用户和脚本编写者可以利用 .NET F ramework的强大功能。

powershell具有在硬盘中易绕过，内存中难查杀的特点。一般在后渗透中，攻击者可以在计算机上执行代码时，会下载powershell脚本来执行，ps1脚本文件无需写入到硬盘中，直接可以在内存中执行

### 0x02 前戏

常见的powershell攻击工具有powersploit、nishang、empire、powercat,试了试这些免杀脚本,发现都不太理想,大部分都被检测到了

想着要不自己尝试尝试?

cs,上号!

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-04db9775e9b358d91c48d806d4cef9f81e9e80c7.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-04db9775e9b358d91c48d806d4cef9f81e9e80c7.jpg)

首先生成一个自带的powershell脚本

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-51b6985b0c7de86746e4ce4cd3aaaea4813aa545.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-51b6985b0c7de86746e4ce4cd3aaaea4813aa545.jpg)

看一下自带的

是把shellcode加载到内存中的代码放到字符串中然后IEX执行代码

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-0717643645df82f271689d808bf14a0b9e5fb113.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-0717643645df82f271689d808bf14a0b9e5fb113.jpg)  
查杀效果:

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d67d4b62071180906df4ca6223dbe2c265db37f0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d67d4b62071180906df4ca6223dbe2c265db37f0.jpg)

并不是很理想,毕竟大家都在用,很多杀软都有了特征和指纹

### 0x03 开始尝试混淆

![RZH5R0.gif](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-00301bccc11ee039f4b44b3f38c5011a0d092918.gif)

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fdc7d569c7faa61ae893f66436c6d7f34b6bbf3a.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fdc7d569c7faa61ae893f66436c6d7f34b6bbf3a.jpg)  
既然是把字符串进行加载不如整个编一个b ase64?然后在解码后加载

想着想着就开始尝试了:

首先把字符串全部给b ase64,我这里先用burp b ase64

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8003a4dbab99a37eb6b45e17b24a69ee0977a12d.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8003a4dbab99a37eb6b45e17b24a69ee0977a12d.jpg)

然后扔进去在加载之前b ase64还原

```php
解密后变量=[System.Text.Encoding]::UTF8.GetString([System.Convert]::Fromb ase64String(加密后变量))
```

把编码后的代码解码后加载,顺便搞一个UTF-8

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d284ef143af6b095225d688c9a7f83ce883d6160.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d284ef143af6b095225d688c9a7f83ce883d6160.jpg)

执行执行一下看看是否可以上线:

```php
Powershell -ExecutionPolicy Bypass -File .\payload.ps1
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-69d390967317a52cc90a52c117f2432439684449.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-69d390967317a52cc90a52c117f2432439684449.jpg)

查看cs是否上线:

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7852f66160907f68339fb26c9d89aa81dbe1b387.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7852f66160907f68339fb26c9d89aa81dbe1b387.jpg)  
发现cs成功上线

去查看一下[免杀效果](https://www.virustotal.com):

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9bb8193dab9a6c5e60e61901f129369ab14ce4c1.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9bb8193dab9a6c5e60e61901f129369ab14ce4c1.jpg)

[![RZqtNd.gif](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f6f94afe28024c8403c88469806aac456f3cd4a5.gif)](https://imgtu.com/i/RZqtNd)

...这就把杀软干懵逼了?

尝试修改变量的名称来绕过

发现没什么太大的用处,还剩两个

尝试把b ase64编码后的字符串拆开看看

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d03a738af1fa78582791795f07c97926ed952fee.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d03a738af1fa78582791795f07c97926ed952fee.jpg)

把上面的b ase64的字符串猜开来在b ase64的时候组合一下

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6d777e24513ac05cb4db7cbe02a7011bca8485d5.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6d777e24513ac05cb4db7cbe02a7011bca8485d5.jpg)

查看cs是否上线:

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a87a3cfe81008158a227328070cd35eeba7ac1a5.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a87a3cfe81008158a227328070cd35eeba7ac1a5.jpg)

查看免杀效果:

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-77b1495efffb9deb4b3d6d6a9f0498c42e1e31b9.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-77b1495efffb9deb4b3d6d6a9f0498c42e1e31b9.jpg)

这就完事了,不过只是静态免杀

### 0x04 实战

这一次测试一下,某绒,某60  
(这两个杀软一装,我虚拟机都有点扛不住)

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ebaac9d83c3f1eec6f70ba1ae55a1bb44a6d7cca.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ebaac9d83c3f1eec6f70ba1ae55a1bb44a6d7cca.jpg)

全部更新到最新,先静态扫描试试

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6f172f4000262f361b6b9152d07c600329b84983.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6f172f4000262f361b6b9152d07c600329b84983.jpg)

激动人心得时候到了,试试运行

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-55e5d0d95dad3ad2e41d5b672c75cfc6b9219c6c.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-55e5d0d95dad3ad2e41d5b672c75cfc6b9219c6c.jpg)

发现他们一点反应都没有

查看cs是否上线:

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e49982d52ad73b4eee86a9055960f8c9066e75d9.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e49982d52ad73b4eee86a9055960f8c9066e75d9.jpg)

成功上线

没想到这么顺利

### 0x05 结语

在测试过程中的一些发现:

如果是没有改证书的话貌似会被某绒给检测到

改证书参考:  
[Cobalt Strike 绕过流量审计](https://paper.seebug.org/1349/ "Cobalt Strike 绕过流量审计")

根据b ase64加密的方法还可以推断出使用其他加密比如ascii码加密也有同样的效果

大家可以根据我的方法变形,比如可以拆成很多段,在配合其他的加密和解密手段进行免杀,制作属于自己的免杀