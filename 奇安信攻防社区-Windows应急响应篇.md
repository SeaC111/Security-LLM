一、概述：
-----

 近年来，随着互联网的发展网络安全攻击事件也是大幅度增多，如何在第一时间发现攻击事件，并实施应急处置，能够有效的将损失降到最低。在实施应急响应的过程中，需要从多方面进行联动工作，具体的流程和依据可以参考《GB∕T 38645-2020 信息安全技术 网络安全事件应急演练指南》，本篇主要以windows下应急响应的基础技术手段进行介绍。

二、技术分析
------

### 1、准备工作

 在正式实施应急响应之前，需要先进行以下工作，  
 第一、信息收集，先对安全事件进行详细的了解，包括系统、服务以及业务类型  
 第二、思路梳理，通过以上信息收集初步梳理自己的分析思路  
 第三、工具准备，提前准备好需要用到的工具脚本等资料  
 第四、数据备份，所有涉及到分析以及证据的材料都需要提前进行备份，这样也方便之后还有分析人员或者防止数据被篡改或者覆盖。  
 第五、时间校准，查看系统时间和北京时间是否同步准确，如果不准确那么系统日志等信息的事件可能会存在误差，所以必须提前校准时间。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c279bc2b298c0a2a9d3a5dee88aaf0a6e109f11a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c279bc2b298c0a2a9d3a5dee88aaf0a6e109f11a.png)

### 2、账号分析

 首先查看系统所有的账户，是否存在恶意新增账户，进行远程控制等问题，具体方式如下。  
 1）cmd命令行输入net user查看用户账户，该方法有一个弊端就是无法查看系统建立的隐藏账户；  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3d712d8e99cf8b20d88de91179736f1bf83a8457.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3d712d8e99cf8b20d88de91179736f1bf83a8457.png)  
 2）计算机管理-&gt;系统工具-&gt;本地用户和组-&gt;用户，可以查看系统现有账户，其中账户后面带$的则为隐藏账户，即test$  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-47a4ed35adb1d3d7e32ce7f57806f0a9c6ad6f3e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-47a4ed35adb1d3d7e32ce7f57806f0a9c6ad6f3e.png)  
 3)控制面板-&gt;用户账户-&gt;用户账户-&gt;管理账户，也可以查看所有系统账户  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-021d2cb201ce5c8e47ee6c123262b5b05a825b65.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-021d2cb201ce5c8e47ee6c123262b5b05a825b65.png)  
 4）Win+R输入regedit.exe进入注册表编辑器，在下面注册表   
HKEY\_LOCAL\_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names中也可以查看系统现有账户  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7876a0a8adb57ea7d0f646fede6a9a69a53ac5c5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7876a0a8adb57ea7d0f646fede6a9a69a53ac5c5.png)  
 5） 在cmd命令行中利用net user administrator可以查看administrator该账户的详细信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5134c70f3592f032fcab165eedf798129fe7e4f1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5134c70f3592f032fcab165eedf798129fe7e4f1.png)  
 6）在cmd命令行中利用query user可以查看目前登录的账户  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b3f19b41011b8d06810ba2a3ae1795d1b47b262c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b3f19b41011b8d06810ba2a3ae1795d1b47b262c.png)

### 3、最近打开过的文件分析

 1）键盘输入win+R打开运行窗口输入recent  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0283004b9746810c64563fab9b2bdc006f21bfa7.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0283004b9746810c64563fab9b2bdc006f21bfa7.png)  
 打开C:\\Administrtor\\Recent，可以查看最近打开过的所有文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3a7bc90204910ed37e337eb8ecd0886b79ed9816.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3a7bc90204910ed37e337eb8ecd0886b79ed9816.png)  
 2）设置最新使用的项目查看最近打开的文件  
 开始菜单右键-&gt;属性-&gt;开始菜单（自定义）-&gt;勾选最近使用的项目  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6c28912259729bc7918e14ce23e2aefcf89ba91f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6c28912259729bc7918e14ce23e2aefcf89ba91f.png)  
 打开开始菜单，可以看到最近使用的项目中有所有最近打开编辑过的文件；  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-828f63deb83810d5d27efa40291706b75e98b517.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-828f63deb83810d5d27efa40291706b75e98b517.png)  
 3）Win10中查看最近打开的文件  
 在文件夹选型勾选快速访问，在快速访问中可以查看最近打开编辑过的文件；  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-87dd56086fd98b286b20cb9699d431dc9949c480.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-87dd56086fd98b286b20cb9699d431dc9949c480.png)  
 4）回收站查看最近删除文件  
 回收站中可能会存在一些攻击者删除的最近打开编辑后的文件资料等痕迹，也是需要注意的；  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-10e10ee03020a915bbdd2a24466fadb59379848a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-10e10ee03020a915bbdd2a24466fadb59379848a.png)

### 4、日志分析

 日志分析包括操作系统的日志记录以及web应用的日志记录，一般来说操作系统的日志主要记录针对该系统的操作行为事件，但是web应用日志则会记录web程序访问该应用程序的时候的操作行为和事件，一般针对日志分析时候也是需要从操作系统和web应用日志两块结合分析。  
 1）操作系统日志  
 操作系统日志存放着计算机关于系统、应用程序的告警信息以及安全日志等信息，一般存放在C:\\Windows\\System32\\winevt\\Logs，可以通过事件查看器进行查看。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-063d0ffbc5efb6637e9860c00773156c38dcf641.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-063d0ffbc5efb6637e9860c00773156c38dcf641.png)  
 系统日志中存放了Windows操作系统产生的信息、警告或错误。通过查看这些信息、警告或错误，用户不但可以了解到某项功能配置或运行成功的信息，还可了解到系统的某些功能运行失败，或变得不稳定的原因。[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0f4768c6bf4268ea893f0573c2ea42be517ae6e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0f4768c6bf4268ea893f0573c2ea42be517ae6e4.png)  
 应用程序日志中存放应用程序产生的信息、警告或错误。通过查看这些信息、警告或错误，用户可以了解到哪些应用程序成功运行，产生了哪些错误或者潜在错误。程序开发人员可以利用这些资源来改善应用程序。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-32bb4506e0af51ea0861cba4eea8fcf296d4f27a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-32bb4506e0af51ea0861cba4eea8fcf296d4f27a.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c29780f7dc743e2e2fc83e2e3a6bc2ec2d352868.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c29780f7dc743e2e2fc83e2e3a6bc2ec2d352868.png)  
 一般在操作系统日志分析过程中更关注安全日志的分析，因为安全日志中存放了审核事件是否成功的信息。通过查看这些信息，用户可以了解到这些安全审核结果为成功还是失败。同时安全日志会存放攻击者远程登陆后或者通过提权等方法拿到权限后的一些操作行为，更有助于定位攻击者对操作系统的攻击行为。  
 Windows事件日志通过不同的EVENT ID代表了不同的意义，针对常用的安全事件的事件ID还是需要熟练掌握。 其中4624：代表成功的登录；4625：代表失败的尝试；4672：代表授予特殊权限；4720：代表添加用户；4726：代表删除用户；4634：代表成功的注销；4672：代表超级用户登录。  
 因此想要查看账户登录事件，筛选日志中事件ID填入4624则可以筛选登录成功事件，4625则可以筛选登录失败事件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f06620ed6b83566b517b218993e2c9aa1ffb9b7c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f06620ed6b83566b517b218993e2c9aa1ffb9b7c.png)  
 当有人使用mstsc远程登录某个主机时，使用的帐户是管理员帐户的话，成功的情况下会有事件ID为4776、4648、4624、4672的事件产生；  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-573c6845c79c169dce1bcff050efe549329f0f54.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-573c6845c79c169dce1bcff050efe549329f0f54.png)  
 安全日志中除了会记录改事件的成功失败以外还会记录该事件的ip地址和端口，因此如果发现某个远程登陆时，通过查看详细信息便可以分析出远程登陆的ip地址和他机器的端口。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e8352e35955733e2227dae6055253283d1c4bd1d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e8352e35955733e2227dae6055253283d1c4bd1d.png)  
 2）Web应用日志  
 IIS服务日志，一般存放在 %systemroot%\\system32\\logfiles\\W3SVC1\\目录下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-61a872d4d270d61305b3c2077f1c592e0299ab86.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-61a872d4d270d61305b3c2077f1c592e0299ab86.png)  
 打开详细日志可以查看到该请求的时间，发起请求的ip，该请求的请求方法（get或者post等），请求的url、端口以及使用浏览器的useragent等信息。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-70fc368afa87ac5fcc1da9a3b9c005d76aad06a2.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-70fc368afa87ac5fcc1da9a3b9c005d76aad06a2.png)  
 Apache服务的日志存放在/apache/logs/目录下，详细信息和上述IIS的日志类似，apache的日志中会记录有access和error的日志，分别记录着请求成功的行为以及失败错误的行为。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-250bef049b8e86f0ea96cbd96fe6e446a8515979.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-250bef049b8e86f0ea96cbd96fe6e446a8515979.png)

### 5、进程、网络连接分析

 一般检查进程和网络连接是同步进行的，相互结合着进行分析是否有异常程序进行远程连接。  
 1）网络连接  
 windows中的网络连接可以通过netstat命令进行定位，查看正则监听以及连接的网络连接。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d3b423064f1f93b0b1159e1f7ed0ef9e32afa079.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d3b423064f1f93b0b1159e1f7ed0ef9e32afa079.png)  
 netstat结合findstr可以查看不同端口的网络连接信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0875e9b34a7b028d3900fc1e7fbbbf22a4228b39.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0875e9b34a7b028d3900fc1e7fbbbf22a4228b39.png)  
 2）进程检查  
 在msinfo32中查看现有进程（开始-&gt;运行-&gt;输入msinfo32）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3b73c6dc9c58a1ca03f8c5ad47bc6b3a4ad442eb.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3b73c6dc9c58a1ca03f8c5ad47bc6b3a4ad442eb.png)  
 打开windows任务管理器，可以查看系统进程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3d8765ad37332e506c1d33becf3fb5373d31ac90.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3d8765ad37332e506c1d33becf3fb5373d31ac90.png)  
 cmd命令行输入tasklist查看进程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-91a3fe96117bd7252daf3375822dc455f0a723b1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-91a3fe96117bd7252daf3375822dc455f0a723b1.png)  
 tasklist 结合findstr可以查看不同pid对应的程序  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ee790f33410842754d97794141af853970ac6273.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ee790f33410842754d97794141af853970ac6273.png)  
 因此可以通过一台windows对外连接的端口，利用netstat结合findstr定位该端口建立的网络连接的pid，再利用该pid使用tasklist结合findstr定位到该程序了，这个过程也是要熟练掌握管道符以及findstr等命令。

### 6、计划任务分析

 windows的计划任务是方便运维人员在不同时间段对系统进行一些操作的功能，但是在恶意攻击中被黑客用来做为恶意程序的启动等手段，也是windows应急响应中必须分析的功能。  
 windows的计划任务一般存放在C:\\Windows\\System32\\Tasks\\、C:\\Windows\\SysWOW64\\Tasks\\以及C:\\Windows\\tasks\\等目录下。一般利用图形化界面可以打开，运行-&gt;taskschd.msc,打开任务计划程序。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-89aa6cf7f56a390b4a323d4ec88013245ec63b3a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-89aa6cf7f56a390b4a323d4ec88013245ec63b3a.png)

### 7、自启动分析

 自启动功能表示每次系统开机启动后程序也跟着启动，也是很多恶意程序最喜欢的功能，如果被加到自启动项的程序便会出现在该项目下。  
 1）运行-&gt;msconfig打开系统配置可以查看；  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-758335a17022fa9b7ae2c8001a9e2b396ae48e8c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-758335a17022fa9b7ae2c8001a9e2b396ae48e8c.png)  
 2）运行-&gt;msinfo32打开系统信息，在软件环境下的启动程序也可以查看。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7a10193cb449855f12f217bcecea20c577d388bc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7a10193cb449855f12f217bcecea20c577d388bc.png)

### 8、host文件分析

 host文件是windows下用来构建映射关系的文件，局域网没有DNS服务器，通过hosts建立给服务器建立IP映射，通过分析可以查看是否存在本地DNS篡改，该文件在C:\\Windows\\System32\\drivers\\etc目录下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fa0ea008144bf6ec0ee64b027f666563736216ae.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fa0ea008144bf6ec0ee64b027f666563736216ae.png)  
 打开后可以查看详细对应关系  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1617aed96c75d8efea5d8d2fd3a64b5235a9c458.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1617aed96c75d8efea5d8d2fd3a64b5235a9c458.png)

### 9、webshell查杀分析

 通过上述一系列的分析完成之后，如果在数据文件备份均以完成，且客户可分析允许的情况下，可以对系统进行病毒的扫描，以及web服务下的webshell扫描，扫描可以用的D盾等一系列webshell查杀工具。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-12e0cb7bd0e3547c0fd47d4a3e08fc18668ce3ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-12e0cb7bd0e3547c0fd47d4a3e08fc18668ce3ca.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f97002309a336499cb998edd93cb95e682d8dba1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f97002309a336499cb998edd93cb95e682d8dba1.png)

三、总结
----

 以上便是我对windows应急响应过程中常用的一些功能和分析方法，从9个方面进行了描述。当然往往一些安全事件的复杂性可能超出了这些范围，但是当我们将基础的一些思路和方法都掌握了，对于一些变化上的分析灵活运用和实操便可。