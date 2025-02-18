### 前言

菜鸡一次从web到域控的测试

渗透开始
----

先在fofa上面寻找目标  
语句：body="10.4.5 404 Not Found" &amp;&amp; country="CN" &amp;&amp; region="TW"  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1094d65cfdc57d3905a18dbb05ff2a346e176bcf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1094d65cfdc57d3905a18dbb05ff2a346e176bcf.png)

打开直接这个页面  
Weblogic 404页面 因为是java站直接用工具测测 已经爆出的漏洞

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-72834f0176ea797e297c7fabe8ec1da173e56473.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-72834f0176ea797e297c7fabe8ec1da173e56473.png)

发现漏洞存在

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d36040b728255d9abf0ed1c4d70eea19909f586d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d36040b728255d9abf0ed1c4d70eea19909f586d.png)

命令执行成功

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9bfb876d667d20f117351d29a37ad0492eabbcc3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9bfb876d667d20f117351d29a37ad0492eabbcc3.png)

Linux系统  
但是目前不知道路径 所以需要找路径  
先dirsearch一波

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-286d22b19b5fa6efca5b243b69b97c87e8c89700.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-286d22b19b5fa6efca5b243b69b97c87e8c89700.png)

打开这个路径

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6b4a3b13d5006fb3b727a03816c84569dadbad4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6b4a3b13d5006fb3b727a03816c84569dadbad4.png)

发现了一个jsp文件 然后利用weblogic工具全局搜索这个文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-109b8afb2fd9622091aa28efb8069b9437ab294b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-109b8afb2fd9622091aa28efb8069b9437ab294b.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-251719a5b1fb18673d429d7dab095bbf3a9844ac.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-251719a5b1fb18673d429d7dab095bbf3a9844ac.png)

然后依次查看每个config.xml 文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8d9b0a33704e967a56c7e01b6a29581e7584070d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8d9b0a33704e967a56c7e01b6a29581e7584070d.png)

复制到txt中 找端口9003 因为url上是9003

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6c47b4216da04a9df61c1ce37e3e26ba596d2a18.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6c47b4216da04a9df61c1ce37e3e26ba596d2a18.png)

路径应该是找到了  
上传一个txt试试能不能访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71aab55d8983e18991ea85db464fd21a29e205a6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71aab55d8983e18991ea85db464fd21a29e205a6.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b53ebe8b59c295bda07303f74228dbac8eefbabf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b53ebe8b59c295bda07303f74228dbac8eefbabf.png)

然后去浏览器访问看看能不能访问到  
能成功访问到 然后直接上冰蝎马

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8e472734e417be6f8188179d5cf0a708efd1d42b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8e472734e417be6f8188179d5cf0a708efd1d42b.png)

直接连接

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2ea7aacac9a38c42ff5e82ce29de3518bb9ee19e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2ea7aacac9a38c42ff5e82ce29de3518bb9ee19e.png)

成功连接  
先看看能不能出网

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-66b1b08d4a5c54c7a5bc10bae0720e98b63e7089.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-66b1b08d4a5c54c7a5bc10bae0720e98b63e7089.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c1dc15f87afb2d4d08e3cc05bf7649b96bb484d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c1dc15f87afb2d4d08e3cc05bf7649b96bb484d1.png)

发现是能出网的 出网就好办了啊

查看下arp缓存

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0a7471f226f30c7c6b9f6ec92b4885c457c74358.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0a7471f226f30c7c6b9f6ec92b4885c457c74358.png)

发现是有域的 直接上frp 开始打内网  
讲frp配置好 讲serve端传上去

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-048e9996a186cb682b8660ccd33b261a9fc064f9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-048e9996a186cb682b8660ccd33b261a9fc064f9.png)

然后客户端传到我们直接的vps上  
毕竟流量弄到本地来整好操作

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a45003e13093f541776acbc241a707b4b8fe4e21.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a45003e13093f541776acbc241a707b4b8fe4e21.png)

本地用Proxifier 代理流量  
然后在上传一个测试文件  
访问他的内网ip的资产，代理成功

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2cf1f6cba9825f080b7a42aecff93a134fa50cc7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2cf1f6cba9825f080b7a42aecff93a134fa50cc7.png)

因为通过arp缓存知道 还有122，123网段  
接着探测到存在122,123网段  
先直接用永恒之蓝工具盲打一波  
好的，工具人上线，永恒之蓝扫一遍

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5e1d107d7083471c0d9a879785eb6f37e6d42e8b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5e1d107d7083471c0d9a879785eb6f37e6d42e8b.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7617296d4e8833f8440d007067939caa4bfa9910.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7617296d4e8833f8440d007067939caa4bfa9910.png)

两个网段存在永很之蓝的共5个  
192.168.122.29  
192.168.122.217  
192.168.123.84  
192.168.123.103  
192.168.123.209

接着掏出nbtscan

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fb9e4c6ee6dc5b4e02cd2b9fd22b612749a94586.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fb9e4c6ee6dc5b4e02cd2b9fd22b612749a94586.png)

超时了，那就先打永恒之蓝吧

msf直接拿命令执行看看能不能直接上线cs

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e801d4783d8cf026eff72b9d1d3dedd7d3a6767e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e801d4783d8cf026eff72b9d1d3dedd7d3a6767e.png)

**其实在这里小子有个疑问 为什么只有msf打17010的时候流量可以带出去 搞其他想扫描啥的时候流量就不走代理**

然后直接用cs生成一个powershell命令  
这里执行的时候需要注意给引号转义  
执行之后  
这里直接上线了一台：192.168.122.217

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-58a61abdb6ccf62082923049079ea8cf7bc06fb4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-58a61abdb6ccf62082923049079ea8cf7bc06fb4.png)

这里选择了一个常用的进程，然后进程迁移

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-34a00b61ecf26cc2af2d965be567dbfc0a5e1ff5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-34a00b61ecf26cc2af2d965be567dbfc0a5e1ff5.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75c0f6021b5cf07b0455233e97179257799716cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75c0f6021b5cf07b0455233e97179257799716cf.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-92ae6a8fe2003be302ef31692dfc2c6f09a739dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-92ae6a8fe2003be302ef31692dfc2c6f09a739dd.png)

成功

接着看看能不能读到密码

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-949c22b1be86d4c322d69f857df595d18e0a28f3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-949c22b1be86d4c322d69f857df595d18e0a28f3.png)

可以直接抓到密码 应该是没有杀软

查看域管理员 net group "domain admins" /domain

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4d24231e00e798fafb2dc7f056d2ff008df1309f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4d24231e00e798fafb2dc7f056d2ff008df1309f.png)

3个域管理员：casperwu mascot steve

查看域控：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c16774b3d8685ebecc58726d65373f8fe71a1691.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c16774b3d8685ebecc58726d65373f8fe71a1691.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f92b130a9439d8c7f385dee3573ef9b690a8697e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f92b130a9439d8c7f385dee3573ef9b690a8697e.png)

两台DC，而217这台本来就是一个其中一个DC，所以我们要找第二台名为AD的DC

查看域控

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8a519ac251751fda318838a6e10057f2122eb87f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8a519ac251751fda318838a6e10057f2122eb87f.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a56742694f7849090626691ad9e2ade08fb6966.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a56742694f7849090626691ad9e2ade08fb6966.png)

做DNS解析的大概率就是另一个域控AD了  
既然他们是在同一个域，那么设置的策略都是相同的，所以可以通过域管理员账号登录192.168.123.219这台机器，所以现在咱们要整一个域管理员的账号密码

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-833c79bfc70f93e0df26c07bb98f7eb958b68817.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-833c79bfc70f93e0df26c07bb98f7eb958b68817.png)

正好之前读密码读出来了steve ay**\*\***  
用命令开启共享连接：

> shell net use \\192.168.123.219\\ipc$ "ay*****" /user:"ty*****\\steve"

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9bf7907f09a870c6fe022dff178e0b24ea117e24.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9bf7907f09a870c6fe022dff178e0b24ea117e24.png)

传个马儿上去 先改为jpg格式

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d044671bd910d99564226099194bcc9b24d4186d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d044671bd910d99564226099194bcc9b24d4186d.png)

然后将木马给传到192.168.123.219的c:\\windows\\temp\\目录下，名为mac.exe

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1d232a97488705577cf82c104b84c3f0f375d16d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1d232a97488705577cf82c104b84c3f0f375d16d.png)

接着wmic远程执行命令，运行那个马儿

> shell wmic /node:192.168.123.219 /user:ty****\\steve /password:ay2**** process call create "cmd.exe /c C:\\Windows\\Temp\\mac.exe"

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cb886dff563afe026ab446af49fcd9be0adcc060.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cb886dff563afe026ab446af49fcd9be0adcc060.png)

运行成功，来了来了

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07438a4a42c4f10344f035d8d3da1fd5f0bbe2d5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07438a4a42c4f10344f035d8d3da1fd5f0bbe2d5.png)

这里做进程迁移，将shell给搞到了spoolsv.exe中

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d4a4fb51f6cd52c2c6a68454edfbdebfc102cbc9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d4a4fb51f6cd52c2c6a68454edfbdebfc102cbc9.png)

好了，现在ty\*\*\*的两个域控都拿下了

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c2022000dd78ca686963162870f985bc35fe6a55.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c2022000dd78ca686963162870f985bc35fe6a55.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f7ee3b929fa9e75e7865500bd29965aa9d2a2a9c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f7ee3b929fa9e75e7865500bd29965aa9d2a2a9c.png)

查看域信任：nltest /domain\_trusts

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6e7d7e47c89a5b229ddccc7f3fa9454ff591924d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6e7d7e47c89a5b229ddccc7f3fa9454ff591924d.png)

三个域：a001.ty**\*n.com.tw、ty****n.com.tw、ty****y.com.tw，第一个是第三个的子域  
其中的tyt\*\*\***y.com.tw已经被拿下，所以考虑另外一个域  
查看ty\*\*\*\*n.com.tw的ip

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1eda2a68b2f59f6ff678ed79bc643b0ef73385b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1eda2a68b2f59f6ff678ed79bc643b0ef73385b2.png)

一般只有域控才做DNS解析，所以192.168.123.2大概率就是域控了

在192.168.123.217上面与192.168.123.2建立共享连接  
这里用steve的账号密码去登录了192.168.123.2 的smb，所以steve也是上面的域管

> shell net use \\192.168.123.2\\ipc$ "ay***" /user:"ty***y\\steve"

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b29893bd3953299ea666a5f538589fbafb717cb8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b29893bd3953299ea666a5f538589fbafb717cb8.png)

查看192.168.123.2的c盘下的文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-133fdfd17f754543e4627731e944b69dde7e2681.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-133fdfd17f754543e4627731e944b69dde7e2681.png)

然后将木马给传到192.168.123.2的c:\\windows\\temp\\目录下，名为ak.exe

> shell copy c:\\windows\\temp\\hex.jpg \\192.1618.123.2\\c$\\windows\\temp\\ak.exe

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c7502e581060cf14361e4789d9e037c7dd52a6fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c7502e581060cf14361e4789d9e037c7dd52a6fd.png)

接着wmic远程执行命令，运行那个马儿

> shell wmic /node:192.168.123.2 /user:ty****y\\steve /password:ay****9 process call create "cmd.exe /c C:\\Windows\\Temp\\ak.exe"

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-49c675a051a1f90127dfc2f01778ae5b25bc59b8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-49c675a051a1f90127dfc2f01778ae5b25bc59b8.png)

但是没有上线 怎么回事  
查看下123.2 的sysinfo  
利用wmic 执行命令输出到文件 然后查看  
放到在线杀软查询 发现有一个微软的杀软

然后重新传了一个免杀马  
成功上线

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-838fb6b6c39936e8b6056a6467ae9dc03cc549eb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-838fb6b6c39936e8b6056a6467ae9dc03cc549eb.png)

最后一台域控也成功拿下  
后续的权限维持不太会 就没有操作了  
删马结束  
over

### 最后

其实还是有些地方有点不明白 横线ay域的时候 用的是ty域的账号  
msf的流量代理也是 只能带17010打的时候的流量 就有点懵  
师傅们轻点喷 ~ 师傅们指点