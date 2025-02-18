### 前言

由客户授权的一次攻防演练，从外网钓鱼到内网遨游，也算是幸不辱命，攻击路径绘制了流程图，接下来会按照我画的攻击流程图来进行讲解，流程图如下：  
![报告流程图.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-ddf66b26aaff5de9710206b314ed18c36e222537.png)

### 外网钓鱼

首先外网收集相关信息，添加微信，构造与客服业务相对  
应的话术，诱导对方点击木马，过程如下图：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-988f652381f25cbd86156703e65b6f4f7bd7d072.png)  
客服成功上线如下图：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-52be3404c8753fd0b1294e7e062e9ac779721ac1.png)  
然后对该企业的总监同样实施微信钓鱼，构造的话术为商务合作，诱导对方点击木马如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0bef17220f296034309263deb19d2e443c7d7ce0.png)

同样上线：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-d9f12065f8460892c20dbb6715649a21930f6ce5.png)

### 内网遨游

#### 登陆相关系统

翻阅客服终端，发现密码本，成功登陆**邮箱系统**，发现大量内部办公邮件如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-820a3a3dde2fc8da01f07c6975ada0f655257583.png)

通过密码本登陆**运营平台**，发现2000w+记录如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-8c98debe7a89b026a5c8382c6e146bd496e6bfd7.png)  
同时还发现该运营系统存在SQL注入如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-640ec6a9f1eae2c7f62eea22cbcd74f756a446b4.png)  
使用sqlmap获取数据库用户密码如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-c4c30f516f92e6018ccf806f87828a0581319b43.png)

通过密码本登陆**Zabbix**系统如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-6e0c5da0bb86e267241cdc0b04070acaa440a175.png)

#### 发现某源码，开审！

翻阅另一台终端文件时，发现了一个压缩包为install.zip,解压查看，发现为某系统源码：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-71e16af3075b163d2a1308da75480fb40b7e830c.png)  
语言为PHP如下:

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-927f28602ca2900f3e348e2f54ef926863523c8d.png)

审计源码发现该系统后台插件添加处存在任意文件上传漏洞，通过添加插件的方式对向服务器中写入webshell获取到多台服务器权限。  
重点在Build()函数里  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-896717d8f778a37149357eed943608f631db494b.png)

直接把请求的config数据写入到插件目录下的config.php文件中了，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-7b6d7a4251af8daaaa063e09dcfd00b9c412b68c.png)

burp构造数据包发包：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-b8485c63007d8bc06113601eaedcd88bb947c701.png)  
解析成功，getshell如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-00f37e51c06faf9c2192fec3d54f8995487a48ba.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-b449552dc19c15dd7f50f58349a5b64ff3b7626a.png)

通过此0day拿下多台服务器权限如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-84f58a657f78b5e544bed09c241e766251745b1e.png)

#### 掌控云上资产

通过前面控制的机器，在其中一台机器中，翻阅配置文件，找到数据库账号密码，登陆数据库在其中一个表中发现了AK/SK如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-74a8ff0aa24c76c56197f741f3a8d3fbeb94758a.png)  
可以接管阿里云所有系统：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-f6e6e5baa551346da0a7fc90f04ad76a33853b17.png)

#### 拿下gitlab

通过linux历史记录获取到gitlab后台权限如下  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-baf4e9f16c8396975f8a50424a284bdf460acd7a.png)

通过探测发现gitlab存在历史漏洞CVE-2021-22205，利用该漏洞获取到gitlab服务器权限  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-68b121ea7dc84606ac243431e9eeb61f806d109e.png)

利用gitlab的redis未授权访问漏洞写入ssh密钥，获取到root权限如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-419de222dda81c71e882feef877f89f51b9291f3.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a65104572f953540786f3e78edd653233a1cd5c7.png)

在gitlab的代码中进行翻阅，发现禅道数据库账号密码，真香，同时也在这里提个小建议，如果进入内网并发现gitlab，第一时间拿下来，好处多多。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-1555f6bd3ec2fa46983e13ab00bfb5a018d97663.png)

数据库直接修改root密码进入后台：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-046a294d4b2daad24db932601c2007a43b6d0568.png)  
通过后台功能getshell如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-6015600ede015947f22f7f544cbb24cc3dbfc0a1.png)

#### 征服Jenkins

通过gitlab系统发现该机器存在nginx，通过**查看nginx配置文件**，发现对sonar\\jenkins\\等多个系统进行反向代理，通过在jenkins.conf文件中配置日志 获取cookie格式，获取到了jenkins用户登陆cookie如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-d1f2fd3af68178ae16978f17e2c9e86650efb048.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-e5994c55043c679916b0afa0e553874fc595da29.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-6c3de66b85e0794876114a3851a83d9ebff58b87.png)

使用获取到的cookie成功登陆Jenkins：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-47773901a38c00e70c6b2e71dcb2eabe29552087.png)

### 小结

通过社工钓鱼撕开口子，内网转了一大圈，也获取了一些成果，咱们下期见。