0x01 资产发现
---------

对资产目录进行扫描，发现其dss后台系统登录界面，对其进行了弱密码爆破，成功获取到管理管理员的账号密码。

[![](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-0b3a75a8ca3f759b3595aad0de68b7b438090a8f.png)](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-0b3a75a8ca3f759b3595aad0de68b7b438090a8f.png)

0x02 config配置界面获取数据
-------------------

右上角登录到配置界面，管理员账号密码通用。在数据库配置界面可以配置数据库异地备份，配置ftp服务器后，可以获取数据库所有数据。

[![](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-362bddb984820e63d9de2acc9f56ed977ad4f7e7.png)](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-362bddb984820e63d9de2acc9f56ed977ad4f7e7.png)

0x03 任意文件下载漏洞
-------------

既然都进来了，那就顺便看一下历史漏洞，找到一个CNVD-2020-61986，动手测试。  
通过协议flie://对服务器文件进行下载。

payload：http(s)://`ip`/itc/attachment\_downloadByUrlAtt.action?filePath=file:///etc/passwd

[![](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-be2d04ed2d9082a355e34856c7b77d2592177fd9.png)](https://shs3.b.qianxin.com/attack_forum/2021/05/attach-be2d04ed2d9082a355e34856c7b77d2592177fd9.png)

0x04 最后
-------

至于漏洞修复相关请到官网查询

文章参考：  
<https://www.cnvd.org.cn/flaw/show/CNVD-2020-61986>