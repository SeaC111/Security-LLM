0x01 序言
=======

事情起源于在服务器上看到了命名随机的jsp文件，打开内容一看是webshell。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-73195b0d167d82c7838561460415136abb692c5d.jpg)  
根据webshell修改时间，将当天的`D:/WEAVER/Resin/logs/access.log`和`D:/WEAVER/Resin/log/stderr.log`取出来进行分析，以查找其利用路径。  
在stderr.log中发现，攻击者利用SQL注入执行xp\_cmdshell命令来上传的文件  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-fa5df8413e3ac29d75b744e4337a574361ec73d3.jpg)  
存在SQL注入的mapper已经确定是`GetSqlDataMapper.xml`.于是便开启了对该漏洞的分析研究

0x02 getSqlData接口SQL注入分析
========================

2.1 漏洞分析
--------

首先来到`GetSqlDataMapper.xml`，看一下其SQL拼接情况，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-37fc2beae47cb36530b22e98dc9c288f62e1d1e0.jpg)  
直接将传入的sql参数的值，作为SQL语句进行执行。向上寻找该mapper的调用过程。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4d790b72c459adec40d73c132fc8674392b87e9c.jpg)  
继续寻找GetSqlDataMapper接口的调用者  
在`classbean/com/engine/portal/cmd/elementecodeaddon/GetSqlDataCmd.class`中，逻辑如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ad3c64f937cbdda987b84855cd7d54b070787544.jpg)  
所以，可以认定此处存在SQL注入。然后我们寻找Web访问接口的位置，因为都是class搜索调用十分不方便，所以使用Windows命令搜索：

```bash
findstr /c:"GetSqlDataCmd" /d:"D://WEAVER//ecology//classbean//" /si *.class
```

然后其调用关系：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7f0c21e41261042fe1a592f45248ae8f1fe0ebba.jpg)  
所以，找到web入口

```bash
/Api/portal/elementEcodeAddon/getSqlData?sql=
```

这个接口的SQL注入在互联网早已不稀奇，翻看了大多数利用方法都是SQL注入查信息，并没有使用xp\_cmdshell获取权限的案例。

2.2 漏洞利用
--------

### 2.2.1 查询管理员信息

这是往上比较常见的利用方法，可以通过执行SQL语句查询ecology的管理员账号密码，从而登录后台。  
payload如下：  
`/Api/portal/elementEcodeAddon/getSqlData?sql=Select%20*%20from%20HrmResourceManager%20where%20loginid=%27sysadmin%27`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-5ee1d9750e22d5c18fb00462cccb1e5565e95884.jpg)  
然后利用账号密码登录后台  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-40c5aff52ca3cc8d16a5e62802ac82b2b8ffa8fb.jpg)

### 2.2.2 执行命令

ecology的数据库大多数是使用mssql的，而mssql在SQL注入中，常用于执行命令的是`xp_cmdshell`，加上该接口直接传入SQL语句，那么我们可以直接通过`exec xp_cmdshell`来执行命令。测试如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-5404d1d21dd5f3f1364ce26890e5c2ac876dc380.jpg)  
在ecology的《Ecology系统安全配置说明.docx》有做相关说明，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9e1285ba87a3055db22b22567f70a4bec1f13e5f.jpg)  
所以带有`xp_cmdshell`是肯定会被拦截的，但是想到刚才分析漏洞时，传入的sql会以`$`进行分割。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ca06eb7d376a96448ca670b726008485d94a245b.jpg)  
那么，如果我传入`exec xp_cmd$shell 'whoami';`，则最终的语句会是：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3ab1458fd0303d850dcdb70c900d87fce1f9bb70.jpg)  
所以，可以用该方法进行绕过。测试如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6a5a5c9c6345b1105050b9cbfc386bcf519011f1.jpg)  
最终payload：

```bash
/Api/portal/elementEcodeAddon/getSqlData?sql=exec%20xp_cmd$shell%20%27whoami%27;
```

当然要先激活`xp_cmdshell`，激活方法：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c6fd849cad3186414f99f4d89cea1fb8bae60cd2.jpg)

2.3 武器化
-------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-657a0a8e194457b472e10b17bc1294d795d9324b.jpg)