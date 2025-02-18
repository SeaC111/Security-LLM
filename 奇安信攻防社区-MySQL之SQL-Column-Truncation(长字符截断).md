1.介绍
====

mysql超长字符截断又名为“SQL-Column-Truncation”。

在mysql中的一个设置里有一个`sql_mode`选项，当`sql_mode`设置为default 时，即没有开启`STRICT_ALL_TABLES`选项或者`TRADITIONAL` 选项或者加上的是`ANSI`选项时（MySQL sql\_mode默认即default)，MySQL对插入超长的值只会提示 warning，而不是error，这样就可能会导致一些截断问题。

比如：  
第一种：没有开启`STRICT_ALL_TABLES`选项或者`TRADITIONAL` 选项  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fdf4162bb7dcd0e120f6bd2a983c446a2f0c0e89.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fdf4162bb7dcd0e120f6bd2a983c446a2f0c0e89.png)

第二种：加上的是`ANSI`选项  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-48173ba95cc016f75a50b91aa656dcc60bdb7a21.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-48173ba95cc016f75a50b91aa656dcc60bdb7a21.png)

在这里，`username`为`varchar(5)`，即最大规定长度为5，而输入的值为`admsddsff`，长度为9，超过规定长度，可是并没有报错。通过查询可知被截断了。那么我们可以利用这个漏洞。  
第一种和第二种都是如图这样的结果：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ed3df04e03a4ac09e363c6eea63eb8ed7db97bec.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ed3df04e03a4ac09e363c6eea63eb8ed7db97bec.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-57108383307c1064ce16a161cb7b799993bba8fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-57108383307c1064ce16a161cb7b799993bba8fd.png)

2.sql-mode的各项设置
===============

MySQL5.0以上版本支持三种sql\_mode模式：`ANSI`、`TRADITIONAL`和`STRICT_TRANS_TABLES`。

1、`ANSI`模式：  
宽松模式，更改语法和行为，使其更符合标准SQL。对插入数据进行校验，如果不符合定义类型或长度，对数据类型调整或截断保存，报warning警告。对于本文开头中提到的错误，可以先把sql\_mode设置为ANSI模式，这样便可以插入数据，而对于除数为0的结果的字段值，数据库将会用NULL值代替。

2、`TRADITIONAL`模式：  
严格模式，当向mysql数据库插入数据时，进行数据的严格校验，保证错误数据不能插入，报error错误，而不仅仅是警告。用于事物时，会进行事物的回滚。 注释：一旦发现错误立即放弃INSERT/UPDATE。如果你使用非事务存储引擎，这种方式不是你想要的，因为出现错误前进行的数据更改不会“滚动”，结果是更新“只进行了一部分”。

3、`STRICT_TRANS_TABLES`模式：  
严格模式，进行数据的严格校验，错误数据不能插入，报error错误。如果不能将给定的值插入到事务表中，则放弃该语句。对于非事务表，如果值出现在单行语句或多行语句的第1行，则放弃该语句。

**STRICT\_TRANS\_TABLES：**  
在该模式下，如果一个值不能插入到一个事务表中，则中断当前的操作，对非事务表不做限制。必须设置，以后各项可能依赖于该项的设置

**NO\_ENGINE\_SUBSTITUTION：**  
如果需要的存储引擎被禁用或未编译，那么抛出错误。不设置此值时，用默认的存储引擎替代，并抛出一个异常

**ONLY\_FULL\_GROUP\_BY：**  
对于GROUP BY操作，如果在SELECT中出现的单独的列，没有在GROUP BY子句中出现，那么这个SQL是不合法的

**NO\_AUTO\_VALUE\_ON\_ZERO：**  
该值影响自增长列的插入。默认设置下，插入0或NULL代表生成下一个自增长值。如果用户希望插入的值为0，而该列又是自增长的，那么这个选项就有用了

**NO\_ZERO\_IN\_DATE：**  
在严格模式下，不允许日期和月份为零

**NO\_ZERO\_DATE：**  
设置该值，mysql数据库不允许插入零日期，插入零日期会抛出错误而不是警告

**ERROR\_FOR\_DIVISION\_BY\_ZERO：**  
在INSERT或UPDATE过程中，如果数据被零除，则产生错误而非警告。如果未给出该模式，那么数据被零除时MySQL返回NULL

**NO\_AUTO\_CREATE\_USER：**  
禁止GRANT语句创建密码为空的用户

**PIPES\_AS\_CONCAT：**  
将“||”视为字符串的连接操作符而非或运算符，这和Oracle数据库是一样的，也和字符串的拼接函数Concat相类似

**ANSI\_QUOTES：**  
启用ANSI\_QUOTES后，不能用双引号来引用字符串，因为它被解释为识别符  
也可以在命令行查看和设置sql\_mode变量

3.测试
====

新建一张表测试，表结构如下(mysql 5.1):

```php
CREATE TABLE USERS(
                    id int(11) NOT NULL,
                    username varchar(7) NOT NULL,  //长度为7
                    password varchar(12) NOT NULL
)
```

分别插入以下SQL语句（注入提示消息）。

1.插入正常的SQL语句。

```php
mysql> insert into users(id,username,password) values(1,'admin','admin');
Query OK,1 row affected (0.00 sec)  //成功插入，无警告，无错误
```

2.插入错误的SQL语句，此时的“admin ”右面有三个空格，长度为8，已经超过了原有的规定长度。

```php
mysql> insert into users(id,username,password) values(2,'admin   ' ,'admin');
Query oK,1 row affected,1 warning (0.00 sec)    //成功插入，一个警告
```

3.插入错误的SQL语句，长度已经超过原有的规定长度。

```php
mysql> insert into users(id,username,password) values(3 ,'admin   x','admin');
Query OK，1 row affected，1 warning (0.00 sec)    //成功插入，一个警告
```

MySQL提示三条语句都已经插入到数据库，只不过后面两条语句产生了警告。那么最终有没有插入到数据库呢?执行SQL语句查看一下就知道了。

```php
mysql> select username from users;
+----------+
| username |
+----------+
|admin    |
|admin    |
|admin    |
+----------+
3 rows in set (0.00 sec)
```

可以看到，三条数据都被插入到数据库，但值发生了变化，此时再通过length来取得长度，判断值的长度。

```php
mysql> select length(username) from users where id =1;
+------------------+
| length(username) |
+------------------+
|              5|
+------------------+
1 row in set (0.00 sec)

mysql> select length(username) from users where id =2;
+------------------+
| length(username) |
+------------------+
|              7|
+------------------+
1 row in set (0.00 sec)

mysql> select length(username) from users where id =3;
+------------------+
| length(username) |
+------------------+
|              7|
+------------------+
```

可以发现，第二条与第三条数据的长度为7，也就是列的规定长度，由此可知，在默认情况下，如果数据超出列默认长度，mysql会将其截断。

但这样何来攻击一说呢?下面查询用户名为`'admin'`的用户就知道了。

```php
mysql> select username from users where username= 'admin';
+----------+
| username |
+----------+
|admin    |
|admin    |
|admin    |
+----------+
```

只查询用户名为admin 的用户，但是另外两个长度不一致的admin用户也被查询出，这样就会造成一些安全问题，比如，有一处管理员登录是这样判断的，语句如下:

```php
$sql = "select count(*) from users where username='admin' and password='*****'";
```

假设这条SQL语句没有任何注入漏洞，攻击者也可能登录到管理页面。

假设管理员登录的用户名为admin，那么攻击者仅需要注册一个“admin “用户即可轻易进入后台管理页面，像某些著名的建站系统就被这样的方式攻击过。

4、预防方法
======

在sql-mode里加上`STRICT_TRANS_TABLES`或者`TRADITIONAL`。  
加上`STRICT_TRANS_TABLES`或者`TRADITIONAL`后，输入的数据超过规定长度就会报错，不能输入。

第一种：加上`TRADITIONAL`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1f4ace7058531aee118a4ba54285a52064ce87c5.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1f4ace7058531aee118a4ba54285a52064ce87c5.png)

第二种：加上`STRICT_TRANS_TABLES`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-07c17a7cea4ac3f34ebc22f66bcc31c555ee2978.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-07c17a7cea4ac3f34ebc22f66bcc31c555ee2978.png)

两种都是如下的结果：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-421edda84098906d018a684db11419dd4d70fca6.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-421edda84098906d018a684db11419dd4d70fca6.png)