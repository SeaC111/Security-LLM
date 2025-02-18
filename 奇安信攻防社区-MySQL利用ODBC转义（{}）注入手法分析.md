前言
--

最近由于工作需要在看libinjection的源码，查到一位师傅发了一篇绕过libinjection的文章，

<https://www.o2oxy.cn/2772.html>

由于URL编码和HEX编码的问题，感觉这位师傅写的不是很对，就发评论跟他讨论，当然他整个libinjection的流程分析还是很不错的。

讨论了半天，这位师傅又抛出了一个payload,说libinjection也检测不出来

`1={date(if(mid((updatexml(1,concat(0x7e,(select user()),0x7e),1)),1,1)='1',2,1))}`

尝试了一下的确如此:  
![](https://shs3.b.qianxin.com/butian_public/faf670a6b472fef2c4b5a24d31cd09938.jpg)  
翻看MySQL语法分析的产生式  
很久之前看到过这种注入的手法，当时没有深究，这次打算好好研究一下。

mysql的SQL解析语法文件：
----------------

[https://github.com/mysql/mysql-server/blob/8.0/sql/sql\_yacc.yy#L9899](https://github.com/mysql/mysql-server/blob/8.0/sql/sql_yacc.yy#L9899)

（这个是yacc的产生式文件，有兴趣的师傅可以去找找lex&amp;yacc的资料，顺便看看编译原理更佳~）

PS：开头注释表明5.7之后语法分析就没有变过

看这个文件懵逼了很久，最后直接搜索’{’（三个字符）找到了关键点：

![](https://shs3.b.qianxin.com/butian_public/fc095cb4c18e009462fd959eac6a00a42.jpg)

'{' 标志符 表达式 '}'是simple\_expr(简单表达式)的一种，走PTI\_odbc\_date这个类的解析方法

[https://github.com/mysql/mysql-server/blob/8.0/sql/parse\_tree\_items.cc#L619](https://github.com/mysql/mysql-server/blob/8.0/sql/parse_tree_items.cc#L619)

通过注释可以看出，该功能是为了解析ODBC的转义形式语法而写的，并且最后如果标志符部分不是d、t、ts，就会直接返回表达式的内容。

![](https://shs3.b.qianxin.com/butian_public/f77086324499773c36859a68172eaa337.jpg)

实际上效果上来说，标志符部分可以任意写，表达式部分都可以正常执行

![](https://shs3.b.qianxin.com/butian_public/fc9981522a14b0c6df82d6895a9789bfa.jpg)

所以可以尝试通过这种形式进行SQL注入防御的绕过。

MySQL手册相关  
<https://dev.mysql.com/doc/refman/8.0/en/expressions.html>

<https://downloads.mysql.com/docs/refman-4.1-en.a4.pdf>

这块感谢同事donky16师傅，实际上手册中有写这种用法，之前搜关键词braces和curly brackets，就是没搜curly braces。。。。：

![](https://shs3.b.qianxin.com/butian_public/f6383689f18e474abac2f70223ecbd040.jpg)

上面那波分析，多少有点走弯路了。

从手册中可以看出，从3.23开始就已经存在了ODBC转义语法。

回到Payload

`1={date(if(mid((updatexml(1,concat(0x7e,(select user()),0x7e),1)),1,1)='1',2,1))}`

payload中，date并不代表一个函数，而是一个标识符， 后面整个括号包裹的if部分是表达式，并且可以不适用括号分割而，转而使用空格之类的进行分割：

![](https://shs3.b.qianxin.com/butian_public/f74aa83fad01c4b44dd5a68c5a20aebe7.jpg)

可以看到两个效果是一样的，都可以正常触发报错，说明updatexml函数已经被执行了。

但是后一种写法是可以被libinjection检测出来的：

![](https://shs3.b.qianxin.com/butian_public/f494276b7ce450465cb02256b86e2fd4d.jpg)

而libinjection中实际上已经考虑了ODBC转义的情况：

![](https://shs3.b.qianxin.com/butian_public/fcc4286b060693b7d669283f59e01c1a9.jpg)

原因分析
----

libinjection中有种token类型为bareword

bareword可能被认为:label 、 句柄 、函数 、 普通字符串

libinjection特定位置上只有非关键字列表（方法名、变量名、select union之类的关键字）才会被认为是bareword。

在libjection的token折叠函数中，’{’+BAREWORD的组合会进行折叠，而像’{date’这种形式会被解析成’{’+FUNCTION的Token串，不会被折叠导致了绕过。

{foo expr}

而在ODBC转义语法的语境中，上述foo位置都会被认为是标识符或者说bareword。

所以此处解决办法有两个：

1. 加特征，将’{’+FUNCTION的情况包进去
2. 优化折叠代码，考虑’{’+FUNCTION的情况

最后选用了第二种方法进行完善，可以正常的检测出来该SQL注入：

![](https://shs3.b.qianxin.com/butian_public/f9d587223759421f2ea697a31e60a9db9.jpg)

引用内容
----

libinjection源码（语义分析SQL注入检测）：

<https://github.com/client9/libinjection>

感谢这位师傅，涨知识了~：

<https://www.o2oxy.cn/2772.html>

MySQL源码：

<https://github.com/mysql/mysql-server/>

MySQL手册：

<https://dev.mysql.com/doc/refman/8.0/en/expressions.html>

原文转载于自己博客，原文地址为：<https://blog.csdn.net/fnmsd/article/details/108650568>