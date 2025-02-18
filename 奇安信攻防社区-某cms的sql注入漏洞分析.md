一.前言
====

某开源商城是基于thinkphp3.2.3，此商城中的sql注入漏洞很多，这篇文章主要举几个比较典型的例子，讲讲对漏洞的分析和自己审计代码时的一些思路。

二.代码审计
======

0x00.请求过程
---------

ThinkPHP的控制器是一个类，而操作则是控制器类的一个公共方法。

控制器类的命名方式：控制器名(驼峰命名法)+Controller

控制器文件的命名方式：类名+.class.php(类文件后缀)

首先通过`getController`和`getAction`两个方法定义`CONTROLLER_NAME`和`ACTION_NAME`的值

![image-20230511173121317](https://shs3.b.qianxin.com/butian_public/f438736be943a0a422ee43a9ddbab8858bee64656ad80.jpg)

然后通过`CONTROLLER_NAME`获取当前操作名

![image-20230511173341658](https://shs3.b.qianxin.com/butian_public/f88462926082db6c81fbb7b3938b496d62e0e7c1c0549.jpg)

然后通过`ACTION_NAME`获取类所在的路径并创建控制器实例

![image-20230511173637375](https://shs3.b.qianxin.com/butian_public/f7837952271d2cbd0b49383510f503bf8fa6de03bf4ce.jpg)

然后通过反射方法`ReflectionMethod`获取这个对象下对应的方法， 并且后续没有进行权限判断，导致所有请求都可以通过未授权访问

![image-20230511172521716](https://shs3.b.qianxin.com/butian_public/f214473192952391138361640c787679d57bf70a6d951.jpg)

最后执行对应的应用程序

![image-20230511174924625](https://shs3.b.qianxin.com/butian_public/f5183395c0075ea010e3c31f5e1141c9d974903b4ef6f.jpg)

0x01.sql注入漏洞1
-------------

在`Modules/Home/Controller/ApiuserController.class.php`文件中的`group_info`方法

![image-20230426152942973](https://shs3.b.qianxin.com/butian_public/f2430952443142e82b085ff94e39448a2206f9563a77c.jpg)

$order\_id通过get请求传入，接着直接拼接进sql语句中，由于没有对参数进行过滤，并且没有对传入的`token`参数进行校验，直接拼接sql语句进行未授权执行。

### 漏洞复现：

payload：

[http://127.0.0.1/index.php?s=/Apiuser/group\\\_info&amp;order\\\_id=1%20and%20updatexml(1,concat(0x7e,database(),0x7e),1](http://127.0.0.1/index.php?s=/Apiuser/group%5C_info&order%5C_id=1%20and%20updatexml(1,concat(0x7e,database(),0x7e),1))

![image-20230426153242419](https://shs3.b.qianxin.com/butian_public/f887423c30196020216bddec4218994ad4759b5f19e25.jpg)

0x02.sql注入漏洞2
-------------

在`Modules/Home/Controller/VipcardController.class.php`文件中的`get_vipgoods_list`方法

![image-20230426153721428](https://shs3.b.qianxin.com/butian_public/f2239794ca36c24e0d11f5bf8d6b3e10ec060a8216404.jpg)

order\_id通过get请求传入，然后拼接到where语句中，由于是字符串，`$this->options['where']`的键就是`_string`

![image-20230427150146495](https://shs3.b.qianxin.com/butian_public/f55534784261c7851bae5f8a12304e8f3eca70f772cf1.jpg)

所以导致**不会**进入到下面的if判断语句中，`_parseType`方法用来检测传入的类型，由于传入的字符串类型，所以也就不会去判断是否符合字段数据类型

![image-20230427150720492](https://shs3.b.qianxin.com/butian_public/f56956674202c3194b05416b42bfa2582c95a7df74164.jpg)

最终拼接成sql语句进行执行

![image-20230426160351858](https://shs3.b.qianxin.com/butian_public/f483328aa92509c363584f7e2b437f09184ce9b14f366.jpg)

还有注意一点的是，非array传出的参数会被添加()，所以有时候无法闭合的时候可以尝试添加括号看看

### 漏洞复现

payload：

[http://127.0.0.1/index.php?s=Vipcard/get\\\_vipgoods\\\_list&amp;gid=1](http://127.0.0.1/index.php?s=Vipcard/get%5C_vipgoods%5C_list&gid=1) and updatexml(1,concat(0x7e,database(),0x7e),1)

![image-20230427114410368](https://shs3.b.qianxin.com/butian_public/f4400477b952d49a8e5e6098a998a5091f61bab24f628.jpg)

0x03.sql注入漏洞3
-------------

在`Modules/Home/Controller/ApiuserController.class.php`中的set\_default\_address方法

![image-20230427160741552](https://shs3.b.qianxin.com/butian_public/f784394c42ef93f1e0391f3066e3f5e9fcc5c29c53f78.jpg)

然后跟进`where`和`save`方法，然后在save方法中跟进`_parseOptions`方法

![image-20230427162110263](https://shs3.b.qianxin.com/butian_public/f536516c1ccb48e2f3caf82fcc32df789737eb03baa8c.jpg)

在`_parseOptions`方法中，由于这里`$val`是一个数组，所以`is_scalar`判断不是标量，也就不会进入`_parseType`方法用来检测传入的类型

![image-20230427152713737](https://shs3.b.qianxin.com/butian_public/f5192472f178ddc2f0e23dee6331cbe251fa0d1a6508a.jpg)

在where子单元分析函数`parseWhereItem`中，`$exp`去了array中的第一个值bind，然后在下面的判断语句中拼接`$whereStr`

![image-20230427154802743](https://shs3.b.qianxin.com/butian_public/f270474b128251ac1ce8eeabcf73d4b60bacc40c8a8b7.jpg)

最后形成下面的sql语句，但此时的sql语句中任存在`:0`

![image-20230427155145586](https://shs3.b.qianxin.com/butian_public/f82279506b6f2313ffdeb1212e7fec5d6e4fc5b2a366d.jpg)

在`execute`中，是将`:0`替换为外部传进来的字符串，所以我们让我们的参数也等于0，这样就拼接了一个`:0`，然后会通过`strtr()`被替换为1

![image-20230427161521183](https://shs3.b.qianxin.com/butian_public/f95350766308c9a5e8748870fc5bb604aed178a32fa37.jpg)

### 漏洞复现

payload:

[http://127.0.0.1/index.php?s=Apiuser/set\\\_default\\\_address&amp;id\\\[0\\\]=bind&amp;id\\\[1\\\]=0%20and%20(updatexml(1,concat(0x7e,user(),0x7e),1](http://127.0.0.1/index.php?s=Apiuser/set%5C_default%5C_address&id%5C%5B0%5C%5D=bind&id%5C%5B1%5C%5D=0%20and%20(updatexml(1,concat(0x7e,user(),0x7e),1)))

![image-20230427162255830](https://shs3.b.qianxin.com/butian_public/f83200323aadfea7e8438e27158be59c2d731adfac3a9.jpg)

三.tp框架下SQL注入漏洞挖掘思路总结
====================

tp框架采用MVC架构，即`模型`（Model），`视图`（View）,`控制器`（Controller）。他们大致的运行流程是用户与应用程序交互，向`控制器`发送请求，然后`控制器`收到请求分析用户请求，并调用响应的`模型`操作，`模型`操作访问数据库或其他数据源，对数据进行处理并返回给`控制器`，`控制器`接受模型返回的数据，并传递给`视图`，最后`视图`将数据呈现给用户。

在MVC架构下对于挖掘sql注入漏洞应该首先关注其模型，因为他是与数据库交互的地方，如果我们能发现其过滤不严导致直接将用户数据带入数据库中执行从而造成sql注入。

### 1.使用`QUERY`方法对原生的SQL查询和执行操作

示例代码：

$gid \\= $\_GPC\['gid'\];  
$sql \\= "select xxx from xxx where gid='$id';"  
$result \\= M()-&gt;query($sql);

这种写法如果不对传入的gid变量加以过滤，很容易造成sql注入。

我们可以通过正则`M\(.*?\)->query\(.+?\)`搜索代码中使用query方法的代码，然后查看传入的参数是否可控.

![image-20230426163555537](https://shs3.b.qianxin.com/butian_public/f3494037a6904cf43b1d370ac59233342a5cd0ccb8c75.jpg)

2.使用字符串作为查询条件
-------------

示例代码：

$gid \\= $\_GPC\['gid'\];  
$resultt \\= M('xxx')-&gt;where( "pid = {$gid}" )-&gt;select();

我们可以通过正则`M\(.*?\)->where\(((?!array).)*\)`搜索代码中使用where方法且不是通过array传参的代码，然后查看传入的参数是否可控.

![image-20230427165636705](https://shs3.b.qianxin.com/butian_public/f31090351c255ebe82eaed4e3d8ba41aa7f1c0f5b865e.jpg)

3.使用数组作为查询条件
------------

示例代码：

$gid \\= $\_GPC\['gid'\];  
$resultt \\= M('xxx')-&gt;where( array('gid' \\=&gt; $gid) )-&gt;save();

当使用数据进行传参情况就不一样了

如果传参是通过array的话，**会**进入到下面的if判断语句中，会对传入值的类型进行判断，若判断为int类型，参数将直接传唤为int类型将丢失后面的payload，

![image-20230427151141569](https://shs3.b.qianxin.com/butian_public/f3839976d60e048a237c661da54365122e9eb19294e22.jpg)

![image-20230427145520525](https://shs3.b.qianxin.com/butian_public/f6261243aa22dfb3a6ebf86423eab84d09ac5c7f602bc.jpg)

就算传入的类型可以为字符型也还会对传入的参数关键字符进行转义

所以这里我们只能另辟蹊径，只能通过tp3.2.3框架的几个sql注入漏洞来利用

例如这里我们可以使用tp3.2.3框架的bind注入，漏洞所在的地方一般都需要update的操作

我们可以通过正则`M\(.*?\)->where\(.+?\).>save\(.+?\)`搜索代码中使用where方法且不是通过array传参的代码，然后查看传入的参数是否可控.

![image-20230427163129100](https://shs3.b.qianxin.com/butian_public/f363963efb205f67754fdbf03222c4c03c8d1e761fb32.jpg)

另外tp3.2.3中还可以通过exp注入，原理和上面的bind注入差不多，但其条件参数必须是通过全局数组传参，而不是`I()`函数，因为`I()`函数会调用`think_filter()`函数，其中过滤了`exp`。在这一套cms中所有参数都是通过`I()`函数传参的，所以无法使用exp注入。