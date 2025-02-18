0x00 前言
=======

WeiPHP5.0是一个开源，高效，简洁的移动应用系统，它实现一个后台同时管理和运营多个客户端。WeiPHP5以前的版本都是基于ThinkPHP3.2版本开发，5.0以后升级了ThinkPHP5的架构。

WeiPHP在5.0版本存在多个SQL注入漏洞，也被分配了CNVD编号，有一定的影响力，然而网上只流传着一纸poc，没有相关的分析干货，基于学习探究的目的，笔者试着就其中一个SQL注入的漏洞进行分析。

漏洞来源：

[WeiPHP5.0 SQL注入漏洞2\_N0puple的博客-CSDN博客\_weiphp](https://blog.csdn.net/csdn_Pade/article/details/124620983)

0x01 poc
========

```php
POST /weiphp5/public/index.php/home/Index/bind_follow HTTP/1.1
Host: 192.168.249.128:81
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh-TW;q=0.9,zh;q=0.8,en;q=0.7,zh-HK;q=0.6,en-US;q=0.5
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 80

uid%5b0]=exp&uid[1]=)%20and%20updatexml%0a(1,concat(0x7e,/*!user*/(),0x7e),1)--+
```

0x02 分析
=======

是一个免登录的前台sql，危害较大

先根据报错信息定位漏洞入口文件

![Untitled.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-116c7a0ad29ec829f2be3aa3582c59e1552174d3.png)

进入`/application/home/controller/Index.php`

![Untitled 1.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d0ede917f9a58a8e711e7e9f7b4f5f65f6573d46.png)

对thinkphp架构熟悉的话，可以知道 `I` 函数就是一个过滤输入的函数，先`ctrl` 跟进看看代码

来到 `application/common.php`

![Untitled 2.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-19630e7ecd0393e5517352033899894f0de85041.png)

继续进入 `input` 函数

![Untitled 3.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6e894d4c5dc9ac91a92a7c490960d86b614782ff.png)

`input` 首先判断输入的数据是否以 `?` 开头，是的话去掉 `?` ，并将 `$has` 赋为 `true`

接着找数据中是否有 `.` ，有的话以 `.` 为界限分割数据

最后看看 `has` 函数， `thinkphp/library/think/facade/Request.php`

![Untitled 4.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7391d0ce3e6040a0c67dc6a9cd995ab859091372.png)

可见 `I` 函数对注入没什么过滤作用

接着进到 `wp_where` 函数

![Untitled 5.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9da253f9f45a161b54377b4ceef1c4ba6d735b24.png)

遍历 `$map` 数组，由于传入的只有两个值，这段代码会进入`elseif`

如果`$value[0]=='exp'` ，并且`!is_object($value[1]` ，进入`Db::raw` `thinkphp/library/think/Db.php`

![Untitled 6.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8611160c813022abf573e800e050d55ee4ef9051.png)

注意到这是静态方法，`Db.php`有一个魔术方法`__callStatic()` ，其会在调用没有声明的静态方法时自动调用，作用和原型都类似于 `__call()` ，并且由于`Db.php`没有继承任何类，`static::connect` 在这里调用的是当前类的 `connect` 方法

![Untitled 7.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-949eee65c69e10dccaec59655436b640edc7536f.png)

打下断点发poc跟进

传入回调的 `$method` 和 `$args`

![Untitled 8.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5e03a7aec86d403f66417db44c74a7f7aae7e324.png)

进入 `connection` 构造函数（`\think\db\Query`）

![Untitled 9.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-687b3c33978a774433b96fa4ec2466bbac7b31cb.png)

`getConfig` 返回数据库前缀

进入`raw`函数

![Untitled 10.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2311e6700fc87fad905bc8bbc06460b0fe61dfec.png)

进入`raw`函数所在的类 `think\db\Expression`

初始化处理传入值后，返回到 `\think\db\Query::where`

![Untitled 11.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-24563c3c4c32418e0f4c00fd7bcc31d30cfc6a23.png)

不断步入到 `Index.php`，进入 `\think\db\Query::find`

![Untitled 12.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-11a66387599017eab3ebaa7688bb122da9c5b957.png)

继续跟进 `find()` 函数（ `\think\db\Connection::find` ），查找单条记录的函数，分析查询表达式，最后生成查询sql语句

![Untitled 13.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a4d5919ef5b1d89911c3c1d3cb4d18eaf7ab5092.png)

`select` 函数解析并格式化查询语句

跟进 `select` 函数，逐个跟进每个 `parse` 函数

![Untitled 14.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0c977fb9d7601f0746f6cbab74cac5d311dd87f4.png)

顾名思义，`parseTable` 函数返回 table名，跟进前面几个函数都是返回一些格式化信息，跟到`parseWhere` 关键函数

![Untitled 15.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d35d916ad7285e3617b1756a859cdb6a6e7a19f0.png)

接着到 `\think\db\Builder::buildWhere` ，遍历 `$val` 数组的值，传给 `$value`数组，这里的`publicid`是默认的

![Untitled 16.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-28bffd09751066bc7d89094d30044b503e439dbc.png)

`array_shift` 函数的作用是删除数组中的第一个元素，并且返回被删除元素的值，这里的作用可以理解成把数组中的值逐个取出做sql解析

![Untitled 17.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c0bf7a1565e56f7e903c3cdc63d850163fdf8a3c.png)

`$filed` 赋值为 `publicid` 后传入 `parseWhereItem` 函数

![Untitled 18.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d73840c3c31d003dfc08f0bfe9918639703a2c56.png)

经过`array_shift` 函数后 `$value` 也就变成了 `{"=", ""}` ，`$exp` 被赋值为 `=`

![Untitled 19.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-868110e55b70e62bbe3a69bbea0d1ff88e72ddad.png)

接着进入 `\think\db\Query::bind` 函数

![Untitled 20.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1e0f0dd7024c46acf1b1e3e19361542add4b3a65.png)

返回一个 `name` 值 `ThinkBind_1_`

![Untitled 21.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-aa855013a82f56e7e2ee83f77eab25af0e5841eb.png)

`\think\db\Builder::parseWhereItem` 中赋值 `:ThinkBind_1_`

![Untitled 22.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7607ecdb7cf9bef5af292aeabb3592efad4fa0e4.png)

经过 `\think\db\Builder::parseCompare` 处理，最终 `\think\db\Builder::parseWhereItem` 返回 `publicid = :ThinkBind_1_`

到这里拿到sql语句前半段

![Untitled 23.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-129fa38f74a3c16125acdd61d80f23bc679db883.png)

接着返回到遍历数组的语句，继续传入 `$val` 的第二个键值对，也就是poc中post data传入的 `uid[0]=exp&uid[1]=)%20and%20updatexml……`

![Untitled 24.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fbdaa0ba6733a947369b538c187743f17f2549f7.png)

这里开始与前面的步骤一样，经过 `array_shift` 函数处理， `$field` 赋值为 `uid` ，并且数组变成 `{"exp", think\db\Expression}` ，后者即传入的恶意sql语句 `) and updatexml\n(1,concat(0x7e,/*!user*/(),0x7e),1)--`

![Untitled 25.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0134a221e9dfaffc460c9981a017dc107a99f862.png)

重复上面解析`publicid`的一系列函数处理，一步步将 `think\db\Expression` 的值解析出来，赋值给`value`

![Untitled 26.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bf5b6e54679101b01f372cb84bb8cc32fd6d5a51.png)

最终在 `\think\db\Builder::parseExp` 处拼接左右括号和 `$key` ，用 `getValue` 取值

![Untitled 27.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8041138d949d1805396f8a8845c8f06742f922c4.png)

而 `getValue` 函数直接返回 `value` 的值 (`\think\db\Expression::getValue`)，中间的函数并没有对传入的`uid`数组进行相关的字符过滤、转义或者检查等操作

![Untitled 28.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-782d8337e4a900549c949c3ff3c105dbcc2000d5.png)

`value` 闭合括号即产生了注入

与上文一样在`\think\db\Builder::parseWhereItem` 返回解析后的值

![Untitled 29.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2be7f2450753f751ff7d678cdc23875436e36ee7.png)

接着把两次处理后的值拼接起来

![Untitled 30.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-804e997b7d65c44535a8a0136b5e5b20f57ddedf.png)

作为`\think\db\Builder::parseWhere` 的返回值，回到 `select` 函数完成后续的 `parse` 函数， 再返回给前文的`select`语句

![Untitled 31.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-40d4d5bdde7da8050fb82a0bf12d9c2342b76a98.png)

最终的 `$sql` 语句

```sql
SELECT * FROM `wp_user_follow` WHERE  `publicid` = :ThinkBind_1_  AND ( `uid` ) and updatexml\n(1,concat(0x7e,/*!user*/(),0x7e),1)--  ) LIMIT 1
```

然后执行查询 `$sql`

![Untitled 32.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5dcbd2598ed1d6da3602d7f68f66867ce78a6002.png)  
后面初始化、连接数据库等就不赘述了

到这里的堆栈

```php
Connection.php:644, think\db\Connection->query()
Connection.php:844, think\db\Connection->find()
Query.php:3132, think\db\Query->find()
Index.php:161, app\home\controller\Index->bind_follow()
Container.php:395, ReflectionMethod->invokeArgs()
Container.php:395, think\Container->invokeReflectMethod()
Module.php:132, think\route\dispatch\Module->think\route\dispatch\{closure}()
Middleware.php:185, call_user_func_array:{C:\ALLHERE\phpstudy\phpstudy_pro\WWW\weiphp5\thinkphp\library\think\Middleware.php:185}()
Middleware.php:185, think\Middleware->think\{closure}()
Middleware.php:130, call_user_func:{C:\ALLHERE\phpstudy\phpstudy_pro\WWW\weiphp5\thinkphp\library\think\Middleware.php:130}()
Middleware.php:130, think\Middleware->dispatch()
Module.php:137, think\route\dispatch\Module->exec()
Dispatch.php:168, think\route\Dispatch->run()
App.php:432, think\App->think\{closure}()
Middleware.php:185, call_user_func_array:{C:\ALLHERE\phpstudy\phpstudy_pro\WWW\weiphp5\thinkphp\library\think\Middleware.php:185}()
Middleware.php:185, think\Middleware->think\{closure}()
Middleware.php:130, call_user_func:{C:\ALLHERE\phpstudy\phpstudy_pro\WWW\weiphp5\thinkphp\library\think\Middleware.php:130}()
Middleware.php:130, think\Middleware->dispatch()
App.php:435, think\App->run()
index.php:55, {main}()
```

0x03 利用情况
=========

![Untitled 33.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-400d424ae0f815f0143a7277c66fc11a1fa7185e.png)

0x04 总结
=======

看到poc的时候原本以为只是一个简单的未对用户输入进行过滤的SQL注入漏洞，一看代码才发现没那么简单。虽然一样是未过滤，但是形成原因有点复杂，涉及到了ThinkPHP框架原生的SQL操作类(Db.php等)代码以及其操作思路，debug过程很漫长，打了好多断点逐步找到关键函数，整个过程经过了很多的函数处理，文中省略了很多步骤，一路F7十分考验耐心和细心，并且也借此机会多了解了一些ThinkPHP架构的代码思路。最终的闭合居然是在处理解析sql语句的过程中被闭合的，想必发现这个漏洞也一定是对thinkphp代码架构比较熟悉并且比较细心。总的来说，这次分析还是比较具有代表意义的。