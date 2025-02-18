本文仅用于技术讨论与研究，文中的实现方法切勿应用在任何违法场景。如因涉嫌违法造成的一切不良影响，本文作者概不负责。

0x00 前言
-------

近期与朋友一起看的两个洞，`Piwigo` 的两枚 `SQL` 注入漏洞，二次注入的漏洞挺有意思的，在这里记录一下。

0x01 漏洞环境
---------

`Piwigo` 可以通过 `github` 或者其官网下载。

`github` 地址：<https://github.com/Piwigo/Piwigo>

官网：<https://piwigo.org/>

0x02 CVE-2022-26266
-------------------

### 漏洞描述

`Piwigo` 在 12.2.0 版本的 `pwg.users.php` 文件中发现一枚`SQL` 注入漏洞，可通过该漏洞获取数据库中的数据。

### 漏洞分析

`cve` 官方漏洞描述中已经点出漏洞文件为 `pwg.users.php` ，我们直接看到这里，位于 `include/ws_functions/pwg.users.php`

这里很多数据库操作，而且很多都是在拼接，出现注入的概率确实挺大的。

这个文件全都是函数，也就是说我们无法直接访问到这里，因此现在需要做的是找到调用的位置

第一个函数是 `ws_users_getList` ，直接全局搜索该函数

![image-20221117221711630.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-553cab1969d41ce63f0499c558ad8cf626cf7750.png)

在这里的 `ws.php` 中，`ws_users_getList` 被 `addMethod` 添加到 `$service` 的 `method` 列表中，实际上这里是 `piwigo` 自身定义的访问模式，这里就不细讲了，大概就是将一些路由与函数绑定在一起，当出现访问时，通过回调的方式去访问。

要想访问 `ws_users_getList` ，我们只需要访问 `ws.php` ，并 `get` 一个 `method` 参数，值为 `pwg.users.getList` 即可。

我们再回来看这个 `ws_users_getList` 的内容

![image-20221117224118489.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-95da594ef47f1543b42dacb59b10ef814bb6ebe1.png)

`$params` 中存放的是我们请求的值与系统默认的一些值，看到上图，当我们的输入中带有单引号等特殊字符时，会自动转义，这是系统对输入值的过滤，不允许直接输入单双引号等危险字符。如上很多的拼接字符串都使用不了，因为他们都需要闭合前面的引号，我们只能找可以直接拼接而不用闭合引号的参数。

`order by` 是常用的突破点，我们直接找到此处 208 行，并在输入中输入 `order` 参数

![image-20221117224722221.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-58848e7462351727fa92735176d6b96849f0d561.png)

这里我们不用闭合单引号，因此可以直接对其进行注入

### 漏洞复现

本漏洞需要登录后台利用，登录后如下点击

```php
用户 -> 管理 -> 用户列表
```

![image-20221117220404252.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-054578ee702d7dde07eac34ffa7ef995d67a37f2.png)

抓包，但是放掉第一个包，进入第二个包如下

![image-20221117220555569.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9b1453a724238ac8b9c73ceb82375e53b9924d88.png)

这里并没有 `order` 参数，我们添加进去即可，之后发包可见报错

![image-20221117220751998.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6499cdc9a62b9ac0c09dca4c8d35b78704aec807.png)

仅验证，点到即止

0x03 CVE-2022-32297
-------------------

### 漏洞描述

`Piwigo` 在 12.2.0 版本的搜索功能中存在一个二次`SQL` 注入漏洞，该漏洞可以从前台获取数据库中的数据。

### 漏洞分析

#### 数据插入部分分析

我们先来到前台搜索处，随意搜索，然后抓包查看，这里游客身份进入即可

通过抓包，我们可以抓到处理搜索功能的文件为 `qsearch.php` ，进入后直接下断点

![image-20221117233046830.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-67161f3a234ba21f2c67eb87906705f12d7ded94.png)

顺利进入该文件，跟进代码，看之后经历的操作，根据网上的信息，该漏洞为二次注入漏洞，因此可以格外关注 `insert into` 的数据库操作。

从上面的图中可以看到搜索的参数为 `q` ，而在代码中也有体现

![image-20221117233335010.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-df8b98475cafb92dc1899544de27ba9923f2bcfe.png)

这里实际上就是根据搜索的 `q` 得到 `search` 数组，序列化数组并用 `addslashes` 处理后查找，存在该搜索就更新，不存在就插入，成功插入后返回搜索的 `id` ，这里序列化操作后 `addslashes` 处理了，因此不存在直接的注入漏洞。

这里先简单说一下，其余的部分在后面写出来

#### 管理员操作部分

插入值后，寻找该值被使用的位置，直接可以搜索 `SEARCH_TABLE`

![image-20221117233902452.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0907013d8c0a25f10d1e4d860505604a3a1f6444.png)

调用的位置不多，可以一个个看，主要关注取值的位置，来到 `admin/history.php` ，根据取值的位置找到如下代码

![image-20221117234121204.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-855d94ca11ee76cad115b3f530426784cd16a883.png)

当存在`get` 的参数中存在 `search_id` 时，就会根据 `search_id` 查找 `rules` ，从上一部分的分析来看，这个 `rules` 是被序列化后的查询数据，我们也可以通过直接去看数据库内容看出来

![image-20221118231419112.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b7a0cfb8dab4581b6271654e7d01cfebf8a8ba38.png)

取出来的值直接反序列化，得到 `$page['search']` ，当 `get` 的参数中还存在 `user_id` 时，则会将 `$page['search']` 序列化后再次插入数据库中，但是这里的序列化数据并没有进行处理，也就是说数据里面存在单引号等就可以直接闭合，刚好这里的数据是我们可以利用第一部分的搜索操作控制的，因此造成了一个二次注入。

这里的构造需要很巧妙，既要闭合 `SQL` 操作，又要通过序列化操作，不得不说这个漏洞发现者很强，在此之前我是想不到还可以这样玩的。

这里简单说一下构造，因为 `insert` 是支持一次性插入多条数据的，通过逗号隔开即可，我们第一步的搜索语句中，插入时存在 `addslashes` ，因此插进去时是什么样子，拿出来也会是什么样子，这里一部分先闭合，随意给一个值即可，比如给一个 `test'` ，此处 `insert` 只有一个字段，因此必须先闭合括号，然后开启插入的第二个数据，写一下大概就是如下

```php
test'),
```

由于这个字段的数据都是序列化后的，因此我们必须满足序列化的规则才方便被正常取出，我们先构造一个获取管理员密码的语句如下：

```php
SELECT password FROM piwigo_users where id=1
```

使用这条语句获取到密码后，再将其放入模板中

```php
a:1:{s:1:"q";s:4:"xxxx";}
```

`xxxx` 就是我们获取到的密文，前面的4跟随密文长度变化，我看了下，这里加密方式产出的密文好像都是 34 位，因此这里直接设 34。

密码获取需要通过上面的语句获取，使用 `concat` 拼接获取，配合前面的内容得到

```php
test'),((select concat('a:1:{s:1:"q";s:34:"',(SELECT password FROM piwigo_users where id=1),'";}')))#
```

构造如上 `payload` ，通过前台搜索功能插入后，在这里就可以获取到密文，并将密文存储到数据库中

#### 访问前台获取密码

接下来是获取该数据库内容，因此涉及的数据库仍然是刚刚的数据库，可以继续搜索 `SEARCH_TABLE` ，找到一处前台获取该数据库内容的位置，位于 `include/functions_search.inc.php`

![image-20221121204114680.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ccd7892f9139f74fb6822f266c4728f7c9090527.png)

这里是一个函数，直接根据 `$search_id` 搜索，然后反序列化 `rules` 后返回，我们看看调用位置

![image-20221121204231387.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-4cebe728e72e17d093fe41b2b4c00f88cac1a38d.png)

定位到 `search_rules.php`

![image-20221121204308272.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0b29f4cd770845edc058e5131deaa164160764de.png)

比较简单就知道可以成功获取。

### 漏洞复现

#### 将payload通过前台插入数据库

按照之前说的注入

![image-20221121204807619.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8a3458db874398863ad8f0e5efdaf934682a1818.png)

记录返回的 `id` 值，对应插入记录的 `id`

但是发现之后的利用会出错，这是为什么呢？按照前面说的，这里的 `q` 写入的是什么，之后获取就应该是那个值，但是 `$_GET` 在利用前实际上会被处理一次，位于 `include/common.inc.php` ，这是文件开头就会调用的

![image-20221121215142137.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ecf9f7a9603d75f23bec14cd8ded77c7eac19480.png)

因此我们这里写入的 `payload` 中的单引号会被加上 `\` ，就像上面图中的数据库 一样

这里的解决方法是将参数 `q` 作为一个数组写入，数组的键为 `payload` ，而 之后的处理由于是序列化，因此这个键也会被写入，之后取出来也适用。

![image-20221121215634944.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-b209161024595dad5901199d7566a3ae2d6803e3.png)

如此，进入数据库的值就不会被转义了

#### 管理员用户点击该漏洞链接

此操作需要管理员权限

![image-20221121215728409.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-6e1e02e739b2e338198231a590c7090f72e1bd9c.png)

可以看到，执行完后，会在数据库中生成两条记录，其中一条就获取到了密文

#### 攻击者前台访问获取密码

这里唯一需要注意的一点是我们需要知道 `search_id` ，也就是插入的那条含有密文的数据的 `id` 值

![image-20221121220108758.png](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c32d2e20f0fd12f083ceb7fb451dfacfc5be944d.png)

0x04 总结
-------

相对来说，`CVE-2022-32297` 会更有意思，而且该漏洞比较难以发现，虽然需要管理员用户点击，但用户可以从前台获取到数据，比 `CVE-2022-26266` 的危害更加大。这个漏洞让我想起了 `Laravel` `CVE-2021-3129` 漏洞，同样是取出来后又放进去，从而导致了漏洞，虽然造成漏洞的本质并不一样，但有着异曲同工之妙。