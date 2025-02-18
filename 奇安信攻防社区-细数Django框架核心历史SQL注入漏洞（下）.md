本文仅用于技术讨论与研究，文中的实现方法切勿应用在任何违法场景。如因涉嫌违法造成的一切不良影响，本文作者概不负责。

0x00 前言
=======

最近总结了一下 `Django` 框架曾经出现的 `SQL` 注入漏洞，总共有七个 `CVE` ，分别都简单分析复现并写了文章，总体来说会觉得比较有意思，在这里分享一下。本篇文章是下篇。上篇请查看：[细数Django框架核心历史SQL注入漏洞（上）](https://forum.butian.net/share/1923)

0x01 目录
=======

本篇文章分享三个 `CVE` ，其他四个 `CVE` 在上篇文章展现。

- CVE-2022-28346
- CVE-2022-28347
- CVE-2022-34265

0x02 CVE-2022-28346
===================

漏洞描述
----

`Django` 在2022年发布的安全更新，修复了在 `QuerySet` 的 `annotate()`， `aggregate()`， `extra()` 等函数中存在的 `SQL` 注入漏洞。

漏洞影响
----

- Django 2.2.x &lt; 2.2.28
- Django 3.2.x &lt; 3.2.13
- Django 4.0.x &lt; 4.0.4

需要使用了 `annotate` 或者 `aggregate` 或 `extra` 方法

漏洞分析
----

我们可以直接来到 `github` 修复记录

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5201c55d6564fb69cc3104261aa72d04af0f54e4.png)

这里给 `add_annotation` 和 `add_extra` 两个函数中的参数添加了正则过滤，接下来我们就是要找到哪里使用到了这两个函数

这里其实可以通过测试用例来进行判断，我们可以看到修复记录中也存在测试用例的修复有点多，这里只选取一个进行分析

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-63c4519f6ab58acdadb6bd72d9293939d36ce841.png)

这里使用到了如下语句

```php
Author.objects.aggregate(**{crafted_alias: Avg("age")})
```

`crafted_alias` 是用来测试的 `payload` ，我们先找到 `aggregate` 的实现位置

最终可以找到这里 `django\db\models\query.py`

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-bd51de850d455698da427ce6c171d0a99229619c.png)

传进来的 `args` 与 `kwargs`会经过 `_validate_values_are_expressions` 处理，但没有进行过滤

之后进过 `add_annotation` 进行赋值，如下

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a849b3a1452e5722ab69909fc998afdc231a0e88.png)

这里就是修复 `sql` 注入的位置，对 `alias` 进行了过滤，而目前这里没有进行过滤，直接成为了 `self.annotations` 的键，之后跟进会发现这个`self.annotations` 在 `resolve_ref` 函数中被取出来

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7e7124fbc237e7bff96d4a09281269f29df98875.png)

这里会将我们之前的 `alias` 的值最终放到 `transform` 中，直接被使用

其他的漏洞函数与这个类似，就不分析了。

漏洞复现
----

复现环境参考之前的 `CVE-2020-7471` ，只需要更改 `views.py`

```php
from django.shortcuts import render, HttpResponse
from .models import Collection
from django.contrib.postgres.aggregates.general import StringAgg
from django.db.models import Count

# Create your views here.

def vuln(request):
    query = request.GET.get('q')
    qs = Collection.objects.annotate(**{query:Count("name")})
    return HttpResponse(qs)

```

`payload` 如下

```php
http://127.0.0.1:8000/vuln/?q=aaaaa%22
```

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-000238186b3b0753d14ff7ad3395eb8315827b5b.png)

0x03 CVE-2022-28347
===================

漏洞描述
----

`Django` 在2022年发布的安全更新，修复了在 `QuerySet` 的 `explain()`函数中存在的 `SQL` 注入漏洞。

漏洞影响
----

- Django 2.2.x &lt; 2.2.28
- Django 3.2.x &lt; 3.2.13
- Django 4.0.x &lt; 4.0.4

需要使用了 `explain` 方法，并且参数可控

漏洞分析
----

我们可以直接来到 `github` 修复记录

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-cddb9e748873897fe5b9c917bbd2b3ac33226e06.png)

这里首先做的就是对 `options` 的内容进行过滤，如果包含敏感的字符，那么就报错，仅仅这些还没够，还做了如下更改

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-fdad3b4482a4a85682c265ded0557d02bed993a8.png)

这里做了一个白名单，只有在这个白名单中的字符串才可以被使用，不会直接将所有的都拼接进去

有了修复的记录，我们就很容易定位到出现问题的地方，这里 `django\db\models\sql\compiler.py` 是将代码变成 `sql` 语句，在这里有一句关于 `explain` 的处理

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e9d6e74e6f8bf9a7d21ce9e9a8289b666d0b1a05.png)

`result` 是一个数组，里面的字符串最后都会拼接到一起，这里调用 `explain_query_prefix` 进行处理 `self.query.explain_options` 的内容，我们这里使用 `postgres` 数据库，并且 `postgres` 对这个函数存在重写，因此这里也直接看该数据库相关的处理

`django\db\backends\postgresql\operations.py`

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4935dee16c6abb7498b8763ba9fe202e792873c8.png)

经过父类的处理后，在下面，会将`options` 中的每一个取出来，键直接为键，值存在就为 `true` ，因此值无法被更改，但是键会直接写入，最后拼接到 `prefix` 上去，因此这里的键存在注入。

漏洞复现
----

复现环境参考之前的 `CVE-2022-28346` ，只需要更改 `views.py`

```php
from django.shortcuts import render, HttpResponse
from .models import Collection
from django.contrib.postgres.aggregates.general import StringAgg
from django.db.models import Count

import json
# Create your views here.

def vuln(request):
    query = request.GET.get('q')
    query = json.loads(query)
    qs = Collection.objects.filter(name="tom").explain(**query)
    return HttpResponse(qs)

```

`payload` 如下

```php
http://127.0.0.1:8000/vuln/?q={%22ANALYZE%20true)%22:%22aaa%22}
```

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c8ef87f8d507a4fb80e7a96af01671739da138fb.png)

0x04 CVE-2022-34265
===================

漏洞描述
----

`Django` 在2022年发布的安全更新，修复了在 `Trunc()` 和 `Extract()` 函数中存在的 `SQL` 注入漏洞。

漏洞影响
----

- Django 3.2.x &lt; 3.2.14
- Django 4.0.x &lt; 4.0.6

需要使用了 `Trunc()` 或 `Extract()` 方法，并且参数可控

漏洞分析
----

我们可以直接来到 `github` 修复记录

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c57b9a193b3f27b3ee2a20f7abf74b13dd1fdc7b.png)

在这里是直接给 `Extract` 类或者 `Trunc` 类的 `as_sql` 方法添加了一层正则过滤。

这里我们以 `Extract` 为例，可以多关注被过滤的那个参数，也就是 `self.lookup_name`

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5a8908dd86be8c073fa5ebe1bea567b2a4def94f.png)

这里我们可以进入多个分支，但之后得处理实际上都差不多，我们先进入 `datetime_extract_sql`

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-37d7c58f060c44201b9f0d15082aa74ff4f5726b.png)

这里还是进入了和上面一样的 `date_extract_sql` 函数，而且没有经历其他的处理

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-30867840118a06bd472ae1774357e035979a0a74.png)

看到 `lookup_type` ，就是我们之前传入的被过滤的参数，最后在 `else` 直接拼接了，直接造成 `sql` 注入。

`trunc` 也是一样，不过进入的是 `datetime_trunc_sql` 或者 `time_trunc_sql` 等函数

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-392dc59d0242e6e5885b05bc7097928cfbcf8098.png)

漏洞复现
----

漏洞复现可以参照修复记录中的 `test` ，这里直接使用 `vulhub` 的环境，可以直接在下面获取

`payload`

```php
http://127.0.0.1:8000/?date=aaa%27
```

![](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-dde1e68c97006b5bbfe56a3df0b1312c3ee18773.png)

0x05 链接
=======

环境与 `poc` 都可以在如下链接获取

<https://github.com/N0puple/vulPOC>

参考链接
----

<https://github.com/vulhub/vulhub>