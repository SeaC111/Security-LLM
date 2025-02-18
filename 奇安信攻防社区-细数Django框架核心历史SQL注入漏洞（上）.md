本文仅用于技术讨论与研究，文中的实现方法切勿应用在任何违法场景。如因涉嫌违法造成的一切不良影响，本文作者概不负责。

0x00 前言
=======

最近总结了一下 `Django` 框架曾经出现的 `SQL` 注入漏洞，总共有七个 `CVE` ，分别都简单分析复现并写了文章，总体来说会觉得比较有意思，在这里分享一下。

0x01 目录
=======

本篇文章分享四个 `CVE` ，剩余三个 `CVE` 将在下篇文章展现。

- CVE-2019-14234
- CVE-2020-7471
- CVE-2020-9402
- CVE-2021-35042

0x02 CVE-2019-14234
===================

漏洞描述
----

`Django` 在2019年发布的一个安全更新，修复了在 `JSONField`、`HStoreField` 两个模型字段中存在的SQL注入漏洞。

漏洞影响
----

- Django 2.2.x &lt; 2.2.4
- Django 2.1.x &lt; 2.1.11
- Django 1.11.x &lt; 1.11.23

该漏洞需要开发者使用了 `JSONField` 或者 `HStoreField` ，并且 `QuerySet` 中的键名可控，`Django` 自带的 `Django-admin` 中就存在这样的写法，可以利用其进行攻击。

漏洞分析
----

当我们进行查询时，会使用到 `QuerySet` ，一般形式为

```php
Collection.objects.filter(blog__author__extra='tom').all()
```

`filter` 中包含三个部分，由 `__` 分割，第一部分被称为 `transform` ，比如此处，就是查找 `blog` 表中的 `author` 字段，一般这里就是通过外键表现两个表之间的关系，但也存在特殊情况，比如存在 `JSONField` 类型的字段时，那么就是从 `JSON` 字段中查找；第二部分是字段，表的字段或者 `JSON` 的字段；第三部分被称为 `lookup` ，表示为后面值之间的对比关系，可不写，默认为 `extra`。

此处我们选择 `JSONField` 进行分析，当 `blog` 字段为 `JSONField` 类型时，

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-783e6509eefbe3289b27a25aeb014cf678ad3ed6.png)

`JSONField` 继承自 `Field` ，`Field` 又是继承 `RegisterLookupMixin` ，已经存在一个 `get_transform` 方法，此处由于获取方式不同，因此重写该方法，之后是返回了一个 `KeyTransformFactory(name)` ，接下来看看这里的代码

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-20ebb9b17d987942314bb78be523b18616ae40e5.png)

直接被调用时，又会触发 `KeyTransform(self.key_name, *args, **kwargs)`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4b85aaa14347017c817f410acf1ed87c739d382e.png)

在这里，最后会被执行 `as_sql` 方法，目的是生成 `sql` 语句，但是这里的 `self.key_name` 没有经过任何过滤就被拼接并直接返回，因此造成了注入。

漏洞复现
----

复现直接借助了 `vulhub` 的环境，直接启动，环境代码可以直接在最下面的参考链接中找到

如下所示，`Collections` 就是在 `model` 中使用了 `JSONField`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-708bd8344b05e828af12e77a01b23b068447003c.png)

代码和细节如下

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c2e69a72fd9b352b8c14d8a9e00c7f4e653b792e.png)

此处的 `detail` 使用了 `JSONField` ，访问链接即可触发漏洞

```php
http://your-ip:8000/admin/vuln/collection/?detail__a%27b=123
```

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-54c0ced4429c62ae1e35a2f97d3f5f694136519b.png)

0x03 CVE-2020-7471
==================

漏洞描述
----

`Django` 在2020年发布的一个安全更新，修复了在 `StringAgg` 中存在的SQL注入漏洞。

漏洞影响
----

- Django 2.2.x &lt; 2.2.10
- Django 3.0.x &lt; 3.0.3
- Django 1.11.x &lt; 1.11.28

该漏洞需要开发者使用了 `StringAgg` ，并且 `delimiter` 参数可控，则可以利用其进行攻击。

漏洞分析
----

先来看到 `github` 上的代码比对

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a2811d200b58a606ca1f959f0df9ef47aafa93c9.png)

这里说明两点问题，第一， `delimter` 参数没有经过过滤就传入，第二，`delimter` 会直接进行字符串拼接，因此也是导致了存在 `SQL` 注入漏洞的原因。

接下来我们要做的就是找到使用该漏洞类的地方，关于 `StringAgg` 的使用可以看官方文档 `https://docs.djangoproject.com/zh-hans/4.1/ref/contrib/postgres/aggregates/`

很容易就可以得到一个可以利用的场景

```php
Collection.objects.annotate(tempname=StringAgg('name', delimiter=query)).values('name')
```

漏洞复现
----

`vulhub` 中没有找到相应的环境，找一个类似的环境改改，注意也需要使用 `postgres` 数据库

`views.py`

```php
from django.shortcuts import render, HttpResponse
from .models import Collection
from django.contrib.postgres.aggregates.general import StringAgg

# Create your views here.

def vuln(request):
    query = request.GET.get('q', default=0.05)
    qs = Collection.objects.annotate(tempname=StringAgg('name', delimiter=query))
    print(qs.query)
    return HttpResponse(qs)

```

`models.py`

```php
from django.db import models
from django.contrib.postgres.fields import JSONField

class Collection(models.Model):
    name = models.CharField(max_length=128)
    detail = models.CharField(max_length=128)

    def __str__(self):
        return self.name

```

`urls.py`

```php
from django.contrib import admin
from django.urls import path
from vuln import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('vuln/', views.vuln),
]

```

最后可以得到如下 `poc`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-50848517d89393f00438038c0d849f4e6f7ac88b.png)

0x04 CVE-2020-9402
==================

漏洞描述
----

`Django` 在2020年发布的安全更新，修复了在 `GIS` 查询功能中存在的 `SQL` 注入漏洞。

漏洞影响
----

- Django 2.2.x &lt; 2.2.11
- Django 1.11.x &lt; 1.11.29
- Django 3.0.x &lt; 3.0.4

需要使用了 `GIS` 聚合查询，用户使用 `oracle` 的数据库且存在可控 `tolerance`

漏洞分析
----

首先看 `github` 的分析 `https://github.com/django/django/commit/fe886a3b58a93cfbe8864b485f93cb6d426cd1f2`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ae883b51fa084d233b6dfb7bdf66d4ed1a4233fb.png)

这里修补了两处漏洞，都是同一个参数 `tolerance` 引起的，看到这里会觉得还比较简单，直接从 `self.extra` 中获取到参数，直接进行拼接，得到最后的 `sql` 代码，`as_oracle` 方法，就是得到的 `oracle` 的 `sql` 代码，也就是这个漏洞应该只存在于使用 `oracle` 数据库时

虽然知道这里存在漏洞，我们更重要的是去获取什么时候会触发这两个漏洞，所以要去看代码，可以直接搜索 `tolerance`

### 第一处漏洞

位于 `django\contrib\gis\db\models\aggregates.py`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9fec48f68a8189f483e58383c5f4abc2e7db0404.png)

此类继承于 `django.db.models.aggregates.Aggregate` ，然后下面这个 `Union` 类又继承 `GeoAggregate`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7bec580ef91ff2ff4fdfb7a4de6df042c6ea589c.png)

因此可以通过使用 `GIS` 中的 `Union` 类来触发第一个漏洞

### 第二处漏洞

位于 `django\contrib\gis\db\models\functions.py`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9906b02d74911217bb26c95747a8d3234b899f96.png)

这里逻辑也是一样，没有任何过滤，接下来就是去找可以直接调用这里的位置，也就是找继承的位置，可以找到下面这个 `Distance`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4f7d2f14a3bf250fe48b81b07bd986e61468397c.png)

至于接下来该如何去直接使用这两个类，可以查看官方文档，这里我直接看的 `vulhub` 中的

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8257d188a670418971b81f0a2a9f5ae3f8cc3d97.png)

漏洞复现
----

复现直接借助了 `vulhub` 的环境，直接启动，环境代码可以直接在最下面的参考链接中找到

第一处 `payload`

```php
http://127.0.0.1:8000/vuln/q=?20) = 1 OR (select utl_inaddr.get_host_name((SELECT version FROM v$instance)) from dual) is null OR (1-1
```

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a2d890de7366859e71f79639df9d99e0a275913e.png)

第二处 `payload`

```php
http://127.0.0.1:8000/vuln2/q=?0.05))) FROM "VULN_COLLECTION2" where (select utl_inaddr.get_host_name((SELECT user FROM DUAL)) from dual) is not null --
```

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f2e47695b21c6163c7fcbc134bf202948a826a6d.png)

0x05 CVE-2021-35042
===================

漏洞描述
----

`Django` 在2021年发布的安全更新，修复了在 `order_by` 中存在的 `SQL` 注入漏洞。

漏洞影响
----

- Django 3.1.x &lt; 3.1.13
- Django 3.2.x &lt; 3.2.5

需要使用了 `order_by`

漏洞分析
----

出现问题的点是在 `order_by` ，先搜索这个方法

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-577bfe7a1117c167476c32fb90dcb940f1199306.png)

首先 `clean_ordering` ，也就是将 `ordering` 置空

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-564a2e31b03aa5209ad2335ef8ce7fe2fda20aa2.png)

然后进行 `add_ordering`

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-344f2ff1af8bd24cc3e2dfd8d9585947407db748.png)

想要将传进来的字段添加到 `order_by` ，需要经过一些验证

将每一部分取出来进行比较，是字符串时进行比较，包含点号时，直接 `continue` ，跳过了后面的 `names_to_path` 验证，因此可以通过添加点号的形式绕过。

处理带点号的代码位于文件 `django/db/models/sql/compiler.py`的 `get_order_by`函数中，核心代码如下

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-57a5819067b959ed26482ba49de5de9c1523926b.png)

在这里对 `table` 进行了过滤，但是并没有对 `col` 进行过滤，因此造成了注入。

漏洞复现
----

复现直接借助了 `vulhub` 的环境，直接启动，环境代码可以直接在最下面的参考链接中找到

简单来个报错的 `payload`

```php
http://127.0.0.1:8000/vuln/?order=aaa.tab'
```

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d632b37ce19cf70944921fb22dd6ec1023d47775.png)

0x06 链接
=======

环境与 `poc` 都可以在如下链接获取

<https://github.com/N0puple/vulPOC>

参考链接
----

<https://github.com/vulhub/vulhub>