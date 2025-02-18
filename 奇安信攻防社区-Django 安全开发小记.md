0x0前言
=====

这是一篇关于 Django 安全小记的文章，分享我在完成毕设作品 **[FlawPlatform 漏洞靶场](https://gitee.com/J0hNs0N/FlawPlatform)** （Django + Vue 前后端分离项目）过程中关于安全开发的一些小经验。如果有误，欢迎各位师傅指正。

0x1SECRET\_KEY 密钥
=================

Django 在 `settings.py` 中的密钥非常重要，包括注释也在提示：**对生产中使用的密钥保密！**，`SECRET_KEY` 本质是是一个加密盐，密钥用于（参考 [Django 4.0 SECRET\_KEY 官方文档](https://docs.djangoproject.com/en/4.0/ref/settings/#std:setting-SECRET_KEY)）：

- 所有**[会话](https://docs.djangoproject.com/en/4.0/topics/http/sessions/)**，如果您使用任何其他会话后端`django.contrib.sessions.backends.cache`，或者使用默认设置 **[`get_session_auth_hash()`](https://docs.djangoproject.com/en/4.0/topics/auth/customizing/#django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash)**。
- 如果您使用 或 的所有**[消息](https://docs.djangoproject.com/en/4.0/ref/contrib/messages/)**。**[`CookieStorage`](https://docs.djangoproject.com/en/4.0/ref/contrib/messages/#django.contrib.messages.storage.cookie.CookieStorage)[`FallbackStorage`](https://docs.djangoproject.com/en/4.0/ref/contrib/messages/#django.contrib.messages.storage.fallback.FallbackStorage)**
- 所有**[`PasswordResetView`](https://docs.djangoproject.com/en/4.0/topics/auth/default/#django.contrib.auth.views.PasswordResetView)**代币。
- **[加密签名](https://docs.djangoproject.com/en/4.0/topics/signing/)**的任何使用，除非提供了不同的密钥。

这里可以使用 **`utils.get_random_secret_key()`** 在每次启动编译后，重新自动生成随机密钥。但是在开发过程中每次修改代码后会重新编译，所以推荐在生产环境中使用。

```python
from django.core.management import utils

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = utils.get_random_secret_key()
```

0x2前后端分离身份验证
============

2.1 使用 JWT 的安全隐患
----------------

我在刚接触 Django 前后端分离项目时，提供身份认证最多的文章就是使用 JWT 提供是身份认证。在 JWT 密钥不泄露的情况下，使用 JWT 提供身份认证没有问题。一旦密钥泄露，就可以通过密钥来伪造用户 Token，相当于没有用户身份认证了。

2.2 Django 身份认证
---------------

个人认为既然 Django 提供了身份认证，那为什么不去使用 Django 的身份认证呢？但 Django 的身份认证体系是用 COOKIE 保证前后端身份的，前后端分离，跨域之后就不支持 COOKIE 了。下面简单的介绍一下主要流程

通过Django 提供的 login 方法进行登录，通过 SESSION 存储身份信息

*django.contrib.auth.login*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2973765b4431a375fec356946899b62a7c97a0b5.png)

在 **`SessionMiddleware`** 中间件 **`process_response`** 中通过 COOKIE 将 SESSION ID 响应请求，让浏览器自动存储。

*django.contrib.sessions.middleware.SessionMiddleware.process\_response*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4ec46b866f45c5bf01063d505658921b330a82eb.png)

在 **`SessionMiddleware`** 中间件 **`process_request`** 中，在每次请求前从 COOKIE 中获取 SESSION ID 并设置

*django.contrib.sessions.middleware.SessionMiddleware.process\_request*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c9231b11dadc61cd6baad1252f4a48682114c01f.png)

2.3 修改身份认证体系兼容前后端分离身份认证
-----------------------

只要认准两个步骤就好了，首先是响应 **`SessionMiddleware.process_response`** 通过在请求通知设置 COOKIE 将存储了用户信息的 SESSION ID 返回给前端，每次请求前再通过 **`SessionMiddleware.process_request`** 从 COOKIE 中获取 SESSION 并设置到 reuqest 中。

### 2.3.1 新流程

将这两个步骤重写，登录成功后，从响应数据中返回 SESSION ID，前端存储 SESSION ID, 每次请求时在请求头中带上，通过 **`process_request`** 方法时，从请求头中获取 SESSION ID 并设置即可。

### 2.3.2 登录

通过 **`AuthenticationForm`** 的验证后，调用 **`login`** 进行登录，并将 SESSION ID 返回给前端

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-12a6a7fcb5eb61cd91eaa04f2fc4fb49d615dc87.png)

### 2.3.3 重写中间件身份验证

继承并重写 **`SessionMiddleware`** 如果 COOKIE 是空的就从头部中请求**（这是为了兼容Django 自带的 admin 后台）**，需要注意的是，我在请求头中设置的 `X-Token: xxxx` Django 处理后会变成 **`HTTP_X_TOKEN`**

```python
from django.contrib.sessions.middleware import SessionMiddleware

class RestFulSessionMiddleware(SessionMiddleware):
    """
    前后端分离重写 Django 默认身份验证
    """

    def process_request(self, request):
        # 如果 COOKIE 是空的就从头部中请求
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        if session_key is None:
            # 如请求头中传入的 KEY 为：X-Token 实际上会被转成 HTTP_X_TOKEN
            session_key = request.META.get("HTTP_X_TOKEN")
            request.session = self.SessionStore(session_key)
```

### 2.3.4 前后端分离不做 CSRF 认证

前后端分离后其实Django的 CSRF 认证，也没什么用了

```python
class RestFulCsrfViewMiddleware(MiddlewareMixin):
    """
    API 不设 CSRF 校验
    """

    def process_request(self, request):
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        if session_key is None:
            setattr(request, '_dont_enforce_csrf_checks', True)
```

### 2.3.5 跨域头

需要注意的是 **`response['Access-Control-Allow-Headers']`** 允许的请求头，这里我加多了一个 `x-token` 不然，前端无法通过请求头 `x-token` 进行请求。

```python
class CorsHeadersMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        """
        处理跨域响应头
        """

        response['Access-Control-Allow-Methods'] = 'POST,GET,OPTIONS'
        response['Access-Control-Max-Age'] = 'POST,GET,OPTIONS'
        response['Access-Control-Allow-Headers'] = 'content-type,x-token'
        response['Access-Control-Allow-Origin'] = '*'
        return response
```

### 2.3.6 配置中间件

将新建的中间件设置到 **`MIDDLEWARE`** 中

*settings.py*

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    'common.middleware.CorsHeadersMiddleware',                  # 新增
    'common.middleware.RestFulSessionMiddleware',               # 新增
    'common.middleware.RestFulCsrfViewMiddleware'               # 新增
]
```

0x3Admin Action 后台动作安全
======================

这个我之前就有出过文章，这里简单提一下，可以参考 [这篇文章](https://blog.csdn.net/qq_41954715/article/details/118910721)。

3.1 鉴权的转变
---------

如下图是我 2020年1月19日 在 B 站发的自定义动作的代码分析。其中 ② 是检测权限。

*django.contrib.admin.actions.delete\_selected*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3c76b8a454261ca409875a069eb4087a8a1ac9ff.png)

但在新版中，取而代之的是 **`decorator`** (装饰器)：**`action()`** 通过参数 **`permissions`** 设置该动作所需的权限。

*django.contrib.admin.actions.delete\_selected*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a26092e2605b965e63fb7e10c5c7603d3032c838.png)

3.2 文章投毒
--------

而百度后大多数文章，根本就没有做权限的限制。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3fc737dbab914406c9b890097112e323f2f865b0.png)

0x4Admin Model 复杂的数据验证
======================

当想使用 Django 自带的后台时，又有复杂的验证要求，下面就解决这个问题。

4.1 重写 save 方法
--------------

其实我第一时间想到的是重写 Model 的 save 方法，重写 save 方法确实可以做到自定义数据的验证，即使他可能不怎么样优雅。

### 4.1.1 抛错问题

但是存在一个问题：如何提示错误信息呢？save 方法并不会传入 request（请求） 或 response（响应） 对象, 直接抛出一个 Exception 异常吗？

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7380bb1730ab73b40addf92227c55545513a8ae1.png)

好像看起来也可以，错误信息也看得见。但这只是在 **`DEBUF=True`** 的情况下，生成环境不可能开着 debug。如果关了 debug，就看不到报错信息了。

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-002c0b6220064e7a707e50117d7823556a2974da.png)

4.2 重写 clean 方法
---------------

通过翻阅 Model 的源码，可以得知 **`Model.full_clean`** 方法中，会调用 **`Model.clean`** 方法。并对该方法进行了异常处理处理。和 Form 一样，处理的是 **`django.core.exceptions.ValidationError`** 异常

*django.db.models.base.Model.full\_clean*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-80120c87c64d676b0a8aa87512b7eb07509d43d3.png)

**`Model.clean`** 默认是空方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8962c723e4e0beec6784bb4e1da8872f70c6b7fd.png)

### 4.2.1 总觉得差点什么

继承重写后进行测试

```python
error_messages = {
        'test': '测试验证'
    }

def clean(self):
    raise ValidationError(self.error_messages['test'], code='test')
```

抛错也被处理了，但总确定缺点什么！

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6b74bc3ff32d216e2c8014a3b9a1d80915dd1660.png)

4.3 重写 models 数据验证流程
--------------------

前面通过重写 **`Model.clean`** 方法，达到了后台自定义数据验证的要求。但总觉得缺点什么，看下图，缺的是细分到每个字段的提示效果。并且所有自定义验证都写在 **`Model.clean`** 方法中，不方便维护

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0ec98aefc4064912cc45e0e7807b1bfa9f3b1fa3.png)

### 4.3.1 了解 models 字段验证流程

在 **`Model.full_clean`** 中调用了 **`Model.clean_fields`** 方法，对字段进行数据验证

*django.db.models.base.Model.full\_clean*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2f4b2a712f14f8ee382c07a98ffdd61b8d41180d.png)

1291 行获取原始数据，1272 - 1273 行 判断如果数据是空值，并且 **Field** 设置了 **`blank=True`** 就跳过验证，开发人员确保该字段提供有效的值。1274 - 1278 行调用 **`f.clean()`** 方法（每个字段的 **`clean`** 方法），特别注意的是异常处理中的 **`errors[f.name] = e.error_list`** 就可以细分到每个字段的错误提示。1279 - 1280 行抛出异常

*django.db.models.base.Model.clean\_fields*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-dcf550da3cb57c211f27f19dbeca50f0334c986f.png)

进入 **`Field.clean`** 方法，这个 Field 是指 Model 中定义的字段，如：CharField、TextField、IntegerField 等

*django.db.models.fields.Field.clean*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c77c7f3c6b66efc204895f79e620de756e83a735.png)

进入 **`Field.to_python`** 方法，不重写的情况下，不会做任何处理。

*django.db.models.fields.Field.to\_python*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5020d30650c19a0930db1953c5f37c357efe479e.png)

进入 **`Field.validate`** 方法，638-640 行 若无修改直接跳过验证。642 - 656 行 choices 的验证。658 - 589 行如果没有传值（None）并且没有设置 **`null=True`** 抛出错误：”值不能为 null“。 661 - 662 行如果值为空值并且没有设置 **`blank=True`** 抛出错误：”该字段为必填项“。

*django.db.models.fields.Field.validate*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e23ed927c9cec4a6c7a6fed41547e3385338918c.png)

进入 **`Field.run_validators`** 方法，该方法循环执行调用 `validators` 中的验证器进行验证，那么验证器在哪里设置呢？

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0bb551ad6aa71fd4ed83010925c85b4eae327ab5.png)

如 **`EmailField`** 中设置了 **`default_validators = [validators.validate_email]`**

*django.db.models.fields.EmailField*

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b995e7b84dd59f802423f9c11f5125b7018755e4.png)

### 4.3.2 设计与实现

我们需要的效果：细分到每个字段的验证分离，且提示在字段上。但对每一个字段重写验证，是不可能的，工作量太大了。所以我选择从 **`Model.clean_fields`** 下手，重写 **`Model.clean_fields`** 方法。可以参考我的毕设作品 **[FlawPlatform 漏洞靶场](https://gitee.com/J0hNs0N/FlawPlatform/blob/master/common/models.py)** 中的写法。

```python
class BaseModels(models.Model):
    """
    数据库公共父类
    """

    class Meta:
        abstract = True

        def pre_field_clean(self, field: models.Field, raw_value):
        """
        于函数 clean_fields() 中, pre_clean_[field.name] 与 models.Field.clean 前
        """

        return raw_value

    def post_field_clean(self, field: models.Field, value):
        """
        于函数 clean_fields() 中, models.Field.clean 与 post_clean_[field.name] 后
        """

        return value

    def clean_fields(self, exclude=None):
        """
        重写 clean_fields 方法，为 models 新增自定义字段验证的方法，下列方法由上往下执行

        # 调用字段 Field.clean 调用的函数前调用，这里我特地将其写到了跳过空验证的前面
        pre_field_clean(self, field: models.Field, raw_value) -> (models.Field, Any)

        # 调用字段 Field.clean 调用的函数前调用，这里我特地将其写到了跳过空验证的前面
        pre_clean_[Field.name](self, field: models.Field, raw_value) -> (models.Field, Any)

        # 调用字段 Field.clean 调用的函数后调用
        post_clean_[Field.name](self, field: models.Field, raw_value) -> (models.Field, Any)

        # 调用字段 Field.clean 调用的函数后调用
        post_field_clean(self, field: models.Field, value) -> (models.Field, Any)
        """

        # 排除列表
        if exclude is None:
            exclude = []

        errors = {}
        for f in self._meta.fields:

            # 如果字段再排除列表中跳过字段验证
            if f.name in exclude:
                continue

            # 获取值
            raw_value = getattr(self, f.attname)

            try:
                raw_value = self.pre_field_clean(f, raw_value)

                # 增加类似 forms post_clean_[field.name] 方法
                if hasattr(self, 'pre_clean_%s' % f.name):
                    raw_value = getattr(self, 'pre_clean_%s' % f.name)(f, raw_value)

                # 当 blank=True 时跳过验证空字段验证
                # 开发人员负责确保它们具有有效的值。
                if f.blank and raw_value in f.empty_values and f.name:
                    continue

                # 调用字段的 clean 方法, 调用 default_validators 中的验证其
                value = f.clean(raw_value, self)

                # 增加类似 forms post_clean_[field.name] 方法
                if hasattr(self, 'post_clean_%s' % f.name):
                    value = getattr(self, 'post_clean_%s' % f.name)(f, value)

                value = self.post_field_clean(f, value)

                # 设置值
                setattr(self, f.attname, value)

            except ValidationError as e:
                errors[f.name] = e.error_list

        if errors:
            raise ValidationError(errors)
```

后面的 Model 继承 BaseModels 即可, 可以参考我的毕设作品 **[FlawPlatform 漏洞靶场](https://gitee.com/J0hNs0N/FlawPlatform/blob/master/dockerapi/models.py#L73)** 中的写法。

```python
class TestValidateModel(BaseModels):

    error_messages = {
        'null': '名称不能为空'
    }

    name = models.CharField(max_length=120, null=True, blank=True, verbose_name="名称")

    def pre_clean_name(self, field: models.Field, raw_value):
        """ 
        自定义验证 name 名称
        """

        if raw_value in models.Field.empty_values or raw_value is None:
            raise ValidationError(self.error_messages['name'], code='name')

        return raw_value
```