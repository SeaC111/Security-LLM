0x00 Django 中的 XFF 问题
=====================

最近在用 Django 开发限制访问只能通过 127.0.0.1 或者内网地址访问后台的功能，关注到 Django 中存在的 XFF 问题。

文中 \[1. 后台访问地址/域名功能\] 主要说的是从开发到发现问题的过程。

如果想直接看 Django 的 XXF 问题可以直接跳转至文中的 \[2. Django Bypass 访问地址限制\]

0x01后台访问地址/域名功能
===============

最近在开发一个 Django 限制访问后台的功能，只有通过IP **`127.0.0.1`** (可设置，多个)才能访问后台，功能已经写完了。代码如下，通过正则匹配只要访问 URL 以 **`/admin/`** 开头的就会校验访问的地址，当地址错误时，会抛出 **`DisallowedHost`** 异常，

这个功能代码有问题吗？毫无疑问他有，在哪里？

```python
class AdminHostMiddleware(MiddlewareMixin):
    """
    校验后台访问地址/域名
    """
    def process_request(self, request):
        full_path = request.get_full_path()

        if re.match(r'^/' + settings.ADMIN_URL + '/.*', full_path, flags=0):
            host = request._get_raw_host()
            # 如果 ALLOWED_HOSTS 为空且 DEBUG=True ，啧允许通过本地主机的方法访问。
            admin_allowed_hosts = settings.ADMIN_ALLOWED_HOSTS
            if settings.DEBUG and not admin_allowed_hosts:
                admin_allowed_hosts = ['.localhost', '127.0.0.1', '[::1]']

            domain, port = split_domain_port(host)
            if not (domain and validate_host(domain, admin_allowed_hosts)):
                msg = "Invalid HTTP_HOST header: %r." % host
                if domain:
                    msg += " You may need to add %r to ADMIN_ALLOWED_HOSTS." % domain
                else:
                    msg += " The domain name provided is not valid according to RFC 1034/1035."
                raise DisallowedHost(msg)
```

1.1 环境准备
--------

在 **`settings.py`** 同目录下，创建 **`middlewares.py`** 并新建中间件。

*common.middlewares.AdminHostMiddleware*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6d8954f85ed52ac4290ff8b6e774f22f8ac9b035.png)

注册组件，设置后台URL，允许访问的地址，同时关闭 DEBUG，并设置 **`ALLOWED_HOSTS`** 为 \**`*`\*\* ，允许通过所有可访问地址访问站点。

*common.settings*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-42aad4817b4b344d6c02fda5c22ba14007811261.png)

没有通过 **`127.0.0.1`** 访问后台，响应状态码 400

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8cbc8b3391e18f48c9cfd58f42a4913964865c5e.png)

通过 **`127.0.0.1`** 访问站点，正常可访问。静态文件丢失是因为静态文件路径的配置问题

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-35e09b3ad942773206df6d5cb74d21752cfaa39a.png)

1.2 Bypass 限制
-------------

拦截数据包后，发送到 `Repeater` 重发中，可以看到确实成功限制住了访问

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-01cbd6c2e5f237d6d9823b6bd0e47474b5f720c8.png)

修改请求头中的 Host 为：`127.0.0.1:8000` 成功绕过限制，

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5b645d76dfbd88bab3b9bb5e7b5105283f564d9c.png)

1.3 代码分析
--------

回到 **`middlewares`** 中，肯定是获取 **`host`** 的地方出问题了，跟进 **`request.\_get\_raw\_host()**`

*common.middlewares.AdminHostMiddleware.process\_request*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3e9c0a4c5afa4decb80a8e2131197c206e60dd0c.png)

`host` 既然来自于请求头中的信息

*django.http.request.HttpRequest.\_get\_raw\_host*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1a567e7597754136f26be819dda14d95e96c60a7.png)

第一次判断中的 **`settings.USE_X_FORWARDED_HOST`** 默认为 **`Flase`** 所以默认不会从 `X-Forwarded-For` 中获取

*django.http.request.HttpRequest.\_get\_raw\_host*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-aee1fcb11fd626d4cecdd78e8a5dd70469fb2578.png)

我们进入的是第二次判断 **`'HTTP_HOST' in self.META`**  这是大多情况，请求头中一般情况下默认会带上 **`Host`** 请求头。

*django.http.request.HttpRequest.\_get\_raw\_host*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7a8d9152e2f55d38719e514faa9e28774a518943.png)

0x02 Django Bypass 访问地址限制
=========================

Django 中其实也是通过同样的方法进行限制的

2.1 环境准备
--------

随机准备一个视图

*common.urls*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-bd1d391e9c847ff586f3adc8745e14439b80ab13.png)

修改 **`ALLOWED_HOSTS`** 限制只能通过 **`127.0.0.1`** 进行访问

*common.settings*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7fa3e19d278569c976a2c2ad346b6d8013b33d77.png)

通过 **`127.0.0.1`** 访问正常

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6735f5a269a46db3bddd378cd1ccf851e219deef.png)

通过别的地址访问被拦截

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-84ddb9eec282ef3e838b15c4abaeb12f2d40e4f6.png)

2.2 Bypass ALLOWED\_HOSTS 限制
----------------------------

拦截数据包后，发送到 `Repeater` 重发中，可以看到确实成功限制住了访问

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-744a0fcd4c30044b7246a5ebfbbe31a166e86646.png)

修改请求头中的 Host 为：`127.0.0.1:8000` 成功绕过限制

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7a46a869398ad10a498d98c11b7613ceb5788a82.png)

2.1代码分析
-------

限制访问是在 **`CommonMiddleware`** 中间件中，跟进

*common.settings*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2ff7d051e912cea216f25d9c8b6e9a51ca23d930.png)

在 **`CommonMiddleware.process_request`** 方法中调用了 **`request.get_host()`** 方法

*django.middleware.common.CommonMiddleware.process\_request*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0ce128d90073bcc063be936377d1b342441dabf6.png)

进入到 **`HttpRequest.get_host`** 方法中，看到了熟悉的方法调用 **`self._get_raw_host()`**

*django.http.request.HttpRequest.get\_host*

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b70e732d108d0d75dbba4873198c85176e20fdd6.png)

进入到 **`_get_raw_host()`** 方法就是存在问题的地方了

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d6b04706239bc4307c061f1df9ebd874090cd506.png)

0x03修复建议
========

最简单粗暴直接通过 Nginx 进行限制即可。由于功底很差，这里就不误导师傅们了。