一、写在前面
------

随着HW、攻防对抗的强度越来越高，各大厂商对于webshell的检测技术愈发成熟，对于攻击方来说，传统的文件落地webshell的生存空间越来越小，无文件攻击已经逐步成为新的研究趋势。

这里介绍一种通过模拟fastcgi协议直接控制php-fpm执行任意php文件的方法，全程无文件落地。

php web 项目常见的部署模式为 nginx反向代理 + php-fpm。

一般来说外部访问的流程如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-8360cefd3394861f7959d891a2dc045029a047d2.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-8360cefd3394861f7959d891a2dc045029a047d2.png)

fastcgi协议是服务器中间件和后端进行数据交换的协议。

php-fpm可以理解为fastcgi协议解析器。

Nginx等服务器中间件将用户请求按照fastcgi的规则打包好通过TCP传给php-fpm，php-fpm按照fastcgi协议将TCP流解析成真正的数据。

换句话说，当php-fpm可访问时（未授权访问或者ssrf），通过构造Fastcgi协议，向php-fpm发起请求可以执行"任意文件"。

二、fastcgi解析过程
-------------

举个栗子： [http://127.0.0.1/index.php?a=1&amp;b=2](http://127.0.0.1/index.php?a=1&b=2)

如果web目录是/var/www/html，那么Nginx会根据该请求生成如下key-value对：

```php
{
    'GATEWAY_INTERFACE': 'FastCGI/1.0',
    'REQUEST_METHOD': 'GET',
    'SCRIPT_FILENAME': '/var/www/html/index.php',
    'SCRIPT_NAME': '/index.php',
    'QUERY_STRING': '?a=1&b=2',
    'REQUEST_URI': '/index.php?a=1&b=2',
    'DOCUMENT_ROOT': '/var/www/html',
    'SERVER_SOFTWARE': 'php/fcgiclient',
    'REMOTE_ADDR': '127.0.0.1',
    'REMOTE_PORT': '12345',
    'SERVER_ADDR': '127.0.0.1',
    'SERVER_PORT': '80',
    'SERVER_NAME': "localhost",
    'SERVER_PROTOCOL': 'HTTP/1.1'
}
```

`SCRIPT_FILENAME`的值指向的PHP文件将会被执行，也就是`/var/www/html/index.php`。

三、攻击原理
------

因此，当php-fpm可访问时（未授权访问或者ssrf），我们通过构造fastcgi协议，直接发送给php-fpm，将会执行"任意文件"。

注意这里有几个前提：

1. **这个任意文件必须是目标服务器上的文件，并不是我们能控制的文件。**
2. 需要借助`auto_prepend_file`和`auto_append_file`。`auto_prepend_file`是告诉PHP，在执行目标文件之前，先包含`auto_prepend_file`中指定的文件；`auto_append_file`是告诉PHP，在执行完成目标文件后，包含`auto_append_file`指向的文件。
3. 如果想实现webshell执行任意命令的话，需要设置`auto_prepend_file`为`php://input`。等同于在执行任何php文件前都要包含一遍POST的内容。所以，只需要把待执行的代码放在Body中就能被执行了。

协议包Demo:

```php
{
        'GATEWAY_INTERFACE': 'FastCGI/1.0',
        'REQUEST_METHOD': 'POST',
        'SCRIPT_FILENAME': '/',
        'SCRIPT_NAME': uri,
        'QUERY_STRING': '',
        'REQUEST_URI': uri,
        'DOCUMENT_ROOT': '/',
        'SERVER_SOFTWARE': 'php/fcgiclient',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '9985',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': "localhost",
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'CONTENT_TYPE': 'application/text',
        'CONTENT_LENGTH': "%d" % len(content),
        'PHP_VALUE': 'auto_prepend_file = php://input',
        'PHP_ADMIN_VALUE': 'allow_url_include = On'
    }
```

因此当`auto_prepend_file = php://input`且`allow_url_include = On`时，可以通过构造fastcgi POST请求，content为我们要执行的PHP代码，如`'<?php phpinfo(); exit; ?>'`，即可执行任意命令。

这又涉及到PHP-FPM的两个环境变量，`PHP_VALUE`和`PHP_ADMIN_VALUE`。  
这两个环境变量就是用来设置PHP配置项的，`PHP_VALUE`可以设置模式为`PHP_INI_USER`和`PHP_INI_ALL`的选项，`PHP_ADMIN_VALUE`可以设置所有选项。经过测试，`disable_functions`除外，这个选项是PHP加载的时候就确定了，在范围内的函数直接不会被加载到PHP上下文中，貌似无法直接修改。

四、攻击Demo
--------

可参考P师傅构建fastcgi client的代码，膜膜膜。

<https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75>

五、检测思路
------

1. 检查`PHP_VALUE`和`PHP_ADMIN_VALUE`中以上敏感字段是否被修改过。
2. 由于php-fpm可能存在多个worker，因此需要循环检测多次，以便覆盖到所有worker。