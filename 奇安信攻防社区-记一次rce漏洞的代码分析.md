前几日在浏览github项目时，发现之前审计过的一个cms更新了，从日志中看到修复了一个安全漏洞，并且源码是开源的，所以根据版本对比找到修补的地方，进而发现一个命令执行的漏洞

0x01 漏洞发现
=========

前几日在浏览github项目时，发现之前审计过的一个cms更新了，从日志中看到修复了一个安全漏洞，由于源码是开源的，所以可以根据版本对比找到修补的地方，进而发现其修复的地方。

![image-20240422173133556](https://shs3.b.qianxin.com/butian_public/f892671df16cf216de7d68a1f939560ee21fe773a6315.jpg)

然后查看修改记录，最后锁定这样一处可疑的地方，因为只有这里对参数进行了判断。修复方式时通过对post传入的参数进行了判断是否为空且是否为字符串

![image-20240422174219419](https://shs3.b.qianxin.com/butian_public/f9937073fbb5a034d5a7d3473f0361d205532a218cebc.jpg)

然后我们下载未修复的版本，使用phpstrom定位到代码进行审计。

0x02 漏洞分析
=========

了解了该cms的路由，接下来查看被修复的这个地方，通过POST传参`out_trade_no`之后传递给了下面的`where`语句

关键语句：

```php
$out_trade_no = $_POST['out_trade_no'];
$order = D('order')->field('id,order_sn,status,userid,username,paytype,money,quantity,`type`,`desc`')->where(array('order_sn' => $out_trade_no))->find();
```

通过这个代码可以分析出是执行了数据库查询的语句，但是这里也不可能发生sql注入，应为where语句中的参数采用了数组的传递方式，可以有效的避免sql注入漏洞，因为通过数组传递的参数会经过`addslashes`和`htmlspecialchars`的过滤。

![image-20240423165516548](https://shs3.b.qianxin.com/butian_public/f311008c3872bf9323de76878e8842567f34e1505a57e.jpg)

所以主要查看`where`语句中是对`out_trade_no`是如何处理的

这里对传入的`$arr`有两种处理方法，首先判断`$arr`是否为数组，我们先将判断为数组的部分折叠。如果不是数组，则直接拼接到`$this->key['where']['str']`中返回，这里如果没有对参数做相关过滤会造成sql注入。但是这里传入的是个数组，所以暂时不关注这里

![image-20240426145539397](https://shs3.b.qianxin.com/butian_public/f731125bff34af7522a27e2dcbdef5f73bed65a42d7ac.jpg)

接着我们主要查看where方法时如何处理数组的。

![image-20240426145921171](https://shs3.b.qianxin.com/butian_public/f748627b0658e3b490c2655b43f1449f65a429866f67c.jpg)

先看前半部分，`func_get_args()` 是 PHP 中的一个函数，用于获取传递给函数的所有参数。首先会遍历该数组，并且判断对每个值中的键值对进行遍历，其中 `$kk` 是该数组的键，`$vv` 是该数组的值。 当`$vv`不是个数组，会根据`$vv`的值构建SQL语句匹配条件。

在上面的补丁中也强制判断了参数必须是字符串，所以漏洞应该出现在传入的参数时数组的情况下。

所以主要来看一下当`$vv`为数组的情况下是如何处理的。

![image-20240426163330342](https://shs3.b.qianxin.com/butian_public/f82643532066492158df2361412e5f25c92fe4672eb20.jpg)

这里首先就看到了`$fun($rule)`这个地方，**如果`$fun`和`$rule`就可以执行任意函数和传参**，这里通过一个三元运算符判断的。

这里的`$fun`和`$rule`又是通过`$vv[1]`和`$vv[2]`得来的。至于`$vv[0]`则是通过上面的`$exp_arr`得到对应的运算符和逻辑表达式。

除此之外，由于`$exp`也是从`$vv[0]`得来的，所以在传参是必须有要这个键，从三元表达式可以看出，该值可以为空，也可以是从`$exp_arr`中的任意一个键

了解完漏洞的原理，其次会对该cms的路由进行分析，查看怎样才能触发这个函数。

0x03 路由分析
=========

经过分析该cms有三种获取路由信息的方式：

在初始化过程会在这里解析PATH\_INFO模式，这里会先判断是否存在`$_GET['s']`，如果存在则直接赋值给`PATH_INFO`，

![image-20240513152253625](https://shs3.b.qianxin.com/butian_public/f4151813151caf33f9009d3b99c352fca298fc84ca17a.jpg)

或者对url路径使用`/`为分隔符，并去除结尾的`.html`后缀和`index.php`，然后分别取第一位第二位和第三位作为`$_GET['m']`,`$_GET['c']`,`$_GET['a']`

![image-20240513151815903](https://shs3.b.qianxin.com/butian_public/f44211912fc7821d2be0526a307fa7c26ae3ff766441c.jpg)

然后根据`route_m``route_c``route_a`这几个方法分别通过从url中获取`m` `c` `a`参数作为模块名，控制器名和方法名。

![image-20240426141554790](https://shs3.b.qianxin.com/butian_public/f96441489094bf19475712b0051b24f6e57be41340e8b.jpg)

通过这种方式可以得出

第一种路由信息为`http://127.0.0.1/s=模块名/控制器名/方法名`

第二种路由信息为：`http://127.0.0.1/模块名/控制器名/方法名.html`

第三种路由信息为`http://127.0.0.1/?m=模块名&c=控制器名&a=方法名`。

所对应的文件路径为 ./application/模块名/controller/控制器.php，所对应的方法则是传递过来的方法

0x04 漏洞复现
=========

接下来查看他的路由

![image-20240426171311312](https://shs3.b.qianxin.com/butian_public/f944948b35716533213ea5f7a478403dcd4ccb504a666.jpg)

所以这里构建poc：

```php
POST /?m=pay&c=index&a=pay_callback HTTP/1.1
Host: 127.0.0.1:8081
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Cookie: XDEBUG_SESSION=PHPSTORM
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 61

out_trade_no[0]=eq&out_trade_no[1]=whoami&out_trade_no[2]=system
```

![image-20240426163635220](https://shs3.b.qianxin.com/butian_public/f7269737749365018a9b4024d38ba58545dea44a733b7.jpg)

成功执行命令。

0x05 举一反三
=========

既然知道了出发点是通过`where`语句的，并且从官方的修复方式来看只是对传参的地方做了修复，那会不会存在其他对参数控制不严的地方直接拼接到where语句。首先可以再找找哪里调用`where`语句，并且满足以下条件：参数必须是以数组形式传递的，并且传递的数组的值是可控的。

使用正则`->where\(array\(.*?\)->`进行搜索，然后寻找传递的数组的值是可控的的地方，当然也可以使用正则`->where\(\)->`进行搜索，因为参数是在别的地方复制的数组类型。

![image-20240510143140452](https://shs3.b.qianxin.com/butian_public/f9837982fde8971c1379d51202fe16de08d8d74a257de.jpg)

这里找到这样一处，在后台添加管理员的地方，这里的`$_POST["adminname"]`是直接传参的

![image-20240510151118617](https://shs3.b.qianxin.com/butian_public/f9600086b0f5c8a4defdb09000a66c6a03d0de6fb6815.jpg)

登陆后台后点击管理员管理，在点击添加管理员，

![image-20240510150745459](https://shs3.b.qianxin.com/butian_public/f4436974949f667a206003f2c442e94376a87547c2ea4.jpg)

随便输入用户名和密码，然后抓包

![image-20240510150852382](https://shs3.b.qianxin.com/butian_public/f3265988e0e4b6732bbc37da5a41b502b905ee5295320.jpg)

然后修改**roleid**为下面payload发包

![image-20240510151048511](https://shs3.b.qianxin.com/butian_public/f578053142df9243a12dd017e28570f221dd09e6ea1b2.jpg)