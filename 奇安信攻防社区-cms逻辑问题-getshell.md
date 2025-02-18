前言
==

如果存在exec进行拼接的漏洞，该如何绕过 &lt;mark&gt;一黑俩匹配 &lt;/mark&gt;？  
当前如果是拼接和编码这种手法就不说了，现在在看的师傅您是审计大牛的话，这文章可以忽略不看。

黑名单
---

```php
$_GET[
$_POST[
$_REQUEST[
$_COOKIE[
$_SESSION[
file_put_contents
file_get_contents
fwrite
phpinfo
base64
`
shell_exec
eval
assert
system
exec
passthru
pcntl_exec
popen
proc_open
print_r
print
urldecode
chr
include
request
__FILE__
__DIR__
copy
call_user_
preg_replace
array_map
array_reverse
array_filter
getallheaders
get_headers
decode_string
htmlspecialchars
session_id
strrev
substr
php.info
```

第一个匹配：
------

```PHP
/([\w]+)([\x00-\x1F\x7F\/\*\<\>\%\w\s\\\\]+)?\(/i
```

第二个匹配：
------

这里不能有$符号，这里是重点 ,当然如果你想编码也可以，或者啥的手法都行，不过我在此之前没想到过，可以继续往下看

```PHP
/\{pboot:if\(([^}^\$]+)\)\}([\s\S]*?)\{\/pboot:if\}/
```

正文
==

先看效果

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-62f3dd339f45d80931b37789e4bb30cf0f47b7b0.png)

审计流程
----

通过审计工具半自动筛选出漏洞点。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-462d0cecf1dcf6a3e52f74db4d9bc615df13abfc.png)

跟进该漏洞点文件：apps/home/controller/ParserController.php

最终是通过了`$matches[1][$i]`进入到eval函数中。

### 第一个黑名单

接着往上看，这里有黑名单，如果`$matches[1][$i]`有黑名单就会跳出解析

&lt;mark&gt;这里的\\\\是社区编辑器默认加上防止转义，太多就懒得改了&lt;/mark&gt;

```php

// 过滤特殊字符串

if (preg\_match('/(\\(\[\\w\\s\\.\]+\\))|(\\$\_GET\\\[)|(\\$\_POST\\\[)|(\\$\_REQUEST\\\[)|(\\$\_COOKIE\\\[)|(\\$\_SESSION\\\[)|(file\_put\_contents)|(file\_get\_contents)|(fwrite)|(phpinfo)|(base64)|(\`)|(shell\_exec)|(eval)|(assert)|(system)|(exec)|(passthru)|(pcntl\_exec)|(popen)|(proc\_open)|(print\_r)|(print)|(urldecode)|(chr)|(include)|(request)|(\_\_FILE\_\_)|(\_\_DIR\_\_)|(copy)|(call\_user\_)|(preg\_replace)|(array\_map)|(array\_reverse)|(array\_filter)|(getallheaders)|(get\_headers)|(decode\_string)|(htmlspecialchars)|(session\_id)|(strrev)|(substr)|(php.info)/i', $matches\[1\]\[$i\])) {

$danger = true;

}

// 如果有危险函数，则不解析该IF

if ($danger) {

continue;

}
```

黑名单分别是拦截以下内容：

```php

$\_GET\[

$\_POST\[

$\_REQUEST\[

$\_COOKIE\[

$\_SESSION\[

file\_put\_contents

file\_get\_contents

fwrite

phpinfo

base64

\`

shell\_exec

eval

assert

system

exec

passthru

pcntl\_exec

popen

proc\_open

print\_r

print

urldecode

chr

include

request

\_\_FILE\_\_

\_\_DIR\_\_

copy

call\_user\_

preg\_replace

array\_map

array\_reverse

array\_filter

getallheaders

get\_headers

decode\_string

htmlspecialchars

session\_id

strrev

substr

php.info

```

这可以看出过滤了好多函数，当然既然是黑名单就有绕过的方式，这里可以是加密形式绕过，不过加密后的密文做成payload就逆向解密不了了，因为是由特殊不可见数据流存在就会导致反解密会不到原来的明文。

这里可以用file和fputs函数绕过

### 第一个过滤

继续往上看，看到这个if判断，这里也是将`$matches[1][$i]`进行过滤，保证用户输入的字符串是无危害的，简单来说就是‘括号前面不能有字母、数字字符串’。

```php

// 带有函数的条件语句进行安全校验

if (preg\_match\_all('/(\[\\w\]+)(\[\\x00-\\x1F\\x7F\\/\\\*\\<\\>\\%\\w\\s\\\\\\\\\]+)?\\(/i', $matches\[1\]\[$i\], $matches2)) {

foreach ($matches2\[1\] as $value) {

if (function\_exists(trim($value)) && ! in\_array($value, $white\_fun)) {

$danger = true;

break;

}

}

foreach ($matches2\[2\] as $value) {

if (function\_exists(trim($value)) && ! in\_array($value, $white\_fun)) {

$danger = true;

break;

}

}

}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2334cf44a2e5e76bca1dee08975b31c68c4db129.png)

当然这里也是黑名单，直接`/*--*/`绕过

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-b930644aa54dc85b2d19628ef0613c4620e099d7.png)

### 4.3. 第三个过滤

这个就比较好过了就是指定的标签语法，使用这个`{pboot:if(312313)}(13123){/pboot:if}`

#### 4.3.1. 注意：

这里不能有$符号，这里是重点

```php

$pattern = '/\\{pboot:if\\((\[^}^\\$\]+)\\)\\}(\[\\s\\S\]\*?)\\{\\/pboot:if\\}/';

if (preg\_match\_all($pattern, $content, $matches)) {

}

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-773c68b3fa6a72c4802dd4065efffdfe009036ae.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-b14ae2ab4e140407e3e8478a861471d2475af9a6.png)

### 构建payload

由于这里不能用美元符号”$“，前面第一个过滤说过，可用file函数绕过，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ba31c4516eafd28fe335fe40669d79d955f5c2b1.png)

通过上面file函数获取的美元符号，并且通过fputs进行写文件，当然需要绝对路径才能读取美元符，这里就比较简单了，直接让cms报错就好了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a307a243faa41b1e0ba35b64079e044117de9ca0.png)

### 调用链

```php

ParserController.php:84, app\\home\\controller\\ParserController->parserAfter()

TagController.php:47, app\\home\\controller\\TagController->index()

IndexController.php:50, app\\home\\controller\\IndexController->\_empty()

2:2, core\\basic\\Kernel::axqjlxzuuxaapu328937ae1368b88e8bf79cb6b342866a()

2:2, core\\basic\\Kernel::run()

start.php:17, require()

index.php:23, {main}()

```

访问首页就会进入到apps/home/controller/IndexController.php的`_empty()`方法，需要get的参数带有tag就可进入该判断

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4d74c5d43f0bc018f925bb12dd6ff66c35d4394b.png)

跟进到apps/home/controller/TagController.php的`inde()`方法，跟进第47行并跟进到apps/home/controller/ParserController.php`parserAfter()`方法，最后就会到84行的漏洞方法中。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ad6e2514e65ba04ec1f68e16f4f907cb4b7ed14d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4300321ca7d02ac68a6966861f8e825ea4c6c4e9.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4e17136db5ad7a5e09d0568c598aa10ac44fc347.png)

### 目前新版本未发现有该处函数