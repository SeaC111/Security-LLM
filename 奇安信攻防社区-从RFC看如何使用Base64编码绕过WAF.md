Base64编码
--------

简单来说Base64编码，就是简单的3换4，将3个char共24bit，分成4个部分，每个部分6个bit，所以总共可以标识0-63共64个数，然后重新进行编码，由于当存在不足3个char时，是无法组成24个bit的，所以最后会使用`=`作为padding进行补充，标准的base64编码字母标为

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5f21f814799184e127d855668dd605420fb28a53.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5f21f814799184e127d855668dd605420fb28a53.png)

WAF拦截机制
-------

由于目前大部分waf还是基于规则进行拦截的，其中一部分waf没有实现对请求数据的处理，比如遇到base64编码的数据，并不会解码，而是直接拿base64编码的数据和规则进行匹配。如果waf实现了对base64解码的处理，那么遇到base64编码直接进行解码，就可以拿解码后的数据与规则进行匹配，这样能够节省规则的编写。这里为了能更好理解，简单使用waf拦截蚁剑Webshell的base64-php版本请求进行举例

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-15c635f9a5f25d0680c9befe0ff5f60324f53bcd.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-15c635f9a5f25d0680c9befe0ff5f60324f53bcd.png)

首先拦截这种请求，如果规则中有base64\_decode函数等关键字，是肯定能够拦截的。由于本文主要探讨如何绕过base64编码，所以这里主要看如何让waf拦截这个经过base64编码的参数。解码下这个参数值

```php
@ini_set("display_errors", "0");@set_time_limit(0);$opdir=@ini_get("open_basedir");if($opdir) {$oparr=preg_split("/\\\\\\\\|\\//",$opdir);$ocwd=dirname($_SERVER["SCRIPT_FILENAME"]);$tmdir=".d47b6980f578";@mkdir($tmdir);@chdir($tmdir);@ini_set("open_basedir","..");for($i=0;$i<sizeof($oparr);$i++){@chdir("..");}@ini_set("open_basedir","/");@rmdir($ocwd."/".$tmdir);};function asenc($out){return @base64_encode($out);};function asoutput(){$output=ob_get_contents();ob_end_clean();echo "25606f"."0a6023";echo @asenc($output);echo "d00298"."01067d";}ob_start();try{$D=dirname($_SERVER["SCRIPT_FILENAME"]);if($D=="")$D=dirname($_SERVER["PATH_TRANSLATED"]);$R="{$D}\t";if(substr($D,0,1)!="/"){foreach(range("C","Z")as $L)if(is_dir("{$L}:"))$R.="{$L}:";}else{$R.="/";}$R.="\t";$u=(function_exists("posix_getegid"))?@posix_getpwuid(@posix_geteuid()):"";$s=($u)?$u["name"]:@get_current_user();$R.=php_uname();$R.="\t{$s}";echo $R;;}catch(Exception $e){echo "ERROR://".$e->getMessage();};asoutput();die();
```

对于不支持base64编码的waf来说，可以直接选取`ini_set(`的base64编码形式`QGluaV9zZXQo`作为关键字拦截，这样这种形式的webshell请求将会被拦截。

对于支持base64编码的waf来说，可以直接使用`ini_set(`作为关键字拦截，这样当遇到base64编码数据，解码之后就会命中`ini_set(`规则。

解码器
---

Base64解码时，就是将4个base64字母，共24bit，分为3个部分，每个部分8个bit，用来代表一个字符。但是当编码后的数据不是标准的规范格式解码器会如何工作呢？

为了能够更全面的测试各种解码器的解析方式，这里选取了5种解码器

1. php: base64\_decode()
2. python: base64.b64decode()
3. go: encoding/base64.StdEncoding.DecodeString()
4. java1: java.util.Base64.getDecoder().decode()
5. java2: sun.misc.BASE64Decoder().decode(）

解析方式
----

根据RFC4648中的规范，总结出5个维度来进行测试，我们用简单的字符串`test`，其base64编码后的数据为`dGVzdA==`作为基础数据。

### 换行符

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9f4d672ff95a974e6030c1e30e81e9b156880307.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9f4d672ff95a974e6030c1e30e81e9b156880307.png)

在base64编码中的数据中，是不允许含有换行符的，除非根据本规范具体规范在特定数量字符后面添加换行符。其实这种场景时常见的，如果base64编码数据过长，可以直接一行表示，有时可能会将过长的数据进行换行了。

测试数据`dG\nVzdA==`，作为base64编码后得数据，通过上述5个base64解码进行解码（下同），结果为

1. php: test
2. python: test
3. go: test
4. java1: 报错
5. java2: 非test

接着使用`dG\n\r\tVzdA==`测试可以解码的

1. php: test
2. python: test
3. go: 报错

接着测试`dG\n\rVzdA==`，发现go可以解码正常

这里特殊的就是go，java两种都不支持，php/python全支持，而go只支持`\r\n`

用上面webshell请求来测试，由于使用的php版本，发送以下数据

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d5278bad7b8fc0edf2f81c431c717c35f83b58f1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d5278bad7b8fc0edf2f81c431c717c35f83b58f1.png)

在base64数据中添加`\n`，当然这个可以在随意位置添加，对于不支持base64解码的waf，自然无法匹配中`QGluaV9zZXQo`，对于支持的，如果waf像java1那种解析方式，就会解析失败，自然无法匹配中规则，由于测试的php版本，后端是使用`base64_decode`函数，也就是我们介绍的第一种解码器，是支持`\r\n`的，这种情况，后端依旧正常解析，但是在效果上是能够绕过waf的。

### 非字母表字符（除\\r\\n）

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-98db6bc27654a65551c019c6471546d53d17fd75.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-98db6bc27654a65551c019c6471546d53d17fd75.png)

按照规定，实现MUST拒绝所有非字母表中的字符，当然也有特殊情况进行忽略。上面我们已经测了`\r\n`这种特殊的回车换行控制符.

接着测试`dG~-VzdA==`

结果

1. php: test
2. python3: test
3. go: 报错
4. java1: 报错
5. java2: 非test

对于go/java1/java2来说是符合预期的，但是python和php即使遇到非字母表字符，就会直接忽略，这会像rfc说的那样，夹带一些危险字符，或用来绕过waf。

这种绕过waf的方式与上面是相似的，只要把`\n`换成非字母表字符即可。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f6aece31beb0bebf747885b0c34f657bfa2f0c74.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f6aece31beb0bebf747885b0c34f657bfa2f0c74.png)

### Padding 不足

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ce81ff0d021191f92ffb0947a0ec3bbfe088ef93.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ce81ff0d021191f92ffb0947a0ec3bbfe088ef93.png)

这里rfc并没有规定解码器在遇到Padding不足的时候应该怎么解码，但是规定了，实现必须在末尾加上适当的填充字符编码数据。是不是就可以理解成，在需要Padding时，这个Padding是必须增加的，那么解码器在解码时遇到Padding不足的时候应该认定为不正确的base64编码数据。当然并不是所有解码器都是这么实现，因为我们见过很多不写Padding的情况。

测试`dGVzdA`

结果为

1. php: test
2. python: 报错
3. go: 报错
4. java1: test
5. java2: 非test

可以看到php依旧坚挺，还是能够解码成功，但是java1也能解码成功了，python虽然支持非字母表字符，却不支持Padding缺少。  
如果waf引擎在解码base64时并不支持padding不足，但是后端支持，我们就可以构造payload的base64编码形式，并将需要的padding进行去除的方式进行绕过。

这种方式绕过，只能适合支持base64解码的waf，并且解码器并不支持padding不足，但是后端支持的情况

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-bf88e5904506da23e2a16d29031f7bff1a3d44b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-bf88e5904506da23e2a16d29031f7bff1a3d44b2.png)

### Padding过多

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-fe07b8538d9a19eed6522e6cf8118bc1832ddf8c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-fe07b8538d9a19eed6522e6cf8118bc1832ddf8c.png)

可以看到，如果忽略了非字母表字符，那么多余的Padding字符也将会被忽略。

接着测试`dGVzdA===`

1. php: test
2. python: test
3. go: 报错
4. java1: 报错
5. java2: test

可以看到，结果与第二部分非字母表字符部分是基本一致的，这是符合rfc的，但是java2却出现了不同，其他情况，虽然没有报错，但是都没有正确解码出test字符串，但是Padding过多情况下，竟然解码出了test。

这种绕过和上面padding不足类似，绕过得场景也是一样得，只需要增加padding即可

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b6fcbf904b6490a6568e238246246a43e7d45e91.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b6fcbf904b6490a6568e238246246a43e7d45e91.png)

### Padding后增加编码数据

padding之所有叫padding，就是因为在末尾时不够编码，所以进行的填充，也就是说Padding后不应该含有正确格式base64编码数据。

接着测试`dGVzdA==dGVzdA==`

1. php: testFW7@
2. python: test
3. go: 报错
4. java1: 报错
5. java2: testtest

很有趣的是，java2把重复的test都解码成功了，而python遇到padding直接后面不要了

如果waf引擎在解码base64时并不支持padding后添加编码数据，但是后端支持，我们就可以构造payload的base64编码形式，使用`dGVzdA==payload`进行绕过，对于waf来说会解析成`test`，并不会触发规则，对于后端来说会解码成`test`和payload，当然这里的test应该设置为不会影响payload执行的数据，这样就可以绕过waf。

总结
--

目前来看，go是遇到不规范的格式，直接报错，但是对于回车换行可以忽略，java1类似于go，但是有个补全padding的功能，python和php类似都会忽略非字母，也会忽略多余的padding，但是python不具有补全padding的功能，而java2从解码结果来看，就是没有任何容错，就是有什么解码什么，padding不够按照padding不够的解析，padding后有数据就继续解析。这里有个问题，就是php在最后一种情况下，既没有像python那样忽略padding后数据，也没有像java2那样解析出正常数据，有兴趣的同志可以看下具体实现。

可以看到不同的解码器在实现上差距非常大，所以如果waf在实现上和后端存在差异，那么我们就可以使用这种不规范的数据进行waf的绕过，或者危险数据的注入。

简而言之，只要是发送的base64编码的数据被waf拦截了，都可以利用上述5个特性来进行测试，来尝试去绕过waf。

参考
--

<https://datatracker.ietf.org/doc/html/rfc4648>

<https://t.zsxq.com/uvFqNFy>