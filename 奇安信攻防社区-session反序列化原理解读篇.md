session反序列化原理解读篇
================

前言
--

看了好多session反序列化的文章，发现都有点晦涩难懂，关键的原理地方都没说清楚，所以我就索性写一篇，供各位师傅一起学习。

导读
--

什么是session？其实就是服务器为了保存用户状态而创建的一个保存用户信息的特殊对象，是存储在服务端的，有session那肯定就有sessionid了，他是怎么来的？当我们浏览器第一次访问服务器时，服务器创建一个session对象并且该对象有一个唯一的id,叫做sessionId,服务器会将sessionid以cookie的方式发送给浏览器，当浏览器再次访问服务器时，会将sessionId发送过来，服务器依据sessionId就可以找到对应的session对象，在这创建session对象的时候服务端先进行序列化再存储到session文件里（session文件就是专门保存序列化后的对象的），相反服务器依据sessionId找到对应的session对象的过程就是通过提取session文件来反序列化生成对象的，就是在这过程中就有可能产生session反序列化漏洞了，**前提条件使用不同的引擎来处理session文件，这个后面就会说**，不同引擎什么鬼？其实就是用两种不同的方法序列化和反序列化对象，还有就是不同引擎怎么处理，说的比较普通点就是两个不同页面处理这个由客户端发来的sessionid的时候用了两种不同的方法序列化和反序列化对象，这样大家就理解了吧。

正文
--

现在就言归正传了，那么一般要用到session就肯定要有php.ini文件了，他就是设定一些参数和规定的。

```php
session.save_path="" //设置session的存储路径
session.save_handler=""//设定用户自定义存储函数，如果想使用PHP内置会话存储机制之外的可以使用本函数(数据库等方式)
session.auto_start boolen//指定会话模块是否在请求开始时启动一个会话默认为0不启动
session.serialize_handler string//定义用来序列化或者反序列化的处理器名字。默认使用php（这个就是我们上面说的引擎了）
```

前面三个用处不大，后面注释就可以理解了，我们就直接说第四点。

PHP是有三个引擎的（就处理器），就是对于第四点可以选三种方式，官方说明如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6aa1991ef3a8f1bc28aee2675418131664605e25.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6aa1991ef3a8f1bc28aee2675418131664605e25.png)  
我们一个个试过去

### php\_serialize:

```php
<?php
ini_set('session.serialize_handler','php_serialize');
session_start();
$_SESSION['good'] = $_GET['g'];
var_dump($_SESSION);
?>
```

说到这里肯定会有人就会问这个**session\_start()**和**$\_SESSION**是什么意思？这个session\_start()其实就如字面意思，就是开启session功能， 只要开启了内部会依据客户端传来的PHPSESSID来获取现在所对应的会话数据（就是session文件了）， 然后就会反序列化他把它还原成对象，并且把它存在这个$\_session全局变量中，我们可以把这个$\_\_session看成是存储在服务器端的数组，专门存储这个序列化的值的。

我们把good1传给变量g，结果输出：

```php
a:1:{s:5:"good";s:3:"good1";}
```

我们可以看到他直接当数组存储了，其中good我们可以看成这个数组的下标就像0,1,2这样的下标，good1就是具体的值了。

其实这里我们通过get传参和赋值是很少见的，实战肯定不是这样的，我们这里只是为了更好理解这个原理，那实战里没了get传参，那是怎么序列化和反序列化并传参的呢？当程序一开始运行到这个session\_start()就会判断是否有sessionid，分成两种情况。

#### 1、有sessionid

就会反序列化这个id对于的session文件，并自动存储（就是相当于我上面的赋值操作了）到这个$\_session数组中，之后就是通过用户传过来的口令与这个$\_\_session对比操作了，最后就是返回账号秘密是否错误这些操作了。

#### 2、没有sessionid

没有就根据用户信息在生成一个对象，通过用户传过来的口令等生成一个对象再序列化，并自动存储到这个$\_session数组中，我个人理解这个就是在那些注册账号的情况了吧。  
最后我为什么要get传参和赋值？因为我这简单的代码，就根本没有这个sessionid这东西啊，要得话肯定要cs联动的，所以就不会赋值，因此我就必须加上这个get型赋值来代替这个session\_start()的赋值功能。后面的另外两个引擎也是这样的所以我就不再啰嗦了。

### php：

```php
<?php
ini_set('session.serialize_handler','php');
session_start();
$_SESSION['good'] = $_GET['g'];
var_dump($_SESSION);
?>
```

我们这里还是把good1传给变量g，结果输出：

```php
good|s:3:"good1";
```

他这里没有当成数组了而是用|符号把这个数组下标和具体值区分开来了，这个|符号就是后面反序列化漏洞形成的关键一部分。

### php\_binary：

```php
<?php
ini_set('session.serialize_handler','php_binary');
session_start();
$_SESSION['good'] = $_GET['g'];
var_dump($_SESSION);
?>
```

把good1传给变量g，结果输出：

```php
good:3:"good1";
```

这个和前面的php引擎的序列化有点相似，就不多说了，其实就是前面的多了个|。

漏洞利用
----

终于可以讲一讲这个漏洞是怎么形成的了，其实就是不同的引擎对这个|产生的歧义问题，怎么说呢，嗯，就是在php\_binary或者php\_serialize里面他都不会识别这个|符号而且他对输入的具体值他不会当成一个由对象序列化的字符串来反序列化，他好像就直接把输入的字符串当成一个具体的值来反序列化了，然而这个php就完全不同了，他会把这个|后的字符串当成一个由对象序列化的字符串来反序列化，就是利用这一个关键点就可以实现反序列化漏洞的利用了，  
下面我们就举一个具体的例子瞧瞧：

页面一源码：

```php
//1.php
<?php
ini_set("session.serialize_handler", "php_serialize");
session_start();
$_SESSION['good'] = $_GET['g'];
?>
```

页面二源码：

```php
//2.php
<?php
ini_set('session.serialize_handler', 'php');
session_start();
class hello
{
public $my;      
public $you;
function __wakeup()
{
echo $this->my;
echo $this->name;
}
}
?>
```

可以看到这两个源码他的引擎一个是php\_serialize，另外一个是php的，这就构成了条件，会这样一般是程序没有设计好才导致的。

我们可以看到在页面二里面他有一个class的类我们可以根据他构造payload

```php
<?php
    class hello
{
    public $my='you are';
    public $you='so smart!';
}
?>
    $A=new hello();
    echo serialize($A);
```

结果为：

```php
O:5:"hello":2:{s:2:"my";s:7:"you are";s:3:"you";s:9:"so smart!";}
```

我们在最前面加上这个’|‘：

```PHP
|O:5:"hello":2:{s:2:"my";s:7:"you are";s:3:"you";s:9:"so smart!";}
```

把这个值用g变量赋值给页面一，然后再访问页面二，就可以发现这个hello类所实例化的值变了。

```php
http://127.0.0.1/1.php?g=|O:5:"hello":2:{s:2:"my";s:7:"you are";s:3:"you";s:9:"so smart!";}
```

结果：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f0153837e29b600b67dbdfed948256177f56a6f3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f0153837e29b600b67dbdfed948256177f56a6f3.png)  
因为他把这个|后的值通过php引擎反序列化了，说到这肯定有人会问为什么把这个值赋值给页面一再访问页面二，其实我们把值赋值给页面一是因为我们没有sessionid也不会创建类来赋值，所以要使$\_session有值就只能手动赋值，当然实战不可能会这样的，再来为什么访问页面二，其实是它的引擎是php的，他才会触发这个反序列化。最后一个就是为什么页面一的payloa会在页面二里面起作用？  
我们可以这样去想这只一个用户的两个不同页面，他只是切换了页面，而且两个页面都做了session认证，那么肯定都是调用同一个用户的session文件。

结语
--

这篇文章的很多地方都是我个人的见解，如果有误请师傅们帮忙点评一下。