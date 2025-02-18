### 审计准备

CMS审计很少提到环境搭建，这个还是要说一下，源码中有一个单独的文件夹www，一般来说里面的最好还是和上层目录中的`coreframe`放在同一个路径下面，就不要夹着一层文件夹了。`coreframe`文件夹里面是整个CMS的框架目录，里面包含了模块应用程序，诸如一些功能部分；`www`只是网站根目录；而网站根目录的定义路径在`coreframe/configs/wz_config.php`中

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-44850d308f1c20e0a0d4cdaf2ae3fc6ec9ab5498.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-44850d308f1c20e0a0d4cdaf2ae3fc6ec9ab5498.png)

除此之外还看了一下能找到的路由配置文件，根据代码结合CMS整个文件结构，`m`为调用的`coreframe`中具体的文件夹名称，`f`为调用的类名，`v`不出意外是类中的函数方法名。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-63b477f83199836050c9f6c574904344152b455c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-63b477f83199836050c9f6c574904344152b455c.png)

### 目录穿越-&gt;任意文件删除

根据cnvd提供的信息，漏洞功能点在后台，通过功能的逐个尝试，最后定位到漏洞功能点应该位于管理员后台拓展模块-&gt;附件管理-&gt;目录模式  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3913df3169a18041439492c751b9c8e21247561b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3913df3169a18041439492c751b9c8e21247561b.png)

点击进入`qr_image`文件夹，接着在点击返回上一级目录的时候进行抓包  
根据最开始分析的路由，结合README中对于各个模块的介绍，定位到代码位置  
`coreframe/app/attachment/admin/index.php`

```php
public function dir()
    {
        $dir = isset($GLOBALS['dir']) && trim($GLOBALS['dir']) ? str_replace(array('..\\', '../', './', '.\\'), '', trim($GLOBALS['dir'])) : '';
        $dir = str_ireplace(array('%2F', '//'), '/', $dir);
        $lists = glob(ATTACHMENT_ROOT . $dir . '/' . '*');
        if (!empty($lists)) rsort($lists);
        $cur_dir = str_replace(array(WWW_ROOT, DIRECTORY_SEPARATOR . DIRECTORY_SEPARATOR), array('', DIRECTORY_SEPARATOR), ATTACHMENT_ROOT . $dir . '/');
        include $this->template('dir', M);
    }
```

从代码来看首先对传入的$dir进行去除首尾空格，之后会进行正则匹配替换，如果有传入数组中的字符串就会被替换为空；再接着调用`str_ireplace`函数再次进行替换，`URL`编码过或者双斜杠都替换为单斜杠，且该函数忽略大小写；之后调用`glob`原生方法列出指定路径下的文件，这里对`$dir`进行了字符串拼接操作。  
再回到发送的数据包，对拼接操作处理过的`$dir`进行输出

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e87bf2f7be0cd30d392119232579cebf422865fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e87bf2f7be0cd30d392119232579cebf422865fd.png)

可以看到当给$dir传参为.的时候，列出的是当前路径下的文件夹，既然不允许传入的参数为`..\,../,./,.\`  
那么当传入两个点的时候，经过字符串的拼接操作之后就是`../`,就能够达到目录穿越的目的,当然还有别的可用字符串比如`....//`等

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c310b56ecaf15d0234706cf22d3944830f69455d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c310b56ecaf15d0234706cf22d3944830f69455d.png)

下面就可以删除文件了，但是这里可能还会有限制，所以需要审计删除文件的方法看看是否能够造成任意文件删除

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c040c5d9e41f2b5bdcef2be5549cebea54126ad3.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c040c5d9e41f2b5bdcef2be5549cebea54126ad3.png)

通过抓包发现这里不会传入id参数，所以if那段判断代码直接不看；对传入的url会调用`remove_xss`函数，针对可能造成XSS攻击的特殊字符进行过滤；之后对url进行过滤，匹配到`http://localhost/uploadfile/`就替换为空，这里不影响；之后代码就很简单了，到数据库中去查找有没有对应的信息，`id`未传入，所以这里`$att_info`为空， 直接调用类中的`my_unlink`方法

```php
private function my_unlink($path)
    {
        if(file_exists($path)) unlink($path);
    }
```

可以看到该方法，只要传入的路径下存在指定的文件，就直接进行操作，那么就能达到任意文件删除的目的，尝试删除`README.md`文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-eac7dd7770218f534ee0d2b75146f86018963102.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-eac7dd7770218f534ee0d2b75146f86018963102.png)

维护界面-&gt;模板管理，此处也存在目录穿越，代码逻辑类似，删除的操作默认为html文件，就不再细看了

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f8a41155f577761e08afe9ad9de7c25514b1a46a.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f8a41155f577761e08afe9ad9de7c25514b1a46a.png)

### RCE

`coreframe/app/attachment/admin/index.php#156`  
首先对是否有传入`submit`参数进行判断，有会进行缓存信息的写入，没有会读取缓存信息

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-167fdebb51240852aa61fb98f00a0e83a790c185.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-167fdebb51240852aa61fb98f00a0e83a790c185.png)

`cache_in_db`方法，模块设置保存进数据库的逻辑处理；接着会调用`set_cache`方法，跟进该方法  
`coreframe/app/core/libs/function/common.func.php#392`

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-949b9ba79a6f72f4e05c0e1c326ef378113ba863.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-949b9ba79a6f72f4e05c0e1c326ef378113ba863.png)

对`$dir`是否为空进行判断，`$di`r默认值为`_cache_`,非空；之后对`$filename`进行匹配过滤，未匹配到就返回false，默认传入为`v`；之后就是对应目录下是否存在存储缓存文件的目录，不存在就进行创建；后面会将$data数据写入缓存文件当中，`$data`的值可控，由传入的`$setting`进行传递，所以可以尝试写入shell。到这里poc也就出来了  
poc

```php
?m=attachment&f=index&_su=wuzhicms&v=ueditor&submit=1&setting=<?php phpinfo();?>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0501b555d887869476f7d323987b556115db936b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0501b555d887869476f7d323987b556115db936b.png)

再看一下未传入`sumbit`参数时调用的`get_cache`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-41691688cac5c36e1cef402832f61e54721d2453.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-41691688cac5c36e1cef402832f61e54721d2453.png)

前面传入的文件名和写入操作是一样的，由于生成的缓存文件名唯一，所以这里默认会传入缓存文件，只要文件存在就会进行包含。所以，打出shell的poc

```php
?m=attachment&f=index&_su=wuzhicms&v=ueditor
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a6845761ab5873a7a0ff8fc9b066ea5d01d40d22.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a6845761ab5873a7a0ff8fc9b066ea5d01d40d22.png)

### Finally

每一次审计总会期待有所收获，没审出来也没事，总归多少会有点收获。