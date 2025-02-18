### 环境搭建

<https://www.fastadmin.net/download.html> 下载完整包，丢到phpstudy里面就可以了，本地环境符合安装要求就会跳转到安装界面，填写数据库等信息完成安装  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ae0ab5e580908d879e04d60a6bbb0a823647087d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ae0ab5e580908d879e04d60a6bbb0a823647087d.png)  
新版本在完成安装之后会对管理员后台的路径进行重命名处理，看源代码可以找到加密函数，起到隐藏的后台的作用，避免资产暴露在公网时后台被攻击者拿下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0f519edf6dc38f61457d464948ae7b780f89dfe3.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0f519edf6dc38f61457d464948ae7b780f89dfe3.png)

### 漏洞分析

漏洞点位于后台分类管理-&gt;添加，既然有源码，当然是搭建环境，功能点测试与源码分析结合会来的更加容易  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-451f0422d6a59113a50d482fcc1cd805f20b0ede.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-451f0422d6a59113a50d482fcc1cd805f20b0ede.png)  
这里的点是文件上传，上传正常的图片文件，burp抓包,修改文件后缀为php，修改文件内容，看看能不能顺利上传木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5b1e68efdab67ef13b22ad2135d0f35032a6411c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5b1e68efdab67ef13b22ad2135d0f35032a6411c.png)  
接着以黑盒测试的角度来看待此处的上传限制，在不看源代码的情况下尝试绕过，尝试了php3,php4,php5等文件后缀，全部都上传失败；修改content-type为其他诸如gif、jpg等类型，还是失败，这说明最新版本的黑名单写的还是比较好的，在不分析源代码的情况下还是比较安全的  
下面还是来分析一下源代码吧，结合上传时burpsuite抓包时post传参的路径来分析  
根据上传的路径定位到`application\admin\controller\Ajax.php#107`[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8d0e856aecab86f2bde4af5708ed9280f401f5f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8d0e856aecab86f2bde4af5708ed9280f401f5f5.png)  
默认情况为普通文件上传，通过实例化`Upload`类，传入获取到我们要上传的`$file`文件  
跟进一下该`Upload`类  
`application/common/library/Upload.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5e0344a9918f176b44537986772f383da4bff93f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5e0344a9918f176b44537986772f383da4bff93f.png)  
`$this->config`变量值是从`upload.php`配置文件中获取的，在后面的部分校验中会用到  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-be6f954842034cbf7dea2ed738c0231039881256.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-be6f954842034cbf7dea2ed738c0231039881256.png)  
跟进`setFile`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4e1f7ba8530eb80b7d6a77ae29f3f79aac8cdf83.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-4e1f7ba8530eb80b7d6a77ae29f3f79aac8cdf83.png)  
该方法对上传的文件进行了部分的处理，通过`pathinfo`函数截取文件名的后缀，再转换了大小写，这就限制了利用大小写绕过黑名单，之后调用`preg_match`函数对截取的后缀名进行处理，如果出现特殊字符就直接将文件后缀重命名为`file`  
接着往下，跟进`checkExecutable()`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-89ab03585995c7e28bfe52e6f31d1a327e10cff5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-89ab03585995c7e28bfe52e6f31d1a327e10cff5.png)  
上面经过处理后获取的文件后缀为php、html、htm或者上传的文件类型属于数组中的就直接抛出异常上传限制，也就是上面burp中的响应包  
回到`Ajax.php`文件，跟进`$upload`实例调用的`upload()`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-413c2c6cc685ec02dc045c5a3ab976a5cfb2bf1c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-413c2c6cc685ec02dc045c5a3ab976a5cfb2bf1c.png)  
这里会调用四个方法对我们上传的文件进行校验，第一个`checkSize`就是检测上传的文件大小，对上传并没有什么太大的影响；第二个`checkExecutable`方法上面已经看过了，限制了上传php和html文件；只要来看一下后面的两个方法；由于`$savekey`为空，会调用`getSavekey`方法，后面来看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6509a9b70a00c8f1058f27d137cc6980143ec0f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6509a9b70a00c8f1058f27d137cc6980143ec0f5.png)  
该方法从注释来看就是验证文件后缀，$mimetypeArr的值就是前面提及的`$this->config`变量中的值

```php
$this->config['mimetype']= [jpg,png,bmp,jpeg,gif,zip,rar,xls,xlsx,wav,mp4,mp3,pdf]

```

这里校验了文件后缀名和文件的type值，只需要满足一个条件就可以，利用type值为数组中任意一个即可绕过该校验[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a37759f3df80eeb87f4ec4253c90b2ee20421459.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a37759f3df80eeb87f4ec4253c90b2ee20421459.png)  
该方法中的判断还是一样，验证是否为图片文件，只需要满足type的校验就可以绕过对文件名后缀的检验了  
再来看一下`getSavekey`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ec98249a5a0db305acf6b62d5f01b560d068f41d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ec98249a5a0db305acf6b62d5f01b560d068f41d.png)  
会对上传之后的文件名部分进行MD5加密转化处理，也就是无法控制上传之后的文件名，也就不能通过上传覆盖·`htaccess`、`.user.ini`等思路来拿shell

### 漏洞利用

通过上面的分析，最终还是能绕过黑名单限制的，上传正常的图片，然后再通过修改type字段绕过检测，修改文件后缀名为phtml、php3、php4等就可以[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-131a1352754c2179be47c5dc3b702ab05efd5b68.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-131a1352754c2179be47c5dc3b702ab05efd5b68.png)  
访问一下上传的文件地址[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-82d0f75b9778c2c43f96cba8ef1e8d1bd08dbeca.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-82d0f75b9778c2c43f96cba8ef1e8d1bd08dbeca.png)  
成功写入了，但是不解析，找遍了资料在不修改apache配置文件的前提下，上传其他诸如php3、php4等后缀文件都不解析  
本来以为到这里就结束了，但是想起以前打比赛的经历，记得看到过apache配置文件里是有写默认正则匹配php3等后缀名文件当作php来解析的，找了挺久，找到了，ubuntu、debian apache2满足条件，debian apache2看一下配置文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2fda594ff653e713dfdf16e24262c3cb4cd0e634.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2fda594ff653e713dfdf16e24262c3cb4cd0e634.png)  
默认会包含mods-enabled路径下的.conf文件，该路径下的php7.4.conf配置文件刚好会被包含，而该配置文件中的默认配置是将phtml当作php来解析的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d93cf4f96f3c2c6ae609f6cec5a13054cbcb28d5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d93cf4f96f3c2c6ae609f6cec5a13054cbcb28d5.png)  
所以到这里只需要将项目重新搭建在kali或者ubuntu上就可以利用这个后台文件上传漏洞了，重复一下上面上传的步骤[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a009fdd8228b492dcf105db6e226d17289387b7d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a009fdd8228b492dcf105db6e226d17289387b7d.png)

### 写在最后

这个洞到这里基本也算是利用成功了，但是利用条件还是比较苛刻的，从上面的利用利用部分就可以看出来了，这个洞的起因还是代码逻辑上出现了问题，判断条件全部改成与，那么基本就不会有绕过的可能了，虽然有点鸡肋，指不定哪天就用上了...

### 漏洞已修补

该漏洞已经报给厂商进行修复了，当天就推出了最新版，已交CNVD，有使用的赶紧升到最新版  
新版连接：[https://github.com/karsonzhang/fastadmin/releases/tag/v1.2.2.20211011\_beta](https://github.com/karsonzhang/fastadmin/releases/tag/v1.2.2.20211011_beta)