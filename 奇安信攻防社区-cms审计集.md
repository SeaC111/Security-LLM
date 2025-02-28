youdiancmsv9.0
--------------

上次一个项目遇到了该cms二开之后的系统，注释里面标明了是该系统，v9.2的，当时下载了源码去审，没有审出来东西，找了不少低版本的poc，都没打成功，那就先审审低版本的，争取把新版本的给拿下来。

### write webshell

漏洞点位于后台模板管理-》任一模板文件

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c2e76ee9359f7426e2293a1c0fa48ad2ccc806ce.png)

`App\Lib\Action\Admin\TemplateAction.class.php#68`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-619a7146b28474dc099126a0c24c4b67af7a693c.png)

先调用了YdInput类中的`checkFileName`方法对传入的文件名进行了处理，跟进，代码很短，检查文件名不能出现的特殊字符并且替换为空

```php
static function checkFileName($str){
        $str = str_replace('..', '', $str);
        return $str;
    }
```

接着调用`ltrim`方法去除文件名开头的空白字符之后拼接成完整的文件路径，接着调用了本类中的`isValidTplFile`方法对模板文件进行校验；可以看到主要的手段就是通过限制文件名的后缀，先进行大小写转换之后再进行白名单检测

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6fc916a4f05815a3e7d284edebf661405f4162de.png)

后面会调用`htmlspecialchars_decode`进行实体编码的解码，这里不影响写入的`shell`，然后就是调用`file_put_contents`将文件的所有内容写入到模板文件当中；写入的`html`文件本身就会被包含，所以其中的`php`代码就会被`php`解析器执行

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-87d9acc51dbc274b1f45f842cca51da7f63a8f93.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2738f4a0e1fa64729e6948159c25d4dd631ff5c7.png)

Kitecms
-------

### write webshell

以前打比赛的经验，搜索危险函数,`file_put_contents`，这里定位到了这个位置  
`application\admin\controller\Template.php#25`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9bf956c4ea0e7824b7bfdde64e83d2f42a560d8f.png)

调用Request类中的`param`方法进行获取`path`参数，这里实例化了`Site`类的对象赋值给了`$siteObj`参数，并且调用了类中的方法去数据库中进行查询，这里`$template`的值从数据库中取到值为`default`  
经过处理之后的`$rootpath=root_path/theme/default/$path`,`root_path`的值为即是网站根目录下,`$path`路径为可控点

```php
if (!file_exists($rootpath) && !preg_match("/theme/", $rootpath)) {
            throw new HttpException(404, 'This is not file');
        }
```

这里对处理之后的路径进行校验，必须存在并且路径中包含有`/theme/`，不然就会抛出相应的异常  
接着往下

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c1a196ca9dc41dcdd9c139fb862f8aa864836cc6.png)

POST有传参就满足条件，接着会调用`is_write`方法对指定路径下的文件进行可写权限判断，如果可写就会调用`file_put_contents`方法，将调用`htmlspecialchars_decode`方法进行实体解码之后的输入内容写入到$rootpath文件当中，实体解码对于我们的`shell`并没有影响，并且前面对路径进行了拼接处理，这里就可以进行路径穿越将`shell`写入到指定的文件当中去  
poc

```php
POST /admin/template/fileedit HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://localhost/admin/template/fileedit
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Origin: http://localhost
Connection: close
Cookie: PHPSESSID=r0mbjo57rneu1l81c79rbf12e0
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin

path=../../index.php&html=<?php phpinfo();?>
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f011ea5c70a4f65cca73a9666096a72ef5d5069a.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1b1ac8051f328cb1e1f62d3f3e7d6d5968ffabed.png)

### any file reading

`application\admin\controller\Template.php`  
还是一样的位置，接着往下看

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8dff457273696d86a6de330eb7050eebf891dd1f.png)

只要不是以`post`传参，就会校验指定文件可读权限，如果可读就会调用`file_get_contents`读取，这里一样可以结合目录穿越进行任意文件读取  
poc

```php
?path=../../filename
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3086000a756dec1bf9395f1e00baa629e6f4d68.png)

### upload getshell

系统=&gt;上传处这里可以增加上传的图片类型，之前的小结文章中也有提到过这种getshell的后台

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b9a478c855c78a14b6fee53ffaf91ab7c3cc50df.png)

之后看到站点=》新建，这里可以开启新建文件，并且可以上传文件，之后抓包跟进代码  
`application\admin\controller\Upload.php`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ef3cc0d6e0545662edffd820dd60cb3a52af78a.png)

Request类中的file方法获取到上传的文件的所有信息，后面实例化UploadFile类并调用类中的upload方法，跟进  
`application\common\model\UploadFile.php#127`,根据传入的fileType=image，只看相关的代码就可以了，这里先看一下默认的图片上传配置

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db43fbc2c14f973d6ea33f3fc18236b75c823c3f.png)

`config\site.php`中的默认配置没有更改，前面增加的上传后缀php实际上是有生效的

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-953c8942e54c55dc8e89d79dd43da8eb0dc5ae47.png)

接着跟进check方法，`thinkphp\library\think\File.php#226`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bdba7736e2a0b0811f34f2eacae9251bd0b1e30f.png)

可以看到这里判断判断条件为或，只要有一个为`true`那么就会为真，而我们的目的是返回true，也就是if条件判断不能成立；这里`$rule`数组中只有两个键值对，而文件大小是肯定满足的，所以只需要检查后缀就可以了，这里通过调试输出，`$rule['ext'] == 'jpg,png,gif,php'`，上传`php`文件肯定是成立的，所以下面只需要跟进`checkImg`方法

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7dec59518feab662ab58b198724c7b9f8bdd7491.png)

这里还是要返回值为`true`，因为上传的文件后缀是`php`，所以肯定不在数组中，第一个`in_array`返回值为`false`，这里为与逻辑，所以`if`判断恒不成立，返回`true`，所以最后`check`方法返回`true`，那么`shell`文件就上传成功了  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7a7a944100a3bd773f7f47bfce3f9bcaa3e4215e.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-292d83a6697152198b10571d5450612a82af1b3c.png)

PS
--

youdianCMS一直在更新中，漏洞均已修复；kitecms已经挺多年没有更新了，官网关站，文中的漏洞均在GitHub的issue中，作者已知悉但未推出迭代版本并且没有使用群体。