审计两个版本 v2021.0521152900 和v2021.0528154955，7月2号爆出的v2021.0521152900存在任意文件删除和任意文件上传，审计出来以后又审计了一下下一版本，图片都是当时审计时做的笔记的图片

*暑假七月份想训练一下代码审计，于是去cnvd上看近几天有哪些cms有编号，然后找到了这个小cms*

任意文件删除漏洞产生原因
------------

由于已经知道是什么漏洞了，所以直接去搜索一下相应的函数即可，于是搜索了一下unl ink()函数，翻着看了一下定位到了这个文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af6a3b9d1c14900386de4c4ec9abb31e366d91ef.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-af6a3b9d1c14900386de4c4ec9abb31e366d91ef.jpg)  
代码如下

```php
function delfile($fileUrl)
{
$fileUrl = path_absolute($fileUrl);
$fileUrl = stristr(PHP_OS, &amp;quot;WIN&amp;quot;) ? utf82gbk($fileUrl) : $fileUrl;
@clearstatcache();
return is_file($fileUrl) ? unl ink($fileUrl) : false;
}
```

看到

```php
  $fileUrl = path_absolute($fileUrl
```

跟进path\_absolute函数

```php
function path_absolute($path)
{
$path = PATH_WEB . str_replace([
    "../", "./", PATH_WEB,
], "", $path);
$path = str_replace("\/", "\\", $path);
return is_dir($path) ? path_standard($path) : $path;
}
```

可以看到过滤规则，但是开发人员忽略了cms是搭建在windwos系统上那么就可以利用..\\来进行跨目录  
知道这一点后找哪里应用了delfile()  
在后台中有个备份功能,当备份了以后可以执行删除操作  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f66898c40c35b0889fb9f500a21847b362f2408.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f66898c40c35b0889fb9f500a21847b362f2408.png)  
删除操作在datab ase.class.php中

```php
        case 'del':                                                          $file = PATH_WEB . 'backup/data/{$_L['form']['name']}';
        if (is_file($file)) {
            delfile($file);
            ajaxout(1, '删除成功');
        } else {
            ajaxout(0, '文件不存在');
        }
        break;
```

可以看到这里应用了delfile()  
于是bp抓包，修改一下数据包  
当时在备份文件目录下创建了一个txt文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8786e243c243e16f2b5c4e18908cb81c5958b8e3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8786e243c243e16f2b5c4e18908cb81c5958b8e3.png)  
在数据包中将data名修改为1.txt发送即可，但是当时没有将bp数据包截图，只有下一版本的任意文件删除漏洞有截图

任意文件上传
------

漏洞产生的原因在于没有将后添加进白名单的文件名进行检测过滤  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-42a226cc8a3cc346e465b67674dcbc6698c901b5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-42a226cc8a3cc346e465b67674dcbc6698c901b5.png)  
然后直接到这里添加附件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-65084fae948a1d878e780676cc3c0867271e21ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-65084fae948a1d878e780676cc3c0867271e21ca.png)  
直接上传即可getshell  
漏洞产生原因:  
上传控制文件位于：upload.class.php  
upload先截取文件的后缀名,截取以后再对后缀名和白名单文件名列表进行比较

```php
 $mime = substr($file['name'], strrpos($file['name'], ".") + 1);

 if (stripos($_L['config']['admin']['mimelist'], $mime) !== false)
```

当添加进去文件白名单后,upload.class.php过滤规则中就会有你写的白名单文件名  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9e936acd353e00293eba8babc07e27d166064bc8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9e936acd353e00293eba8babc07e27d166064bc8.png)

下一版本任意文件删除[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-069f87327741a10c3c0daf090e872939fde1bc16.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-069f87327741a10c3c0daf090e872939fde1bc16.jpg)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

可以看到由于上一版本的过滤原因，这一版本添加了过滤规则,在过滤规则中添加了 ..\\和.\\  
但是加了之后真的安全了吗？表面上看起来雀食如此,但根据过滤规则我在在线php工具上写出了代码，然后进行调试  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4458f73d0940f591e04628bf444cc1c84c5e4bbd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4458f73d0940f591e04628bf444cc1c84c5e4bbd.png)  
成功了，可以看到最后我的payload最后输出成为了..\\，这就代表着在windows系统下依然存在任意文件删除漏洞  
打开bp再次抓包，这一次当时选择了根目录下的README.md文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07053a7dff66c644064a523a86e5e800806c5c67.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07053a7dff66c644064a523a86e5e800806c5c67.png)  
然后像之前一样修改数据包，根据目录放上payload  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-27e6cdca860b21902d7e2a5f2e66a1d50523e9db.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-27e6cdca860b21902d7e2a5f2e66a1d50523e9db.png)  
发送之后就可以看见  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e07c1773c936c08bcc51802b67494e5b340d855a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e07c1773c936c08bcc51802b67494e5b340d855a.png)  
直接删除掉了.

**措辞轻浮，内容浅显，操作生疏。不足之处欢迎大师傅们指点和纠正，感激不尽。**