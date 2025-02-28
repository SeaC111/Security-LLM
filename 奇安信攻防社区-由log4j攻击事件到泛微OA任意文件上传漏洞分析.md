![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ff6c98874cbe130e65cb1fe0afaebf20600bd1ef.png)  
根据攻击者的poc显然是log4j的利用，对攻击源IP进行了溯源，微步情报显示为恶意IP，并且带有log4j的标识，显然就是攻击者的IP地址了  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9f7731668edbf0dc47d0ca347ea43dff4ff2fbd1.png)  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-86e026b0d626fbd20b5052c153ecbb515a8a0c90.png)  
正当以为此次应急事件就此结束之时，在流量设备上搜索攻击者IP发现了另一起攻击事件，，根据攻击路径去进行溯源，结合搜索到的资料，发现是前不久微步公开捕获的泛微e-office任意文件上传漏洞  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab8b5c6aea2d96b6d206da643ca4b338122ee0b9.png)  
之后在征得同意之后登录到了这台winserver机器上，并找到了攻击者上传的恶意代码，下载到了本地，用微步沙箱进行检测确认为哥斯拉的马，之后协助进行了后门的清除。  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1e149360cd73ed25c9902b4c8c25e61e37150dd9.jpg)  
紧接着进行了漏洞利用的复现，根据捕获的数据包，利用BurpSuite进行构造攻击，根据响应包输出的logo-eoffice.php,远程登录到机器上找到文件，可以看到已经成功写入了复现构造的恶意代码。  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-49a4f1923de5087df047b066ac5e1be7b447d4b2.png)  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-18eccf2370b130bd5579d92dc3073eda75c96385.jpg)  
之后根据cnvd的通报到泛微官网下载了更新包打上了补丁，封堵漏洞入口。应急结束之后，和一个大哥提起这个漏洞，巧的是刚好有e-office的安装包，那就借此机会来分析一下。

### 环境搭建

这里在安装的时候，如果本地有启php+mysql服务需要先关闭，安装程序在安装的时候会直接启动php+mysql，避免因为冲突导致mysql运行失败，数据库无法连接

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-735a0c4a4fed9727f1729f874a40f1f5eba8d216.png)

漏洞分析  
根据poc定位到漏洞点  
`webroot\general\index\UploadFile.php`  
调用的是UploadFile类中的`uploadPicture`方法

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca4de891a174f0ce6fc178c2bd5159fbe1c0b474.png)

这里首先会对获取到的`$_FILES`数组进行判断，如果数组为空那么就不会接着往下，并且也不会有任何的异常抛出；调试可以发现数组中有五个键值对，包括上传时的文件名，临时文件名，文件的类型，大小以及是否有异常  
接着`$uploadTyp`e获取到的是GET或者POST传参传递的`uploadType`值，并且下面的代码都与这个`uploadType`参数值直接相关，根据poc传入的`uploadType=eoffice_logo`，直接来看到对应的代码部分  
`general\index\UploadFile.php#124`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cc785b2c78ffaacc5127b80e07faa4f6fa01fac4.png)

跟进查看`$_SERVER['DOCUMENT_ROOT']`默认值为空，所以$targetPath=/images/logo/,之后会判断是否存在对应的路径，如果不存在就会创建相应的文件夹。自会后调用类中的`getFileExtension`方法，传入方法中的参数为前面提到过的二维数组中的文件名，跟进方法

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c5bbecdc25d709cd81eeb4f18eb8dae794ea41ea.png)

调用strrpos来获取.在$file参数中最后出现的位置，之后调用substr来截取$file从$pos位置开始的所有字符串，简而言之就是获取到上传的文件名后缀  
回到上面，接着往下

```php
$_targetFile = "logo-eoffice" . $ext;
$targetFile = str_replace("//", "/", $targetPath) . "/" . $_targetFile;
if (move_uploaded_file($tempFile, $targetFile))
```

这里会进行两次拼接最后拼接成上传的文件存储的路径和相应的文件名  
后面可以看到调用`move_uploaded_file`方法将上传后临时保存的$tempFile移动到最后的$targetFile路径下面，后面的代码部分涉及到数据库操作，和这个漏洞并没有太大的关系。所以整个的漏洞分析就到这里了  
利用poc来打一下  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8c51b6b4b218ad91d1638d171243bad13f96f873.png)  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b521affac984c26005783174d57fa6f6c39df2c5.png)

### 漏洞修复

对比补丁包中的更新代码部分，对可以上传的文件后缀进行了限制。  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1063ef569f244734bdb8a979fd5cd36b466d13c.png)  
此外通过审计Uploadfile类中uploadPicture方法中其他几种uploadType的代码，可以发现都是有相应的文件后缀白名单限制的。由此可以推测这里应该是开发人员的失误导致忘记添加白名单，也就造成了该任意文件上传漏洞，并且并不需要管理员权限。