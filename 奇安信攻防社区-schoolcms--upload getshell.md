### 环境搭建

```html
windows10  phpstudy
schoolCMS建站源码
```

搭建直接把源码丢到WWW目录下就好，这里提一下PHP配置文件中mysqli的拓展前面的注释符需要去掉，不然会报错，因为build文件中用到了拓展类中的mysqli类来进行数据库的操作  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a38b998218a33eaf6e755ca02fd9eae2045b6512.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a38b998218a33eaf6e755ca02fd9eae2045b6512.png)  
出现这个页面也就搭建成功了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-555b4067921650884d73fc1eb0de82ead2c081a7.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-555b4067921650884d73fc1eb0de82ead2c081a7.png)

### 漏洞分析

用默认账号登录后台，找到了两处可以上传文件的地方，一处是网站管理-&gt;主题管理，另一处是站点配置-&gt;站点设置处，可以上传网站的logo;两个地方都来看一下

#### 网站管理-&gt;主题管理

审计代码结合功能点测试能够帮助更快定位到相关功能代码的位置  
一般主题管理都是上传压缩包，功能代码应该会有一步解压缩的操作，所以制作一个压缩包，放一张正常的图片，一个PHP文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-07d9280217444a357a4e009935df49c24f9ae750.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-07d9280217444a357a4e009935df49c24f9ae750.png)  
返回的`json`数据进行unicode解码，编辑成功，但是主题哪里并没有多，也就不清楚到底有没有上传成功，根据上传的路径跟一下源码  
`Application/Admin/Controller/ThemeController.class.php#184`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-013e3a020d38b2694e34a554b1e7145233e4e242.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-013e3a020d38b2694e34a554b1e7145233e4e242.png)  
首先会对上传的文件进行一个校验，跟进`FileUploadError`方法，该方法相当于是一个表单验证，如果`POST`表单中存在`name`为`type`的，就继续，并且文件成功上传返回true，若不能正常上传成功会返回对应的错误信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9c5f5312c2e4ae20de6b085990ae2806518f6214.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9c5f5312c2e4ae20de6b085990ae2806518f6214.png)  
接着回到Upload方法中，对上传的文件类型进行校验，这里是写死的白名单，只能是数组里两种数值中的一种，因为是正常上传的压缩包所以并没有影响，接着会继续向下，看一下`Upload`方法后面的操作  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5d5e4aa5c6627df9a524ab1666b2b1f00ae84fa0.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5d5e4aa5c6627df9a524ab1666b2b1f00ae84fa0.png)  
接下去会对上传的压缩包进行解压缩，并对其中的项目名称进行校验，首先排除临时文件和临时目录，之后只有文件名中含有`_Html`或者`_Static`才会进行路径的拼接，`$this->html_path`和`$this->static_path`都是类中定义好的路径

```php
$this->html_path = 'Application'.DS.'Home'.DS.'View'.DS;
$this->static_path = 'Public'.DS.'Home'.DS;
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4f4a31adbb9319105fb6990bcd5d2d425e452101.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4f4a31adbb9319105fb6990bcd5d2d425e452101.png)  
之后再将$file中的两个字符串替换为空，截取文件路径，下面就是判断是否存在文件夹，判断文件是否是文件夹不是就进行文件的写入  
所以接下来只需要对压缩包进行重新修改就可以了，还是一样的文件，文件夹的名字改成`xx_Html`,打成压缩包之后重新上传，成功传入，可以看到上传之后文件名会被修改为压缩文件`xx+文件`本来的名称  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fae1aeffd502ee60be0ad61e8a4127d0e6d23d0d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fae1aeffd502ee60be0ad61e8a4127d0e6d23d0d.png)  
通过主题模块查看默认模板可以知道上传之后的文件所在路径为`Application/Home/View`,后面直接跟上拼接之后的文件名就可以访问到shell了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4d0a171ee8f136255d7250758c6dde90cfb39605.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4d0a171ee8f136255d7250758c6dde90cfb39605.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-eb49dee8d8f8dc63a949af4bcd141a25d1443e62.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-eb49dee8d8f8dc63a949af4bcd141a25d1443e62.png)

#### 站点配置-&gt;站点设置

站点logo处可以进行文件上传，上传的文件会被重命名，覆盖掉原本的logo文件，也就是说只能该目录下只能有一个logo文件名的文件  
上传一个正常的图片文件，Burp抓包之后获取路径，通过路径定位到上传方法的控制器  
`Application/Admin/Controller/SiteController.class.php#72`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-480291024c65f90591a9a4338eae46e6367b8a46.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-480291024c65f90591a9a4338eae46e6367b8a46.png)  
还是一样会先经过`FileUploadError`方法的处理，重点部分在断点位置，调用了`explode`方法对文件上传的`type`进行了处置，以`/`为分隔符，获取到值后分别赋给了`$type`和`$suffix`,之后就是判断是否存在`image`文件夹没有就会进行创建；`$filename`会进行重命名，这里是重点，文件名会被重写，拼接的后缀恰巧是前面从`type`中获取到值的`$suffix`。  
正常的上传png图片，获取到的`content-type`为`image/png`，经过`explode`处理之后，`$type`和`$suffix`的值分别为`image`和`png`，所以文件名还会是png后缀，再通过`move_uploaded_file`方法将上传的文件移动到指定的路径下。  
利用代码逻辑这文件重命名的漏洞，上传图片之后修改`content-type`为`image/php`，就可以获取shell了  
burp请求包如下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-44fc67e239e51a2e91f86980b9127a03a761df89.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-44fc67e239e51a2e91f86980b9127a03a761df89.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cbfdbd2182007fe251d9e02bdd5c09f03657f053.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cbfdbd2182007fe251d9e02bdd5c09f03657f053.png)  
通过前端代码可以获取到路径，文件名固定为home\_logo，从代码中也可以看到，访问shell即可  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-33544ab783056b4416887761726f290869fd8241.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-33544ab783056b4416887761726f290869fd8241.png)

### 写在后面

这个CMS还是比较简单的，可能就是因为比较旧了吧，本来想着ZIP拿shell还可以申请个CVE来着，去看了一下issue发现两年前已经有人提了，那就把这个审计的过程记录一下。