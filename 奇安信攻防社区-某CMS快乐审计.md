### upload-getshell

根据CNVD披露的信息，确定该CMS后台是存在文件上传漏洞的，无非就是功能点上传，那就把后台能够进行文件上传的功能点对应的代码都审一遍。

#### 用户管理-&gt;个人信息(fail)

在个人信息处能够上传个人头像，上传一张图片，同时抓包

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b34d5ba88f40f6a3141befd6aaad31af9efb7f0d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b34d5ba88f40f6a3141befd6aaad31af9efb7f0d.png)  
根据上传的路径定位到代码位置

`admin/controller/Index.php#4032`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-08b9de5e6e3168aaeeb6cde7479bdcc9017ee8c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-08b9de5e6e3168aaeeb6cde7479bdcc9017ee8c0.png)

首先会对请求方式做一个校验，之后调用`request`方法来获取`file`类的实例对象，可以看到这里写着上传的白名单；接着调用了`file类`的`validate`方法，跟进，代码就只有几行，发现只是设置了上传文件的规则；接着重点是调用的`move`方法，来看一下代码，有点长不好截图

```php
 public function move($path, $savename = true, $replace = true)
    {
        // 文件上传失败，捕获错误代码
        if (!empty($this->info['error'])) {
            $this->error($this->info['error']);
            return false;
        }
        // 检测合法性
        if (!$this->isValid()) {
            $this->error = 'upload illegal files';
            return false;
        }
        // 验证上传
        if (!$this->check()) {
            return false;
        }
        $path = rtrim($path, DS) . DS;
        // 文件保存命名规则
        $saveName = $this->buildSaveName($savename);
        $filename = $path . $saveName;
        // 检测目录
        if (false === $this->checkPath(dirname($filename))) {
            return false;
        }
        // 不覆盖同名文件
        if (!$replace && is_file($filename)) {
            $this->error = ['has the same filename: {:filename}', ['filename' => $filename]];
            return false;
        }
        /* 移动文件 */
        if ($this->isTest) {
            rename($this->filename, $filename);
        } elseif (!move_uploaded_file($this->filename, $filename)) {
            $this->error = 'upload write error';
            return false;
        }
        // 返回 File 对象实例
        $file = new self($filename);
        $file->setSaveName($saveName)->setUploadInfo($this->info);

        return $file;
    }
```

从代码可以看到如若上传出错，会直接返回`false`；接着会调用类中的`isValid`方法对文件合法性进行检查，最主要的是调用的check方法，这里对文件后缀的校验白名单就来自前面`$validate`数组，这里没有办法进行绕过  
全局搜索了`upload`相关的函数名，发现都做了白名单校验，直接上传行不通，那么就需要通过上传压缩包来达到`getshell`的目的了,后面三个都是成功getshell的点，除了最后一个前面两个还挺简单的

#### 关键搜索

在上传之前直接全局搜索和`zip`相关的代码，看看存不存在对压缩包内容进行解压缩的方法，找到了三个函数，一处为`uploadtheme`函数，刚好对应主题上传的功能点；另一处为`upgrading`函数，最后一处为`pluginlist`方法，先来看主题上传

#### 系统设置-&gt;主题(success)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f5f02e04a6ff304616823bd4d95fe552f0d1df7c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f5f02e04a6ff304616823bd4d95fe552f0d1df7c.png)

几个方法都是前面分析过的，所以上传压缩包肯定是没有问题的；之后会实例化`ZipArchive`类，该类为`PHP`的原生类，针对`ZIP`压缩文件进行相关的操作；这里调用了`ZipArchive`类中的`open`方法，并且传递的参数为`overwrit`e或者`create`；之后会调用`extractTo`方法，该方法将压缩文件解压缩到指定的目录，解压缩之后的路径为`/runtime/transfer/theme/zip文件名`

```php
ZIPARCHIVE::CREATE (integer)
如果不存在则创建一个zip压缩包。
ZIPARCHIVE::OVERWRITE (integer)
总是以一个新的压缩包开始，此模式下如果已经存在则会被覆盖。
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fb28c3fddc87600816ada0f63ab4684ee2b30143.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fb28c3fddc87600816ada0f63ab4684ee2b30143.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8265821841386e15b535d04d6a042318bf1b5c70.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8265821841386e15b535d04d6a042318bf1b5c70.png)

然后上传之后到指定的路径下去查看却没有发现解压缩之后的文件；结合前端代码，通过查看源代码定位原先默认的`theme`路径，在同路径下找到了我们上传解压缩之后的文件夹，成功`getshell`  
`/public/theme/tt`

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e85697eac6bb02971a0ed928f7a408e2a01e276b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e85697eac6bb02971a0ed928f7a408e2a01e276b.png)

#### 网站相关-&gt;插件列表(success)

`admin/controller/index.php#2649`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0254e308a0853ef8dbe3393983e56d1ddefeb826.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0254e308a0853ef8dbe3393983e56d1ddefeb826.png)

首先调用`checkUser`方法对用户的身份信息进行了验证， 只有管理员才能够进行相关操作  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c698bfbafedb4d8f9686aeeb0a635cdf34ef3dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c698bfbafedb4d8f9686aeeb0a635cdf34ef3dd.png)  
之后的代码逻辑跟上面getshell的差不多，就不多分析了，由于缺少插件存放的文件夹，所以会在根目录下自动创建存储的文件夹；上传之后的文件路径为`/plugins/tt`，也是能够getshell的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0dc5ad2cbd1b06ac4d605b6b454fcaca58124834.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0dc5ad2cbd1b06ac4d605b6b454fcaca58124834.png)

#### 系统设置-&gt;系统升级(success)

`admin/controller/index.php#4140`,这几个上传的函数方法主主体部分都差不多，存储路径不太一样，都是遍历了上传的压缩包内容，之后调用`file`类中的方法对文件后缀、大小等进行校验，校验符合白名单的就能够上传成功；这里上传成功之后，并没有解压缩操作，还是差了一步  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a02f75cefe370f87ff838ad89e2c02257d837310.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a02f75cefe370f87ff838ad89e2c02257d837310.png)

经过全局搜索，定位到`admin/controller/index.php#4168`，`upgrading`方法， 猜测应该就是对上传的系统升级压缩包进行处理  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d6f9c7b83de6fbf5280e5f24f64c990fd919f56f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d6f9c7b83de6fbf5280e5f24f64c990fd919f56f.png)

首先会调用`Catfish`类中的`getPost`方法，跟进，由于传入的`param`不为空，直接来看`else`代码部分；由于`$param=auto`,所以直接进入断点处的else,接着会调用`Requsest`类中的`has`方法对POST请求中是否有`auto`参数进行判断，`auto`参数可控，不传参直接返回false；这只会影响存储路径，继续往下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ac307bfd8b9e40824d2a6ea3dba95ea83df4f718.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ac307bfd8b9e40824d2a6ea3dba95ea83df4f718.png)

接着调用`Catfish`类的`get`方法获取更新文件的路径，跟进之后发现通过缓存来进行获取，这里猜测先通过上传压缩包，传递的`post`数据包不变，直接调用`upgrading`方法，就能够从上传缓存中获取到存储路径  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-63b4f8f931d7837a3269b44322bec0585874b22a.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-63b4f8f931d7837a3269b44322bec0585874b22a.png)

下面就是调用`ZipArchive`原生类对更新包进行解压缩操作了，那么这里也是能够利用成功的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bec41dc3c5c71b1686938196992d62f16fa3d211.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bec41dc3c5c71b1686938196992d62f16fa3d211.png)

先调用`upgradepackage`方法上传，再调用`upgrading`方法从缓存获取存储路径再进行解压缩  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a97ce81550063a7f34237625ecf49b2a30454088.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a97ce81550063a7f34237625ecf49b2a30454088.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1a01a43c18b718d5722015ac19788d91f9eda277.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1a01a43c18b718d5722015ac19788d91f9eda277.png)

解压出的文件存储在网站根目录下面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3ea7368f36fcfdd044ec67850ff61007cba50077.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3ea7368f36fcfdd044ec67850ff61007cba50077.png)

### 写在后面

经过一天的奋战，应该算是把文件上传getshell的点找齐了，还是得多审计呀，有些漏洞类型就审计的不是特别拿手，后续可能要去审计JAVA的CMS了。。。  
对了，最后一处为什么shell会在根目录下，可以去下载官方的更新包，会发现更新包里的文件都是根目录下的关键代码文件夹，应该是替换掉进行升级操作，也就能解释我们上传的shell为什么会在根目录下存储了。