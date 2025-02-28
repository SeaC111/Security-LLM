最近发现这个cms有个上传洞，于是心血来潮的审计了一下，整体技术含量不是特别大，代码审计初学者也可以学习一下。

#### RITEcms

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-cb2e05adcaaeb2b1f63c2471add1a9c7d3f21f95.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a04ac93692c797eaf377b3a9eb852720b951e28b.png)

#### 访问admin.php，然后输入默认账密admin admin，再次访问admin.php进入后台

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8fb8cb3b1c851bc987b5b3d3de3840cae1c67b65.png)

#### File Manager

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a6435ba6fa66cf45bfbc1eeb7bffb6f7673367f2.png)

#### Upload file

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f099cbd644e2949c89cb724eeedeff39fde97dc4.png)

#### 选择文件

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-28890200f7b5d1af78f392caacb9118fffd4e31f.png)

#### OK-Upload file

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b809d807c7366e70e26f32417441e6d8576efe1f.png)

#### 下面进入代码审计

##### Admin.php中，进入到filemanage.inc.php文件

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-664a85179285b1eb6a19a86fe9aa5d66a707ae6f.png)

##### 进入之后看到fileupload函数，这里new一个类，把对象赋值到upload，然后全局搜索FileUpload，发现是在cms/includes/classes/FileUpload.class.php文件当中

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-328a1946f1c4ab14ebc7d3d4ecca033f05d36ba9.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-92c07003bd0819665e3ff4346c14d543d980caff.png)

##### 这里赋值了upload和uploaddir参数，因为这里是一个构造方法，它的构造方法，就是在这个实例化对象的时候才会调用，然后construct后面两个参数是在实例化的时候加进去的

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c472988c8da69c2ac67d83d72d7804e461588381.png)

##### 继续往下走

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-83ad5e86cf2fd6838a7a8add3147362aad1b1690.png)

##### 在73行有move\_uploaded\_file函数进行上传，前面的$this-&gt;upload\[‘tmp\_name’\]是之前上传的文件临时文件夹的后缀名，后面的$this-&gt;uploadDir.$tempFileName是BASE\_PATH.$directory.’/’

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3321b70ee017d0c280e12b2de187f4bba9a68d6c.png)

##### 然后回到刚刚的filemanager.inc.php文件

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-81ccd87e3512c12597ca8d99ecd33fcb19819916.png)

##### 看到base\_path，我们再去全局搜索一下，在文件/data/settings.php中

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-050956192b31cce1fd1d95c09b6407d1cb94f13e.png)

##### 在settings.php文件中可以到，返回了绝对路径的上一级目录

##### 然后跟踪directory参数

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d195831f7846ef4073f3d9f1944f62aa4e7d6abc.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2bcd77fa23582ed30efcfefa6957e42e4aebcf59.png)

##### 这里的目录是不固定的，如果判断为true，则是/files，如果为false，则 是/media

##### 然后继续往下走

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-81c55d3db7e1333b10c4dfc28d2a6b00deabe43e.png)

##### 如果为false进入else语句，调用savefile函数

##### 这里把file\_name传进去，对应public function saveFile($filename=’’)的filename，这里的filename和file\_name的变量名不一样但是传的内容是一样的

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1fe7732d0b93730e525752e80c33f826488b0ee6.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9b1fc64fe0977368b00bd88278c10ae896921b24.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2e8f2111711f80267d5d8402fd47639cf62c42d1.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-6046c1111e9cb23b7e6d9363408fe480d16c09b8.png)

##### 该函数直接用copy函数将临时文件复制到后面的文件中

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5714c13d872c5fe327c51e4d76b21f9c97a0448e.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-902e9b28acffbb061826a50f6d2e1d1520a7aeef.png)

##### 这是copy函数中的参数来源

##### 任意文件删除

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-dc7a57be3ff3233b2665eb2e9c25b8919e0b1eac.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-791966e606ebcfacc72d25bf91144b11b9ce7fd7.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5a1ecb44fd0f8a55d35554b1c830f038ee368fad.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9fc2cefbcf3447070d8079bc745b8e0856017238.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f91ef73cc850ebec1e8f1b8abf2f82ecb6e6c396.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-efdfd67d1fd97b6366185361f6d31dbc66306957.png)

##### 在filemanager.inc.php文件中，如果传过来delete，并且存在cofirmed，就会进入unlink语句判断，因为没有做任何的过滤，这里就可以造成任意文件删除，BASE\_PATH参数跟上面的文件上传是一个参数，这里就不在赘述了

##### 心血来潮审计一下，目前最新版依旧存在该漏洞，有兴趣的师傅可以自行下载审计一下，还是比较简单的，源代码： <https://ritecms.com/download>

##### 微信公众号 ZAC安全

##### 因为这篇文章写的较快，所以难免会有错误和遗漏的地方，如有师傅对文章有疑问或者发现错误等，辛苦师傅联系我一下，本人微信 zacaq999