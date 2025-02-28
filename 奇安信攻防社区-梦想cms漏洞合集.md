### 前台SQL注入

根据更新特地指出的说明，确定引起前台SQL注入的为`p`函数，全局搜索`P`函数，定位到`function/common.php`，暂时先不看，由于是前台SQL诸如点，所以需要先找到漏洞点，index文件夹当中存储的都是前台可以访问的页面即调用的方法  
反向搜索调用了p函数的文件，定位到`c/index/TagsAction.class.php`

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7debc938b39eddf1857899332bd25f90e1ed377d.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7debc938b39eddf1857899332bd25f90e1ed377d.png)

在调用p函数对`$data`进行赋值之后，会调用`string`类中的`delHtml`方法对`$data['name']`进行去除html

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-763ebf0108af026743957e3243b92df4a402d9e7.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-763ebf0108af026743957e3243b92df4a402d9e7.png)

根据前面传入的参数，这里的`data`值通过`$_GET`进行传参，`$pe和$sql`都为`1`，`$mysql`默认为`false`，按照1为`true`，会调用`filter_sql`方法对$data进行处理；之后对$data是否为数组进行判断，这里可控，由于`$pe=1`,接着会调用`addslashes`方法对传入的值进行转义，然后返回值；下面来看一下

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6aa5985235be36db4a5e5bb4a03b7568fc902d00.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6aa5985235be36db4a5e5bb4a03b7568fc902d00.png)

首先对$data中的值是否为数组进行判断，当然没有任何影响，如果是数组就会进行循环调用filter\_sql方法罢了；之后会转换大小写并检测是否有黑名单中的关键词，有的话就直接报错  
回到最开始的构造方法，在url解码之后，会调用tagsModel类中的getNameData方法，跟进  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9c1250b3a3524eaed8ce5fe5edcc658a952ea657.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9c1250b3a3524eaed8ce5fe5edcc658a952ea657.png)

这里会调用父类的`oneModel`方法对`$param`进行处理，继续跟进

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc1245879e7f295e736f82a8829f3a6001b6a063.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc1245879e7f295e736f82a8829f3a6001b6a063.png)

调用父类的oneDB方法，继续跟进

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e1fded9db085cbd8eeac0c655a0b823886eddcae.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e1fded9db085cbd8eeac0c655a0b823886eddcae.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6a7efff94c822c8a2ada8799ccebf5c79712c86c.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6a7efff94c822c8a2ada8799ccebf5c79712c86c.png)

这里调用了类中的where方法对前面传递过来的$param进行处理，一开始的name就是可控的，所以这里的`$We="name=xxx"`,这里是进行了字符串的拼接，所以在执行时候会造成`SQL`注入，这里才是最后的注入点  
而触发点在最开始类中的index方法，这里会对结果进行打印输出  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d75e73dfb0bc6026ff1b25588d6c6ef65438eddc.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d75e73dfb0bc6026ff1b25588d6c6ef65438eddc.png)  
`index`方法中调用到的`parse`类中的`tags`方法这里就不深究了，感兴趣可以自己去看看  
poc

```sql
需要进行两次URL编码来进行绕过，浏览器默认解析一次
union联合查询：
SELECT * FROM lmx_tags WHERE name = '-1' union select 1,(select group_concat(table_name) from information_schema.tables where table_schema=database()),3,4,5,6,7,8,9,10,11,12#
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b05d9fdabb09d25aab63ef30305f6f3b33ca24d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b05d9fdabb09d25aab63ef30305f6f3b33ca24d1.png)  
一开始本来是想用union注入来打的，但是后面发现缺少相应的文件，没办法跳转，就拿不到回显，SQLMAP也是因为这个判断不了是否注入成果而跑不出结果，恰巧这里有报错信息，这里就是上面提到的tags方法中的内容，因为会到数据库里进行相应的查询操作，所以这里改为报错注入

```sql
报错注入
' and (updatexml(1,concat(0x7e,(database()),0x7e),1)) and '1'='1
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5aa71222278ed8135ba4210cb8ca56882f3a84d0.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5aa71222278ed8135ba4210cb8ca56882f3a84d0.png)  
要用sqlmap也是可以的，就是需要指定以下tamper脚本，两次URL最方便，实际上前面关键词WAF的绕过不止一种方法，像是用&lt;&gt;来进行绕过也是可以的

```sql
sqlmap.py -r 'burp数据包路径' --technique=E -v3 --tamper=chardoubleencode -p name --dbs
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2fb70da0561e1e3951bb3336c635e0a859341ec6.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2fb70da0561e1e3951bb3336c635e0a859341ec6.png)

### 任意文件删除

漏洞点位于后台首页-&gt;图片管理，选择一张图片进行删除，Burp抓包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac6a89038c3477e8e6aa054f1917a4fb7226e8c2.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac6a89038c3477e8e6aa054f1917a4fb7226e8c2.png)

根据请求路径，定位到代码  
`c/admin/FileAction.class.php`

```php
 public function delete(){
        if(!$_POST['fid']) rewrite::js_back('请选择要删除的文件');
        $this->fileModel->delete($_POST);
        addlog('删除文件、图片');
        rewrite::succ('删除成功');
    }
```

先判断$fid参数是否进行传参，之后调用`delete`方法进行了传入的数据处理，跟进，发现调用到了`FileModel`类中的`delete`方法  
`m/FileModel.class.php`

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2ea65895e3ca42912df3821f932bf8a388ee5085.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2ea65895e3ca42912df3821f932bf8a388ee5085.png)  
传入的$data是一个数组，存有`POST`传递的三个参数，根据`POST`包中的数据，`$data['type']=`0,接着会循环遍历$data，键值指定为`$fid`,之后会调用explode方法对$v值进行分割处理，`$fileInfo[1]`才是我们指定想要删除的文件的真实路径，并且在传递之前会去除首尾的`/`；后面调用implode函数将一维数组转换为字符串重新赋值给`$fid`;下面的if始终满足为true，之后就会调用unLink方法进行文件删除了。  
经过测试，可以进行目录穿越，也就可以进行任意文件删除操作

```php
poc
type=0&fid%5B%5D=1#####/filepath
```

### 任意文件读取

定位到代码位置  
`c/admin/TemplateAction.class.php#81`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9d9e7a7554df059f75a1fbb5f8c8639b74108792.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9d9e7a7554df059f75a1fbb5f8c8639b74108792.png)

直接通过`GET`传参传入文件的路径，由于这里没有`POST`传入的几个参数，所以直接跳过if判断，直接到下面将文件的路径进行赋值，调用`file`类的`getcon`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3604bd5e635ad15170483b4706fe51e20ba4aa49.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3604bd5e635ad15170483b4706fe51e20ba4aa49.png)  
该方法直接读取了文件内容， 并且会检查文件的权限问题；之后调用string类中的html\_char方法转换html实体并去除空格  
这里就可以利用路径穿越来读取任意文件了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5c92acf8a4efc9042060c9d5bd8094ffd467e093.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5c92acf8a4efc9042060c9d5bd8094ffd467e093.png)

### 写在后面

SQL注入还是审计的少了，在打POC那里卡了好久，愣是没想到用报错注入可以直接打出结果，后面在大哥的提醒下还是顺利解决了，后面的两个漏洞属于鸡肋了，毕竟需要后台权限，没什么作用。  
ps：漏洞已经在新版本修复了~  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c98bd0f688458b0941f713eb4e66cc3a6896600c.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c98bd0f688458b0941f713eb4e66cc3a6896600c.png)