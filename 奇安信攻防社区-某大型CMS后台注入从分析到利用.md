### 搭建环境

[Github](https://github.com/yangzongzhuan/RuoYi/releases)找一下若依4.6.1版本下载到本地，丢到IDEA里面，数据库文件导入，druid连接池配置文件中修改username和password  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9d36b77ee3946b96b55fd21fb2347480dfb329ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9d36b77ee3946b96b55fd21fb2347480dfb329ff.png)  
在application.yml文件中可更改服务默认端口，80端口被占用修改成其他空闲端口  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e7cf4e0c54c577f62b42698790cb45528dc92107.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e7cf4e0c54c577f62b42698790cb45528dc92107.png)  
完成数据库导入和配置文件一些必要信息的修改之后就可以运行整个项目了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e492a3ce690133d7d21b1e3772ec068deb01fa7a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e492a3ce690133d7d21b1e3772ec068deb01fa7a.png)

### 漏洞分析

若依cms这个后台SQL注入貌似还没有公开漏洞细节，相关的分析内容很难找，Google到了其中一篇文章，获取到了关键的污点传播路径，整理如下：

```php
RuoYi/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java:56,`role`为污点源
->RuoYi/ruoyi-common/src/main/java/com/ruoyi/common/core/domain/entity/SysRole.java:37,污点源从`role`传递至`dataScope`
->RuoYi/ruoyi-system/src/main/java/com/ruoyi/system/mapper/SysRoleMapper.java:19,污点传入selectRoleList方法
->RuoYi/ruoyi-system/src/main/resources/mapper/system/SysRoleMappper.xml:36,'SQLI'类型触发注入
```

初看比较疑惑，顺着污点传播路径跟进不太明白poc是怎么整出来的，看到最后的xml文件也就是漏洞触发点也就清楚是怎么一回事了，先从污点源开始看  
`RuoYi/ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-718e54872c53feab94fc8c5641fd632b62753bbe.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-718e54872c53feab94fc8c5641fd632b62753bbe.png)  
查看代码可以确定利用的漏洞路径为`/system/role/list`，以POST的方式进行传参，可以看到初始的污点源为传递给`TableDataInfo`的参数`role`，跟进方法中调用的`startPage()`方法  
`Ruoyi/ruoyi-common/src/main/java/com/ruoyi/common/core/controller/BaseController.java`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-812ca8afcc70df09e6e27d64c2a65a8bf9fce518.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-812ca8afcc70df09e6e27d64c2a65a8bf9fce518.png)  
函数体打断点处，调用了`TableSupport`类的`buildPAgeRequest()`,如果`pageNum`和`PageSize`两个参数值不为空的话就会进行分页处理，调用的是pagehelper这个第三方插件，跟进`buildPAgeRequest()`方法分析是如何进行赋值处理的  
`Ruoyi/ruoyi-common/src/main/java/com/ruoyi/common/core/page/TableSupport.java`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f14197fad98a297c1fa1c42ec62b5c8b62746149.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f14197fad98a297c1fa1c42ec62b5c8b62746149.png)  
实例化一个`PageDomain`类，并通过`ServletUtils`类从post传递的数据中获取对应的参数值,所以这几个参数值对漏洞利用并没有太大的影响，让其获取到的都为空就可以，第一部分poc

```php
pageSize=&pageNum=&orderByColumn=&isAsc=
```

顺着污点传播链，跟进`RuoYi/ruoyi-common/src/main/java/com/ruoyi/common/core/domain/entity/SysRole.java`文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-33b82a2334725c529312de832dd6dc227f9dc78d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-33b82a2334725c529312de832dd6dc227f9dc78d.png)  
对`dataScope`参数的一个拼接，并且进行了类型的转换，继续跟传播链，`RuoYi/ruoyi-system/src/main/java/com/ruoyi/system/mapper/SysRoleMapper.java`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ed790d429d85109bd05ef8ce9c29c398def8ca25.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ed790d429d85109bd05ef8ce9c29c398def8ca25.png)  
注释已经写明此处根据分页查询角色数据，暂时不知道污点为何会传入`selectRoleList()`方法，继续跟传播链  
`RuoYi/ruoyi-system/src/main/resources/mapper/system/SysRoleMappper.xml`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-265e0aefa142babd3dd84ae00890987a24bb4245.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-265e0aefa142babd3dd84ae00890987a24bb4245.png)  
可以看到这里是SQL查询语句，具体为什么这么写可以去自行百度一下，可以看到这里直接将`${params.dataScope}`拼接入了SQL语句中，因此构造SQL注入语句就能够查询我们想要获取的数据，到这里也就不难理解为什么污点源会变成`dataScope`,现在根据公开的poc来捋一捋整个链

role为初始污点源-&gt;调用`RuoYi/ruoyi-system/src/main/java/com/ruoyi/system/service/ISysRoleService.java#selectRoleList`方法-&gt;`selectRoleList`方法调用`RuoYi/ruoyi-common/src/main/java/com/ruoyi/common/core/domain/entity/SysRole.java`中的`SysRole`类，该类会对`dataScope`参数进行处理-&gt;`dataScope`传入了`RuoYi/ruoyi-system/src/main/java/com/ruoyi/system/mapper/SysRoleMapper.java#selectRoleList`方法-&gt;调用SQL查询时拼接`dataScope`参数值进行了注入

可能并不是很准确，但是自己是这么理解的，有师傅理解更到位的话请多多指教  
第二部分poc

```php
roleName=&roleKey=&status=&params[beginTime]=&params[endTime]=&arams[dataScope]=and extractvalue(1,concat(0x7e,substring((select database()),1,32),0x7e))
```

将两部分poc结合也就得到了公开的poc，其实从poc入手，再直接看到最后的漏洞注入点能够更好理解poc为什么是这么构造的，其他参数的值皆为空默认就会为null，只传入dataScope这个参数值也是可以的

```php
url/system/role/list

POST:pageSize=&pageNum=&orderByColumn=&isAsc=&roleName=&roleKey=&status=&params[beginTime]=&params[endTime]=&params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))
```

### 本地复现

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-81b5300a136840d396744343ddfc046c5e913edf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-81b5300a136840d396744343ddfc046c5e913edf.png)  
可以看到通过报错注入获取到了数据库的名字，后面更改SQL语句就能够获取到详细的数据库信息了

### 项目测试

打开给定的地址，看到这个界面就觉得很熟悉，之前审报告的就是就看到很多回，若依没跑了，站点应该只是更改了一些静态资源。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9327d95341d4da39e9844a7d6dfc5be6bc60d030.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9327d95341d4da39e9844a7d6dfc5be6bc60d030.png)  
登录还是常规手段尝试弱口令，admin/admin123，直接进去了后台  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8b8eaa9027f822e105265905662c54dc8fa34293.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8b8eaa9027f822e105265905662c54dc8fa34293.png)  
burp抓个包，poc打过去，获取到了数据库名  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fe835d70dc5f58a1e4fc4d4039a7fd9edcdfc3b8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fe835d70dc5f58a1e4fc4d4039a7fd9edcdfc3b8.png)  
得到如下部分数据库中的信息，详细的就不公开了

```php
exam_banner,exam_collect,exam_p 表名
id,title,banner_img,is_put,cont  #exam_banner表中的列名，不完整，长度限制，可以分长度读出
```

### 总结

整个到这里就差不多结束了，漏洞分析的可能不是特别到位，师傅们轻喷，只是想知道poc的参数是怎么构造的才去扒拉源码分析的，跟着poc去分析会更好理解，也就有了这篇文章。