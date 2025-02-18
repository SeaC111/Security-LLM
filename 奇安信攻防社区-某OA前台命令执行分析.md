前言
--

**本文所涉及漏洞均为互联网上已公开漏洞,仅用于合法合规用途，严禁用于违法违规用途。**

### 漏洞描述

通达OA（OfficeAnywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。通达OA11.9存在**命令执行漏洞**，攻击者可以通过命令执行漏洞并获取服务器权限，导致服务器失陷。

### 漏洞分析

webroot\\general\\appbuilder\\modules\\portal\\controllers\\GatewayController.php#actionGetdata

首先这里判断是否存在id参数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4cb8bf7c32bde7518028d62c18cdbaed55c0803a.png)

在确定存有id参数值后，判断传入的module的值后依次执行GetData与toUTF8方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a6e0dc81a1211274b9479dc3f7760194d60ed441.png)

GetData
-------

首先跟进GetData方法，根据id值进行查询

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-da1014ce051d75c1b8fb1393200ee16cc7041470.png)

数据库中内容如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-57bb64133d0356f427886191b4b0ce2d3e5c5fb6.png)

接下来判断查询出的$source变量的值，对$data赋值后将值返回

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4ca02cf99eb095cbc144053cc9bff497f818fe0d.png)

当查询出的 $source 不为 custom\_link 时 调用modules\\portal\\components\\AppDesignComponents #data\_analysis 这里会根据传入的$model值调用不同类的get\_data方法，所以在这种情况下$model值必须为已有的类名

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-5f3e92b62e0e7101b24d66aeff0ce185d9f50b7c.png)

随意跟进一个get\_data方法，这里也会根据 $source 值进行匹配，所以传入的id值在数据库中必须有对应的 $source 值

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-03ab0a3e1ca2c76322204bf0e17110c65bd1deae.png)

data值仅有 activeTab 是用户传进来的，其余都是根据id值在数据库中查询出来的

```php
$data = array("page_total" => "", "total_nums" => "", "curnum" => "", "pagelimit" => "", "open_mode" => $open_mode, "activeTab" => $activeTab, "data_sources" => $source, "data" => $url);
```

ToUTF8
------

将data经过GBK转UTF-8后,传入eval进行代码执行

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-7f1fa11a44fcb86ccda4cf62482e6d800a782b1b.png)

转码时候就与sql注入时接触到的宽字节注入一样，输入%df%27时首先经过上面提到的单引号转义变成了%df%5c%27（%5c是反斜杠\\），然后%df%5c正好属于gbk的汉字编码范围，经过iconv转换到utf-8编码转换后变成了汉字，从而吞掉了反斜杠使得单引号逃脱出来，下面就是一个简单的示例

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-cb3520e2e7940d0adb81bfdf7263cff1bd684f8e.png)

漏洞复现
====

> [http://192.168.31.70:8088/general/appbuilder/web/portal/gateway/getdata?activeTab=%df%27,1%3D%3Eeval($\_POST\[c\]));/\*&amp;id=19&amp;module=Carouselimage](http://192.168.31.70:8088/general/appbuilder/web/portal/gateway/getdata?activeTab=%DF%27,1%3D%3Eeval($_POST%5Bc%5D));/*&id=19&module=Carouselimage)

经过上述的分析过程，三个参数的值均不唯一，给出的复现链接仅供参考

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-7002f80c5b74bff5c1bc9f82e045325697738091.png)