前几天在逛github时发现有个开源cms出了个sql注入的漏洞，虽然时几个月前被提出来的，最新版也已经被修复，但是网上没有详细的分析过程，所以这里对这个漏洞进行分析并给出其他几种payload

0x00 漏洞复现
=========

```php
POST /api.php?c=call&f=index HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1/
Sec-Fetch-Dest: script
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
Connection: close
Cookie: PHPSESSION=bd34va2vksdhvqr8t1sll4lva7; XDEBUG_SESSION=PHPSTORM
Content-Type: application/x-www-form-urlencoded
Content-Length: 67

data={"m_picplayer":{"_alias":"abc","fields_need":"CASE 1 WHEN (substr((select database()) from 1 for 1)=0x70) THEN sleep(5) ELSE 1 END"}}
```

0x01路由分析
========

网站有三个入口（前端，接口，后台）都是从`framework/_init_phpok.php`这里执行，进行初始化处理

![image-20230526154045135](https://shs3.b.qianxin.com/butian_public/f2057366114986e5ebb06e6d9735840f08951ea009ea9.jpg)

我们以`action_api`为例，`$ctrl`和`$func`分别通过get请求中的`c`和`f`获取，默认值为`index`

![image-20230720142838728](https://shs3.b.qianxin.com/butian_public/f729556df2e7fa5f88b04d3d8c1b8590c445244fa1226.jpg)

然后在`_action_phpok4`中调用相关的控制器和方法，例如访问`http://127.0.0.1/api.php?c=call&f=index`就会调用`framework\api\call_control.php`中的`index_f`方法

![image-20230529161031587](https://shs3.b.qianxin.com/butian_public/f793726d3f111534a2084cef64a37ced5fde3280ae336.jpg)

0x02 漏洞分析
=========

我们首先来先看`framework/api/call_control.php`中的`index_f`方法，

对应的url请求路径为`/api.php?c=call&f=index`

![image-20230718184220323](https://shs3.b.qianxin.com/butian_public/f347223aff02bff74528c2a3c1fa41f7e84ec0fd792e0.jpg)

这里首先判断传入的值是否以`{`为首，如果是就将其转换为json格式

`$call_all`然后通过`$this->model('call')->all($this->site['id'],'identifier')`然后通过取得站点下的全部数据，并对数据进行格式化

在`all（）`方法中会获取数据库中的内容，并将`ext`中的数据反序列化

![image-20230718174335827](https://shs3.b.qianxin.com/butian_public/f3162218b37ae175004906acf2c35b7fd4adf9ac708eb.jpg)

下图时数据库存放数据的格式

![image-20230718164419191](https://shs3.b.qianxin.com/butian_public/f1603628a815dc8a5b23aff8f23ec8c4a3a4bb81c834e.jpg)

所以最终`$call_all`获取到的值如下图，其键为数据库中`identifier`列中的数据，值为`ext`反序列化后的数据

![image-20230718164202798](https://shs3.b.qianxin.com/butian_public/f56246091877fa43ce69a51df02196c585954cfc94ca3.jpg)

接着会遍历data中的数据

![image-20230718164345899](https://shs3.b.qianxin.com/butian_public/f441079ae59fffeda10fcf55344cd69adaf9dfdb6b055.jpg)

然后再下面的`if($call_all && $call_all[$key] && $call_all[$key]['is_api'])`判断`$call_all[$key]['is_api']`为真，那么就只有下面几个符合条件

![image-20230718172736208](https://shs3.b.qianxin.com/butian_public/f45340250cf6a805d67d47be40d5195f422bed43a3c60.jpg)

并将data中的键和值传递给`framework/phpok_tpl_helper.php`中的`phpok`方法，

![image-20230718181934492](https://shs3.b.qianxin.com/butian_public/f2697073a0689bd1dc46c86cebb726e5279483b91896f.jpg)

然后继续跟踪，这里又继续调用了`framework/phpok_call.php`中的`phpok`方法，下图是`phpok`方法代码片段

![image-20230718165237509](https://shs3.b.qianxin.com/butian_public/f7341614794f04b2ca510a6fb1b0ea2a14480ceefe1eb.jpg)

在第一个红框中获取到的`func`就是获取到内容的`type_id`，即到时候调用的函数名为`_arclist`

在第二个红框里注意默认开启了缓存，如果两次请求的数据一样则会直接返回缓存的数据，所以每次构建payload的时候需要改变数据

最后调用`_arclist`方法，并传递参数

其中在`_arclist`方法中调用`_arc_condition`方法，我们直接来看这个函数

![image-20230718165818563](https://shs3.b.qianxin.com/butian_public/f885211985f5b52a74b024bd60bd116237744e1ba86cd.jpg)

这里判断是否存在`fields_need`。若存在，通过`,`进行分割，由于payload中没有逗号，所以直接拼接到sql语句中。

![image-20230718172032442](https://shs3.b.qianxin.com/butian_public/f493660dc8e700a4276c6994901ebcc9955833326a873.jpg)

然后会将`$condition`参数传入到`arc_count`中方法，从截图中可以看出已经将payload带入。

![image-20230718172213648](https://shs3.b.qianxin.com/butian_public/f6670262884dcc18abf9408333bf805de7981adce3a3c.jpg)

在`arc_count`方法中拼接sql语句进行执行

0x03 梅开二度
=========

理解了漏洞的利用方式，我可以寻找是否还有别的地方也存在漏洞，

从调用函数执行的地方可以看到**程序是从数据库中获取方法名然后动态调用的**，所以我们的思路就是寻找可以动态调用的方法，在数据库中寻找`is_api`为1的数据，然后去通过`type_id`来查看这些方法中是否存在对其他参数过滤不严的地方。

![image-20230718172736208](https://shs3.b.qianxin.com/butian_public/f45340250cf6a805d67d47be40d5195f422bed43a3c60.jpg)

例如我们可以寻找`_catelist`方法中  
![image-20230719153942375](https://shs3.b.qianxin.com/butian_public/f30328261cf7a00aa446b26f3a6433074a4af6583cf66.jpg)

在这里发现并没有对`$rs['cateid']`进行任何过滤，如果存在该变量就直接将其放入模型中，这里再来看看`cate_all`是如何执行的：

![image-20230719154147457](https://shs3.b.qianxin.com/butian_public/f928897bec9fe8a2089299d24cdaad4636b58aa7f435c.jpg)

直接将拼接到sql语句中的orderby后然后执行

既然调用的是`_catelist`方法，对应的data的键就是`catelist`用以下payload可以证明我们的猜想：

```php
data={"catelist":{"_alias":"abc","orderby":"if(2=1,1,sleep(0.5))"}}
```

![image-20230719155620679](https://shs3.b.qianxin.com/butian_public/f22550880f731de4106dc528cdcce4a6000f2c35c5e11.jpg)

测试的时候发现延迟的时间并不是sleep(0.5)中的0.5秒，而是大于0.5秒，因为这里的延迟的时间和所查询的数据的条数是成倍数关系的

0x04 修复方式
=========

来看一下官方的修复方式

![image-20230718155402748](https://shs3.b.qianxin.com/butian_public/f452836248007369e1a4913c81ee08a3e131899c8da38.jpg)

这里对data传过来的值首先将他转化为json格式后使用`safe_text`方式进行过滤，同时在`safe_text`中新增了对`(`,`)`,`0x`进行过滤。