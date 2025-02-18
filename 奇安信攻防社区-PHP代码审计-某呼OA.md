环境搭建：
=====

使用phpstudy进行环境搭建  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678672815814-fee15537-f691-4eb8-b9a6-14774471dcaa.png)  
进入下一步。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678672825628-abe83c2d-9796-46be-8f86-ee6d92818369.png)  
使用用户名和密码进行登录。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678672839728-fb92add2-d476-49fe-b435-69a7823a77d0.png)

代码审计：
=====

1.文件上传
------

进入个人办公-工作日报-我的日报，使用新增功能。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673121083-dd775c77-2ab3-4e98-83fc-71361d5786e6.png)  
然后上传文件  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673150065-706e42e0-6556-46ae-b03f-d092ed16e95f.png)

通过burpsuite抓包，定位路由。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673222993-876e25ec-bae8-4d01-9494-49443e9de851.png)

通过抓包分析定位到了源码，这里调用了uploadAction.php下的upfileAjax() 方法。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673353898-a4bfbf00-effd-4ea7-9941-d314bbab5eca.png)

在代码44行中调用了 c() 方法，并包含了 upfileChajian.php 文件。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673379644-6105b466-268b-40c0-ad9b-acceb724f6aa.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673409617-08cd9613-03fd-44ca-9b27-221424a3f7af.png)  
在代码的49行调用了 upfileChajian.php 下的up()方法，  
我们去跟进up()方法。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673500788-cd1cf488-13cf-48e3-b9dc-d896511ee781.png)

我们从 upfileChajian.php 文件中发现该upfileChajian类就是用来实现文件上传的一个类，而这的up()方法中的issavefile()方法是用来进行后缀判断的，我们跟进该方法。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673559215-927ad497-c799-45e3-b71f-0da2cb287390.png)

如果后缀为白名单中的则 $bo 返回true,否则返回false。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673609790-68f82d0f-5dce-4953-8489-738c00b9c041.png)

进入filesave()方法，我们跟进该方法![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673674861-46dcf36d-7655-4ad5-a3a0-bd7f12695b49.png)

通过描述我们大致知道该方法是将不在白名单中的文件保存问uptemp文件形式，代码254-256中可以看到，这里读取了我们上传的文件内容并且将文件内容base64编码，并将文件内容写入到 .uptemp 文件中，最后将我们上传的恶意文件进行删除。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673710620-adc5c5e9-454e-4624-860e-c91a0b07fcfe.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673759285-674f92ed-8821-4367-817f-bf3b48abbf79.png)

回到 upfileAciton() 方法中， $upses 接收 up() 方法返回的数据并将数据通过 downChajian.php 中uploadback() 方法备份到数据库，并以json形式返回。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678673975152-fb081640-2d11-44a1-839b-4f92579b2652.png)  
我们发现这里上传到的.php文件后缀会被替换为 .uptemp 后缀的文件，并返回了上传路径。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678674022347-3db0496a-5f68-44a6-9061-30bd1e03e891.png)

在查找关键函数的时候，我们发现可以解密 base64 文件的方法，关键可以通过控制id来还原 .uptemp 后缀为之前上传的后缀。从代码2的内容也可以看出，这里就是上面上传处理的一个反向操作，并且是通过 $fileid 参数来控制上传的文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678674113934-a1e4c5f6-2d38-4a1e-8d1f-8da0ad0ae3ab.png)

### 漏洞复现：

查看源代码。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678674530755-b1875914-0d69-4d8c-a6d0-0ab7eb7fe0ae.png)

然后替换上传id为我们之前上传的 eval.php 的文件id值

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678674689168-1a5c9221-a094-418e-8cf2-35f679dee4c4.png)  
漏洞url:[http://127.0.0.1/task.php?m=qcloudCos|runt&amp;a=run&amp;fileid=12](http://127.0.0.1/task.php?m=qcloudCos%7Crunt&amp;a=run&amp;fileid=12)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678674932263-8207e63f-d88f-4380-91d4-899c05e65d34.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678674974459-2a95579a-3c5e-4489-8500-4ea5475df191.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678675196844-7c7a78d2-8b62-4f5a-ac51-c0c820ec15af.png)

2.文件包含
------

全局搜索include\_once关键字时

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678675466671-faeb53f9-4970-42bc-a759-3371bbd1c3ab.png)

回溯包含的 $mpathname 变量，发现代码都对 $mpathname 这个变量进行了赋值，先来看前面的代码，这里由两个变量进行拼接， $tplpaths 、 $tplname 。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678675528931-05b3b3e9-466a-4278-98a8-6eee90c89f97.png)

从下面的我们可以发现这里的 $tplname 的后缀是被限制死的，这里只能是包含html文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678676138712-54f8b790-96d9-4673-8529-51c8e3564536.png)

接着去看对 $mpathname 的赋值，然后发现 $xhrock 变量，向上回溯该变量发现在代码37行处这里去实例化了一个类，而该处的 $clsname 变量是通过 $m 控制的，但这里的 $m 是可以通过前端传入的。  
我们跟进 strformat() 函数

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678676225674-2bd70d97-768c-4e76-9b39-757bea7286c6.png)

在代码中发现 $m 是可控的，所以我们要找到一个类文件中 $displayfile 可控的地方。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678676284963-d7b13e31-b040-4a04-8850-9fa67479538d.png)

然后搜索 displayfile ，我们发现其中indexAction.php的 getshtmlAction 函数中的 displayfile 变量是通过 $file 进行赋值的。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678676352460-84eef014-e78a-4265-9137-1a17ef8ec90c.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678676380382-119dc3cb-5bed-43e2-ac3e-63554520d1c9.png)

而回到View.php中这里我们可以控制$m来调用indexAction.php文件并且实例化文件中的indexClassAction 类，并且可以任意调用该类下的方法，也就是可以调用 indexClassAction 类下的getshtmlAction 方法，具体可以看下面代码。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678676512566-d5122f71-ea0f-4a98-898d-649d24b898ce.png)

### 漏洞复现：

我们在根目录下创建x.php进行测试

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678676599205-6f98d90e-beec-4374-8427-701fe4a618c3.png)

这里的surl要进行base64编码，这是由于代码中对 $surl 参数进行了base64解码。

<http://127.0.0.1/?m=index&amp;a=getshtml&amp;surl=eC5waHA==>

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678687852939-1ec7ccea-0479-4658-99fe-2a27007e61a4.png)

3.SQL注入漏洞
---------

进入webmain/system/geren/gerenAction.php文件，发现函数 changestyleAjax() ，可以通过post传入style参数来实现update的SQL注入。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678687937389-a8f5cc8c-61e6-453b-aa6b-f6fb9754a109.png)  
接着看post是如何传参的，发现封装的post()函数可以接收post以及get传参，而下面的jmuncode()函数

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678687978447-a863c4e6-997a-40fd-baf4-6f8d48e78d4d.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688031147-b8e21b8d-46e2-431e-88e5-c326950b52db.png)

jmuncode() 函数是用来对传入的参数进行过滤以及非法检测的。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688107839-ed3127f7-5add-496d-a360-38f605902442.png)

所以这里我们就可以通过传入style参数来控制修改admin数据表中的内容。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688182048-dfa962e4-1f7f-478c-9c59-2b97cdf85dd3.png)

这里的 $\_confpath 指的是要写入的路径，通过调试发现其实是写入到了webmain/webmainConfig.php 文件中，其中 $str 的内容中 $this-&gt;adminname 其实是对应的admin表中的name字段值，我们可以通过执行该方法来进行验证。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688348246-21c7e590-e387-4f77-b4ba-5505c731b18e.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688440056-2e6dadad-5093-4b26-8e67-1bacdeb71728.png)

我们可以发现在 webmainConfig.php 中写入了刚才的文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688481224-b87e2827-6688-4e22-aa29-082e47069b56.png)

这样我们就可以把上述的两个点进行利用，通过SQL注入update更改admin表中的name字段值。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688551299-2071e812-8731-4af4-9b50-a08f823664d2.png)  
在通过file\_put\_contents()写入到配置文件中。由于该配置文件不能直接访问，所以要获取shell就要找到一处包含该文件并能通过路由访问到的文件。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688573804-827a4bba-92f4-4812-8a3b-cb55440e08e2.png)

我们可以通过控制 changestyleAjax() 函数中的style参数来实现SQL注入更改admin表中的内容，这里的name传值需要使用十六进制编码，这样就可以绕过POST函数的检测。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688648302-e8798e95-4ca5-4173-ae68-ae8037aa9bbf.png)

### 漏洞复现：

我们通过如下路由：

/index.php?a=savecong&amp;m=cog&amp;d=system&amp;ajaxbool=true

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678688692544-e84e6a6a-f060-430c-a8b9-819be2d00463.png)  
构造payload我们可以将数据库中的 name 字段改为一句话，并且通过换行来绕过单行注释实现注释的绕过。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678689130430-1d085ca6-28eb-496d-ae61-25b319c24f18.png)  
成功写入配置文件。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678689228636-624d6b64-a677-49d8-bf13-5aa9a14a246f.png)  
访问文件进行触发漏洞。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678689426757-5a9322aa-34ee-402e-814b-56ec066dba5c.png)

4.SSRF漏洞
--------

进入include/chajian/curlChajian.php文件中，  
发现如下函数 getcurl() ,该函数中用到了函数curl\_exec()

函数。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678689966246-36fb29ba-53d3-46c5-8d17-1ac79347edcb.png)

我们发现调用了 getcurl() 函数，而这里的 $url 是通过Model层的 reimModel.php 中的 $url =$obj-&gt;serverhosturl 。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678690007068-817d71ce-f06f-410a-9661-d11a3ba66219.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678690042763-e1e089dd-ebd8-4c73-bdb9-31e7c450e694.png)

这里调用了option表，通过getval()来获取reimhostsystem对应的值，这里知道上述 $url 的值的获取方式。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678690130127-420286be-af88-4daf-90d4-ba4d30ceb376.png)

在webmain/main/xinhu/xinhuAction.php中 setsaveAjax() 方法中可以设置该处字段值，这里可以通过传入host来控制该处字段值。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678690171646-1ecd98bd-1f6c-43e7-b7e6-fd6494501b1d.png)

### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678690353729-9444f307-d6f7-49f9-8ed4-59a6a26e89b4.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678690441461-b1a2893f-549f-46cc-8b67-f9757645b58a.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678690423580-fc6e8451-aca5-47b0-bea3-ac37cfdb559a.png)

5.XSS漏洞
-------

定位到\\webmain\\login\\loginAction.php文件

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678691527227-fc1cc5a9-9204-4578-9b30-af8ee80ae26a.png)  
跟进ActionNot类。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678691593671-3ed075fe-692a-4d45-bd02-f18ab6962a57.png)

ActionNot类将大多数xxxAjax方法覆盖为空，然后getoptionAjax方法没有被重写，看一下getoptionAjax方法的逻辑。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678691623159-c0f9ffd9-bc3e-4f14-814d-e9db999743b6.png)

跟进getdata方法。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678691979867-8e7ad828-e533-4ea6-a559-4e261e4d4919.png)

getpids方法中调用了getmou方法，这里$num由于是get方法传递过来的，没有过滤反斜杠（\\）的。

跟进getmou方法。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678692078234-6bc12373-8433-449f-b551-825b56668d91.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678692141542-4dff50d6-01d3-4ae4-ae2e-670e0118eb73.png)

当num最后一位为反斜杠时，SQL语句变为，select xxx from xxx where abc=’\\’，至此SQL语句出现问题，从而抛出异常，触发debug的addlogs方法，在该cms中，debug是默认被开启的，我们跟进addlogs方法。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678692238309-bc7d3794-6172-4f4b-8b3b-5de5882e4bb0.png)

我们跟进insert方法，

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678692340040-cec2d191-ce8f-45cb-8e7d-d04bfc78f3e5.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678692540268-77c28306-92d0-4d9f-afa4-7585903731b7.png)

### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678693821440-266935cb-733c-4710-93b1-114fdafb6758.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678693720174-75ac4c7b-8a75-4179-a488-5cdbc05da0a8.png)

6.后台配置文件getshell
----------------

全局搜索gerenClassAction方法

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678696527040-b2759a78-657c-47c1-ad03-0594e8db7dc1.png)

发现在V2.3.0版本后，int强转只取第一个参数的值

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678696602578-67455383-1bbc-4c78-9550-fde4bbd7f9e7.png)

之前版本

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678696667847-8a689ccd-f939-4c00-81f8-bc4a51e915c6.png)

新版本，新版本已经对这个漏洞进行了增加了限制。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678696683413-86cba0ba-11a0-4076-8e4d-67799cb1ac6b.png)

但是saveCongAjax函数没任何变化

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678696741576-a0c0d045-3349-405e-b6d1-c78e7976d507.png)

直接利用后台的用户改名功能重命名管理员的名称，在rockClass.php新建了函数过滤，eval不能使用。直接用assert代替即可  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678696793202-cc4d12ca-bffb-4f3c-97bd-6dc41772d3d6.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678697022031-79ecb08f-a96a-4ec2-b4fc-0d42c1840dd6.png)

### 漏洞复现：

进入用户中心。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678694639810-9013dec8-183d-43a1-983c-621fc416e594.png)  
修改用户名。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678694700384-0510a2cc-c366-404b-8521-290fec58e5c9.png)  
发现成功写入了配置文件。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678694774807-d95d6426-a8ad-4150-84da-3e98f645ff91.png)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678695239259-7bc56507-37f3-4020-a9c4-fa655d516d22.png)

REF:  
\[<https://www.freebuf.com/articles/web/286380.html>\]  
[https://wx.zsxq.com/dweb2/index/topic\_detail/214514585882881](https://wx.zsxq.com/dweb2/index/topic_detail/214514585882881)  
<https://www.cnblogs.com/p00mj/p/11797819.html>