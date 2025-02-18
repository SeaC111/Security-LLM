某系统信息
-----

```php
http://x.x.x.x:8086/
```

感觉应该是手机端页面

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-28389d2e87dcc55edb02b36c21eada412b4df184.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-28389d2e87dcc55edb02b36c21eada412b4df184.png)

随便加个 admin 路径, 直接报错了

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-04cb9239406a50e1d24dc8446172d8c4d993fc6c.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-04cb9239406a50e1d24dc8446172d8c4d993fc6c.png)

TinkPHP3.2.3 版本  
路径也出来了  
据我所知tp3，有sql注入和日志泄露的问题  
结果找了半天没有发现注入点

日志
--

常见的日志路径

```php
Application//Runtime/Logs/Admin/20_05_01.log
Application//Runtime/Logs/Index/20_05_01.log
Application/runtime/logs/home/16_09_09.log
```

发现了一款比较好用的工具

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3e973d9872fb2a64022eb79dab754f293b05a7c5.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3e973d9872fb2a64022eb79dab754f293b05a7c5.png)

找到了两个用户名但是没有密码

```php
admin
test
```

日志路径也有了,打开看看

```php
http://x.x.x.x:8086/Application/Runtime/Logs/Admin/20_11_18.log
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-211d893d92a6501317d9c17f41593c500488567f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-211d893d92a6501317d9c17f41593c500488567f.png)

发现一个可疑的路径，应该是登录后才能访问的页面  
打开链接直接跳转登录页面

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-83d61a6399c567a3d71c5e052c535d4503d704b6.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-83d61a6399c567a3d71c5e052c535d4503d704b6.png)

继续往下翻，直接搜索admin关键词

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3a4edae12f7d799de58b96dcca1bd10759383f59.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3a4edae12f7d799de58b96dcca1bd10759383f59.png)

发现md5加密的密文  
可以破解密码

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-2383b2fb292724135763326d0da80e3c7947166f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-2383b2fb292724135763326d0da80e3c7947166f.png)

成功登录系统

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-441fe2febb3bd97b6d57e47db4a354e7c666a6ac.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-441fe2febb3bd97b6d57e47db4a354e7c666a6ac.png)

最后
--

后台功能很简陋，没有上传，不能getshell