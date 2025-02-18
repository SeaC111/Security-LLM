在网上发现一Phone Shop Sales Management System的店面管理登录系统  
\[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c25a6e3c00d82912fcf82e895c60585b347351db.jpg)\]  
用户名admin  
密码a‘or 1=1/\*  
登录成功  
\[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f7e4db8dfbfb23078fa0b1117fca2c7d2c75f9c9.png)\]  
但并没有用户信息，可见后台并没有限制访问，此处可能并不是sql注入漏洞  
接着我们点进invoice发票  
\[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-027e8c242f0ac95e0a39760bf2d4bcad46c0c7b0.png)\]  
可以看到大量发票信息和id号，我们随便点一个看看  
\[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c65b97e24c0e068d38f463eb99a0612e7edfcde8.png)\]  
可以看到一些发票信息  
但我们更需要注意Invoice.php? id=3005这个  
试着访问Invoice.php? id=3006  
\[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e8eae58a7d34c367d56965418a585cf590314296.png)\]  
可以看到其他信息  
经过分析，这应该是对象引用错误导致的，且没有对后台进行严格的权限控制