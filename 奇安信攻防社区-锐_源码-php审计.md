锐捷网络-EWEB网管系统代码审计
=================

路由规则：
-----

/文件夹名/文件名.php?a（action）=flowEasy（方法名）  
/文件夹名/文件名.php?c（controller）=flowEasy（控制器名）

### 例子：

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2943b0a4a259f4d2101b78d8b7ddedc8b60a9d9c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2943b0a4a259f4d2101b78d8b7ddedc8b60a9d9c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5cc54eeee8bed8c345bd04a0fd7c9053a80d84bb.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5cc54eeee8bed8c345bd04a0fd7c9053a80d84bb.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bf52f61df24cf6d8ed2ee71231294154181ca09e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bf52f61df24cf6d8ed2ee71231294154181ca09e.png)

审计步骤：
-----

### 查找关键点一：全局搜索关键词exec

在这里发现了一个关键点，继续往下看。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f58a76b8662666537fd9ed4f3503c20c1210e1b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f58a76b8662666537fd9ed4f3503c20c1210e1b4.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f1e20ab672748c126d755d8d363b7fc61b35c32a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f1e20ab672748c126d755d8d363b7fc61b35c32a.png)  
而P方法存在于/mvc/lib/core.function.php的类里面，是用来接收POST传参。  
post传mode\_url、command、answer参数，将mode\_url赋值为exec  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e71dc72da7b652fc958a5938f600cfad194c816c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e71dc72da7b652fc958a5938f600cfad194c816c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7bbdd4e0ea4fe79c5e989c8eef2f012c892b5d72.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7bbdd4e0ea4fe79c5e989c8eef2f012c892b5d72.png)  
然后将三个参数的值传到/mvc/lib/core.function.php类的execCli方法中，然后判断command是否存在并且是否为空，最后到下面的php\_exec\_cli函数（不知道是函数还是方法，文件里找不到）进行执行从而导致命令执行

利用方式：
-----

1：post请求  
2：必须有mode\_url、command（command传命令参数）、answer  
3：a为index  
比如：mode\_url=&amp;command=dir&amp;answer  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d4f13dd706af885ad281d0902b8ed2d1a763fe0b.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d4f13dd706af885ad281d0902b8ed2d1a763fe0b.png)